/**
 * M8B F13 (Brief 3) — cello_initiate_session must not report success when the offer
 * was never accepted.
 *
 * Mechanism under test: when the responder cannot proceed it aborts SILENTLY
 * (session-ceremony.ts wireSessionOfferHandler logs session.offer.abort and sends
 * nothing), and the directory folds an EMPTY counterparty endpoint into the
 * FROST-signed assignment. The initiator then accepted that broken assignment and
 * returned ok:true + sessionId; the failure only surfaced on the first cello_send
 * (session_stream_unavailable) — or never, plus a phantom session row accumulated.
 *
 * Contract pinned here (initiator-side validate-what-you-receive):
 *  1. An assignment carrying an empty counterparty_session_peer_id →
 *     {ok:false, reason:"counterparty_unavailable"} and NO local session state.
 *  2. Regression: a well-formed assignment still returns ok:true with the same shape.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

function makeInjectableSignaling(): () => Promise<ConnectResult> {
  const stream: SignalingStream = {
    send: async () => {},
    onMessage: () => {},
    close: () => {},
  };
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 61));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const TS = 1_700_000_000_000;

function makeAssignment(alicePubkeyHex: string, counterpartyPeerId: string, counterpartyAddrs: string[]): SessionAssignment {
  return {
    session_id: SID_BYTES,
    participant_a: { pubkey: Buffer.from(alicePubkeyHex, "hex"), peer_id: "", multiaddrs: [] },
    participant_b: { pubkey: new Uint8Array(32).fill(9), peer_id: counterpartyPeerId, multiaddrs: counterpartyAddrs },
    relay_endpoint: { peer_id: "", multiaddrs: [] },
    directory_endpoint: { peer_id: "", multiaddrs: [] },
    session_timestamp: TS,
    directory_pubkey: new Uint8Array(32),
    directory_signature: new Uint8Array(64),
    transport_mode: "direct",
    counterparty_session_peer_id: counterpartyPeerId,
    counterparty_session_addrs: counterpartyAddrs,
    signature_type: "frost",
    signer_pubkey: new Uint8Array(32),
  };
}

describe("M8B F13: initiate_session validates the counterparty endpoint before reporting success", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];

  beforeEach(async () => {
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    tempDir = await mkdtemp(join(tmpdir(), "cello-f13-"));
    handles.length = 0;
  });
  afterEach(async () => {
    for (const h of handles) { try { await h.stop("test_cleanup"); } catch { /* ignore */ } }
    handles.length = 0;
    await rm(tempDir, { recursive: true, force: true });
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"]; else process.env["CELLO_ENV"] = priorCelloEnv;
  });

  async function setup(counterpartyPeerId: string, counterpartyAddrs: string[]) {
    const dirA = join(tempDir, "A");
    const agentDir = join(dirA, "agents", "alice");
    await mkdir(agentDir, { recursive: true });
    const kp = await FileKeyProvider.load(join(agentDir, "key"));
    const alicePubkey = Buffer.from(await kp.getPublicKey()).toString("hex");

    const negotiator: SessionNegotiator = {
      async negotiate() {
        return { ok: true, assignment: makeAssignment(alicePubkey, counterpartyPeerId, counterpartyAddrs) };
      },
    };
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: dirA,
      socketPath: join(dirA, "daemon.sock"),
      lockFilePath: join(dirA, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: makeLogger(),
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: makeInjectableSignaling(),
      sessionNegotiator: negotiator,
    };
    const h = await startDaemon(config);
    handles.push(h);
    const client = await connectToDaemon(join(dirA, "daemon.sock"));
    await client.send("ipc.connect", { clientType: "test" });
    expect(((await client.send("cello_start_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    for (let i = 0; i < 100 && !h.getSessionNodeManager().getStandingReceiverReady("alice"); i++) await wait(25);
    return { h, client };
  }

  it("empty counterparty endpoint (offer never accepted) → counterparty_unavailable, no phantom session", async () => {
    const { h, client } = await setup("", []);
    try {
      const res = (await client.send("cello_initiate_session", { target_pubkey: "bb".repeat(32) })) as Record<string, unknown>;
      expect(res.ok, `initiate must not report success on a broken assignment (got ${JSON.stringify(res)})`).toBe(false);
      expect(res.reason).toBe("counterparty_unavailable");
      expect(String(res.guidance)).toMatch(/did not accept|offline|unable to receive/i);
      // No phantom session state (the F9/F10-adjacent accumulation): no row, no node.
      expect(h.getSessionNodeManager().getSessionRecord("alice", SID_HEX)).toBeNull();
    } finally {
      client.close();
    }
  }, 40_000);

  it("regression: a well-formed assignment still returns ok:true with the unchanged shape", async () => {
    const { h, client } = await setup("healthy-counterparty-peer", []);
    try {
      const res = (await client.send("cello_initiate_session", { target_pubkey: "bb".repeat(32) })) as Record<string, unknown>;
      expect(res.ok).toBe(true);
      expect(res.sessionId).toBe(SID_HEX);
      expect(h.getSessionNodeManager().getSessionRecord("alice", SID_HEX)).not.toBeNull();
    } finally {
      client.close();
    }
  }, 40_000);
});
