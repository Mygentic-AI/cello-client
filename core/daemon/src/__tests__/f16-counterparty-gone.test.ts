/**
 * M8B F16 (Brief 4) — counterparty-gone is detected but invisible to the operator.
 *
 * The signal already exists: session.liveness.changed → 'gone' is tracked per session
 * (#sessionLiveness, wired by #wireSessionLiveness) and readable via getSessionLiveness.
 * Nothing consumed it on the MCP surface — a receive on a dead session returned the
 * SAME null timeout as a quiet-but-healthy one, and status said nothing.
 *
 * Contract pinned here:
 *  1. Counterparty killed mid-session → cello_receive returns a distinct
 *     reason:"counterparty_gone" result (guidance pointing at cello_close_session and
 *     the grace window) instead of the plain null timeout.
 *  2. cello_status carries per-session liveness for active sessions.
 *  3. Regression: an alive-but-quiet session still returns the normal null timeout.
 *
 * Harness: the seam-4 two-daemon flow (real libp2p A↔B direct session); B's daemon is
 * stopped to kill the counterparty.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import type { Logger } from "../types.js";
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

function makeInjectableSignaling(injectRef: { inject?: (frame: unknown) => void }): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async () => {},
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  injectRef.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 81));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const TS = 1_700_000_000_000;

describe("M8B F16: counterparty-gone surfaces on cello_receive and cello_status", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];

  beforeEach(async () => {
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    tempDir = await mkdtemp(join(tmpdir(), "cello-f16-"));
    handles.length = 0;
  });
  afterEach(async () => {
    for (const h of handles) { try { await h.stop("test_cleanup"); } catch { /* ignore */ } }
    handles.length = 0;
    await rm(tempDir, { recursive: true, force: true });
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"]; else process.env["CELLO_ENV"] = priorCelloEnv;
  });

  async function makeAgent(celloDir: string, name: string): Promise<string> {
    const dir = join(celloDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  /** Full seam-4 flow: A initiates a real direct session to B; returns both sides. */
  async function establishSession() {
    const dirA = join(tempDir, "A");
    const dirB = join(tempDir, "B");
    const alicePubkey = await makeAgent(dirA, "alice");
    const bobPubkey = await makeAgent(dirB, "bob");

    const injectB: { inject?: (frame: unknown) => void } = {};
    const B = await startDaemon({
    securityGateway: new PassthroughGatewayClient(),
      celloDir: dirB,
      socketPath: join(dirB, "daemon.sock"),
      lockFilePath: join(dirB, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: makeLogger(),
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: makeInjectableSignaling(injectB),
    });
    handles.push(B);

    let bInfo: { peerId: string; addrs: string[] } | null = null;
    /** Set once A's daemon exists; negotiate() needs A's dialing identity (see below). */
    let aHandle: Awaited<ReturnType<typeof startDaemon>> | undefined;
    const negotiator: SessionNegotiator = {
      async negotiate() {
        /**
         * DOD-M15-ASSIGN-1: offer bob the session BEFORE handing alice an assignment.
         *
         * This seam stands in for the entire directory round-trip, and the real one has a step
         * that was missing here: the directory sends bob a `session_offer` naming alice's session
         * peer id, and only signs an assignment once bob has answered it. Bob's standing receiver
         * is narrowed to alice by that offer.
         *
         * The gap was invisible while an unclaimed receiver admitted everyone. Now that it admits
         * nobody until a session names a dialer, a harness that skips the offer has bob refusing
         * alice — correctly. Restoring the step models production; widening the gate would not.
         *
         * Alice dials from her OWN standing receiver (DOD-LOOP-1 — the initiator reuses it as its
         * session node), which is the same peer id her session_request carries to the directory.
         */
        const aliceDialer = aHandle?.getSessionNodeManager().getStandingReceiverInfo("alice");
        if (aliceDialer) {
          injectB.inject!({
            type: "session_offer",
            session_id: SID_BYTES,
            initiator_session_peer_id: aliceDialer.peerId,
          });
          await wait(30);
        }
        const assignment: SessionAssignment = {
          session_id: SID_BYTES,
          participant_a: { pubkey: Buffer.from(alicePubkey, "hex"), peer_id: "", multiaddrs: [] },
          participant_b: { pubkey: Buffer.from(bobPubkey, "hex"), peer_id: bInfo!.peerId, multiaddrs: bInfo!.addrs },
          relay_endpoint: { peer_id: "", multiaddrs: [] },
          directory_endpoint: { peer_id: "", multiaddrs: [] },
          session_timestamp: TS,
          directory_pubkey: new Uint8Array(32),
          directory_signature: new Uint8Array(64),
          transport_mode: "direct",
          counterparty_session_peer_id: bInfo!.peerId,
          counterparty_session_addrs: bInfo!.addrs,
          signature_type: "frost",
          signer_pubkey: new Uint8Array(32),
        };
        return { ok: true, assignment };
      },
    };
    const A = await startDaemon({
    securityGateway: new PassthroughGatewayClient(),
      celloDir: dirA,
      socketPath: join(dirA, "daemon.sock"),
      lockFilePath: join(dirA, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: makeLogger(),
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: makeInjectableSignaling({}),
      sessionNegotiator: negotiator,
    });
    handles.push(A);
    aHandle = A;

    const clientB = await connectToDaemon(join(dirB, "daemon.sock"));
    const clientA = await connectToDaemon(join(dirA, "daemon.sock"));
    await clientB.send("ipc.connect", { clientType: "test" });
    expect(((await clientB.send("cello_start_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
    expect(((await clientB.send("cello_use_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
    for (let i = 0; i < 100 && !bInfo; i++) {
      bInfo = B.getSessionNodeManager().getStandingReceiverInfo("bob");
      if (bInfo) break;
      await wait(25);
    }
    expect(bInfo).not.toBeNull();
    const awaitP = clientB.send("cello_await_session", { timeout_ms: 30_000 }) as Promise<Record<string, unknown>>;
    await wait(30);

    await clientA.send("ipc.connect", { clientType: "test" });
    expect(((await clientA.send("cello_start_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    expect(((await clientA.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    const initRes = (await clientA.send("cello_initiate_session", { target_pubkey: bobPubkey })) as Record<string, unknown>;
    expect(initRes.ok).toBe(true);

    const naPeerId = A.getSessionNodeManager().getSessionNodePeerId("alice", SID_HEX);
    injectB.inject!({
      type: "session_assignment",
      assignment: {
        session_id: SID_BYTES,
        participant_a: { pubkey: Buffer.from(alicePubkey, "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        initiator_session_peer_id: naPeerId,
        session_timestamp: TS,
        signature_type: "frost",
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    });
    const awaited = await awaitP;
    expect(awaited.type).toBe("new_session");

    // The direct A↔B link must be observed alive before we can prove 'gone'.
    for (let i = 0; i < 200 && A.getSessionNodeManager().getSessionLiveness("alice", SID_HEX) !== "alive"; i++) await wait(25);
    expect(A.getSessionNodeManager().getSessionLiveness("alice", SID_HEX)).toBe("alive");

    return { A, B, clientA, clientB };
  }

  it("counterparty killed mid-session → cello_receive returns counterparty_gone (not a plain null timeout) and status shows liveness", async () => {
    const { A, B, clientA, clientB } = await establishSession();
    try {
      clientB.close();
      await B.stop("test_kill_counterparty"); // the counterparty dies without closing
      for (let i = 0; i < 200 && A.getSessionNodeManager().getSessionLiveness("alice", SID_HEX) !== "gone"; i++) await wait(25);
      expect(A.getSessionNodeManager().getSessionLiveness("alice", SID_HEX)).toBe("gone");

      const recv = (await clientA.send("cello_receive", { session_id: SID_HEX, timeout_ms: 200 })) as Record<string, unknown>;
      expect(recv.reason, `a receive on a dead session must say so (got ${JSON.stringify(recv)})`).toBe("counterparty_gone");
      expect(String(recv.guidance)).toMatch(/close.session/); // rendered per surface: `cello close-session` (CLI) / `cello_close_session` (MCP)
      expect(String(recv.guidance)).toMatch(/grace/i);

      // Status: the active session carries its liveness — on BOTH the CLI ("status")
      // and MCP ("cello_status") surfaces.
      const status = (await clientA.send("status", {})) as Record<string, unknown>;
      const active = status.active_sessions as Array<Record<string, unknown>> | undefined;
      expect(active, "status must carry active_sessions with per-session liveness").toBeDefined();
      const row = active!.find((s) => s.sessionId === SID_HEX);
      expect(row).toBeDefined();
      expect(row!.liveness).toBe("gone");
      const mcpStatus = (await clientA.send("cello_status", {})) as Record<string, unknown>;
      const mcpActive = mcpStatus.active_sessions as Array<Record<string, unknown>> | undefined;
      expect(mcpActive, "cello_status must carry active_sessions too (the MCP surface)").toBeDefined();
      expect(mcpActive!.find((s) => s.sessionId === SID_HEX)!.liveness).toBe("gone");
    } finally {
      clientA.close();
    }
  }, 60_000);

  /**
   * DOD-M12B-ACK-1. The receive surface is where the 70-minute lie was actually TOLD: an impaired
   * session looked exactly like a quiet-but-healthy one, so the answer was "nothing arrived, keep
   * waiting, do not resend your last message" while every send was parking.
   *
   * The guidance must also not over-claim. Its first draft asserted the message "was parked for the
   * relay to hand over" and that the caller must not resend — false when the park was refused and
   * the durable enqueue dropped, in which case cello_send has already said "send it again". Two
   * surfaces giving an agent opposite instructions about the same message is worse than either.
   */
  it("DOD-M12B-ACK-1: a session whose sends are failing returns delivery_impaired, and says only what is known", async () => {
    const { A, clientA, clientB } = await establishSession();
    try {
      // One real failed send over a real connection — the fault is injected after the stream opens,
      // so libp2p fires no disconnect and the old code left this session reporting `alive`.
      A.getSessionNodeManager().injectSendFault(1);
      const sent = (await clientA.send("cello_send", {
        session_id: SID_HEX, content: "does not land", signal: "over",
      })) as Record<string, unknown>;
      expect(sent, "the send must resolve one way or the other, not hang").toBeDefined();

      expect(A.getSessionNodeManager().getSessionLiveness("alice", SID_HEX)).toBe("impaired");

      const recv = (await clientA.send("cello_receive", { session_id: SID_HEX, timeout_ms: 200 })) as Record<string, unknown>;
      expect(recv.reason, `a receive on an impaired session must say so (got ${JSON.stringify(recv)})`).toBe("delivery_impaired");
      expect(recv.liveness).toBe("impaired");
      // NOT the dead-session answer: the connection is up, content may still arrive, and nothing
      // here justifies steering the operator toward sealing.
      expect(String(recv.guidance)).not.toMatch(/close.session/);
      // It reports the send failure, and it does not tell the caller to keep waiting quietly.
      expect(String(recv.guidance)).toMatch(/impaired/);

      // Whatever it says about resending must match what actually happened to the message. The
      // impairment record is the only thing that knows, so the guidance is checked against IT
      // rather than against a fixed sentence.
      const impairment = A.getSessionNodeManager().getSessionImpairment("alice", SID_HEX);
      expect(impairment, "an impaired session must record WHY").not.toBeNull();
      expect(impairment!.cause).toBe("direct_send");
      if (impairment!.retained === "lost") {
        expect(String(recv.guidance)).toMatch(/send it again/i);
        expect(String(recv.guidance)).not.toMatch(/do NOT resend/);
      } else if (impairment!.retained === "parked" || impairment!.retained === "durable") {
        expect(String(recv.guidance)).toMatch(/do NOT resend/);
      } else {
        // Unknown retention: the guidance must make NO claim about resending in either direction.
        expect(String(recv.guidance)).not.toMatch(/resend|send it again/i);
      }

      // Both status surfaces carry the new state, or an operator has no way to see it.
      const status = (await clientA.send("status", {})) as Record<string, unknown>;
      const active = status.active_sessions as Array<Record<string, unknown>> | undefined;
      expect(active!.find((s) => s.sessionId === SID_HEX)!.liveness).toBe("impaired");
      const mcpStatus = (await clientA.send("cello_status", {})) as Record<string, unknown>;
      const mcpActive = mcpStatus.active_sessions as Array<Record<string, unknown>> | undefined;
      expect(mcpActive!.find((s) => s.sessionId === SID_HEX)!.liveness).toBe("impaired");
    } finally {
      clientA.close();
      clientB.close();
    }
  }, 60_000);

  it("regression: alive-but-quiet session still returns the normal null timeout", async () => {
    const { A, clientA, clientB } = await establishSession();
    try {
      const recv = (await clientA.send("cello_receive", { session_id: SID_HEX, timeout_ms: 200 })) as Record<string, unknown>;
      expect(recv.ok).toBe(true);
      expect(recv.content).toBeNull();
      expect(recv.reason).toBeUndefined();

      const status = (await clientA.send("status", {})) as Record<string, unknown>;
      const active = status.active_sessions as Array<Record<string, unknown>> | undefined;
      expect(active).toBeDefined();
      const row = active!.find((s) => s.sessionId === SID_HEX);
      expect(row).toBeDefined();
      expect(row!.liveness).toBe("alive");
      expect(A.getSessionNodeManager().getSessionLiveness("alice", SID_HEX)).toBe("alive");
    } finally {
      clientA.close();
      clientB.close();
    }
  }, 60_000);
});
