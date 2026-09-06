/**
 * M8B F14 / FINDING-2 (Brief 2, daemon half) — the inbound accept path must ENSURE a
 * standing receiver, not merely poll for one; and a deaf agent must be VISIBLE in status.
 *
 * Live failure shape (EC2, 2026-07-02): after one EADDRINUSE the agent had no standing
 * receiver and none being created. Every inbound assignment then hit
 * waitForStandingReceiver's 3s poll (which never kicks creation) and was dropped —
 * `session.inbound.accept.failed reason:standing_receiver_unavailable` — while
 * cello_status still looked healthy.
 *
 * Contract pinned here:
 *  1. An inbound assignment arriving while NO receiver exists and none is being created
 *     triggers creation from the accept path itself, and the offer is accepted within
 *     the wait window (the doc comment's "retries on demand" made true).
 *  2. cello_status carries PER-AGENT standing_receiver_ready so a deaf agent is visible.
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
import { makeSignedAssignmentFrame, fixtureIdentity } from "./helpers/signed-assignment.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";

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

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 41));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const TS = 1_700_000_000_000;

describe("M8B F14 (daemon): inbound accept path ensures the standing receiver; deaf agents visible in status", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];

  beforeEach(async () => {
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    tempDir = await mkdtemp(join(tmpdir(), "cello-sr-inbound-"));
    handles.length = 0;
  });
  afterEach(async () => {
    for (const h of handles) { try { await h.stop("test_cleanup"); } catch { /* ignore */ } }
    handles.length = 0;
    await rm(tempDir, { recursive: true, force: true });
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"]; else process.env["CELLO_ENV"] = priorCelloEnv;
  });

  it("assignment with no receiver and none creating → accept path triggers creation, offer accepted; per-agent status flips", async () => {
    const dirB = join(tempDir, "B");
    const agentDir = join(dirB, "agents", "bob");
    await mkdir(agentDir, { recursive: true });
    const bobKp = await FileKeyProvider.load(join(agentDir, "key"));
    const bobPubkey = Buffer.from(await bobKp.getPublicKey()).toString("hex");

    const injectB: { inject?: (frame: unknown) => void } = {};
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: dirB,
      socketPath: join(dirB, "daemon.sock"),
      lockFilePath: join(dirB, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: makeLogger(),
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: makeInjectableSignaling(injectB),
    };
    const h = await startDaemon(config);
    handles.push(h);

    const client = await connectToDaemon(join(dirB, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      expect(((await client.send("cello_start_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
      expect(((await client.send("cello_use_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
      for (let i = 0; i < 100 && !h.getSessionNodeManager().getStandingReceiverReady("bob"); i++) await wait(25);
      expect(h.getSessionNodeManager().getStandingReceiverReady("bob")).toBe(true);

      // ── Reproduce the deaf state: no receiver exists, none being created.
      await h.getSessionNodeManager().removeStandingReceiverForAgent("bob");
      expect(h.getSessionNodeManager().getStandingReceiverReady("bob")).toBe(false);

      // ── Per-agent visibility (fix 5): the deaf agent must be visible in status —
      //    on BOTH the CLI ("status") and MCP ("cello_status") surfaces.
      const statusDeaf = (await client.send("status", {})) as Record<string, unknown>;
      const agentsDeaf = statusDeaf.agents as Array<Record<string, unknown>>;
      const bobDeaf = agentsDeaf.find((a) => a.name === "bob");
      expect(bobDeaf, "status must list agent bob").toBeDefined();
      expect(bobDeaf!.standing_receiver_ready, "a deaf agent must be visible per-agent in status").toBe(false);
      const mcpStatusDeaf = (await client.send("cello_status", {})) as Record<string, unknown>;
      const mcpBobDeaf = (mcpStatusDeaf.agents as Array<Record<string, unknown>>).find((a) => a.name === "bob");
      expect(mcpBobDeaf, "cello_status must list agent bob").toBeDefined();
      expect(mcpBobDeaf!.standing_receiver_ready, "a deaf agent must be visible per-agent in cello_status (the MCP surface)").toBe(false);
      // DOD-M12B-RESERVATION-RETRY-1: and REACHABILITY reaches the same surface. The getter had
      // tests; the wiring did not — delete the two lines in daemon.ts that populate this and every
      // assertion in msg-018 still passes, because they all call the manager directly. This is the
      // half the operator actually reads, and the whole point of the field is that
      // `standing_receiver_ready` alone is TRUE for a receiver no NAT'd peer can dial.
      expect(
        mcpBobDeaf!.standing_receiver_reachability,
        "reachability must reach the MCP surface, not just exist on the manager",
      ).toBe("absent");
      expect(
        bobDeaf!.standing_receiver_reachability,
        "and the daemon status surface too — both are wired separately",
      ).toBe("absent");

      // ── Fix 2: an inbound assignment must KICK creation, not just poll and drop.
      const awaitP = client.send("cello_await_session", { timeout_ms: 20_000 }) as Promise<Record<string, unknown>>;
      await wait(30); // waiter registered before the assignment arrives
      // DOD-M15-RESPONDER-VERIFY-1: the responder verifies inbound assignments, so the frame is
      // genuinely signed. Nothing about signatures is under test here — this is the standing
      // receiver's door, and the assignment now has to get through it the way a real one does.
      const { frame } = await makeSignedAssignmentFrame({
        sessionId: SID_BYTES,
        initiatorPubkey: fixtureIdentity().pubkey,
        responderPubkey: new Uint8Array(Buffer.from(bobPubkey, "hex")),
        initiatorSessionPeerId: "initiator-peer-f14",
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterpartySessionPeerId: "bob-session-peer-id",
        sessionTimestamp: TS,
      });
      injectB.inject!(frame);
      const awaited = await awaitP;
      expect(awaited.type, `offer must be accepted (got ${JSON.stringify(awaited)})`).toBe("new_session");
      expect(awaited.session_id).toBe(SID_HEX);

      // ── After accept + re-arm, the per-agent flag returns to true.
      for (let i = 0; i < 100 && !h.getSessionNodeManager().getStandingReceiverReady("bob"); i++) await wait(25);
      const statusArmed = (await client.send("status", {})) as Record<string, unknown>;
      const bobArmed = (statusArmed.agents as Array<Record<string, unknown>>).find((a) => a.name === "bob");
      expect(bobArmed!.standing_receiver_ready).toBe(true);
    } finally {
      client.close();
    }
  }, 40_000);
});
