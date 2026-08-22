/**
 * Seam 4 — full daemon-IPC two-daemon local orchestration, in-process, real libp2p.
 *
 * In-process M6B-BEHAVIORAL parity for the DIRECT path (NOT a substitute for the live
 * multi-process smoke test — the milestone-close gate is still a separate, real
 * multi-process run). Two real daemons (A initiator, B counterparty) drive a complete
 * session through their PUBLIC IPC tool handlers — cello_initiate_session,
 * cello_await_session, cello_send, cello_receive — with content crossing real Noise/yamux
 * TCP between N_A and B's accepted session node.
 *
 *   A.cello_initiate_session  → stub negotiator returns an assignment (B's standing-receiver
 *                               coords as counterparty, transport_mode:'direct') →
 *                               createSessionNode(N_A) + connectToCounterparty (N_A dials B)
 *   directory push to B        → session_assignment over B's signaling hub carrying N_A's
 *                               peer id → seam-2 handler → B.acceptSession
 *   B.cello_await_session      → returns the inbound session (also the sync point: the event
 *                               is enqueued only after acceptSession registers B's handler)
 *   A.cello_send               → content_frame over the live N_A ↔ B connection
 *   B.cello_receive            → the delivered content; A's awaiting-ACK resolves
 *
 * The test plays the directory's two-round role explicitly (a stub negotiator on A +
 * the assignment push to B) — the same in-process pattern as seams 2/3. No infra, no
 * relay, no live directory. CELLO_ENV is forced to 'local' → the transport selector is the
 * local stub, so the real dial is connectToCounterparty (seam 1b), not a composition dialer.
 *
 * KNOWN follow-on (NOT proven here, intentionally): a SINGLE-round production negotiator
 * cannot yet produce a complete assignment because cello_initiate_session creates N_A
 * AFTER negotiate, so the initiator_session_peer_id is not known at negotiate time — the
 * test supplies it on the push. The WIRE-001 restructure (create N_A before the assignment
 * is finalized) is tracked in the M7 handoff §0/§5.
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
import { makeSignedAssignmentFrame } from "./helpers/signed-assignment.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
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

/** Injectable signaling: records outbound frames; injectRef.inject pushes inbound. */
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

describe("Seam 4: full daemon-IPC two-daemon local orchestration", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];

  beforeEach(async () => {
    // The seam REQUIRES the local transport-selector stub (CELLO_ENV local/test/unset).
    // Force it hermetically so a runner with CELLO_ENV=dev|staging|production can't make
    // createTransportSelector throw and break the test for an unrelated reason (review M2).
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    tempDir = await mkdtemp(join(tmpdir(), "cello-seam4-"));
    handles.length = 0;
  });
  afterEach(async () => {
    for (const h of handles) { try { await h.stop("test_cleanup"); } catch { /* ignore */ } }
    handles.length = 0;
    await rm(tempDir, { recursive: true, force: true });
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"];
    else process.env["CELLO_ENV"] = priorCelloEnv;
  });

  /** Create an agent key dir under a daemon's celloDir; return its pubkey hex. */
  async function makeAgent(celloDir: string, name: string): Promise<string> {
    const dir = join(celloDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function startOne(opts: {
    celloDir: string;
    signalingConnect: () => Promise<ConnectResult>;
    sessionNegotiator?: SessionNegotiator;
  }): Promise<{ h: Awaited<ReturnType<typeof startDaemon>>; events: LogEvent[] }> {
    const { logger, events } = makeLogger();
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: opts.celloDir,
      socketPath: join(opts.celloDir, "daemon.sock"),
      lockFilePath: join(opts.celloDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: opts.signalingConnect,
      sessionNegotiator: opts.sessionNegotiator,
    };
    const h = await startDaemon(config);
    handles.push(h);
    return { h, events };
  }

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 7));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const TS = 1_700_000_000_000;

  it("A initiates → B accepts via signaling → A.cello_send → B.cello_receive, with A's awaiting-ACK resolved", async () => {
    const dirA = join(tempDir, "A");
    const dirB = join(tempDir, "B");
    const alicePubkey = await makeAgent(dirA, "alice");
    const bobPubkey = await makeAgent(dirB, "bob");

    // ── Bring up B (counterparty). DOD-LOOP-1: B's standing receiver is now per-agent — its
    //    coordinates only exist once bob's agent comes online (cello_start_agent, below). Read
    //    them after bob starts (mirrors reality: the directory learns B's session coordinates
    //    only once B is online and advertised).
    const injectB: { inject?: (frame: unknown) => void } = {};
    const { h: B } = await startOne({ celloDir: dirB, signalingConnect: makeInjectableSignaling(injectB) });
    let bInfo: { peerId: string; addrs: string[] } | null = null;

    // ── A's stub negotiator: returns a complete direct-mode assignment whose counterparty
    //    is B's standing receiver. (Crypto fields are zero-filled — nothing verifies them on
    //    the local path; the transport selector is the local stub.)
    const negotiator: SessionNegotiator = {
      async negotiate() {
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
    const { h: A, events: aEvents } = await startOne({
      celloDir: dirA,
      signalingConnect: makeInjectableSignaling({}),
      sessionNegotiator: negotiator,
    });

    const clientB = await connectToDaemon(join(dirB, "daemon.sock"));
    const clientA = await connectToDaemon(join(dirA, "daemon.sock"));
    try {
      await clientB.send("ipc.connect", { clientType: "test" });
      expect(((await clientB.send("cello_start_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
      expect(((await clientB.send("cello_use_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
      // bob is online → poll the async per-agent SR ensure (cello_start_agent kicked it off) for
      // his coordinates. A's stub negotiator (below) reads bInfo at initiate time.
      for (let i = 0; i < 100 && !bInfo; i++) {
        bInfo = B.getSessionNodeManager().getStandingReceiverInfo("bob");
        if (bInfo) break;
        await wait(25);
      }
      expect(bInfo).not.toBeNull();
      // Inner await deadline is generous (governed by the 40s `it` budget, not a value
      // smaller than A's real-libp2p initiate must take — review M1).
      const awaitP = clientB.send("cello_await_session", { timeout_ms: 30_000 }) as Promise<Record<string, unknown>>;
      await wait(30); // ensure the waiter is registered before A initiates

      // ── A initiates. createSessionNode(N_A) + connectToCounterparty (N_A dials B's SR).
      await clientA.send("ipc.connect", { clientType: "test" });
      expect(((await clientA.send("cello_start_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
      expect(((await clientA.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
      const initRes = await clientA.send("cello_initiate_session", { counterparty_pubkey: bobPubkey }) as Record<string, unknown>;
      expect(initRes.ok).toBe(true);
      expect(initRes.sessionId).toBe(SID_HEX);

      // ── The directory pushes the assignment to B, carrying N_A's peer id (known only now).
      //
      // DOD-M15-RESPONDER-VERIFY-1: B VERIFIES this assignment before it hands its standing
      // receiver over, so the push is a genuinely FROST-signed frame rather than one with a
      // zeroed signature. That is the production shape — B has never met alice, so the verifier
      // runs in its internal-consistency mode. What seam 4 is about (the two daemons carrying a
      // session end to end over real libp2p) is unchanged; the assignment now arrives through
      // the same gate a real directory push goes through.
      const naPeerId = A.getSessionNodeManager().getSessionNodePeerId("alice", SID_HEX);
      expect(typeof naPeerId).toBe("string");
      const { frame: assignmentFrame } = await makeSignedAssignmentFrame({
        sessionId: SID_BYTES,
        initiatorPubkey: Uint8Array.from(Buffer.from(alicePubkey, "hex")),
        responderPubkey: Uint8Array.from(Buffer.from(bobPubkey, "hex")),
        initiatorSessionPeerId: naPeerId as string,
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterpartySessionPeerId: "bob-session-peer-id",
        sessionTimestamp: TS,
      });
      injectB.inject!(assignmentFrame);

      // ── B discovers the session via the blocked await (proves seam-2 acceptSession ran).
      const awaited = await awaitP;
      expect(awaited.type).toBe("new_session");
      expect(awaited.session_id).toBe(SID_HEX);
      expect(awaited.counterparty_pubkey).toBe(alicePubkey);

      // ── A sends; B receives over the live N_A ↔ B connection.
      const text = "hello from alice over the full daemon stack";
      const sent = await clientA.send("cello_send", { session_id: SID_HEX, content: text }) as Record<string, unknown>;
      expect(sent.ok).toBe(true);
      expect(sent.sequence_number).toBe(0);

      let recv: Record<string, unknown> | null = null;
      for (let i = 0; i < 160; i++) {
        recv = await clientB.send("cello_receive", { session_id: SID_HEX }) as Record<string, unknown>;
        if (recv && recv.content) break;
        await wait(25);
      }
      expect(recv).not.toBeNull();
      expect(recv!.content).toBe(text);
      expect(recv!.sequence_number).toBe(0);
      expect(recv!.senderPubkey).toBe(alicePubkey);

      // ── A's awaiting-ACK resolved (the delivery-ACK round-tripped back over N_A's link).
      let acked = false;
      for (let i = 0; i < 80; i++) {
        if (aEvents.find((e) => e.event === "content.delivery.acked")) { acked = true; break; }
        await wait(25);
      }
      expect(acked).toBe(true);
    } finally {
      clientA.close();
      clientB.close();
    }
  }, 40_000);
});
