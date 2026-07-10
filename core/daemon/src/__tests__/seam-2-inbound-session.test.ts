/**
 * Seam 2 — inbound session establishment (counterparty side), in-process.
 *
 * Traces the connection point that was broken before this seam: the directory
 * PUSHES a FROST-signed SessionAssignment to the counterparty (B) over B's
 * directory signaling stream as an unsolicited `session_assignment` frame, but
 * the daemon routed only registration + seal-interrupted inbound frames — there
 * was no path from that frame to a live inbound session, and cello_await_session
 * was a `not_implemented` stub.
 *
 * This verifies the wired seam end-to-end IN PROCESS with a stub (injectable)
 * signaling stream and a fake session node:
 *
 *   inbound session_assignment frame
 *     → resolve participant_b → local agent
 *     → SessionNodeManager.acceptSession (standing receiver handed off, bound to A)
 *     → session-core has an ACTIVE session row (queryable)
 *     → inbound event enqueued
 *     → cello_await_session returns { type:"new_session", session_id, counterparty_pubkey, genesis_prev_root }
 *
 * No infra, no relay, no real directory — the directory's push is injected as a
 * trusted frame. The FROST signature verification of the assignment is the
 * SESSION-004 re-home (deferred); this seam asserts that deferral is logged loudly
 * (session.inbound.assignment.unverified), never silent.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

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

// Minimal fake session node — the standing receiver and any session node the
// factory hands out. AutoNAT methods are required by NodeAutoNatService.
class FakeNode implements Partial<CelloNode> {
  stopped = false;
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> { this.stopped = true; }
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const sink: Uint8Array[] = [];
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/**
 * Signaling stub that records outbound frames AND lets the test inject an inbound
 * frame (via injectRef.inject) — the directory's push channel.
 */
function makeInjectableSignaling(
  captured: Record<string, unknown>[],
  injectRef: { inject?: (frame: unknown) => void },
): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async (frame: unknown) => { captured.push(frame as Record<string, unknown>); },
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  injectRef.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("Seam 2: inbound session_assignment → acceptSession → cello_await_session", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-seam2-"));
    handle = null;
  });
  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function start(opts: {
    logger: Logger;
    node: CelloNode;
    signalingConnect: () => Promise<ConnectResult>;
  }): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: opts.logger,
      sessionNodeFactory: new FixedFactory(opts.node),
      signalingConnect: opts.signalingConnect,
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  // session_id is 16 bytes per the protocol; the daemon hex-encodes it.
  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const TS = 1_700_000_000_000;

  /** Build a directory-pushed session_assignment frame addressed to participant_b. */
  function assignmentFrame(opts: {
    sessionId?: Uint8Array;
    initiatorPubkeyHex: string;    // participant_a (our counterparty)
    counterpartyPubkeyHex: string; // participant_b (the local agent)
    initiatorPeerId?: string;
    sessionTimestamp?: number;
    signatureType?: string;
    // DOD-INBOUND-GUARD-1: the responder's accepted endpoint. The directory OMITS this field
    // when nobody accepted the offer (directory-frames.ts encodes it only when non-empty), so
    // `null` here builds exactly that broken frame. Defaults to present — a complete assignment.
    counterpartyPeerId?: string | null;
  }): Record<string, unknown> {
    const assignment: Record<string, unknown> = {
      session_id: opts.sessionId ?? SID_BYTES,
      participant_a: { pubkey: Buffer.from(opts.initiatorPubkeyHex, "hex") },
      participant_b: { pubkey: Buffer.from(opts.counterpartyPubkeyHex, "hex") },
      session_timestamp: opts.sessionTimestamp ?? TS,
      signature_type: opts.signatureType ?? "frost",
    };
    if (opts.initiatorPeerId !== undefined) assignment["initiator_session_peer_id"] = opts.initiatorPeerId;
    const counterpartyPeerId = opts.counterpartyPeerId === undefined ? "bob-session-peer-id" : opts.counterpartyPeerId;
    if (counterpartyPeerId !== null) assignment["counterparty_session_peer_id"] = counterpartyPeerId;
    return { type: "session_assignment", assignment };
  }

  function expectedGenesisHex(initiatorHex: string, counterpartyHex: string, sid: Uint8Array, ts: number): string {
    return Buffer.from(
      computeGenesisPrevRoot(Buffer.from(initiatorHex, "hex"), Buffer.from(counterpartyHex, "hex"), sid, ts),
    ).toString("hex");
  }

  it("turns a pushed session_assignment into an active inbound session that cello_await_session returns", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50); // let signaling connect + standing receiver come up

    const snm = h.getSessionNodeManager();
    // Per-agent standing receiver (DOD-LOOP-1): an inbound assignment for bob can only be accepted
    // once bob's agent is online and his SR exists — provision it as cello_start_agent would.
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = "cd".repeat(32);

    injectRef.inject!(assignmentFrame({
      initiatorPubkeyHex: initiatorPubkey,
      counterpartyPubkeyHex: bobPubkey,
      initiatorPeerId: "alice-session-peer-id",
    }));
    await wait(120); // async inbound handler (accept may wait on standing receiver)

    // (1) Session-core observable: bob now has an ACTIVE session row bound to alice.
    const record = snm.getSessionRecord("bob", SID_HEX);
    expect(record).not.toBeNull();
    expect(record!.status).toBe("active");
    expect(record!.agent_name).toBe("bob");
    expect(record!.counterparty_pubkey).toBe(initiatorPubkey);

    // (2) The deferred FROST-verification gap is logged loudly (never silent).
    expect(events.find((e) => e.event === "session.inbound.assignment.unverified")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeDefined();

    // (3) cello_await_session returns the queued inbound session for bob's connection,
    //     with the CANONICAL two-party genesis_prev_root (not the empty-tree root).
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "bob" });
      await client.send("cello_use_agent", { name: "bob" });
      const res = await client.send("cello_await_session", { timeout_ms: 1000 }) as Record<string, unknown>;
      expect(res.type).toBe("new_session");
      expect(res.session_id).toBe(SID_HEX);
      expect(res.counterparty_pubkey).toBe(initiatorPubkey);
      expect(res.genesis_prev_root).toBe(expectedGenesisHex(initiatorPubkey, bobPubkey, SID_BYTES, TS));
    } finally { client.close(); }
  });

  it("blocks cello_await_session until a session_assignment arrives, then returns it", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "bob" });
      await client.send("cello_use_agent", { name: "bob" });

      // Start the blocking await BEFORE any assignment exists.
      const awaitP = client.send("cello_await_session", { timeout_ms: 2000 }) as Promise<Record<string, unknown>>;
      await wait(40); // ensure the waiter is registered

      const initiatorPubkey = "ab".repeat(32);
      injectRef.inject!(assignmentFrame({
        initiatorPubkeyHex: initiatorPubkey,
        counterpartyPubkeyHex: bobPubkey,
        initiatorPeerId: "alice-session-peer-id",
      }));

      const res = await awaitP;
      expect(res.type).toBe("new_session");
      expect(res.session_id).toBe(SID_HEX);
      expect(res.counterparty_pubkey).toBe(initiatorPubkey);
    } finally { client.close(); }
  });

  it("M1: ignores a retransmitted assignment for an already-accepted session (no double accept/enqueue)", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    // Per-agent SR (DOD-LOOP-1): bob must be online for his inbound assignment to be accepted.
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = "cd".repeat(32);
    const frame = assignmentFrame({ initiatorPubkeyHex: initiatorPubkey, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "alice-peer" });
    injectRef.inject!(frame);
    await wait(120);
    injectRef.inject!(frame); // retransmit
    await wait(80);

    // Exactly one accept; the retransmit was ignored as a duplicate.
    expect(events.filter((e) => e.event === "session.inbound.accepted").length).toBe(1);
    expect(events.find((e) => e.event === "session.inbound.duplicate.ignored")).toBeDefined();

    // And exactly one queued event is available to await.
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "bob" });
      await client.send("cello_use_agent", { name: "bob" });
      const first = await client.send("cello_await_session", { timeout_ms: 500 }) as Record<string, unknown>;
      expect(first.type).toBe("new_session");
      const second = await client.send("cello_await_session", { timeout_ms: 200 }) as Record<string, unknown>;
      expect(second.type).toBe("timeout"); // no second event
    } finally { client.close(); }
    expect(h.getSessionNodeManager().getSessionRecord("bob", SID_HEX)).not.toBeNull();
  });

  it("M2: a burst of two assignments for the same agent are both accepted (standing receiver rebuild not lost)", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);
    // Per-agent SR (DOD-LOOP-1): bob online before the burst; the first push consumes his SR, the
    // second must wait for the async per-agent rebuild rather than being dropped.
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const sidB = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 100));
    const initA = "11".repeat(32);
    const initB = "22".repeat(32);
    // Two pushes back-to-back: the first consumes the standing receiver; the second
    // must wait for the async rebuild rather than being dropped.
    injectRef.inject!(assignmentFrame({ initiatorPubkeyHex: initA, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "peer-a" }));
    injectRef.inject!(assignmentFrame({ sessionId: sidB, initiatorPubkeyHex: initB, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "peer-b" }));
    await wait(300);

    expect(events.filter((e) => e.event === "session.inbound.accepted").length).toBe(2);
    expect(events.find((e) => e.event === "session.inbound.accept.failed")).toBeUndefined();

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "bob" });
      await client.send("cello_use_agent", { name: "bob" });
      const r1 = await client.send("cello_await_session", { timeout_ms: 500 }) as Record<string, unknown>;
      const r2 = await client.send("cello_await_session", { timeout_ms: 500 }) as Record<string, unknown>;
      const ids = [r1.session_id, r2.session_id].sort();
      expect(ids).toEqual([SID_HEX, Buffer.from(sidB).toString("hex")].sort());
    } finally { client.close(); }
  });

  it("M3: ignores an assignment missing initiator_session_peer_id (would gate the receiver to \"\")", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    injectRef.inject!(assignmentFrame({ initiatorPubkeyHex: "cd".repeat(32), counterpartyPubkeyHex: bobPubkey })); // no peer id
    await wait(80);

    expect(h.getSessionNodeManager().getSessionRecord("bob", SID_HEX)).toBeNull();
    const malformed = events.find((e) => e.event === "session.inbound.assignment.malformed");
    expect(malformed).toBeDefined();
    expect(malformed!.context["reason"]).toBe("missing_initiator_peer_id");
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  it("L1: refuses a single-key (M1) assignment as unsupported_signature_type", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    injectRef.inject!(assignmentFrame({
      initiatorPubkeyHex: "cd".repeat(32), counterpartyPubkeyHex: bobPubkey,
      initiatorPeerId: "alice-peer", signatureType: "single",
    }));
    await wait(80);

    expect(h.getSessionNodeManager().getSessionRecord("bob", SID_HEX)).toBeNull();
    const refused = events.find((e) => e.event === "session.inbound.assignment.refused");
    expect(refused).toBeDefined();
    expect(refused!.context["reason"]).toBe("unsupported_signature_type");
  });

  // ─── DOD-INBOUND-GUARD-1 (D3, M8C-PHANTOM-SESSION-FIX-PLAN §4) ─────────────────────────────
  // When the responder never accepts the session offer (standing receiver not up yet), the
  // directory signs an assignment whose counterparty endpoint is EMPTY and pushes it to both
  // parties. The initiator's F13 guard refuses it — the receiver must refuse it too, instead of
  // building a session the initiator never created and auto-replying into a void. Mirrors F13.
  describe("DOD-INBOUND-GUARD-1: the receiver refuses an assignment with no counterparty endpoint", () => {
    async function refusalCase(counterpartyPeerId: string | null): Promise<{
      events: LogEvent[];
      snm: ReturnType<Awaited<ReturnType<typeof startDaemon>>["getSessionNodeManager"]>;
    }> {
      const { logger, events } = makeLogger();
      const bobPubkey = await makeAgentDir("bob");
      const node = new FakeNode();
      const captured: Record<string, unknown>[] = [];
      const injectRef: { inject?: (frame: unknown) => void } = {};
      const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
      await wait(50);
      const snm = h.getSessionNodeManager();
      // Bob is fully online — acceptance WOULD succeed if the guard did not refuse. This keeps
      // the test red for the right reason pre-fix (the assignment is currently accepted).
      await snm.ensureStandingReceiverForAgent("bob");

      injectRef.inject!(assignmentFrame({
        initiatorPubkeyHex: "cd".repeat(32),
        counterpartyPubkeyHex: bobPubkey,
        initiatorPeerId: "alice-session-peer-id",
        counterpartyPeerId,
      }));
      await wait(120);
      return { events, snm };
    }

    function assertRefused(events: LogEvent[], snm: { getSessionRecord(a: string, s: string): unknown }): void {
      // AC2: no session node, no DB row, no accept, no away response.
      expect(snm.getSessionRecord("bob", SID_HEX)).toBeNull();
      expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
      expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
      // SI: the refusal is loud — distinguishable from a dropped frame.
      const incomplete = events.find((e) => e.event === "session.inbound.assignment.incomplete");
      expect(incomplete).toBeDefined();
      expect(incomplete!.level).toBe("warn");
      expect(incomplete!.context["agentName"]).toBe("bob");
      expect(incomplete!.context["sessionId"]).toBe(SID_HEX);
      expect(incomplete!.context["correlationId"]).toBeTruthy();
    }

    it("AC2/AC3: an assignment MISSING counterparty_session_peer_id is refused loudly, and never surfaces on cello_await_session", async () => {
      const { events, snm } = await refusalCase(null); // field omitted — the directory's actual broken frame
      assertRefused(events, snm);

      // AC3: cello_await_session never surfaces the refused assignment.
      const client = await connectToDaemon(join(tempDir, "daemon.sock"));
      try {
        await client.send("ipc.connect", { clientType: "test" });
        await client.send("cello_start_agent", { name: "bob" });
        await client.send("cello_use_agent", { name: "bob" });
        const res = (await client.send("cello_await_session", { timeout_ms: 500 })) as Record<string, unknown>;
        expect(res.type).toBe("timeout");
      } finally { client.close(); }
    });

    it("AC2: an EMPTY-STRING counterparty_session_peer_id is refused the same way", async () => {
      const { events, snm } = await refusalCase(""); // hostile/skewed encoder variant — same refusal
      assertRefused(events, snm);
    });
  });

  it("H2: a session arriving after the awaiting connection disconnected is NOT lost (delivered to a fresh await)", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    // Connection 1 blocks on await, then disconnects before any session arrives.
    const c1 = await connectToDaemon(join(tempDir, "daemon.sock"));
    await c1.send("ipc.connect", { clientType: "test" });
    await c1.send("cello_start_agent", { name: "bob" });
    await c1.send("cello_use_agent", { name: "bob" });
    void (c1.send("cello_await_session", { timeout_ms: 5000 }) as Promise<unknown>).catch(() => {});
    await wait(40); // waiter registered
    c1.close();
    await wait(60); // onDisconnect evicts the dead waiter

    // Now the directory pushes the session. The dead waiter must NOT swallow it.
    const initiatorPubkey = "ef".repeat(32);
    injectRef.inject!(assignmentFrame({ initiatorPubkeyHex: initiatorPubkey, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "alice-peer" }));
    await wait(120);

    // A fresh connection's await receives the session (it landed in the queue, not a dead waiter).
    const c2 = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await c2.send("ipc.connect", { clientType: "test" });
      await c2.send("cello_start_agent", { name: "bob" });
      await c2.send("cello_use_agent", { name: "bob" });
      const res = await c2.send("cello_await_session", { timeout_ms: 1000 }) as Record<string, unknown>;
      expect(res.type).toBe("new_session");
      expect(res.session_id).toBe(SID_HEX);
      expect(res.counterparty_pubkey).toBe(initiatorPubkey);
    } finally { c2.close(); }
  });

  it("ignores a session_assignment not addressed to any local agent (no session, no enqueue)", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    injectRef.inject!(assignmentFrame({
      initiatorPubkeyHex: "cd".repeat(32),
      counterpartyPubkeyHex: "ee".repeat(32), // not a local agent
      initiatorPeerId: "alice-session-peer-id",
    }));
    await wait(80);

    expect(h.getSessionNodeManager().getSessionRecord("bob", SID_HEX)).toBeNull();
    expect(events.find((e) => e.event === "session.inbound.not_local")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  it("logs malformed and ignores a session_assignment frame with no assignment payload", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    injectRef.inject!({ type: "session_assignment" }); // no `assignment`
    await wait(50);

    expect(h.getSessionNodeManager().getSessionRecord("bob", SID_HEX)).toBeNull();
    const malformed = events.find((e) => e.event === "session.inbound.assignment.malformed");
    expect(malformed).toBeDefined();
    expect(malformed!.context["reason"]).toBe("missing_assignment_or_ids");
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });
});
