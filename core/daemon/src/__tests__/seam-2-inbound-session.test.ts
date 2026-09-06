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
 * No infra, no relay, no real directory — the directory's push is injected
 * directly onto the signaling stream.
 *
 * DOD-M15-RESPONDER-VERIFY-1: that injected frame is now GENUINELY SIGNED
 * (`signedAssignmentFrame` below). The responder verifies inbound assignments, so a
 * frame with a zeroed signature no longer reaches any of the behaviour this file is
 * about — it is refused at the gate. The frames that this file deliberately builds
 * BROKEN (no initiator peer id, no counterparty endpoint, single-key signature type,
 * addressed to nobody local) stay unsigned on purpose: every one of them is refused
 * strictly before the verification step, so signing them would assert nothing.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { makeSignedAssignmentFrame, registerFixtureSigner, fixtureIdentity } from "./helpers/signed-assignment.js";
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
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    // 038-KEYBIND: a REAL agent, so the assignment fixture can sign a key binding as it.
    registerFixtureSigner(hex, kp);
    return hex;
  }

  async function start(opts: {
    logger: Logger;
    node: CelloNode;
    signalingConnect: () => Promise<ConnectResult>;
  }): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
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
    /** DOD-FIRSTMSG-WITNESS-1: the relay endpoint + the directory's signature over the assignment. */
    relayPeerId?: string;
    relayDirectorySignature?: Uint8Array;
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
    if (opts.relayPeerId !== undefined) {
      assignment["relay_endpoint"] = { peer_id: opts.relayPeerId, multiaddrs: ["/ip4/127.0.0.1/tcp/1/p2p/" + opts.relayPeerId] };
    }
    if (opts.relayDirectorySignature !== undefined) {
      assignment["relay_directory_signature"] = opts.relayDirectorySignature;
    }
    return { type: "session_assignment", assignment };
  }

  /**
   * The same frame, but one the responder can actually VERIFY — DOD-M15-RESPONDER-VERIFY-1.
   *
   * `assignmentFrame` above builds an assignment with no signature at all. That was accepted while
   * the responder only logged `session.inbound.assignment.unverified` and proceeded; now it is
   * refused before any of the seam this file tests is reached. So every case that must get PAST the
   * gate mints a keypair, rebuilds the session-establishment TBS from the assignment's own contents
   * and signs it — the frame arrives through the real check rather than around it.
   *
   * `relay_directory_signature` is attached AFTER signing, and that is not tampering: the
   * establishment TBS covers the participants, the session id/timestamp and the two session
   * endpoints — not the relay's own signature, which is a separate directory attestation riding
   * beside the assignment.
   */
  async function signedAssignmentFrame(opts: {
    sessionId?: Uint8Array;
    initiatorPubkeyHex: string;    // participant_a (our counterparty)
    counterpartyPubkeyHex: string; // participant_b (the local agent)
    initiatorPeerId: string;
    /** DOD-FIRSTMSG-WITNESS-1: the directory's signature over the RELAY assignment. */
    relayDirectorySignature?: Uint8Array;
  }): Promise<Record<string, unknown>> {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId: opts.sessionId ?? SID_BYTES,
      initiatorPubkey: Uint8Array.from(Buffer.from(opts.initiatorPubkeyHex, "hex")),
      responderPubkey: Uint8Array.from(Buffer.from(opts.counterpartyPubkeyHex, "hex")),
      initiatorSessionPeerId: opts.initiatorPeerId,
      // DOD-INBOUND-GUARD-1: a complete assignment names the responder's accepted endpoint.
      counterpartySessionPeerId: "bob-session-peer-id",
      sessionTimestamp: TS,
    });
    if (opts.relayDirectorySignature !== undefined) {
      (frame["assignment"] as Record<string, unknown>)["relay_directory_signature"] =
        opts.relayDirectorySignature;
    }
    return frame;
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
    const initiatorPubkey = fixtureIdentity().pubkeyHex;

    injectRef.inject!(await signedAssignmentFrame({
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

    /**
     * (2) The assignment is VERIFIED, and the log says which of the two ways.
     *
     * This assertion used to require `session.inbound.assignment.unverified` — a deliberate,
     * loudly-logged record of the gap where the responder did not check the directory's signature
     * at all. `DOD-M15-RESPONDER-VERIFY-1` closed the gap, so that event is gone and the assertion
     * moves to its successor rather than being dropped: the SUBJECT changed on purpose, and a test
     * quietly deleted here would take with it the guarantee that the responder says what it did.
     *
     * `mode` is checked because a verified event with no mode would be the more dangerous shape:
     * `internal` is first contact, which proves the frame was not altered but cannot say which
     * directory signed it, and a reader must never mistake that for `pinned`.
     */
    const verified = events.find((e) => e.event === "session.inbound.assignment.verified");
    expect(verified, "the responder must record that it verified the assignment").toBeDefined();
    expect(["pinned", "bound"]).toContain(verified?.context?.["mode"]);
    expect(
      events.find((e) => e.event === "session.inbound.assignment.unverified"),
      "the deferred-verification event must be GONE — it contradicted the verification above",
    ).toBeUndefined();
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

      const initiatorPubkey = fixtureIdentity().pubkeyHex;
      injectRef.inject!(await signedAssignmentFrame({
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
    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    const frame = await signedAssignmentFrame({ initiatorPubkeyHex: initiatorPubkey, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "alice-peer" });
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
    const initA = fixtureIdentity().pubkeyHex;
    const initB = fixtureIdentity().pubkeyHex;
    // Both frames are built (and signed) BEFORE either is pushed, so the two pushes are still
    // back-to-back with nothing awaited between them — that burst is the whole point of M2.
    // Two distinct initiators means two distinct counterparties, so each may carry its own signer.
    const frameA = await signedAssignmentFrame({ initiatorPubkeyHex: initA, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "peer-a" });
    const frameB = await signedAssignmentFrame({ sessionId: sidB, initiatorPubkeyHex: initB, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "peer-b" });
    // Two pushes back-to-back: the first consumes the standing receiver; the second
    // must wait for the async rebuild rather than being dropped.
    injectRef.inject!(frameA);
    injectRef.inject!(frameB);
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

    injectRef.inject!(assignmentFrame({ initiatorPubkeyHex: fixtureIdentity().pubkeyHex, counterpartyPubkeyHex: bobPubkey })); // no peer id
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
      initiatorPubkeyHex: fixtureIdentity().pubkeyHex, counterpartyPubkeyHex: bobPubkey,
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
        initiatorPubkeyHex: fixtureIdentity().pubkeyHex,
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

    it("AC2/AC3: an EMPTY-STRING counterparty_session_peer_id is refused the same way", async () => {
      const { events, snm } = await refusalCase(""); // hostile/skewed encoder variant — same refusal
      assertRefused(events, snm);

      // AC3, same as the absent-field variant: never surfaces on cello_await_session.
      const client = await connectToDaemon(join(tempDir, "daemon.sock"));
      try {
        await client.send("ipc.connect", { clientType: "test" });
        await client.send("cello_start_agent", { name: "bob" });
        await client.send("cello_use_agent", { name: "bob" });
        const res = (await client.send("cello_await_session", { timeout_ms: 500 })) as Record<string, unknown>;
        expect(res.type).toBe("timeout");
      } finally { client.close(); }
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
    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    injectRef.inject!(await signedAssignmentFrame({ initiatorPubkeyHex: initiatorPubkey, counterpartyPubkeyHex: bobPubkey, initiatorPeerId: "alice-peer" }));
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
      initiatorPubkeyHex: fixtureIdentity().pubkeyHex,
      counterpartyPubkeyHex: "ee".repeat(32), // not a local agent
      initiatorPeerId: "alice-session-peer-id",
    }));
    await wait(80);

    expect(h.getSessionNodeManager().getSessionRecord("bob", SID_HEX)).toBeNull();
    expect(events.find((e) => e.event === "session.inbound.not_local")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  /**
   * ⚠️ THIS TEST CHANGED ITS MIND ABOUT WHAT THIS FRAME *IS* — `DOD-M15-SELFCHAIN-1`.
   *
   * It used to assert a `malformed` warning: a frame with no assignment was filed as a badly
   * shaped message and dropped. Ruled 2026-09-06 that it is nothing of the kind. Every real
   * session is brokered — the directory signs an establishment record, both sides verify it, and
   * the conversation's starting point comes out of those signed bytes. A session offered without
   * one is a conversation whose order could never be proven by anyone, so it is refused as
   * suspicious and the operator is told, rather than tidied into a log line nobody opens.
   *
   * The assertions below are therefore about a SECURITY REFUSAL, not a parse failure.
   */
  it("refuses a session_assignment frame with no assignment payload, loudly and by name", async () => {
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
    const refused = events.find((e) => e.event === "session.inbound.assignment.no_assignment");
    expect(refused, "the refusal must be reported, not swallowed").toBeDefined();
    // ERROR, not warn: nothing legitimate produces this frame, and the level is what decides
    // whether the operator's tooling shows it at all.
    expect(refused!.level).toBe("error");
    expect(
      String(refused!.context["impact"]),
      "the log must say what it COSTS the operator, not just that a field was absent",
    ).toMatch(/starting point/);
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  // ─── DOD-FIRSTMSG-WITNESS-1 · F1 ─────────────────────────────────────────────────────────────
  // THE ONE LINE THAT IS THE FIX. `acceptInboundAssignment` builds the responder's relay params and
  // hands them to `acceptSession` (inbound-sessions.ts:651). Everything else about this fix — the
  // parser, the carry builder, the params builder — is unit-tested six ways, and ALL OF IT is dead
  // if that one call site drops the `assignment` field. Reverting it to the pre-fix inline literal
  // left the whole suite green, which is the exact shape the new test file's own header claimed to
  // have closed. It pinned the builder; nothing pinned the caller.
  //
  // So this asserts on the REAL path: a directory-pushed frame goes in, and the signature the
  // directory put on the wire has to come back out of the object `acceptSession` actually receives.
  it("hands acceptSession the relay assignment carrying the directory's signature (DOD-FIRSTMSG-WITNESS-1)", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await wait(50);

    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    // Spy that CALLS THROUGH — the accept must still really happen, or this would pass against a
    // path that never completes.
    const seen: unknown[] = [];
    const realAccept = snm.acceptSession.bind(snm);
    (snm as any).acceptSession = (...args: unknown[]) => { seen.push(args[5]); return (realAccept as any)(...args); };

    const DIR_SIG = Uint8Array.from(Array.from({ length: 64 }, (_, i) => (i * 7 + 3) & 0xff));
    injectRef.inject!(await signedAssignmentFrame({
      initiatorPubkeyHex: fixtureIdentity().pubkeyHex,
      counterpartyPubkeyHex: bobPubkey,
      initiatorPeerId: "alice-session-peer-id",
      relayDirectorySignature: DIR_SIG,
    }));
    await wait(150);

    expect(seen.length, "acceptSession was never reached — the test proves nothing").toBe(1);
    const relayParams = seen[0] as { assignment?: { assignmentSignature?: Uint8Array } } | undefined;
    expect(relayParams?.assignment, "the responder's relay params carry no assignment — the wiring at inbound-sessions.ts:651 is gone").toBeDefined();
    expect(
      Buffer.from(relayParams!.assignment!.assignmentSignature!).toString("hex"),
      "the directory's signature did not survive the wire boundary into acceptSession",
    ).toBe(Buffer.from(DIR_SIG).toString("hex"));
  });

});
