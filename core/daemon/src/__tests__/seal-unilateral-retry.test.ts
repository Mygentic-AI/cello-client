/**
 * M8B FINDING-1 (Brief 1) — unilateral seal escalation must survive a RETRY close.
 *
 * Root cause under test (daemon.ts close flow, relay-witness path): the unilateral
 * escalation was reachable ONLY on the same cello_close_session call that first
 * submitted the SEAL leaf. A retry hit the #responderSealSubmitted idempotency mark,
 * got `responder_seal_already_submitted` WITHOUT the reportedRootHex/sequenceNumber
 * needed to escalate, and fell into a permanent `seal_pending_bilateral` — the
 * session could never be unilaterally sealed (live session 47d83ad1, 2026-07-02).
 *
 * Contract pinned here:
 *  1. close #1 (grace not elapsed): submit SEAL leaf → bilateral wait times out →
 *     escalate seal_unilateral → directory replies too_early → seal_counterparty_pending,
 *     with the directory's remaining_seconds surfaced in the guidance (F20).
 *  2. close #2 (retry): submitSealLeaf returns already_submitted CARRYING the first
 *     submit's reportedRootHex/sequenceNumber → the daemon MUST re-escalate with a
 *     second seal_unilateral frame (same reported_root) → confirmed → ok:true unilateral.
 *  3. auto-ack regression: when the bilateral seal lands within the wait window, the
 *     close returns the BILATERAL result — no premature unilateral escalation.
 *  4. idempotency: concurrent closes submit exactly ONE relay SEAL ctrl leaf.
 *
 * Harness: one real daemon (full IPC surface), a stub negotiator whose assignment
 * carries a FAKE relay endpoint, a session-node factory returning real libp2p nodes
 * wrapped so relay dials land on an in-process fake relay (auth + hash_submit_ack
 * auto-responder — the same wire contract as session-relay-client.test.ts), and an
 * injectable signaling stream that records outbound frames and lets the test play
 * the directory (seal_unilateral_too_early / _confirmed / session_sealed).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { buildSealTbs } from "@cello-protocol/protocol-types";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { DbRegistrationPersistence } from "../db-identity-store.js";
import { encodeStructure1 } from "../session-relay-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

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

const FAKE_RELAY_PEER_ID = "12D3KooWFakeRelayPeerForSealRetryTests";
const FAKE_RELAY_ADDR = "/ip4/127.0.0.1/tcp/1/p2p/fake-relay-seal-retry";

/**
 * In-process fake relay: implements the relay side of the AgentRelayClient wire
 * contract (auth challenge → auth ok; hash_submit → unsigned hash_submit_ack).
 * Unsigned acks are accepted by evaluateRelayAck (kind "unsigned") — no relay key needed.
 * Records every hash_submit; exposes push() to deliver leaf_deliver frames.
 */
function makeFakeRelayServer() {
  const submits: Record<string, unknown>[] = [];
  let seq = 0;
  const streams: Array<{ push: (frame: Record<string, unknown>) => void }> = [];

  function openStream() {
    const inbound: Uint8Array[] = [];
    let notify: (() => void) | null = null;
    let ended = false;

    const push = (frame: Record<string, unknown>): void => {
      const encoded = lp.encode.single(CBOR_ENC.encode(frame) as Uint8Array);
      inbound.push(encoded instanceof Uint8Array ? encoded : (encoded as { subarray(): Uint8Array }).subarray());
      notify?.();
    };

    const stream = {
      send: (b: { subarray?: () => Uint8Array } | Uint8Array) => {
        const bytes = b instanceof Uint8Array ? b : (b.subarray ? b.subarray() : (b as unknown as Uint8Array));
        void (async () => {
          for await (const chunk of lp.decode([bytes] as unknown as AsyncIterable<Uint8Array>)) {
            const u8 = chunk instanceof Uint8Array ? chunk : (chunk as { subarray(): Uint8Array }).subarray();
            const frame = decode(u8) as Record<string, unknown>;
            if (frame["type"] === "relay_auth_response") {
              push({ type: "relay_auth_ok" });
            } else if (frame["type"] === "hash_submit") {
              submits.push(frame);
              push({ type: "hash_submit_ack", sequence_number: ++seq });
            }
          }
        })();
      },
      close: async () => { ended = true; notify?.(); },
      async *[Symbol.asyncIterator]() {
        while (!ended) {
          while (inbound.length) yield inbound.shift()!;
          if (ended) return;
          await new Promise<void>((r) => { notify = r; });
          notify = null;
        }
      },
    };

    // The client reads the challenge first (AgentRelayClient #authenticate).
    push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    streams.push({ push });
    return stream;
  }

  return {
    openStream,
    submits,
    /** Deliver a frame to every open relay stream (leaf_deliver fan-in). */
    push(frame: Record<string, unknown>) { for (const s of streams) s.push(frame); },
    ctrlSubmits: () => submits.filter((f) => f["leaf_kind"] === 2),
  };
}

/** Real libp2p session nodes, with dial/newStream to the FAKE relay intercepted in-process. */
class FakeRelayNodeFactory implements ISessionNodeFactory {
  constructor(private readonly relay: ReturnType<typeof makeFakeRelayServer>) {}
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const node = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
    const relay = this.relay;
    return new Proxy(node, {
      get(target, prop) {
        if (prop === "dial") {
          return async (addr: unknown) => {
            if (String(addr) === FAKE_RELAY_ADDR) return;
            return (target as unknown as { dial: (a: unknown) => Promise<unknown> }).dial(addr);
          };
        }
        if (prop === "newStream") {
          return async (peerId: unknown, proto: unknown) => {
            if (String(peerId) === FAKE_RELAY_PEER_ID) return relay.openStream();
            return (target as unknown as { newStream: (p: unknown, pr: unknown) => Promise<unknown> }).newStream(peerId, proto);
          };
        }
        const v = Reflect.get(target, prop, target);
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    }) as CelloNode;
  }
}

/** Injectable signaling that RECORDS outbound frames and lets the test inject inbound ones. */
function makeRecordingSignaling(ref: { inject?: (frame: unknown) => void; outbound: Record<string, unknown>[] }): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async (frame: unknown) => { ref.outbound.push(frame as Record<string, unknown>); },
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  ref.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor<T>(fn: () => T | undefined | null, timeoutMs: number, everyMs = 20): Promise<T | null> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v !== undefined && v !== null) return v;
    if (Date.now() > deadline) return null;
    await wait(everyMs);
  }
}

/** frameMessage(context, tbs) — must match frost-threshold-signer.ts (context ‖ 0x00 ‖ tbs). */
function frameSealMessage(tbs: Uint8Array): Uint8Array {
  const ctx = new TextEncoder().encode("cello-frost-seal-v1");
  const framed = new Uint8Array(ctx.length + 1 + tbs.length);
  framed.set(ctx, 0);
  framed[ctx.length] = 0x00;
  framed.set(tbs, ctx.length + 1);
  return framed;
}

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 21));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const TS = 1_700_000_000_000;

describe("M8B FINDING-1: unilateral seal escalation on retry close", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  let priorBilateralMs: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];

  beforeEach(async () => {
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    priorBilateralMs = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "150";
    tempDir = await mkdtemp(join(tmpdir(), "cello-seal-retry-"));
    handles.length = 0;
  });
  afterEach(async () => {
    for (const h of handles) { try { await h.stop("test_cleanup"); } catch { /* ignore */ } }
    handles.length = 0;
    await rm(tempDir, { recursive: true, force: true });
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"]; else process.env["CELLO_ENV"] = priorCelloEnv;
    if (priorBilateralMs === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = priorBilateralMs;
  });

  async function makeAgent(celloDir: string, name: string): Promise<string> {
    const dir = join(celloDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  /**
   * One daemon (agent "alice") + fake relay + recording signaling, with an active
   * relay-witnessed session whose counterparty is GONE (never reachable, never closes).
   * Returns everything the tests drive: the IPC client, the signaling recorder/injector,
   * and the fake relay.
   */
  async function setupSessionWithDeadCounterparty() {
    const dirA = join(tempDir, "A");
    const alicePubkey = await makeAgent(dirA, "alice");
    const relay = makeFakeRelayServer();
    const sig: { inject?: (frame: unknown) => void; outbound: Record<string, unknown>[] } = { outbound: [] };

    const negotiator: SessionNegotiator = {
      async negotiate() {
        const assignment: SessionAssignment = {
          session_id: SID_BYTES,
          participant_a: { pubkey: Buffer.from(alicePubkey, "hex"), peer_id: "", multiaddrs: [] },
          participant_b: { pubkey: new Uint8Array(32).fill(9), peer_id: "dead-counterparty", multiaddrs: [] },
          relay_endpoint: { peer_id: FAKE_RELAY_PEER_ID, multiaddrs: [FAKE_RELAY_ADDR] },
          directory_endpoint: { peer_id: "", multiaddrs: [] },
          session_timestamp: TS,
          directory_pubkey: new Uint8Array(32),
          directory_signature: new Uint8Array(64),
          transport_mode: "direct",
          counterparty_session_peer_id: "dead-counterparty",
          counterparty_session_addrs: [],
          signature_type: "frost",
          signer_pubkey: new Uint8Array(32),
        };
        return { ok: true, assignment };
      },
    };

    const { logger, events } = makeLogger();
    const config: DaemonConfig = {
      celloDir: dirA,
      socketPath: join(dirA, "daemon.sock"),
      lockFilePath: join(dirA, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNodeFactory: new FakeRelayNodeFactory(relay),
      signalingConnect: makeRecordingSignaling(sig),
      sessionNegotiator: negotiator,
    };
    const h = await startDaemon(config);
    handles.push(h);

    const client = await connectToDaemon(join(dirA, "daemon.sock"));
    await client.send("ipc.connect", { clientType: "test" });
    expect(((await client.send("cello_start_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    const srReady = await waitFor(() => h.getSessionNodeManager().getStandingReceiverInfo("alice"), 5_000);
    expect(srReady).not.toBeNull();

    const initRes = (await client.send("cello_initiate_session", { target_pubkey: "bb".repeat(32) })) as Record<string, unknown>;
    expect(initRes.ok).toBe(true);
    expect(initRes.sessionId).toBe(SID_HEX);

    return { h, client, sig, relay, alicePubkey, events, celloDir: dirA };
  }

  it("F20: the too-early reply's remaining_seconds reaches the seal_counterparty_pending guidance", async () => {
    const { client, sig } = await setupSessionWithDeadCounterparty();
    const closeP = client.send("cello_close_session", { session_id: SID_HEX }) as Promise<Record<string, unknown>>;
    const uni = await waitFor(() => sig.outbound.find((f) => f["type"] === "seal_unilateral"), 10_000);
    expect(uni, "close must escalate to a seal_unilateral frame").not.toBeNull();
    sig.inject!({ type: "seal_unilateral_too_early", session_id: SID_BYTES, remaining_seconds: 42 });
    const res = await closeP;
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("seal_counterparty_pending");
    // The directory's remaining_seconds must reach the operator guidance ("~42s").
    expect(String(res.guidance)).toMatch(/42/);
  }, 40_000);

  it("close #2 after grace → unilateral seal completes with the FIRST submit's reported_root (FINDING-1)", async () => {
    const { h, client, sig, relay, alicePubkey } = await setupSessionWithDeadCounterparty();

    // ── Close #1 (inside grace): escalates, directory replies too_early.
    const close1P = client.send("cello_close_session", { session_id: SID_HEX }) as Promise<Record<string, unknown>>;
    const uni1 = await waitFor(() => sig.outbound.find((f) => f["type"] === "seal_unilateral"), 10_000);
    expect(uni1, "close #1 must escalate to a seal_unilateral frame").not.toBeNull();
    sig.inject!({ type: "seal_unilateral_too_early", session_id: SID_BYTES, remaining_seconds: 42 });
    const res1 = await close1P;
    expect(res1.ok).toBe(false);
    expect(res1.reason).toBe("seal_counterparty_pending");

    // ── Close #2 (retry — the live-deadlock path): the SEAL leaf is already submitted;
    //    the daemon MUST still escalate, re-using the FIRST submit's reported_root.
    const close2P = client.send("cello_close_session", { session_id: SID_HEX }) as Promise<Record<string, unknown>>;
    const uni2 = await waitFor(() => sig.outbound.filter((f) => f["type"] === "seal_unilateral")[1], 10_000);
    if (!uni2) {
      // RED against 0.0.20: no second frame is ever sent and the close degrades to
      // seal_pending_bilateral forever. Surface the actual result for the failure message.
      const res2 = await close2P;
      expect.fail(`close #2 never re-sent seal_unilateral; close returned reason=${String(res2.reason)} (FINDING-1 deadlock)`);
    }
    const root1 = Buffer.from(uni1!["reported_root"] as Uint8Array).toString("hex");
    const root2 = Buffer.from(uni2["reported_root"] as Uint8Array).toString("hex");
    expect(root2).toBe(root1);
    expect(uni2["reported_seq"]).toBe(uni1!["reported_seq"]);

    // ── Directory (grace elapsed) confirms: forge a verifiable 'frost' certificate.
    //    A 1-party FROST signature verifies as plain Ed25519 over frameMessage(ctx, TBS);
    //    seed alice's persisted share so commitments[0] is the test key.
    const certKp = generateKeypair();
    const certPub = await certKp.getPublicKey();
    const persistence = new DbRegistrationPersistence({
      db: h.getSessionNodeManager().getDb(),
      agentName: "alice",
      logger: { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger,
    });
    await persistence.persistFrostKeyShare({
      epochId: "test-epoch",
      primaryPubkey: Buffer.from(certPub).toString("hex"),
      identifier: "1",
      signingShare: new Uint8Array(32).fill(1),
      threshold: 1,
      participants: 1,
      commitmentsCbor: CBOR_ENC.encode([certPub]) as Uint8Array,
      verifyingSharesCbor: CBOR_ENC.encode([]) as Uint8Array,
      dkgMethod: "trusted_dealer",
    });
    const sealedRoot = new Uint8Array(Buffer.from(root2, "hex"));
    const leafCount = 1;
    const closeTimestamp = TS + 1;
    const tbs = buildSealTbs(SID_BYTES, sealedRoot, leafCount, closeTimestamp);
    const frostSig = await certKp.sign(frameSealMessage(tbs));
    sig.inject!({
      type: "seal_unilateral_confirmed",
      session_id: SID_BYTES,
      sealed_root: sealedRoot,
      frost_signature: frostSig,
      leaf_count: leafCount,
      close_timestamp: closeTimestamp,
      signature_type: "frost",
    });

    const res2 = await close2P;
    expect(res2.ok).toBe(true);
    expect(res2.seal_type).toBe("unilateral");
    expect(res2.sealed_root).toBe(root2);

    // Idempotency held throughout: both closes produced exactly ONE relay SEAL ctrl leaf.
    expect(relay.ctrlSubmits().length).toBe(1);
    expect(alicePubkey.length).toBe(64);
  }, 40_000);

  it("auto-ack path: bilateral seal landing within the wait window returns the BILATERAL result — no unilateral escalation", async () => {
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "5000";
    const { client, sig, relay } = await setupSessionWithDeadCounterparty();

    // ── The COUNTERPARTY's SEAL ctrl leaf arrives via the relay → auto-ack submits OUR leaf.
    const counterpartyKp = generateKeypair();
    const counterpartyPub = await counterpartyKp.getPublicKey();
    const s1 = encodeStructure1(new Uint8Array(32).fill(0xcd), counterpartyPub, SID_BYTES, 0, TS);
    relay.push({
      type: "leaf_deliver",
      sequence_number: 1,
      leaf_kind: 2,
      session_id: SID_BYTES,
      structure1_cbor: s1,
      structure2_cbor: new Uint8Array([1, 2, 3, 4]),
    });
    const autoAcked = await waitFor(() => (relay.ctrlSubmits().length >= 1 ? true : undefined), 10_000);
    expect(autoAcked, "auto-ack must submit our responder SEAL leaf").toBe(true);

    // ── Explicit close during the bilateral window; the directory seals bilaterally.
    const closeP = client.send("cello_close_session", { session_id: SID_HEX }) as Promise<Record<string, unknown>>;
    await wait(100); // let the close register its waiter inside the (5s) bilateral window
    const bilateralRoot = "ab".repeat(32);
    sig.inject!({ type: "session_sealed", session_id: SID_BYTES, sealed_root: new Uint8Array(Buffer.from(bilateralRoot, "hex")) });
    const res = await closeP;
    expect(res.ok).toBe(true);
    expect(res.sealed_root).toBe(bilateralRoot);
    expect(res.seal_type).toBeUndefined(); // bilateral — not a unilateral escalation
    expect(sig.outbound.find((f) => f["type"] === "seal_unilateral")).toBeUndefined();
    expect(relay.ctrlSubmits().length).toBe(1); // auto-ack's single submit; the close did not double-submit
  }, 40_000);

  it("two concurrent closes submit exactly ONE relay SEAL ctrl leaf (idempotency preserved)", async () => {
    const { client, sig, relay } = await setupSessionWithDeadCounterparty();
    const closeA = client.send("cello_close_session", { session_id: SID_HEX }) as Promise<Record<string, unknown>>;
    const closeB = client.send("cello_close_session", { session_id: SID_HEX }) as Promise<Record<string, unknown>>;
    // Answer the (single) escalation so closeA resolves.
    await waitFor(() => sig.outbound.find((f) => f["type"] === "seal_unilateral"), 10_000);
    sig.inject!({ type: "seal_unilateral_too_early", session_id: SID_BYTES, remaining_seconds: 10 });
    const [resA, resB] = await Promise.all([closeA, closeB]);
    const reasons = [resA.reason, resB.reason].sort();
    // One close runs the flow; the other is rejected by the in-progress guard.
    expect(reasons).toContain("seal_interrupted_in_progress");
    expect(reasons).toContain("seal_counterparty_pending");
    // The invariant with teeth: exactly ONE relay SEAL ctrl leaf was submitted.
    expect(relay.ctrlSubmits().length).toBe(1);
  }, 40_000);

  // ─── DOD-SESSION-NAME-1 — the two clauses only a REAL seal can prove ─────────────────────────
  //
  // These live here, on this harness, deliberately. The unit's own test file closes every session
  // with `force: true`, and that covers exactly one of AC-A7's three terminal paths. Move the name
  // write inside the `if (force)` block and every test in that file still passes, the whole gate
  // stays green, and the name silently stops being persisted on a HEALTHY close — the majority
  // case. A clause named for three paths, tested on one, is not covered.
  //
  // The same harness answers the constraint that actually matters. A grep proving the string
  // `session_name` is absent from the wire packages cannot see a leak built in `daemon.ts`, which
  // is where the frames are CONSTRUCTED — and it is blind to a leak under a different key. So the
  // name here is a NONCE, and the assertion is behavioural: after a real seal ceremony, that string
  // appears in no signaling frame and in no byte the relay received.

  /** A string that cannot occur by accident, so finding it anywhere on the wire is proof of a leak. */
  const NONCE_NAME = "Zorblat-9271 acquisition notes";

  /** Every frame the daemon put on a wire: the signaling channel, and the relay. */
  function wireBytes(
    sig: { outbound: Record<string, unknown>[] },
    relay: ReturnType<typeof makeFakeRelayServer>,
  ): string {
    const frames = [...sig.outbound, ...relay.submits];
    // Byte-level, not key-level: JSON.stringify of a frame carrying the name under ANY key — or
    // buried inside an encoded structure — still contains the substring.
    const asJson = JSON.stringify(frames, (_k, v) =>
      v instanceof Uint8Array ? Buffer.from(v).toString("utf8") : v);
    return asJson;
  }

  it("AC-A7 (bilateral): a name given to a NON-force close survives the real seal — and reaches no wire", async () => {
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "5000";
    const { h, client, sig, relay } = await setupSessionWithDeadCounterparty();

    // Drive the counterparty's SEAL leaf in so the close seals BILATERALLY (not force, not unilateral).
    const counterpartyKp = generateKeypair();
    const counterpartyPub = await counterpartyKp.getPublicKey();
    const s1 = encodeStructure1(new Uint8Array(32).fill(0xcd), counterpartyPub, SID_BYTES, 0, TS);
    relay.push({
      type: "leaf_deliver", sequence_number: 1, leaf_kind: 2, session_id: SID_BYTES,
      structure1_cbor: s1, structure2_cbor: new Uint8Array([1, 2, 3, 4]),
    });
    await waitFor(() => (relay.ctrlSubmits().length >= 1 ? true : undefined), 10_000);

    const closeP = client.send("cello_close_session", { session_id: SID_HEX, session_name: NONCE_NAME }) as Promise<Record<string, unknown>>;
    await wait(100);
    const bilateralRoot = "ab".repeat(32);
    sig.inject!({ type: "session_sealed", session_id: SID_BYTES, sealed_root: new Uint8Array(Buffer.from(bilateralRoot, "hex")) });
    const res = await closeP;

    expect(res.ok, "the close must actually seal — a name must not change that").toBe(true);
    expect(res.sealed_root).toBe(bilateralRoot);

    const record = h.getSessionNodeManager().getSessionRecord("alice", SID_HEX);
    expect(record?.status).toBe("sealed");
    expect(record?.session_name, "the name must survive a BILATERAL close, not just a forced one").toBe(NONCE_NAME);

    expect(wireBytes(sig, relay), "the session name reached the wire").not.toContain("Zorblat");
  }, 40_000);

  it("AC-A7 (unilateral): the name persists on the escalation path too, and rides no seal_unilateral frame", async () => {
    const { h, client, sig, relay } = await setupSessionWithDeadCounterparty();

    const closeP = client.send("cello_close_session", { session_id: SID_HEX, session_name: NONCE_NAME }) as Promise<Record<string, unknown>>;
    const uni = await waitFor(() => sig.outbound.find((f) => f["type"] === "seal_unilateral"), 10_000);
    expect(uni, "close must escalate to a seal_unilateral frame").not.toBeNull();

    // Persisted on the way in, before the ceremony resolves — which is the point: the name must not
    // depend on the seal succeeding, and the seal must not depend on the name.
    expect(h.getSessionNodeManager().getSessionRecord("alice", SID_HEX)?.session_name).toBe(NONCE_NAME);

    sig.inject!({ type: "seal_unilateral_too_early", session_id: SID_BYTES, remaining_seconds: 42 });
    await closeP;

    expect(wireBytes(sig, relay), "the session name reached the wire").not.toContain("Zorblat");
  }, 40_000);
});
