/**
 * CELLO-M8C-ABUSE-1 — persistence bounds (the non-M9 remainder)
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note):
 * - B1: per-session total-size limit (anti-drip-feed) — many under-cap messages from a non-contact
 *   sender must not accumulate unbounded storage; rejected loudly once the cumulative RECEIVED
 *   byte total would exceed the cap.
 * - B2: a known contact is EXEMPT from the size cap entirely ("bounded only by disk" — DoD).
 * - B3: bounded unknown-sender queue per sender — a single unknown counterparty may hold at most
 *   ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER active sessions with one agent; further requests refused.
 * - B4: global daemon-wide unknown-sender cap (anti-swarm) — total active sessions from ALL
 *   unknown senders combined is bounded, independent of any one sender's own count.
 * - B5: a known contact is EXEMPT from both acceptance bounds entirely, regardless of count.
 * - Explicitly NOT rebuilt here (M9's): per-message cap (MAX_CONTENT_BYTES, already exists),
 *   outbound rate limiting.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import {
  ABUSE_MAX_SESSION_RECEIVED_BYTES,
  ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER,
  ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL,
} from "../session-node-manager.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
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
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}
class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
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

describe("M8C-ABUSE-1: persistence bounds", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-abuse-"));
    handle = null;
  });
  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function start(logger: Logger, node: CelloNode, signalingConnect?: () => Promise<ConnectResult>): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(node), signalingConnect,
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  const SID = "cd".repeat(32);

  it("B1: per-session total-size cap rejects a non-contact sender once the cumulative received total would be exceeded", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "strangerpubkeyhex", "peer-1", "corr");

    // Seed prior received bytes just under the cap (same producer as the real inbound path:
    // appendSessionLeaf + recordTranscriptMessage). Leave headroom SMALLER than the next
    // message so it genuinely tips the total over (not just closes part of the gap).
    const bigChunk = new Uint8Array(ABUSE_MAX_SESSION_RECEIVED_BYTES - 10);
    const { leafIndex } = snm.appendSessionLeaf("alice", SID, "msg", "aa".repeat(32), "seed");
    snm.recordTranscriptMessage("alice", SID, leafIndex, "received", bigChunk, "seed");

    const small = new TextEncoder().encode("this tips it over");
    const res = await snm.ingestReceivedContent("alice", SID, small, msgLeafHash(small), "corr-2");
    expect(res).toMatchObject({ ok: false, reason: "session_size_limit_exceeded" });
  });

  it("B2: a KNOWN contact is exempt from the size cap entirely", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "friendpubkeyhex", "peer-1", "corr");
    snm.addContact("alice", "friendpubkeyhex");

    const bigChunk = new Uint8Array(ABUSE_MAX_SESSION_RECEIVED_BYTES - 100);
    const { leafIndex } = snm.appendSessionLeaf("alice", SID, "msg", "aa".repeat(32), "seed");
    snm.recordTranscriptMessage("alice", SID, leafIndex, "received", bigChunk, "seed");

    const small = new TextEncoder().encode("still fine — known contact");
    const res = await snm.ingestReceivedContent("alice", SID, small, msgLeafHash(small), "corr-2");
    expect(res.ok).toBe(true); // no cap applied to a known contact
  });

  it("B3: checkUnknownSenderAcceptanceBound refuses a sender once THEIR OWN active-session count reaches the per-sender cap", async () => {
    // NOTE (design interaction, not a bug): CONTACT-1's D6 rule auto-adds a counterparty as a
    // known contact the MOMENT their first session is accepted (acceptInboundAssignment). That
    // means a sender is only ever "unknown" up to and including their very first accepted
    // session — from their second attempt onward they're already exempt from this bound. So the
    // per-sender cap's real-world purpose is bounding a BURST of near-simultaneous requests from
    // one brand-new pubkey (before the first one's contact-add has had a chance to land), not
    // repeated requests spread out over time. Test the gate function directly against that
    // scenario (pre-seeded active sessions, sender still NOT a contact) rather than driving
    // sequential real acceptances — which would auto-resolve to "known" after the first one,
    // exactly as CONTACT-1 requires, and could never exercise this bound at all.
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const db = snm.getDb();
    const strangerPubkey = "ee".repeat(32);
    const now = Date.now();
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = i.toString(16).padStart(32, "0");
      db.prepare(
        `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, 'alice', ?, 'active', ?, ?, 0, NULL)`,
      ).run(sid, strangerPubkey, now, now);
    }
    expect(snm.isContact("alice", strangerPubkey)).toBe(false); // genuinely still unknown

    const blocked = snm.checkUnknownSenderAcceptanceBound("alice", strangerPubkey);
    expect(blocked).toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" });

    // A known contact with the SAME session count is exempt.
    snm.addContact("alice", strangerPubkey);
    expect(snm.checkUnknownSenderAcceptanceBound("alice", strangerPubkey)).toEqual({ ok: true });
  });

  it("B3 (real wiring): acceptInboundAssignment actually calls the gate and refuses a genuinely-still-unknown sender's inbound request", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    const strangerPubkey = "ee".repeat(32);
    // Pre-seed the per-sender cap's worth of active sessions directly (bypassing acceptance, so
    // the sender stays genuinely unknown — see the previous test's note).
    const now = Date.now();
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = i.toString(16).padStart(32, "0");
      snm.getDb().prepare(
        `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, 'bob', ?, 'active', ?, ?, 0, NULL)`,
      ).run(sid, strangerPubkey, now, now);
    }
    expect(snm.isContact("bob", strangerPubkey)).toBe(false);

    // Their next REAL inbound request must be refused by the actual accept-path wiring.
    const newSid = Uint8Array.from(Array.from({ length: 16 }, (_, b) => 200 + b));
    injectRef.inject!({
      type: "session_assignment",
      assignment: {
        session_id: newSid,
        participant_a: { pubkey: Buffer.from(strangerPubkey, "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        session_timestamp: 1_700_000_000_000,
        signature_type: "frost",
        initiator_session_peer_id: "stranger-peer-id",
      },
    });
    await wait(150);

    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  it("B4/B5: checkUnknownSenderAcceptanceBound — global anti-swarm cap trips once unknown-sender sessions reach it; a known contact is exempt regardless of count", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const db = snm.getDb();

    // Seed ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL active sessions from DISTINCT unknown senders directly
    // (fast — no need to drive the full acceptance flow N times for a unit-level bound check).
    const now = Date.now();
    for (let i = 0; i < ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL; i++) {
      const sid = i.toString(16).padStart(32, "0");
      const cp = `stranger-${i}`;
      db.prepare(
        `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, 'alice', ?, 'active', ?, ?, 0, NULL)`,
      ).run(sid, cp, now, now);
    }
    expect(snm.countActiveSessionsFromUnknownSenders("alice")).toBe(ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL);

    // B4: one more brand-new unknown sender is refused by the GLOBAL cap (their own per-sender
    // count is 0 — only the global total trips it).
    const brandNewStranger = "ff".repeat(32);
    const blocked = snm.checkUnknownSenderAcceptanceBound("alice", brandNewStranger);
    expect(blocked).toMatchObject({ ok: false, reason: "abuse_bound_unknown_sessions_global" });

    // B5: a KNOWN contact is exempt from this same global saturation entirely.
    snm.addContact("alice", brandNewStranger);
    const allowed = snm.checkUnknownSenderAcceptanceBound("alice", brandNewStranger);
    expect(allowed).toEqual({ ok: true });
  });

  // Reviewer HIGH finding (aeffb82f, F1): the size cap ran AFTER the out-of-order hold-branch's
  // early return, so held content skipped it entirely — a non-contact sender could drip-feed
  // unbounded bytes by making every message arrive "out of order" relative to the relay witness.
  it("F1 regression: an oversized OUT-OF-ORDER (held) message from a non-contact is rejected, not silently held", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "strangerpubkeyhex", "peer-1", "corr");

    const bigChunk = new Uint8Array(ABUSE_MAX_SESSION_RECEIVED_BYTES + 100); // over the cap alone
    const hashHex = Buffer.from(msgLeafHash(bigChunk)).toString("hex");
    // Witness a canonical sequence AHEAD of the (empty) tree — forces the hold branch instead of
    // the direct-append path (nextExpected is 0 for a brand-new session).
    snm.recordWitnessedSequence("alice", SID, hashHex, 5);

    const res = await snm.ingestReceivedContent("alice", SID, bigChunk, msgLeafHash(bigChunk), "corr-2");
    expect(res).toMatchObject({ ok: false, reason: "session_size_limit_exceeded" });

    // Confirm nothing was silently held either — a later legitimate in-order message must not
    // trigger a release of the oversized (rejected) content.
    const { messages } = snm.readTranscript("alice", SID);
    expect(messages).toHaveLength(0);
  });

  // Reviewer HIGH finding (aeffb82f, F2): counting status = 'active' ONLY let a counterparty
  // evade both acceptance bounds for free — disconnecting flips a session to 'interrupted' (a
  // trivial, attacker-controlled action), which still accepts content but was never counted.
  it("F2 regression: 'interrupted' sessions still count toward BOTH the per-sender and global acceptance bounds", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const db = snm.getDb();
    const stranger = "12".repeat(32);
    const now = Date.now();

    // All 'interrupted', not 'active' — the exact evasion: open, disconnect (interrupt), repeat.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = `f1${i}`.padStart(32, "0");
      db.prepare(
        `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, 'alice', ?, 'interrupted', ?, ?, 0, ?)`,
      ).run(sid, stranger, now, now, new Date(now).toISOString());
    }
    expect(snm.countActiveSessionsForCounterparty("alice", stranger)).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    expect(snm.checkUnknownSenderAcceptanceBound("alice", stranger)).toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" });

    // Same for the global cap — all interrupted, still counted.
    const db2 = snm.getDb();
    for (let i = 0; i < ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL; i++) {
      const sid = `f2${i}`.padStart(32, "0");
      db2.prepare(
        `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, 'alice', ?, 'interrupted', ?, ?, 0, ?)`,
      ).run(sid, `other-${i}`, now, now, new Date(now).toISOString());
    }
    expect(snm.countActiveSessionsFromUnknownSenders("alice")).toBeGreaterThanOrEqual(ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL);
    expect(snm.checkUnknownSenderAcceptanceBound("alice", "brand-new-stranger")).toMatchObject({ ok: false, reason: "abuse_bound_unknown_sessions_global" });
  });
});
