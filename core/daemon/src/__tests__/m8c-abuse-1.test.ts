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
import { TIER } from "../contacts-tier-migration.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { DaemonDatabase } from "../sqlcipher-db.js";

/**
 * DOD-AGENT-ID-JOINKEY-1: `sessions`/`transcript` are now keyed by the STABLE `agent_id`, not the
 * mutable `agent_name`. Every raw-SQL seed below runs AFTER `makeAgentDir` + daemon start, so the
 * named agent already has a real `agents` row (imported from its flat-file key at startup) —
 * resolve its id off that row rather than writing the (no-longer-a-column) name.
 */
function resolveAgentId(db: DaemonDatabase, agentName: string): string {
  const row = db
    .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
    .get(agentName) as { agent_id: string } | undefined;
  if (!row) {
    throw new Error(
      `test fixture bug: agent '${agentName}' has no 'agents' row yet — create it (makeAgentDir + ` +
        `daemon start) before hand-writing a session row for it`,
    );
  }
  return row.agent_id;
}

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

  it("B2 (DOD-TIER-2): a KNOWN contact gets the larger 100 MB cap — real headroom past UNKNOWN's 25 MB, not exemption", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const db = snm.getDb();
    await snm.createSessionNode(SID, "alice", "friendpubkeyhex", "peer-1", "corr");
    snm.addContact("alice", "friendpubkeyhex");
    // 'exempt entirely' is gone (INV-TIER-BOUND: no tier unbounded). Set the contact to KNOWN (100 MB
    // cap) explicitly — cello_contact_set_tier is Step 3. Prior received == exactly UNKNOWN's 25 MB
    // cap, so a stranger (or an UNKNOWN-tier contact) would be refused; a KNOWN contact has headroom.
    db.prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?")
      .run(TIER.KNOWN, resolveAgentId(db, "alice"), "friendpubkeyhex");

    const bigChunk = new Uint8Array(ABUSE_MAX_SESSION_RECEIVED_BYTES);
    const { leafIndex } = snm.appendSessionLeaf("alice", SID, "msg", "aa".repeat(32), "seed");
    snm.recordTranscriptMessage("alice", SID, leafIndex, "received", bigChunk, "seed");

    const small = new TextEncoder().encode("still fine — 25 MB + this is under KNOWN's 100 MB");
    const res = await snm.ingestReceivedContent("alice", SID, small, msgLeafHash(small), "corr-2");
    expect(res.ok).toBe(true); // 25 MB + small < 100 MB (KNOWN) — would be refused at UNKNOWN's 25 MB
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
    const aliceId = resolveAgentId(db, "alice");
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = i.toString(16).padStart(32, "0");
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
      ).run(sid, aliceId, strangerPubkey, now, now);
    }
    expect(snm.isContact("alice", strangerPubkey)).toBe(false); // genuinely still unknown

    const blocked = snm.checkUnknownSenderAcceptanceBound("alice", strangerPubkey);
    expect(blocked).toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" });

    // DOD-TIER-2: a HIGHER-tier contact with the SAME session count is admitted — the cap is the
    // sender's tier cap, not a flat 3-then-exempt. KNOWN's cap is 5, so 3 active sessions is under it.
    snm.addContact("alice", strangerPubkey);
    db.prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?").run(TIER.KNOWN, aliceId, strangerPubkey);
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
    const bobId = resolveAgentId(snm.getDb(), "bob");
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = i.toString(16).padStart(32, "0");
      snm.getDb().prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
      ).run(sid, bobId, strangerPubkey, now, now);
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
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    });
    await wait(150);

    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  it("DOD-TIER-3 (real wiring): a BLOCKED sender's inbound knock creates NOTHING — no node, no row, no accept, no away/doorbell — refused identically to an over-cap unknown", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    // A BLOCKED contact (tier 0). getTier → BLOCKED → per-sender cap 0 → refused before any state.
    const blockedPubkey = "b0".repeat(32);
    const bobId = resolveAgentId(snm.getDb(), "bob");
    snm.addContact("bob", blockedPubkey);
    snm.getDb().prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?").run(TIER.BLOCKED, bobId, blockedPubkey);

    events.length = 0; // observe only the knock's effects
    const sid = Uint8Array.from(Array.from({ length: 16 }, (_, b) => 100 + b));
    injectRef.inject!({
      type: "session_assignment",
      assignment: {
        session_id: sid,
        participant_a: { pubkey: Buffer.from(blockedPubkey, "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        session_timestamp: 1_700_000_000_000,
        signature_type: "frost",
        initiator_session_peer_id: "blocked-peer-id",
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    });
    await wait(150);

    // Refused with the SAME reason an over-cap unknown gets — no distinguishing oracle (DOD-TIER-3 AC1).
    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    // AC2: nothing created — no session node, no accept, no away reply, no Telegram doorbell. This is
    // the direct test for the reviewer's bypass (moving any of these ABOVE the bound check).
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
    expect(events.find((e) => e.event === "session.node.created")).toBeUndefined();
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    expect(events.find((e) => e.event === "telegram.doorbell.sent")).toBeUndefined();
    // And no session ROW for the blocked sender.
    const row = snm.getDb().prepare("SELECT 1 FROM sessions WHERE agent_id = ? AND counterparty_pubkey = ?").get(bobId, blockedPubkey);
    expect(row).toBeUndefined();
  });

  it("CC-1 (live 3f regression): repeated REAL inbound knocks from one unknown sender stay capped — the sender is NOT auto-added on accept, so the per-sender bound keeps applying (the old auto-add promoted them at session 1, exempting sessions 2+)", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    const strangerPubkey = "3c".repeat(32);
    const knock = async (n: number): Promise<void> => {
      const sid = Uint8Array.from(Array.from({ length: 16 }, (_, b) => (n * 16 + b) & 0xff));
      injectRef.inject!({
        type: "session_assignment",
        assignment: {
          session_id: sid,
          participant_a: { pubkey: Buffer.from(strangerPubkey, "hex") },
          participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
          session_timestamp: 1_700_000_000_000 + n,
          signature_type: "frost",
          initiator_session_peer_id: `stranger-peer-${n}`,
          // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
          counterparty_session_peer_id: "bob-session-peer-id",
        },
      });
      await wait(120); // accepts are serialized — let each settle before the next
    };

    // The first CAP knocks are accepted (sender genuinely unknown, under the per-sender bound).
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) await knock(i);
    expect(snm.countActiveSessionsForCounterparty("bob", strangerPubkey)).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    // CC-1: accepting the connection did NOT make them a contact.
    expect(snm.isContact("bob", strangerPubkey)).toBe(false);

    // The CAP+1'th REAL knock must now be refused by the actual accept-path gate — the exact live
    // 3f failure (4 sequential sessions all accepted) is fixed.
    events.length = 0;
    await knock(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
    expect(snm.countActiveSessionsForCounterparty("bob", strangerPubkey)).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
  });

  it("CC-10 (live Phase-2 block regression): DEAD interrupted 0-received ghosts do NOT permanently consume the per-sender bound — the accept path reaps them first and admits the stranger's next knock", async () => {
    // The live 2026-07-08 failure: a daemon restart flipped the stranger's dead half-open sessions
    // to 'interrupted' (0 received, no live node). They classify as "failed" (invisible in every
    // list), the CC-5 reaper only scanned 'active', and the bound counts 'interrupted' (D18) — so
    // the stranger was silently locked out FOREVER. The accept path must reap dead ghosts before
    // checking the bound.
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    const strangerPubkey = "4d".repeat(32);
    // Seed the cap's worth of GHOSTS: interrupted, created 1h ago, 0 messages, no received rows,
    // no live node (liveness never marked) — the exact post-restart shape from the live block.
    const old = Date.now() - 60 * 60 * 1000;
    const ghostSids: string[] = [];
    const bobId = resolveAgentId(snm.getDb(), "bob");
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = `d${i}`.padStart(2, "0").repeat(16);
      ghostSids.push(sid);
      snm.getDb().prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'interrupted', ?, ?, 0, ?)`,
      ).run(sid, bobId, strangerPubkey, old, old, old);
    }
    expect(snm.isContact("bob", strangerPubkey)).toBe(false);
    expect(snm.countActiveSessionsForCounterparty("bob", strangerPubkey)).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);

    // The stranger's next REAL knock must be ACCEPTED — the ghosts are provably dead.
    const newSid = Uint8Array.from(Array.from({ length: 16 }, (_, b) => 100 + b));
    injectRef.inject!({
      type: "session_assignment",
      assignment: {
        session_id: newSid,
        participant_a: { pubkey: Buffer.from(strangerPubkey, "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        session_timestamp: 1_700_000_000_000,
        signature_type: "frost",
        initiator_session_peer_id: "stranger-peer-id",
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    });
    await wait(150);

    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeUndefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeDefined();
    // And the ghosts went properly terminal — slot released in the DB, not just skipped.
    for (const sid of ghostSids) {
      const row = snm.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(sid) as { status: string };
      expect(row.status).toBe("abandoned");
    }
    // Observability: the reap event carries the ghost's prior status (CC-10 added priorStatus).
    const reaped = events.filter((e) => e.event === "session.half_open.reaped");
    expect(reaped.length).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    for (const e of reaped) expect(e.context["priorStatus"]).toBe("interrupted");
  });

  it("CC-10/D18 guard: old interrupted sessions WITH received content still count — the accept-path reap must NOT free the D18 evasion attacker's slots", async () => {
    // D18's attack: send content, disconnect (→ interrupted), open a fresh session, repeat.
    // Those sessions have RECEIVED bytes on the victim's side, so the reap must skip them and
    // the bound must still refuse. Only 0-received ghosts (zero delivered abuse) are reapable.
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    const attackerPubkey = "5e".repeat(32);
    const old = Date.now() - 60 * 60 * 1000;
    const sids: string[] = [];
    const bobId = resolveAgentId(snm.getDb(), "bob");
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = `e${i}`.padStart(2, "0").repeat(16);
      sids.push(sid);
      snm.getDb().prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'interrupted', ?, ?, 2, ?)`,
      ).run(sid, bobId, attackerPubkey, old, old, old);
      snm.getDb().prepare(
        `INSERT INTO transcript (agent_id, session_id, sequence, direction, blob, created_at)
         VALUES (?, ?, 0, 'received', ?, ?)`,
      ).run(bobId, sid, Buffer.from("attacker content"), old);
    }
    expect(snm.isContact("bob", attackerPubkey)).toBe(false);

    const newSid = Uint8Array.from(Array.from({ length: 16 }, (_, b) => 150 + b));
    injectRef.inject!({
      type: "session_assignment",
      assignment: {
        session_id: newSid,
        participant_a: { pubkey: Buffer.from(attackerPubkey, "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        session_timestamp: 1_700_000_000_000,
        signature_type: "frost",
        initiator_session_peer_id: "attacker-peer-id",
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    });
    await wait(150);

    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
    // The attacker's sessions were NOT reaped — they still count.
    for (const sid of sids) {
      const row = snm.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(sid) as { status: string };
      expect(row.status).toBe("interrupted");
    }
  });

  it("B4/B5: checkUnknownSenderAcceptanceBound — global anti-swarm cap trips once unknown-sender sessions reach it; a known contact is exempt regardless of count", async () => {
    await makeAgentDir("alice");
    const h = await start(makeLogger().logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const db = snm.getDb();

    // Seed ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL active sessions from DISTINCT unknown senders directly
    // (fast — no need to drive the full acceptance flow N times for a unit-level bound check).
    const now = Date.now();
    const aliceId = resolveAgentId(db, "alice");
    for (let i = 0; i < ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL; i++) {
      const sid = i.toString(16).padStart(32, "0");
      const cp = `stranger-${i}`;
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
      ).run(sid, aliceId, cp, now, now);
    }
    expect(snm.countActiveSessionsFromUnknownSenders("alice")).toBe(ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL);

    // B4: one more brand-new unknown sender is refused by the GLOBAL cap (their own per-sender
    // count is 0 — only the global total trips it).
    const brandNewStranger = "ff".repeat(32);
    const blocked = snm.checkUnknownSenderAcceptanceBound("alice", brandNewStranger);
    expect(blocked).toMatchObject({ ok: false, reason: "abuse_bound_unknown_sessions_global" });

    // B5 (DOD-TIER-2): a KNOWN+ contact is not part of the stranger pool — exempt from the GLOBAL
    // anti-swarm cap (still bounded by its own tier cap). Set the tier explicitly (set_tier is Step 3).
    snm.addContact("alice", brandNewStranger);
    db.prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?").run(TIER.KNOWN, aliceId, brandNewStranger);
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
    const aliceId = resolveAgentId(db, "alice");

    // All 'interrupted', not 'active' — the exact evasion: open, disconnect (interrupt), repeat.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      const sid = `f1${i}`.padStart(32, "0");
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'interrupted', ?, ?, 0, ?)`,
      ).run(sid, aliceId, stranger, now, now, new Date(now).toISOString());
    }
    expect(snm.countActiveSessionsForCounterparty("alice", stranger)).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    expect(snm.checkUnknownSenderAcceptanceBound("alice", stranger)).toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" });

    // Same for the global cap — all interrupted, still counted.
    const db2 = snm.getDb();
    for (let i = 0; i < ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL; i++) {
      const sid = `f2${i}`.padStart(32, "0");
      db2.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'interrupted', ?, ?, 0, ?)`,
      ).run(sid, aliceId, `other-${i}`, now, now, new Date(now).toISOString());
    }
    expect(snm.countActiveSessionsFromUnknownSenders("alice")).toBeGreaterThanOrEqual(ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL);
    expect(snm.checkUnknownSenderAcceptanceBound("alice", "brand-new-stranger")).toMatchObject({ ok: false, reason: "abuse_bound_unknown_sessions_global" });
  });
});
