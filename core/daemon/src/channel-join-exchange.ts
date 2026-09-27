/**
 * M16 046-JOINBELL — joining a channel, both sides, with no session.
 *
 * JOINER: the directory lookup returns the channel's relay record (signed by the channel key); the
 * joiner reads the channel's info record from those relays, writes its request — signed by itself,
 * sealed to the admin — into a hashed join slot on them, and rings the admin through the directory.
 * The admin's answer comes back as a `join_answer` notice (045) in the joiner's own notice slot.
 *
 * ADMIN: a ring names the channel and the joiner. The admin's daemon computes the slot, reads the
 * request, verifies it, and decides exactly as it always has — open and public admit at once,
 * invite-only waits for the admin agent — then writes the answer and rings the joiner.
 *
 * ⚠️ **THE SENDER IS A STRANGER.** A ring for a channel this daemon does not administer reads
 * nothing; a request is acted on only when it decodes strictly, verifies against the joiner the ring
 * named, and is newer than the last one from that joiner (one slot per joiner, newest signed time
 * wins); the admin's agent is alerted only on a NEW or CHANGED request; a withdrawal drops the
 * request silently; a request older than the channel's retention has lapsed and is dropped.
 *
 * ⚠️ **THE ANSWER IS THE CHANNEL KEY'S WORD.** The joiner accepts an answer only for a channel it
 * has an outstanding request for, only when the channel key signed it, and only when it is newer
 * than the last answer and than the last ejection it holds from that channel.
 *
 * The join note is free text from a stranger. As before this order, it does not reach the admin's
 * agent — the doorbell names the channel and the joiner, nothing else.
 */
import {
  channelJoinSlot, signChannelJoinRequest, encodeChannelJoinRequest, decodeChannelJoinRequest,
  verifyChannelJoinRequest, signChannelJoinWithdrawal, encodeChannelJoinWithdrawal,
  decodeChannelJoinWithdrawal, verifyChannelJoinWithdrawal, encodeChannelJoinSlotRecord,
  decodeChannelJoinSlotRecord, signChannelJoinAnswer, encodeChannelJoinAnswer,
  decodeChannelRelayRecord, verifyChannelRelayRecord, decodeChannelInfo, verifyChannelInfo,
  type ChannelJoinAnswer, type ChannelJoinRefusedReason, type ChannelAccess,
} from "@cello-protocol/protocol-types";
import { generateGroupKey, wrapGroupKeyFor, unwrapGroupKey, sealToRecipient, type GroupKey, type KeyProvider } from "@cello-protocol/crypto";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { ChannelMembershipStore } from "./channel-membership-store.js";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { extractErrorMessage } from "./error-message.js";

const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const bytesOf = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));

/** Decision 9, verbatim: what the joiner's agent is told when a guard refuses it. */
export const JOIN_THROTTLE_GUIDANCE =
  "Too many join requests to this channel. Wait before trying again. Repeated attempts are recorded against your agent and can affect its reputation.";
/**
 * 048-JOINNOTE Decision 3, verbatim: a key the directory does not know as a channel. A channel made
 * in another region moments ago has not replicated here yet, so the bare reason reads as a verdict.
 */
export const NOT_A_CHANNEL_GUIDANCE =
  "No channel with that key. If it was created in the last minute, it may not have reached every directory yet — try again shortly.";
/** The guard refusals that carry that guidance, from the directory or a relay. */
const GUARD_REASONS = new Set(["rate_limited", "join_slot_cap", "stale_request"]);

/** What this daemon knows about a channel it administers. `null` means it does not administer one. */
export interface LocalChannelAdmin {
  agentId: string;
  adminPubkeyHex: string;
  channelKeyProvider: KeyProvider;
  adminKeyProvider: KeyProvider;
}

/** The admin, or WHY there isn't one (021-WAKE item 21). */
export type AdminLookupOutcome =
  | { ok: true; adminPubkeyHex: string }
  | { ok: false; reason: string };

/**
 * The channel's CURRENT group key for its admin: the key at `settings.key_generation`, started at 1
 * and minted if absent, stored under the admin's own agent id. Used by BOTH admitting a member and
 * publishing, so a post made before anyone joined is readable by the first member.
 * `undefined` for a public channel or a channel with no membership settings.
 *
 * ⚠️ The admin stores its own channel's group key in the same table its subscribers use: a key held
 * only in this process is lost on restart, and the next member would get a DIFFERENT key at the same
 * generation. The generation comes from settings, not "newest key held".
 */
export function ensureCurrentGroupKey(
  deps: { members: ChannelMembershipStore; subscriptions: ChannelSubscriptionStore; now: () => number },
  adminAgentId: string,
  channelHex: string,
): GroupKey | undefined {
  const settings = deps.members.settings(channelHex);
  if (!settings || settings.access === "public") return undefined;
  let generation = settings.key_generation;
  if (generation === 0) generation = deps.members.startGeneration(channelHex);
  const held = deps.subscriptions.keysFor(adminAgentId, channelHex).find((k) => k.generation === generation);
  if (held) return held;
  const minted = generateGroupKey(generation);
  deps.subscriptions.addKey(adminAgentId, channelHex, minted, deps.now());
  return minted;
}

// ─── Stores ──────────────────────────────────────────────────────────────────────────────────────

const REQUESTS_SQL = `
  CREATE TABLE IF NOT EXISTS channel_join_requests (
    agent_id           TEXT    NOT NULL,
    channel_pubkey     TEXT    NOT NULL,
    admin_pubkey       TEXT    NOT NULL,
    access             TEXT    NOT NULL,
    relays             TEXT    NOT NULL,
    guidance           TEXT    NOT NULL,
    retention_seconds  INTEGER NOT NULL,
    signed_at          INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey)
  );
`;

export interface OutstandingJoin {
  agent_id: string;
  channel_pubkey: string;
  admin_pubkey: string;
  access: ChannelAccess;
  relays: string[];
  guidance: string;
  retention_seconds: number;
  signed_at: number;
}

/** The joiner's outstanding requests. Keyed on agent_id; a row exists only while unanswered. */
export class ChannelJoinRequestStore {
  readonly #db: DaemonDatabase;

  constructor(db: DaemonDatabase) {
    this.#db = db;
    this.#db.exec(REQUESTS_SQL);
  }

  put(r: OutstandingJoin): void {
    this.#db.prepare(`INSERT INTO channel_join_requests
        (agent_id, channel_pubkey, admin_pubkey, access, relays, guidance, retention_seconds, signed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (agent_id, channel_pubkey) DO UPDATE SET admin_pubkey = excluded.admin_pubkey,
          access = excluded.access, relays = excluded.relays, guidance = excluded.guidance,
          retention_seconds = excluded.retention_seconds, signed_at = excluded.signed_at`)
      .run(r.agent_id, r.channel_pubkey, r.admin_pubkey, r.access, JSON.stringify(r.relays), r.guidance, r.retention_seconds, r.signed_at);
  }

  get(agentId: string, channelHex: string): OutstandingJoin | null {
    return this.forAgent(agentId).find((r) => r.channel_pubkey === channelHex) ?? null;
  }

  forAgent(agentId: string): OutstandingJoin[] {
    const rows = this.#db.prepare(`SELECT * FROM channel_join_requests WHERE agent_id = ?`).all(agentId) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      agent_id: String(r["agent_id"]), channel_pubkey: String(r["channel_pubkey"]), admin_pubkey: String(r["admin_pubkey"]),
      access: String(r["access"]) as ChannelAccess, relays: JSON.parse(String(r["relays"])) as string[],
      guidance: String(r["guidance"]), retention_seconds: Number(r["retention_seconds"]), signed_at: Number(r["signed_at"]),
    }));
  }

  agentsWithRequests(): string[] {
    const rows = this.#db.prepare(`SELECT DISTINCT agent_id FROM channel_join_requests`).all() as Array<{ agent_id: string }>;
    return rows.map((r) => r.agent_id);
  }

  remove(agentId: string, channelHex: string): void {
    this.#db.prepare(`DELETE FROM channel_join_requests WHERE agent_id = ? AND channel_pubkey = ?`).run(agentId, channelHex);
  }
}

const SEEN_SQL = `
  CREATE TABLE IF NOT EXISTS channel_join_seen (
    channel_pubkey  TEXT    NOT NULL,
    joiner_pubkey   TEXT    NOT NULL,
    signed_at       INTEGER NOT NULL,
    PRIMARY KEY (channel_pubkey, joiner_pubkey)
  );
`;

/** The admin's newest signed time per (channel, joiner) — what makes a repeat silent. */
export class ChannelJoinSeenStore {
  readonly #db: DaemonDatabase;

  constructor(db: DaemonDatabase) {
    this.#db = db;
    this.#db.exec(SEEN_SQL);
  }

  get(channelHex: string, joinerHex: string): number {
    const row = this.#db.prepare(`SELECT signed_at FROM channel_join_seen WHERE channel_pubkey = ? AND joiner_pubkey = ?`)
      .get(channelHex, joinerHex) as { signed_at: number | bigint } | undefined;
    return row ? Number(row.signed_at) : 0;
  }

  set(channelHex: string, joinerHex: string, signedAt: number): void {
    this.#db.prepare(`INSERT INTO channel_join_seen (channel_pubkey, joiner_pubkey, signed_at) VALUES (?, ?, ?)
        ON CONFLICT (channel_pubkey, joiner_pubkey) DO UPDATE SET signed_at = excluded.signed_at`)
      .run(channelHex, joinerHex, signedAt);
  }
}

// ─── Transport, as this file sees it ────────────────────────────────────────────────────────────

export interface JoinRelays {
  /** Deposit a join slot record on every relay: how many took it, and every refusal reason. Never throws. */
  depositJoin: (relays: string[], record: Uint8Array) => Promise<{ accepted: number; refusals: string[] }>;
  /** Every join slot record the relays hold at this slot. Never throws. */
  fetchJoin: (relays: string[], slot: Uint8Array) => Promise<Uint8Array[]>;
  /** The channel's info record from its relays, or null. */
  fetchInfo: (relays: string[], channelHex: string) => Promise<Uint8Array | null>;
  /**
   * 047-JOINPULL: every waiting join slot record the relays hold for this channel. Each relay issues
   * a one-time nonce and `sign` signs its preimage with the CHANNEL key. Never throws.
   */
  listJoins: (relays: string[], channelHex: string, sign: (tbs: Uint8Array) => Promise<Uint8Array>) => Promise<Uint8Array[]>;
}

/** The directory, as the joiner sees it. */
export interface JoinDirectory {
  /** The channel lookup: the admin and the channel-signed relay record, or why not. */
  lookup: (agentId: string, channelHex: string) => Promise<
    | { kind: "admin"; adminPubkeyHex: string; relayRecord?: Uint8Array }
    | { kind: "not_a_channel" } | { kind: "revoked" } | { kind: "unavailable"; reason: string }
  >;
  /** Ring the channel's admin. The directory's answer, including a guard refusal. */
  ring: (agentName: string, channelHex: string) => Promise<{ ok: true } | { ok: false; reason: string }>;
}

// ─── The joiner ──────────────────────────────────────────────────────────────────────────────────

export type ChannelJoinResult =
  | { ok: true; channelHex: string; state: "requested"; rung: boolean }
  | {
      ok: false;
      reason: "not_a_channel" | "unavailable" | "channel_deleted" | "no_relays" | "relay_record_invalid"
        | "channel_info_unavailable" | "relays_unreachable" | "no_key_provider" | "not_requested"
        | "rate_limited" | "join_slot_cap" | "stale_request";
      detail?: string;
      guidance?: string;
    };

export interface ChannelJoinerDeps {
  logger: Logger;
  requests: ChannelJoinRequestStore;
  relays: JoinRelays;
  directory: JoinDirectory;
  keyProviderFor: (agentId: string) => KeyProvider | null;
  now?: () => number;
}

/** Read and verify the channel's info record: what subscription setup needs. Null when none verifies. */
async function channelFacts(
  relays: JoinRelays, relayList: string[], channelHex: string,
): Promise<{ access: ChannelAccess; guidance: string; retention_seconds: number } | null> {
  const bytes = await relays.fetchInfo(relayList, channelHex).catch(() => null);
  if (!bytes) return null;
  const decoded = decodeChannelInfo(bytes);
  if (!decoded.ok || hexOf(decoded.info.channel_pubkey) !== channelHex || !verifyChannelInfo(decoded.info)) return null;
  return { access: decoded.info.access, guidance: decoded.info.guidance, retention_seconds: decoded.info.retention_seconds };
}

/** Seal a joiner-signed record to the admin and write it into the joiner's join slot. */
async function writeSlot(
  deps: ChannelJoinerDeps, myKey: KeyProvider, channelHex: string, adminHex: string, relayList: string[],
  inner: Uint8Array, signedAt: number,
): Promise<{ accepted: number; refusals: string[] } | null> {
  if (!myKey.staticSharedSecret) return null;
  const shared = await myKey.staticSharedSecret(bytesOf(channelHex));
  if (!shared) return null;
  const record = encodeChannelJoinSlotRecord({
    channel_pubkey: bytesOf(channelHex), slot: channelJoinSlot(shared), signed_at: signedAt,
    sealed: sealToRecipient(bytesOf(adminHex), inner),
  });
  return deps.relays.depositJoin(relayList, record);
}

export function createChannelJoiner(deps: ChannelJoinerDeps) {
  const { logger } = deps;
  const now = deps.now ?? (() => Date.now());

  /** Ask to join. Directory → relays → a sealed signed record → a ring. No session, ever. */
  async function join(agentName: string, agentId: string, channelHex: string, note = ""): Promise<ChannelJoinResult> {
    const found = await deps.directory.lookup(agentId, channelHex);
    if (found.kind === "not_a_channel") return { ok: false, reason: "not_a_channel", guidance: NOT_A_CHANNEL_GUIDANCE };
    if (found.kind === "revoked") return { ok: false, reason: "channel_deleted", guidance: "This channel was deleted by its admin." };
    if (found.kind === "unavailable") return { ok: false, reason: "unavailable", detail: found.reason };
    if (!found.relayRecord) {
      return { ok: false, reason: "no_relays", guidance: "The channel's admin has not published where to ask to join. Try again later." };
    }
    const rec = decodeChannelRelayRecord(found.relayRecord);
    if (!rec.ok || hexOf(rec.record.channel_pubkey) !== channelHex || !verifyChannelRelayRecord(rec.record)) {
      logger.warn("channel.join.rejected", { channel_pubkey: channelHex, record: "relay_record", reason: rec.ok ? "signature_invalid" : rec.reason });
      return { ok: false, reason: "relay_record_invalid" };
    }
    const relayList = rec.record.relays;
    const facts = await channelFacts(deps.relays, relayList, channelHex);
    if (!facts) return { ok: false, reason: "channel_info_unavailable", detail: "no relay served a verified info record" };

    const myKey = deps.keyProviderFor(agentId);
    if (!myKey) return { ok: false, reason: "no_key_provider" };
    const signedAt = now();
    const request = await signChannelJoinRequest(myKey, { channel_pubkey: bytesOf(channelHex), note, signed_at: signedAt });
    const wrote = await writeSlot(deps, myKey, channelHex, found.adminPubkeyHex, relayList, encodeChannelJoinRequest(request), signedAt);
    if (!wrote) return { ok: false, reason: "no_key_provider", detail: "this agent's key cannot derive the join slot" };
    if (wrote.accepted === 0) {
      const guard = wrote.refusals.find((r) => GUARD_REASONS.has(r));
      if (guard) return { ok: false, reason: guard as "rate_limited" | "join_slot_cap" | "stale_request", guidance: JOIN_THROTTLE_GUIDANCE };
      return { ok: false, reason: "relays_unreachable", detail: wrote.refusals.join(", ") || "no relay answered" };
    }

    deps.requests.put({
      agent_id: agentId, channel_pubkey: channelHex, admin_pubkey: found.adminPubkeyHex.toLowerCase(),
      access: facts.access, relays: relayList, guidance: facts.guidance, retention_seconds: facts.retention_seconds, signed_at: signedAt,
    });
    logger.info("channel.join.requested", { channel_pubkey: channelHex, relays_ok: wrote.accepted });

    const rung = await deps.directory.ring(agentName, channelHex);
    if (!rung.ok && GUARD_REASONS.has(rung.reason)) {
      return { ok: false, reason: rung.reason as "rate_limited", guidance: JOIN_THROTTLE_GUIDANCE };
    }
    if (!rung.ok) logger.warn("channel.join.ring_failed", { channel_pubkey: channelHex, reason: rung.reason });
    // A ring that did not go out is not a failed request: the admin reads it on its next check.
    return { ok: true, channelHex, state: "requested", rung: rung.ok };
  }

  /** Decision 12: take an outstanding request back. The admin's pending list drops it silently. */
  async function withdraw(agentName: string, agentId: string, channelHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const outstanding = deps.requests.get(agentId, channelHex);
    if (!outstanding) return { ok: false, reason: "not_requested" };
    const myKey = deps.keyProviderFor(agentId);
    if (!myKey) return { ok: false, reason: "no_key_provider" };
    const signedAt = Math.max(now(), outstanding.signed_at + 1);
    const w = await signChannelJoinWithdrawal(myKey, { channel_pubkey: bytesOf(channelHex), signed_at: signedAt });
    const wrote = await writeSlot(deps, myKey, channelHex, outstanding.admin_pubkey, outstanding.relays, encodeChannelJoinWithdrawal(w), signedAt);
    if (!wrote || wrote.accepted === 0) return { ok: false, reason: "relays_unreachable" };
    deps.requests.remove(agentId, channelHex);
    logger.info("channel.join.withdrawn", { channel_pubkey: channelHex });
    // Ring, so the admin's pending list drops it now rather than at lapse. A ring that does not go
    // out leaves the withdrawal on the relays for the admin's next read.
    const rung = await deps.directory.ring(agentName, channelHex);
    if (!rung.ok) logger.warn("channel.join.ring_failed", { channel_pubkey: channelHex, reason: rung.reason });
    return { ok: true };
  }

  // 047-JOINPULL: the joiner rings ONCE. An admin offline at that instant lists the channel's waiting
  // requests itself when it reconnects (`pullRequests` below) — there is no re-ring.
  return { join, withdraw };
}

/**
 * Apply one verified answer on the JOINER's daemon. The notice reader has already checked the
 * channel key's signature, that a request is outstanding, and that it is newer than the last answer
 * and ejection. Returns the doorbell outcome, or null when the body is unusable.
 */
export async function applyJoinAnswer(
  deps: {
    subscriptions: ChannelSubscriptionStore; requests: ChannelJoinRequestStore; logger: Logger;
    keyProviderFor: (agentId: string) => KeyProvider | null; now?: () => number;
  },
  outstanding: OutstandingJoin, answer: ChannelJoinAnswer,
): Promise<{ outcome: "admitted" | "pending" | "refused"; reason?: string } | null> {
  const channelHex = outstanding.channel_pubkey;
  if (answer.outcome === "pending") return { outcome: "pending" };
  if (answer.outcome === "refused") {
    deps.requests.remove(outstanding.agent_id, channelHex);
    return { outcome: "refused", reason: answer.reason ?? "refused_by_admin" };
  }
  const base = {
    agent_id: outstanding.agent_id, channel_pubkey: channelHex, admin_pubkey: outstanding.admin_pubkey,
    access: outstanding.access, relays: outstanding.relays, guidance: outstanding.guidance,
    retention_seconds: outstanding.retention_seconds, joined_at: (deps.now ?? Date.now)(),
  };
  if (outstanding.access === "public") {
    if (answer.key_bundle !== null) return null;
    deps.subscriptions.upsert(base);
  } else {
    const myKey = deps.keyProviderFor(outstanding.agent_id);
    if (!myKey || answer.key_bundle === null) return null;
    const unwrapped = await unwrapGroupKey(answer.key_bundle, bytesOf(channelHex), myKey);
    if (!unwrapped.ok) {
      deps.logger.warn("channel.join.rejected", { channel_pubkey: channelHex, record: "join_answer", reason: unwrapped.reason });
      return null;
    }
    deps.subscriptions.upsert(base);
    deps.subscriptions.addKey(outstanding.agent_id, channelHex, unwrapped.gk, (deps.now ?? Date.now)());
  }
  deps.requests.remove(outstanding.agent_id, channelHex);
  return { outcome: "admitted" };
}

// ─── The admin ───────────────────────────────────────────────────────────────────────────────────

export interface ChannelJoinAdminDeps {
  logger: Logger;
  members: ChannelMembershipStore;
  subscriptions: ChannelSubscriptionStore;
  seen: ChannelJoinSeenStore;
  relays: JoinRelays;
  localChannelAdmin: (channelHex: string) => LocalChannelAdmin | null;
  /** Write a `join_answer` notice for the joiner. `true` when a relay holds it. */
  writeAnswer: (channelHex: string, joinerHex: string, answer: Uint8Array) => Promise<boolean>;
  /** Ring the joiner about its answer, on the admin agent's stream. */
  ringJoiner: (channelHex: string, joinerHex: string) => Promise<void>;
  /** The admin agent's join-request doorbell — a NEW or CHANGED invite-only request only. */
  raiseRequest: (channelHex: string, joinerHex: string) => void;
  /** 043-POSTERS: a member was admitted (and sent its key). */
  onAdmitted?: (channelHex: string, joinerHex: string) => void;
  now?: () => number;
}

export function createChannelJoinAdmin(deps: ChannelJoinAdminDeps) {
  const { logger, members } = deps;
  const now = deps.now ?? (() => Date.now());

  const reject = (channelHex: string, record: string, reason: string): void => {
    logger.warn("channel.join.rejected", { channel_pubkey: channelHex, record, reason });
  };

  async function answer(
    admin: LocalChannelAdmin, channelHex: string, joinerHex: string,
    f: { outcome: "accepted" | "refused" | "pending"; reason?: ChannelJoinRefusedReason; key_bundle?: Uint8Array | null },
  ): Promise<boolean> {
    const signed = await signChannelJoinAnswer(admin.channelKeyProvider, {
      outcome: f.outcome, reason: f.outcome === "refused" ? (f.reason ?? "refused_by_admin") : null,
      key_bundle: f.key_bundle ?? null, signed_at: now(),
    });
    const written = await deps.writeAnswer(channelHex, joinerHex, encodeChannelJoinAnswer(signed));
    if (written) await deps.ringJoiner(channelHex, joinerHex);
    logger.info("channel.join.answered", { channel_pubkey: channelHex, subscriber_pubkey: joinerHex, outcome: f.outcome, written });
    return written;
  }

  /** Admit: the key wrapped for the joiner (none for public), written as an accepted answer. */
  async function accept(admin: LocalChannelAdmin, channelHex: string, joinerHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const settings = members.settings(channelHex);
    if (!settings) return { ok: false, reason: "channel_not_configured_for_membership" };
    let bundle: Uint8Array | null = null;
    if (settings.access !== "public") {
      const gk = ensureCurrentGroupKey({ members, subscriptions: deps.subscriptions, now }, admin.agentId, channelHex);
      if (!gk) return { ok: false, reason: "channel_not_configured_for_membership" };
      bundle = await wrapGroupKeyFor(gk, bytesOf(channelHex), bytesOf(joinerHex), admin.adminKeyProvider);
    }
    if (!(await answer(admin, channelHex, joinerHex, { outcome: "accepted", key_bundle: bundle }))) {
      return { ok: false, reason: "answer_unwritten" };
    }
    deps.onAdmitted?.(channelHex, joinerHex);
    return { ok: true };
  }

  /** The newest join slot record for this joiner, opened and verified; null when there is nothing to act on. */
  async function readSlot(admin: LocalChannelAdmin, channelHex: string, joinerHex: string, relayList: string[]):
    Promise<{ kind: "request" | "withdrawn"; signed_at: number } | null> {
    if (!admin.channelKeyProvider.staticSharedSecret || !admin.adminKeyProvider.openContentSeal) return null;
    const shared = await admin.channelKeyProvider.staticSharedSecret(bytesOf(joinerHex));
    if (!shared) { reject(channelHex, "join_request", "joiner_key_invalid"); return null; }
    const slot = channelJoinSlot(shared);
    let newest: { signed_at: number; sealed: Uint8Array } | null = null;
    for (const bytes of await deps.relays.fetchJoin(relayList, slot)) {
      const d = decodeChannelJoinSlotRecord(bytes);
      if (!d.ok) { reject(channelHex, "join_slot", d.reason); continue; }
      if (hexOf(d.record.channel_pubkey) !== channelHex || hexOf(d.record.slot) !== hexOf(slot)) { reject(channelHex, "join_slot", "wrong_slot"); continue; }
      if (!newest || d.record.signed_at > newest.signed_at) newest = { signed_at: d.record.signed_at, sealed: d.record.sealed };
    }
    if (!newest) return null;
    const inner = await admin.adminKeyProvider.openContentSeal(newest.sealed);
    if (!inner) { reject(channelHex, "join_request", "not_sealed_to_admin"); return null; }
    const asRequest = decodeChannelJoinRequest(inner);
    if (asRequest.ok) {
      const r = asRequest.request;
      if (hexOf(r.channel_pubkey) !== channelHex || hexOf(r.joiner_pubkey) !== joinerHex || r.signed_at !== newest.signed_at || !verifyChannelJoinRequest(r)) {
        reject(channelHex, "join_request", "signature_invalid"); return null;
      }
      return { kind: "request", signed_at: r.signed_at };
    }
    const asWithdrawal = decodeChannelJoinWithdrawal(inner);
    if (asWithdrawal.ok) {
      const w = asWithdrawal.withdrawal;
      if (hexOf(w.channel_pubkey) !== channelHex || hexOf(w.joiner_pubkey) !== joinerHex || w.signed_at !== newest.signed_at || !verifyChannelJoinWithdrawal(w)) {
        reject(channelHex, "join_withdrawal", "signature_invalid"); return null;
      }
      return { kind: "withdrawn", signed_at: w.signed_at };
    }
    reject(channelHex, "join_request", asRequest.reason);
    return null;
  }

  /** Drop a pending request without telling the admin's agent (a withdrawal, or a lapse). */
  const dropPending = (channelHex: string, joinerHex: string, why: "withdrawn" | "lapsed"): void => {
    if (members.statusOf(channelHex, joinerHex) === "pending") members.dropPending(channelHex, joinerHex);
    logger.info(`channel.join.${why}`, { channel_pubkey: channelHex, subscriber_pubkey: joinerHex });
  };

  /**
   * A ring: someone asked to join `channelHex`. Never throws. Non-member guard: a channel this
   * daemon does not administer reads nothing.
   */
  async function onBell(channelHexRaw: string, joinerHexRaw: string): Promise<void> {
    const channelHex = channelHexRaw.toLowerCase();
    const joinerHex = joinerHexRaw.toLowerCase();
    const admin = deps.localChannelAdmin(channelHex);
    const settings = members.settings(channelHex);
    if (!admin || !settings || settings.relays.length === 0) return;
    try {
      const found = await readSlot(admin, channelHex, joinerHex, settings.relays);
      // Nagging guard: a repeat or older record is dropped silently.
      if (!found || found.signed_at <= deps.seen.get(channelHex, joinerHex)) return;
      deps.seen.set(channelHex, joinerHex, found.signed_at);
      if (found.kind === "withdrawn") { dropPending(channelHex, joinerHex, "withdrawn"); return; }
      // Decision 11: a request older than the channel's retention has lapsed.
      if (now() - found.signed_at > settings.retention_seconds * 1000) { dropPending(channelHex, joinerHex, "lapsed"); return; }

      logger.info("channel.join.requested", { channel_pubkey: channelHex, subscriber_pubkey: joinerHex });
      const status = members.statusOf(channelHex, joinerHex);
      if (status === "active") { await answer(admin, channelHex, joinerHex, { outcome: "refused", reason: "already_member" }); return; }
      // An ejected member cannot simply ask again: re-admitting on request would undo the ejection.
      if (status === "ejected") { await answer(admin, channelHex, joinerHex, { outcome: "refused", reason: "ejected" }); return; }
      if (settings.access === "open" || settings.access === "public") {
        members.admit(channelHex, joinerHex, "active", now());
        await accept(admin, channelHex, joinerHex);
        return;
      }
      // invite_only: pending, and handed to the admin agent. Nothing here approves it. A newer
      // request from someone already pending is a CHANGED request, so it alerts again.
      members.admit(channelHex, joinerHex, "pending", now());
      deps.raiseRequest(channelHex, joinerHex);
      await answer(admin, channelHex, joinerHex, { outcome: "pending" });
    } catch (err: unknown) {
      logger.warn("channel.join.handling_failed", { channel_pubkey: channelHex, reason: extractErrorMessage(err) });
    }
  }

  /** The admin agent's explicit decision on a pending request. */
  async function approve(channelHex: string, joinerHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const admin = deps.localChannelAdmin(channelHex);
    if (!admin) return { ok: false, reason: "channel_not_local" };
    const settings = members.settings(channelHex);
    const since = deps.seen.get(channelHex, joinerHex);
    if (settings && since > 0 && now() - since > settings.retention_seconds * 1000) {
      dropPending(channelHex, joinerHex, "lapsed");
      return { ok: false, reason: "request_lapsed" };
    }
    try {
      members.approve(channelHex, joinerHex);
    } catch (err: unknown) {
      return { ok: false, reason: extractErrorMessage(err) };
    }
    return accept(admin, channelHex, joinerHex);
  }

  /** Refuse a pending request. Conditional on `pending` — refusing is not ejecting. */
  async function refuse(channelHex: string, joinerHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const admin = deps.localChannelAdmin(channelHex);
    if (!admin) return { ok: false, reason: "channel_not_local" };
    try {
      members.refusePending(channelHex, joinerHex);
    } catch (err: unknown) {
      return { ok: false, reason: extractErrorMessage(err) };
    }
    await answer(admin, channelHex, joinerHex, { outcome: "refused", reason: "refused_by_admin" });
    return { ok: true };
  }

  /**
   * Decision 11, the admin's half: a pending request older than the channel's retention drops off the
   * pending list with no ring needed. Run on the backstop tick for every channel this daemon runs.
   */
  function sweepLapsed(channelHexes: string[]): void {
    for (const channelHex of channelHexes) {
      const settings = members.settings(channelHex);
      if (!settings) continue;
      for (const joinerHex of members.pendingMembers(channelHex)) {
        const since = deps.seen.get(channelHex, joinerHex);
        if (since > 0 && now() - since > settings.retention_seconds * 1000) dropPending(channelHex, joinerHex, "lapsed");
      }
    }
  }

  /**
   * 047-JOINPULL: on reconnect, list each channel's waiting join requests from its relays (signed
   * with the channel key over each relay's nonce), open each one to learn who asked, and handle it
   * exactly as a ring would. The nagging guard in `onBell` keeps an already-seen request silent.
   * Never throws.
   */
  async function pullRequests(channelHexes: string[]): Promise<void> {
    for (const channelHex of channelHexes) {
      const admin = deps.localChannelAdmin(channelHex);
      const settings = members.settings(channelHex);
      if (!admin || !settings || settings.relays.length === 0) continue;
      if (!admin.adminKeyProvider.openContentSeal) {
        logger.warn("channel.join.pull_skipped", { channel_pubkey: channelHex, reason: "admin_key_cannot_open_seals" });
        continue;
      }
      try {
        const records = await deps.relays.listJoins(settings.relays, channelHex, (tbs) => admin.channelKeyProvider.sign(tbs));
        const joiners = new Set<string>();
        for (const bytes of records) {
          const d = decodeChannelJoinSlotRecord(bytes);
          if (!d.ok || hexOf(d.record.channel_pubkey) !== channelHex) { reject(channelHex, "join_slot", d.ok ? "wrong_slot" : d.reason); continue; }
          const inner = await admin.adminKeyProvider.openContentSeal(d.record.sealed);
          if (!inner) { reject(channelHex, "join_request", "not_sealed_to_admin"); continue; }
          const asRequest = decodeChannelJoinRequest(inner);
          const asWithdrawal = asRequest.ok ? null : decodeChannelJoinWithdrawal(inner);
          const joiner = asRequest.ok ? asRequest.request.joiner_pubkey : asWithdrawal?.ok ? asWithdrawal.withdrawal.joiner_pubkey : null;
          if (!joiner) { reject(channelHex, "join_request", asRequest.ok ? "wrong_shape" : asRequest.reason); continue; }
          joiners.add(hexOf(joiner));
        }
        logger.info("channel.join.pulled", { channel_pubkey: channelHex, records: records.length, joiners: joiners.size });
        // onBell re-reads the joiner's own slot and verifies the signature there — one check path.
        for (const joinerHex of joiners) await onBell(channelHex, joinerHex);
      } catch (err: unknown) {
        logger.warn("channel.join.pull_failed", { channel_pubkey: channelHex, reason: extractErrorMessage(err) });
      }
    }
  }

  return { onBell, approve, refuse, sweepLapsed, pullRequests };
}
