/**
 * M16 045-NOTICEBELL — channel notices are signed records and a ring, never a session.
 *
 * The admin WRITES a record signed by the channel key (a sealed notice slot on the channel's relays,
 * or the info record / the directory's revocation that already exist) and RINGS the member through
 * the directory wake (021-WAKE). The member's daemon, on the ring or its backstop tick, READS what
 * concerns it, strictly decodes, verifies the channel key's signature, applies, and tells its agent
 * through the existing channel doorbells — once, and only on a real state change.
 *
 * ⚠️ **NO SESSION IS EVER OPENED FOR A NOTICE.** The session-based path this replaces showed members
 * sessions that never carried a message, and the ones that failed to close filled the relay's
 * per-pair cap and blocked real conversation.
 *
 * Abuse guards (all four are required):
 *  - a daemon acts only on channels it is SUBSCRIBED to; a ring from anyone else fetches nothing;
 *  - the newest notice per (channel, type) by signed `issued_at` wins; a repeat or older one is
 *    dropped silently;
 *  - the relays cap a notice's size per type and hold one per slot (the relay's half);
 *  - the slot is a hash of the admin/member X25519 secret, so the relay learns no membership.
 */
import {
  CHANNEL_NOTICE_TYPES, channelNoticeSlot, signChannelNotice, encodeChannelNotice, decodeChannelNotice,
  verifyChannelNotice, decodeNoticePassBody, decodeChannelPosterPass, verifyPosterPass,
  decodeChannelInfo, verifyChannelInfo, channelPostingOf, decodeCbor,
  type ChannelNoticeType,
} from "@cello-protocol/protocol-types";
import { sealToRecipient, unwrapGroupKey, type KeyProvider } from "@cello-protocol/crypto";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import type { ChannelPosterPassStore } from "./channel-poster-pass-store.js";
import { extractErrorMessage } from "./error-message.js";

const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const bytesOf = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));

/** The relay half, as the notice code sees it. Implemented over the channel relay client. */
export interface NoticeRelays {
  /** Deposit one record on every relay; resolves with how many accepted it. Never throws. */
  deposit: (relays: string[], record: Uint8Array) => Promise<number>;
  /** Every record the relays hold at this slot (one per answering relay). Never throws. */
  fetch: (relays: string[], slot: Uint8Array) => Promise<Uint8Array[]>;
}

// ─── The admin half ────────────────────────────────────────────────────────────────────────────

/**
 * Write one sealed notice for one member and type. `true` when at least one relay holds it. The
 * body is sealed to the member's identity key; the slot is derived from the channel key and theirs.
 */
export async function writeChannelNotice(
  deps: { relays: NoticeRelays; logger: Logger; now?: () => number },
  channelKey: KeyProvider, relays: string[], memberHex: string, type: ChannelNoticeType, body: Uint8Array,
): Promise<boolean> {
  const channelHex = hexOf(await channelKey.getPublicKey());
  if (!channelKey.staticSharedSecret) throw new Error("channel_key_cannot_derive_slot");
  const shared = await channelKey.staticSharedSecret(bytesOf(memberHex));
  if (!shared) throw new Error("member_key_invalid");
  const notice = await signChannelNotice(channelKey, {
    slot: channelNoticeSlot(shared, type),
    type,
    issued_at: (deps.now ?? Date.now)(),
    sealed: sealToRecipient(bytesOf(memberHex), body),
  });
  const accepted = await deps.relays.deposit(relays, encodeChannelNotice(notice));
  if (accepted === 0) {
    deps.logger.warn("channel.notice.unwritten", { channel_pubkey: channelHex, member_pubkey: memberHex, type, relays: relays.length });
    return false;
  }
  deps.logger.info("channel.notice.written", { channel_pubkey: channelHex, member_pubkey: memberHex, type, relays_ok: accepted });
  return true;
}

// ─── The member half ───────────────────────────────────────────────────────────────────────────

const SEEN_SQL = `
  CREATE TABLE IF NOT EXISTS channel_notice_seen (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    type            TEXT    NOT NULL,
    issued_at       INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey, type)
  );
`;

/** The newest signed `issued_at` this agent has applied, per (channel, type). Keyed on agent_id. */
export class ChannelNoticeSeenStore {
  readonly #db: DaemonDatabase;

  constructor(db: DaemonDatabase) {
    this.#db = db;
    this.#db.exec(SEEN_SQL);
  }

  get(agentId: string, channelHex: string, type: ChannelNoticeType): number {
    const row = this.#db
      .prepare(`SELECT issued_at FROM channel_notice_seen WHERE agent_id = ? AND channel_pubkey = ? AND type = ?`)
      .get(agentId, channelHex, type) as { issued_at: number | bigint } | undefined;
    return row ? Number(row.issued_at) : 0;
  }

  set(agentId: string, channelHex: string, type: ChannelNoticeType, issuedAt: number): void {
    this.#db
      .prepare(`INSERT INTO channel_notice_seen (agent_id, channel_pubkey, type, issued_at) VALUES (?, ?, ?, ?)
                ON CONFLICT (agent_id, channel_pubkey, type) DO UPDATE SET issued_at = excluded.issued_at`)
      .run(agentId, channelHex, type, issuedAt);
  }
}

export interface ChannelNoticeReaderDeps {
  logger: Logger;
  subscriptions: ChannelSubscriptionStore;
  posterPasses: ChannelPosterPassStore;
  seen: ChannelNoticeSeenStore;
  relays: NoticeRelays;
  keyProviderFor: (agentId: string) => KeyProvider | null;
  /** The channel's info record from its relays, or null. Verified here against the channel key. */
  fetchInfo: (relays: string[], channelHex: string) => Promise<Uint8Array | null>;
  /** Did the directory answer that this channel's identity is revoked (deleted)? */
  channelRevoked: (agentId: string, channelHex: string) => Promise<boolean>;
  onMembershipEnded: (agentId: string, channelHex: string, reason: "ejected" | "channel_closed") => void;
  onPosterRemoved: (agentId: string, channelHex: string) => void;
}

export interface ChannelNoticeReader {
  /** Read, verify and apply every notice for this agent's subscribed channels. Never throws. */
  checkNotices: (agentId: string) => Promise<void>;
}

export function createChannelNoticeReader(deps: ChannelNoticeReaderDeps): ChannelNoticeReader {
  const { logger, subscriptions, seen } = deps;

  const reject = (channelHex: string, type: string, reason: string): void => {
    logger.warn("channel.notice.rejected", { channel_pubkey: channelHex, type, reason });
  };

  /** The newest record at this slot that decodes strictly and is signed by THIS channel for THIS slot and type. */
  async function newestValid(
    channelHex: string, relays: string[], slot: Uint8Array, type: ChannelNoticeType,
  ): Promise<{ issued_at: number; sealed: Uint8Array } | null> {
    let best: { issued_at: number; sealed: Uint8Array } | null = null;
    for (const bytes of await deps.relays.fetch(relays, slot)) {
      const decoded = decodeChannelNotice(bytes);
      if (!decoded.ok) { reject(channelHex, type, decoded.reason); continue; }
      const n = decoded.notice;
      if (hexOf(n.channel_pubkey) !== channelHex || hexOf(n.slot) !== hexOf(slot) || n.type !== type) {
        reject(channelHex, type, "wrong_slot"); continue;
      }
      if (!verifyChannelNotice(n)) { reject(channelHex, type, "signature_invalid"); continue; }
      if (!best || n.issued_at > best.issued_at) best = { issued_at: n.issued_at, sealed: n.sealed };
    }
    return best;
  }

  /** Applies one opened notice. Returns false when the body was rejected. */
  async function apply(
    agentId: string, channelHex: string, type: ChannelNoticeType, body: Uint8Array, myKey: KeyProvider, myHex: string,
  ): Promise<boolean> {
    const channelPubkey = bytesOf(channelHex);
    if (type === "eject") {
      let raw: unknown;
      try { raw = decodeCbor(body); } catch { raw = null; }
      if (!Array.isArray(raw) || raw.length !== 1 || !(raw[0] instanceof Uint8Array) || hexOf(raw[0]) !== channelHex) return false;
      subscriptions.markEjected(agentId, channelHex);
      deps.posterPasses.remove(agentId, channelHex);
      deps.onMembershipEnded(agentId, channelHex, "ejected");
      return true;
    }
    if (type === "group_key") {
      const unwrapped = await unwrapGroupKey(body, channelPubkey, myKey);
      if (!unwrapped.ok) return false;
      if (!subscriptions.keysFor(agentId, channelHex).some((k) => k.generation === unwrapped.gk.generation)) {
        subscriptions.addKey(agentId, channelHex, unwrapped.gk, Date.now());
      }
      return true;
    }
    const passBody = decodeNoticePassBody(body);
    if (!passBody) return false;
    const pass = decodeChannelPosterPass(passBody.pass_cbor);
    if (!pass.ok || !verifyPosterPass(pass.pass, channelPubkey).ok || hexOf(pass.pass.poster_pubkey) !== myHex) return false;
    deps.posterPasses.put(agentId, channelHex, {
      pass_cbor: passBody.pass_cbor, issued_at: pass.pass.issued_at, expires_at: pass.pass.expires_at,
      members: passBody.members.map(hexOf),
    });
    return true;
  }

  /** A held pass that the channel's own info record now revokes (or posting closed) is dropped and surfaced. */
  async function checkPosterRevoked(agentId: string, channelHex: string, relays: string[], myHex: string): Promise<void> {
    const held = deps.posterPasses.get(agentId, channelHex);
    if (!held) return;
    const bytes = await deps.fetchInfo(relays, channelHex);
    if (!bytes) return;
    const decoded = decodeChannelInfo(bytes);
    if (!decoded.ok || hexOf(decoded.info.channel_pubkey) !== channelHex || !verifyChannelInfo(decoded.info)) {
      reject(channelHex, "info", decoded.ok ? "signature_invalid" : decoded.reason);
      return;
    }
    const ext = channelPostingOf(decoded.info);
    const revoked = ext.posting === "admin"
      || ext.revoked.some((r) => hexOf(r.poster_pubkey) === myHex && r.revoked_at >= held.issued_at);
    if (!revoked) return;
    deps.posterPasses.remove(agentId, channelHex);
    logger.info("channel.poster_removed", { channel_pubkey: channelHex });
    deps.onPosterRemoved(agentId, channelHex);
  }

  async function checkChannel(agentId: string, channelHex: string, relays: string[], myKey: KeyProvider, myHex: string): Promise<void> {
    if (await deps.channelRevoked(agentId, channelHex)) {
      subscriptions.markClosed(agentId, channelHex);
      deps.posterPasses.remove(agentId, channelHex);
      deps.onMembershipEnded(agentId, channelHex, "channel_closed");
      return;
    }
    if (!myKey.staticSharedSecret || !myKey.openContentSeal) return;
    const shared = await myKey.staticSharedSecret(bytesOf(channelHex));
    if (!shared) return;
    // Eject first: an ejected member applies nothing else from this channel.
    for (const type of ["eject", ...CHANNEL_NOTICE_TYPES.filter((t) => t !== "eject")] as ChannelNoticeType[]) {
      const found = await newestValid(channelHex, relays, channelNoticeSlot(shared, type), type);
      // Nagging guard: a repeat or older notice is dropped silently.
      if (!found || found.issued_at <= seen.get(agentId, channelHex, type)) continue;
      const body = await myKey.openContentSeal(found.sealed);
      if (!body || !(await apply(agentId, channelHex, type, body, myKey, myHex))) {
        reject(channelHex, type, "body_invalid");
        continue;
      }
      seen.set(agentId, channelHex, type, found.issued_at);
      logger.info("channel.notice.applied", { channel_pubkey: channelHex, type, issued_at: found.issued_at });
      if (type === "eject") return;
    }
    await checkPosterRevoked(agentId, channelHex, relays, myHex);
  }

  return {
    async checkNotices(agentId: string): Promise<void> {
      const myKey = deps.keyProviderFor(agentId);
      if (!myKey) return;
      const myHex = hexOf(await myKey.getPublicKey());
      // Non-member guard: only channels this agent is subscribed to. A ring for anything else
      // fetches nothing and tells no one.
      for (const sub of subscriptions.active()) {
        if (sub.agent_id !== agentId) continue;
        try {
          await checkChannel(agentId, sub.channel_pubkey, sub.relays, myKey, myHex);
        } catch (err: unknown) {
          logger.warn("channel.notice.check_failed", { channel_pubkey: sub.channel_pubkey, reason: extractErrorMessage(err) });
        }
      }
    },
  };
}
