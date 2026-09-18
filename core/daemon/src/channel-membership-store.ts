/**
 * ChannelMembershipStore — the PUBLISHER's record of who is in a channel (M16 019-MEMBERSHIP).
 *
 * The mirror of `channel-subscription-store.ts`: that one is what a subscriber knows about somebody
 * else's channel, this is what an admin knows about its own — the access rule, the members, and the
 * key generation counter that ejection advances.
 *
 * ─── Why an ejected row is never deleted ─────────────────────────────────────────────────────
 *
 * Deleting it would make an ejected member indistinguishable from a stranger, so their very next
 * join request would be admitted as a new one — undoing the ejection silently, which is the one
 * thing the whole mechanism exists to prevent. The row stays, with `ejected` on it, for ever.
 *
 * ─── Why the generation moves in the SAME transaction as the status ──────────────────────────
 *
 * An eject that flipped the row and failed to bump the generation is not an eject: every member
 * including the ejected one keeps reading, and nothing anywhere says the ejection did not take. The
 * two facts are one fact, so they commit together or neither does.
 *
 * Keyed on the channel's pubkey and the member's pubkey — identities, never display names.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { ChannelAccess } from "@cello-protocol/protocol-types";

/**
 * ⚠️ **THERE IS NO `channel_settings` TABLE, AND THERE MUST NOT BE ONE.** This store first created
 * its own, duplicating four columns of 018's `channel_config`, and nothing in production ever wrote
 * a row to it. Every membership read came back empty, so every join was refused
 * `not_admin_of_channel` on a channel the daemon demonstrably administered, every eject threw
 * `channel_unknown`, and no group key was ever minted — which meant the fetch key was absent and the
 * relay served the queue to anyone.
 *
 * Two tables holding one fact, with the live path reading the empty one. Collapsed into
 * `channel_config` while the database was still empty. If you are about to add a second table for a
 * publisher's decisions about its own channel: that is this bug.
 */
import { CHANNEL_CONFIG_CREATE_SQL } from "./channel-config-store.js";
export { CHANNEL_CONFIG_CREATE_SQL };

export const CHANNEL_MEMBERS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_members (
    channel_pubkey     TEXT    NOT NULL,
    subscriber_pubkey  TEXT    NOT NULL,
    joined_at          INTEGER NOT NULL,
    -- active | pending | ejected | refused. An ejected row is NEVER deleted — see the header.
    status             TEXT    NOT NULL,
    PRIMARY KEY (channel_pubkey, subscriber_pubkey)
  );
`;

/**
 * `refused` is distinct from `ejected`: one never became a member, the other was removed and cost
 * the channel a re-key. Collapsing them would make the two indistinguishable in every later read.
 */
export type MemberStatus = "active" | "pending" | "ejected" | "refused";

export interface ChannelSettings {
  access: ChannelAccess;
  members_visible: boolean;
  guidance: string;
  retention_seconds: number;
  relays: string[];
  key_generation: number;
  /**
   * The AGENT that admits members and answers join requests. NOT the channel key: the channel signs
   * posts and never converses; the admin holds the sessions. A subscriber checks the agent that
   * answered against THIS, so conflating the two makes the check compare a key with itself.
   */
  admin_pubkey: string;
}

export type ChannelMembershipErrorCode =
  | "channel_unknown"
  | "not_an_active_member"
  | "not_a_pending_request"
  | "eject_not_applicable_open_channel"
  | "eject_not_applicable_public_channel";

export class ChannelMembershipError extends Error {
  readonly code: ChannelMembershipErrorCode;
  constructor(code: ChannelMembershipErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ChannelMembershipError";
    this.code = code;
  }
}

interface SettingsRow {
  access: string;
  members_visible: number | bigint;
  guidance: string;
  retention_seconds: number | bigint;
  relays: string;
  key_generation: number | bigint;
  admin_pubkey: string;
}

export class ChannelMembershipStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_CONFIG_CREATE_SQL);
    this.#db.exec(CHANNEL_MEMBERS_CREATE_SQL);
  }

  /** Create or update a channel's settings. Never touches `key_generation` — only an eject does. */
  putSettings(channelHex: string, s: Omit<ChannelSettings, "key_generation">, now = Date.now()): void {
    this.#db
      .prepare(
        `INSERT INTO channel_config
           (channel_pubkey, access, members_visible, guidance, retention_seconds, relays, admin_pubkey, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (channel_pubkey) DO UPDATE SET
           access = excluded.access, members_visible = excluded.members_visible,
           guidance = excluded.guidance, retention_seconds = excluded.retention_seconds,
           relays = excluded.relays, admin_pubkey = excluded.admin_pubkey,
           updated_at = excluded.updated_at`,
      )
      .run(
        channelHex.toLowerCase(), s.access, s.members_visible ? 1 : 0,
        s.guidance, s.retention_seconds, JSON.stringify(s.relays), s.admin_pubkey ?? "", now,
      );
  }

  settings(channelHex: string): ChannelSettings | null {
    const row = this.#db
      .prepare(
        `SELECT access, members_visible, guidance, retention_seconds, relays, key_generation, admin_pubkey
           FROM channel_config WHERE channel_pubkey = ?`,
      )
      .get(channelHex.toLowerCase()) as SettingsRow | undefined;
    if (!row) return null;

    let relays: string[] = [];
    try {
      const parsed = JSON.parse(row.relays) as unknown;
      if (Array.isArray(parsed)) relays = parsed.filter((r): r is string => typeof r === "string");
    } catch {
      this.#logger.warn("channel.settings.relays_corrupt", { channel_pubkey: channelHex });
    }
    return {
      access: row.access as ChannelAccess,
      members_visible: Number(row.members_visible) === 1,
      guidance: row.guidance,
      retention_seconds: Number(row.retention_seconds),
      relays,
      key_generation: Number(row.key_generation),
      admin_pubkey: row.admin_pubkey,
    };
  }

  /**
   * Record a member. `pending` is an invite-only request awaiting the admin agent's decision.
   *
   * ⚠️ A PENDING MEMBER RECEIVES NO KEY — `activeMembers` excludes them. Counting a request as a
   * membership would auto-approve every stranger who asked, and invite-only admission is the admin's
   * decision, never a heuristic.
   */
  admit(channelHex: string, subscriberHex: string, status: MemberStatus, joinedAt: number): void {
    this.#db
      .prepare(
        `INSERT INTO channel_members (channel_pubkey, subscriber_pubkey, joined_at, status)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (channel_pubkey, subscriber_pubkey) DO UPDATE SET status = excluded.status`,
      )
      .run(channelHex.toLowerCase(), subscriberHex.toLowerCase(), joinedAt, status);
    /**
     * ⚠️ THE EVENT NAMES WHAT HAPPENED. This logged `channel.member.joined` for every status, so an
     * operator grepping for who joined got pending requests and ejections back as joins — the log
     * asserting something the row contradicts.
     */
    const event = status === "active" ? "channel.member.joined"
      : status === "pending" ? "channel.join.pending"
        : status === "ejected" ? "channel.member.ejected" : "channel.join.refused";
    this.#logger.info(event, {
      channel_pubkey: channelHex, subscriber_pubkey: subscriberHex, status,
    });
  }

  /** Move a pending request to active. The admin agent's explicit decision, never automatic. */
  approve(channelHex: string, subscriberHex: string): void {
    const changed = this.#db
      .prepare(
        `UPDATE channel_members SET status = 'active'
          WHERE channel_pubkey = ? AND subscriber_pubkey = ? AND status = 'pending'`,
      )
      .run(channelHex.toLowerCase(), subscriberHex.toLowerCase());
    if (Number(changed.changes) === 0) {
      throw new ChannelMembershipError("not_an_active_member", "no pending request for that subscriber");
    }
    this.#logger.info("channel.member.joined", {
      channel_pubkey: channelHex, subscriber_pubkey: subscriberHex, status: "active",
    });
  }

  /**
   * Refuse a PENDING request. Conditional on `pending`, and that condition is the whole method.
   *
   * ⚠️ **REFUSING IS NOT EJECTING, AND IT MUST NOT BE ABLE TO ACT LIKE ONE.** An earlier version
   * upserted `ejected` unconditionally, so an admin who typed a refusal against an existing MEMBER
   * got `ok: true`, the row said ejected, and the member kept the current group key and fetch key
   * and went on reading indefinitely. The table and reality disagreed with nothing to say so —
   * against the order's own rule that an eject without a generation bump is not an eject.
   *
   * A refused request gets its own status, not `ejected`: they were never a member, and reusing the
   * word would make the two indistinguishable in every later read.
   */
  refusePending(channelHex: string, subscriberHex: string): void {
    const changed = this.#db
      .prepare(
        `UPDATE channel_members SET status = 'refused'
          WHERE channel_pubkey = ? AND subscriber_pubkey = ? AND status = 'pending'`,
      )
      .run(channelHex.toLowerCase(), subscriberHex.toLowerCase());
    if (Number(changed.changes) === 0) {
      throw new ChannelMembershipError(
        "not_a_pending_request",
        `${subscriberHex.slice(0, 16)} has no pending request on this channel. To remove an existing member, eject them — which re-keys the channel.`,
      );
    }
    this.#logger.info("channel.join.refused", {
      channel_pubkey: channelHex, subscriber_pubkey: subscriberHex, reason: "refused_by_admin",
    });
  }

  statusOf(channelHex: string, subscriberHex: string): MemberStatus | null {
    const row = this.#db
      .prepare(`SELECT status FROM channel_members WHERE channel_pubkey = ? AND subscriber_pubkey = ?`)
      .get(channelHex.toLowerCase(), subscriberHex.toLowerCase()) as { status: string } | undefined;
    return row ? (row.status as MemberStatus) : null;
  }

  /** Who a new key goes to. Pending and ejected are excluded, for different reasons — see above. */
  activeMembers(channelHex: string): string[] {
    const rows = this.#db
      .prepare(
        `SELECT subscriber_pubkey FROM channel_members
          WHERE channel_pubkey = ? AND status = 'active' ORDER BY subscriber_pubkey ASC`,
      )
      .all(channelHex.toLowerCase()) as Array<{ subscriber_pubkey: string }>;
    return rows.map((r) => r.subscriber_pubkey);
  }

  /**
   * Eject a member and advance the generation, atomically.
   *
   * Returns the new generation and the members it must be delivered to — the ejected one is simply
   * not in that list, which is the entire mechanism.
   *
   * ⚠️ **AN OPEN CHANNEL CANNOT EJECT**, because the member would rejoin the moment they asked: the
   * re-key would cost every other member a delivery and change nothing. A PUBLIC channel has no
   * members at all. Both refuse BY NAME, because a generic failure leaves an admin retrying
   * something that will never work.
   *
   * ⚠️ **EJECTING SOMEBODY WHO IS NOT AN ACTIVE MEMBER MUST NOT BUMP THE GENERATION.** Every bump
   * re-keys every real member, and every re-key is a delivery that can fail — so a mistyped pubkey
   * would cost the whole channel a key rotation for nothing.
   */
  eject(channelHex: string, subscriberHex: string): { generation: number; remaining: string[] } {
    const channel = channelHex.toLowerCase();
    const subscriber = subscriberHex.toLowerCase();

    const settings = this.settings(channel);
    if (!settings) throw new ChannelMembershipError("channel_unknown", `no settings for ${channel.slice(0, 16)}`);
    if (settings.access === "public") {
      throw new ChannelMembershipError(
        "eject_not_applicable_public_channel",
        "a public channel has no members: anyone may read it, so there is nobody to remove",
      );
    }
    if (settings.access === "open") {
      throw new ChannelMembershipError(
        "eject_not_applicable_open_channel",
        "an open channel admits anyone who asks, so an ejected member would rejoin immediately",
      );
    }

    this.#db.exec("BEGIN IMMEDIATE");
    let generation: number;
    let remaining: string[];
    try {
      // Under the write lock, and conditional on `active`: the status check and the bump are one
      // decision, so a concurrent eject of the same member cannot advance the generation twice.
      const changed = this.#db
        .prepare(
          `UPDATE channel_members SET status = 'ejected'
            WHERE channel_pubkey = ? AND subscriber_pubkey = ? AND status = 'active'`,
        )
        .run(channel, subscriber);
      if (Number(changed.changes) === 0) {
        throw new ChannelMembershipError(
          "not_an_active_member",
          `${subscriber.slice(0, 16)} is not an active member of this channel`,
        );
      }
      this.#db
        .prepare(`UPDATE channel_config SET key_generation = key_generation + 1 WHERE channel_pubkey = ?`)
        .run(channel);
      generation = Number(
        (this.#db.prepare(`SELECT key_generation FROM channel_config WHERE channel_pubkey = ?`)
          .get(channel) as { key_generation: number | bigint }).key_generation,
      );
      remaining = this.activeMembers(channel);
      this.#db.exec("COMMIT");
    } catch (err) {
      try { this.#db.exec("ROLLBACK"); } catch { /* the transaction is already gone */ }
      throw err;
    }

    this.#logger.info("channel.member.ejected", {
      channel_pubkey: channelHex, subscriber_pubkey: subscriberHex,
      generation, member_count: remaining.length,
    });
    return { generation, remaining };
  }

  /** Mint the FIRST generation for a channel that has never issued a key. */
  startGeneration(channelHex: string): number {
    this.#db
      .prepare(`UPDATE channel_config SET key_generation = 1 WHERE channel_pubkey = ? AND key_generation = 0`)
      .run(channelHex.toLowerCase());
    return this.settings(channelHex)?.key_generation ?? 0;
  }
}
