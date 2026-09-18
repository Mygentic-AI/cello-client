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

export const CHANNEL_SETTINGS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_settings (
    channel_pubkey     TEXT    NOT NULL PRIMARY KEY,
    access             TEXT    NOT NULL,
    members_visible    INTEGER NOT NULL DEFAULT 0,
    guidance           TEXT    NOT NULL DEFAULT '',
    retention_seconds  INTEGER NOT NULL DEFAULT 604800,
    relays             TEXT    NOT NULL DEFAULT '[]',
    -- 0 means NO KEY HAS EVER BEEN ISSUED. The first join mints generation 1; each ejection
    -- advances it by one, and that number is what every body and every fetch key is bound to.
    key_generation     INTEGER NOT NULL DEFAULT 0
  );
`;

export const CHANNEL_MEMBERS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_members (
    channel_pubkey     TEXT    NOT NULL,
    subscriber_pubkey  TEXT    NOT NULL,
    joined_at          INTEGER NOT NULL,
    -- active | pending | ejected. An ejected row is NEVER deleted — see the header.
    status             TEXT    NOT NULL,
    PRIMARY KEY (channel_pubkey, subscriber_pubkey)
  );
`;

export type MemberStatus = "active" | "pending" | "ejected";

export interface ChannelSettings {
  access: ChannelAccess;
  members_visible: boolean;
  guidance: string;
  retention_seconds: number;
  relays: string[];
  key_generation: number;
}

export type ChannelMembershipErrorCode =
  | "channel_unknown"
  | "not_an_active_member"
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
}

export class ChannelMembershipStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_SETTINGS_CREATE_SQL);
    this.#db.exec(CHANNEL_MEMBERS_CREATE_SQL);
  }

  /** Create or update a channel's settings. Never touches `key_generation` — only an eject does. */
  putSettings(channelHex: string, s: Omit<ChannelSettings, "key_generation">): void {
    this.#db
      .prepare(
        `INSERT INTO channel_settings
           (channel_pubkey, access, members_visible, guidance, retention_seconds, relays)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (channel_pubkey) DO UPDATE SET
           access = excluded.access, members_visible = excluded.members_visible,
           guidance = excluded.guidance, retention_seconds = excluded.retention_seconds,
           relays = excluded.relays`,
      )
      .run(
        channelHex.toLowerCase(), s.access, s.members_visible ? 1 : 0,
        s.guidance, s.retention_seconds, JSON.stringify(s.relays),
      );
  }

  settings(channelHex: string): ChannelSettings | null {
    const row = this.#db
      .prepare(
        `SELECT access, members_visible, guidance, retention_seconds, relays, key_generation
           FROM channel_settings WHERE channel_pubkey = ?`,
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
    this.#logger.info("channel.member.joined", {
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
        .prepare(`UPDATE channel_settings SET key_generation = key_generation + 1 WHERE channel_pubkey = ?`)
        .run(channel);
      generation = Number(
        (this.#db.prepare(`SELECT key_generation FROM channel_settings WHERE channel_pubkey = ?`)
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
      .prepare(`UPDATE channel_settings SET key_generation = 1 WHERE channel_pubkey = ? AND key_generation = 0`)
      .run(channelHex.toLowerCase());
    return this.settings(channelHex)?.key_generation ?? 0;
  }
}
