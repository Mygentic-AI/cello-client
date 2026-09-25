/**
 * ChannelConfigStore — what a PUBLISHER has decided about its own channel (M16 018-PUBCOLLECT).
 *
 * The mirror image of `channel-subscription-store.ts`: that one is what a subscriber knows about
 * somebody else's channel, this is what a publisher has chosen for its own — which two relays it
 * publishes to, whether the channel is public, what it is for, how long posts are kept.
 *
 * ⚠️ **THE RELAY PAIR LIVES HERE, NOT IN THE INFO RECORD.** The record is the SIGNED STATEMENT of
 * these facts, deposited for subscribers to read; this is the source it is signed from. Deriving the
 * pair from the last record instead would mean a publisher that lost its record could no longer
 * publish, and a relay serving a stale record could quietly redirect one.
 *
 * Keyed on the channel's own pubkey.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { ChannelAccess } from "@cello-protocol/protocol-types";

/** Seven days, matching the relay's own default retention. */
export const DEFAULT_RETENTION_SECONDS = 7 * 24 * 60 * 60;

export const CHANNEL_CONFIG_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_config (
    channel_pubkey     TEXT    NOT NULL PRIMARY KEY,
    access             TEXT    NOT NULL,
    -- JSON array of multiaddrs, in the order the publisher chose them. Two is the design; the column
    -- is a list because the count is the publisher's decision, not the schema's.
    relays             TEXT    NOT NULL,
    guidance           TEXT    NOT NULL DEFAULT '',
    retention_seconds  INTEGER NOT NULL DEFAULT ${String(DEFAULT_RETENTION_SECONDS)},
    -- ─── M16 019-MEMBERSHIP: one table, not two ───────────────────────────────────────────────
    -- 019 first added a channel_settings table duplicating four of these columns, and wired NO
    -- writer to it — so every membership read came back empty and every join was refused on a
    -- channel the daemon genuinely administered. Two tables for one fact, with the live path
    -- reading the empty one. Collapsed here while the database is still empty, which makes it a
    -- schema edit rather than a migration.
    --
    -- Whether members can see each other. A publisher's decision about its own channel.
    members_visible    INTEGER NOT NULL DEFAULT 0,
    -- 0 means NO KEY HAS EVER BEEN ISSUED. The first join mints generation 1; each ejection
    -- advances it, and that number is what every body and every fetch key is bound to.
    key_generation     INTEGER NOT NULL DEFAULT 0,
    -- The AGENT that admits members and answers join requests. Distinct from the channel key: the
    -- channel signs posts and never converses, the admin holds the sessions. Empty until set.
    admin_pubkey       TEXT    NOT NULL DEFAULT '',
    updated_at         INTEGER NOT NULL
  );
`;

export interface ChannelConfig {
  access: ChannelAccess;
  relays: string[];
  guidance: string;
  retention_seconds: number;
  members_visible?: boolean;
  /** The agent that answers join requests. NOT the channel key — see the column comment. */
  admin_pubkey?: string;
}

export class ChannelConfigStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_CONFIG_CREATE_SQL);
  }

  get(channelHex: string): ChannelConfig | null {
    const row = this.#db
      .prepare(
        `SELECT access, relays, guidance, retention_seconds, members_visible, admin_pubkey
           FROM channel_config WHERE channel_pubkey = ?`,
      )
      .get(channelHex.toLowerCase()) as
      | {
          access: string; relays: string; guidance: string; retention_seconds: number | bigint;
          members_visible: number | bigint; admin_pubkey: string;
        }
      | undefined;
    if (!row) return null;

    let relays: string[] = [];
    try {
      const parsed = JSON.parse(row.relays) as unknown;
      if (Array.isArray(parsed)) relays = parsed.filter((r): r is string => typeof r === "string");
    } catch {
      // A corrupt relay list makes the channel unpublishable and says so, rather than publishing to
      // an empty set and reporting success.
      this.#logger.error("channel.config.relays_corrupt", { channel_pubkey: channelHex });
      return null;
    }
    return {
      access: row.access as ChannelAccess,
      relays,
      guidance: row.guidance,
      retention_seconds: Number(row.retention_seconds),
      members_visible: Number(row.members_visible) === 1,
      admin_pubkey: row.admin_pubkey,
    };
  }

  set(channelHex: string, config: ChannelConfig, now: number): void {
    this.#db
      .prepare(
        // ⚠️ `key_generation` is NOT in the update list, and must never be: it is advanced only by an
        // ejection, and letting a settings edit touch it would silently re-key or un-re-key a channel.
        `INSERT INTO channel_config
           (channel_pubkey, access, relays, guidance, retention_seconds, members_visible, admin_pubkey, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (channel_pubkey) DO UPDATE SET
           access = excluded.access, relays = excluded.relays, guidance = excluded.guidance,
           retention_seconds = excluded.retention_seconds, members_visible = excluded.members_visible,
           admin_pubkey = excluded.admin_pubkey, updated_at = excluded.updated_at`,
      )
      .run(
        channelHex.toLowerCase(), config.access, JSON.stringify(config.relays),
        config.guidance, config.retention_seconds,
        config.members_visible === true ? 1 : 0, config.admin_pubkey ?? "", now,
      );
    this.#logger.info("channel.config.set", {
      channel_pubkey: channelHex, access: config.access, relays: config.relays.length,
    });
  }

  /**
   * Delete this channel's config row. Called by the delete verb after a successful retire, so a
   * deleted channel is no longer answered from local config and `info` asks the directory instead.
   */
  forget(channelHex: string): void {
    this.#db.prepare(`DELETE FROM channel_config WHERE channel_pubkey = ?`).run(channelHex.toLowerCase());
  }
}
