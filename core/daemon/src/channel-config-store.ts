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
    updated_at         INTEGER NOT NULL
  );
`;

export interface ChannelConfig {
  access: ChannelAccess;
  relays: string[];
  guidance: string;
  retention_seconds: number;
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
      .prepare(`SELECT access, relays, guidance, retention_seconds FROM channel_config WHERE channel_pubkey = ?`)
      .get(channelHex.toLowerCase()) as
      | { access: string; relays: string; guidance: string; retention_seconds: number | bigint }
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
    };
  }

  set(channelHex: string, config: ChannelConfig, now: number): void {
    this.#db
      .prepare(
        `INSERT INTO channel_config (channel_pubkey, access, relays, guidance, retention_seconds, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (channel_pubkey) DO UPDATE SET
           access = excluded.access, relays = excluded.relays, guidance = excluded.guidance,
           retention_seconds = excluded.retention_seconds, updated_at = excluded.updated_at`,
      )
      .run(
        channelHex.toLowerCase(), config.access, JSON.stringify(config.relays),
        config.guidance, config.retention_seconds, now,
      );
    this.#logger.info("channel.config.set", {
      channel_pubkey: channelHex, access: config.access, relays: config.relays.length,
    });
  }
}
