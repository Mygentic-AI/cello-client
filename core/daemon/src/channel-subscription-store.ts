/**
 * ChannelSubscriptionStore — what a SUBSCRIBER knows about a channel it follows (M16).
 *
 * ⚠️ **THE SCHEMA IS 019's, CREATED HERE.** Order 019 owns membership — joining, the group key, the
 * eject re-key — and defines this table. But 018's collector cannot advance a delivery position
 * without somewhere to put it, so the table is created here with 019's FULL column set rather than a
 * smaller one 019 would have to migrate. Nothing holds real data yet, so the alternative is a
 * migration written for an empty database, which this milestone forbids. RAISED on the order.
 *
 * 018 writes `delivered_through` and reads `relays`, `access` and `admin_pubkey`. 019 fills in the
 * join that populates them and adds `channel_subscription_keys` beside this.
 *
 * ─── TWO POSITIONS, NEVER ONE ────────────────────────────────────────────────────────────────
 *
 *   delivered_through  how far the DAEMON has fetched and verified. Moved by the collector.
 *   processed_through  how far the AGENT has actually read. Moved by nothing here.
 *
 * Collapsing them into one number would mean a fetch marks a post as read, so anything an agent had
 * not yet seen would be silently skipped the moment the daemon collected it. A fetch never touches
 * `processed_through`; a read never touches `delivered_through`.
 *
 * Keyed on `agent_id` — the stable identity — never on `agent_name`, which is a mutable display
 * label and reusable after retirement.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { ChannelAccess } from "@cello-protocol/protocol-types";

export const CHANNEL_SUBSCRIPTION_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_subscriptions (
    agent_id           TEXT    NOT NULL,
    channel_pubkey     TEXT    NOT NULL,
    admin_pubkey       TEXT    NOT NULL,
    access             TEXT    NOT NULL,
    guidance           TEXT    NOT NULL DEFAULT '',
    retention_seconds  INTEGER NOT NULL DEFAULT 604800,
    -- JSON array of multiaddrs: the relays this channel publishes to, in the order the info record
    -- gave them. A column per relay would fix the count at two, and the count is the publisher's.
    relays             TEXT    NOT NULL DEFAULT '[]',
    moniker            TEXT    NOT NULL DEFAULT '',
    delivered_through  INTEGER NOT NULL DEFAULT 0,
    processed_through  INTEGER NOT NULL DEFAULT 0,
    joined_at          INTEGER NOT NULL DEFAULT 0,
    status             TEXT    NOT NULL DEFAULT 'active',
    PRIMARY KEY (agent_id, channel_pubkey)
  );
`;

export interface ChannelSubscription {
  agent_id: string;
  channel_pubkey: string;
  admin_pubkey: string;
  access: ChannelAccess;
  relays: string[];
  delivered_through: number;
  processed_through: number;
  status: "active" | "left" | "ejected";
}

export type ChannelSubscriptionErrorCode = "subscription_unknown" | "position_regression";

export class ChannelSubscriptionError extends Error {
  readonly code: ChannelSubscriptionErrorCode;
  constructor(code: ChannelSubscriptionErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ChannelSubscriptionError";
    this.code = code;
  }
}

interface Row {
  agent_id: string;
  channel_pubkey: string;
  admin_pubkey: string;
  access: string;
  relays: string;
  delivered_through: number | bigint;
  processed_through: number | bigint;
  status: string;
}

export class ChannelSubscriptionStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_SUBSCRIPTION_CREATE_SQL);
  }

  /** Record (or refresh) a subscription. 019's join calls this; 018's tests use it directly. */
  upsert(sub: {
    agent_id: string; channel_pubkey: string; admin_pubkey: string; access: ChannelAccess;
    relays: string[]; joined_at?: number;
  }): void {
    this.#db
      .prepare(
        `INSERT INTO channel_subscriptions
           (agent_id, channel_pubkey, admin_pubkey, access, relays, joined_at, status)
         VALUES (?, ?, ?, ?, ?, ?, 'active')
         ON CONFLICT (agent_id, channel_pubkey) DO UPDATE SET
           admin_pubkey = excluded.admin_pubkey,
           access       = excluded.access,
           relays       = excluded.relays`,
      )
      .run(
        sub.agent_id, sub.channel_pubkey.toLowerCase(), sub.admin_pubkey.toLowerCase(),
        sub.access, JSON.stringify(sub.relays), sub.joined_at ?? Date.now(),
      );
  }

  get(agentId: string, channelPubkeyHex: string): ChannelSubscription | null {
    const row = this.#db
      .prepare(
        `SELECT agent_id, channel_pubkey, admin_pubkey, access, relays, delivered_through, processed_through, status
           FROM channel_subscriptions WHERE agent_id = ? AND channel_pubkey = ?`,
      )
      .get(agentId, channelPubkeyHex.toLowerCase()) as Row | undefined;
    return row ? this.#toSubscription(row) : null;
  }

  /** Every channel this daemon should be collecting for. `left` and `ejected` are not collected. */
  active(): ChannelSubscription[] {
    const rows = this.#db
      .prepare(
        `SELECT agent_id, channel_pubkey, admin_pubkey, access, relays, delivered_through, processed_through, status
           FROM channel_subscriptions WHERE status = 'active' ORDER BY channel_pubkey ASC, agent_id ASC`,
      )
      .all() as Row[];
    return rows.map((r) => this.#toSubscription(r));
  }

  /**
   * Move the DAEMON's position. Never moves backwards: a relay that answers with less than it did
   * last time (a prune, a restart, a different relay) must not rewind a subscriber into re-fetching
   * and re-delivering posts its agent has already been shown.
   */
  setDeliveredThrough(agentId: string, channelPubkeyHex: string, seq: number): void {
    const current = this.get(agentId, channelPubkeyHex);
    if (!current) {
      throw new ChannelSubscriptionError("subscription_unknown", `no subscription for ${channelPubkeyHex.slice(0, 16)}`);
    }
    if (seq < current.delivered_through) {
      throw new ChannelSubscriptionError(
        "position_regression",
        `delivered_through is ${String(current.delivered_through)}; refusing to move it back to ${String(seq)}`,
      );
    }
    if (seq === current.delivered_through) return;
    this.#db
      .prepare(`UPDATE channel_subscriptions SET delivered_through = ? WHERE agent_id = ? AND channel_pubkey = ?`)
      .run(seq, agentId, channelPubkeyHex.toLowerCase());
    this.#logger.debug("channel.delivered.advanced", {
      agent_id: agentId, channel_pubkey: channelPubkeyHex, delivered_through: seq,
    });
  }

  #toSubscription(row: Row): ChannelSubscription {
    let relays: string[] = [];
    try {
      const parsed = JSON.parse(row.relays) as unknown;
      if (Array.isArray(parsed)) relays = parsed.filter((r): r is string => typeof r === "string");
    } catch {
      // A corrupt relay list is an empty one, which makes the channel uncollectable and says so in
      // the log — better than throwing on a read path that several channels share.
      this.#logger.warn("channel.subscription.relays_corrupt", { channel_pubkey: row.channel_pubkey });
    }
    return {
      agent_id: row.agent_id,
      channel_pubkey: row.channel_pubkey,
      admin_pubkey: row.admin_pubkey,
      access: row.access as ChannelAccess,
      relays,
      delivered_through: Number(row.delivered_through),
      processed_through: Number(row.processed_through),
      status: row.status as "active" | "left" | "ejected",
    };
  }
}
