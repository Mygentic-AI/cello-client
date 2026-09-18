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

/**
 * The group keys a subscriber holds, one row per generation.
 *
 * ⚠️ **A SEPARATE TABLE BECAUSE THERE ARE MANY PER SUBSCRIPTION, and every one is kept.** A re-key
 * does not make old posts unreadable — they are still in the relay's queue under the old key — so a
 * single `key` column on the subscription would make the channel's own history undecryptable to its
 * own members the moment anyone was ejected.
 *
 * The key bytes live only here, inside the SQLCipher database, and are never logged.
 */
export const CHANNEL_SUBSCRIPTION_KEYS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_subscription_keys (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    generation      INTEGER NOT NULL,
    key             BLOB    NOT NULL,
    received_at     INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey, generation)
  );
`;

export interface ChannelSubscription {
  agent_id: string;
  channel_pubkey: string;
  admin_pubkey: string;
  access: ChannelAccess;
  relays: string[];
  /** A local display label. The pubkey is the identity; this is what an operator calls it. */
  moniker: string;
  /** What the channel is for, in the publisher's words — and how long its posts last. Both arrive
   * on the acceptance and have no other source, so a subscriber that drops them cannot recover them. */
  guidance: string;
  retention_seconds: number;
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
  moniker: string;
  guidance: string;
  retention_seconds: number | bigint;
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
    this.#db.exec(CHANNEL_SUBSCRIPTION_KEYS_CREATE_SQL);
  }

  /** Record (or refresh) a subscription. 019's join calls this; 018's tests use it directly. */
  upsert(sub: {
    agent_id: string; channel_pubkey: string; admin_pubkey: string; access: ChannelAccess;
    relays: string[]; joined_at?: number; guidance?: string; retention_seconds?: number;
  }): void {
    this.#db
      .prepare(
        /**
         * ⚠️ TWO THINGS THIS USED TO GET WRONG, both silent.
         *
         * `guidance` and `retention_seconds` arrive on the acceptance frame, are validated, and were
         * then DROPPED — the columns existed and nothing ever wrote them. The order says to store
         * them; a subscriber that does not has no idea what the channel is for or how long its posts
         * last.
         *
         * And `status` was not in the update list, so a subscriber who LEFT and later rejoined got a
         * fresh key, an `ok`, and a row still marked `left`. `active()` excludes it, so the collector
         * never fetched: a channel they had just rejoined that produced nothing, for ever.
         */
        `INSERT INTO channel_subscriptions
           (agent_id, channel_pubkey, admin_pubkey, access, relays, guidance, retention_seconds, joined_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
         ON CONFLICT (agent_id, channel_pubkey) DO UPDATE SET
           admin_pubkey      = excluded.admin_pubkey,
           access            = excluded.access,
           relays            = excluded.relays,
           guidance          = excluded.guidance,
           retention_seconds = excluded.retention_seconds,
           status            = 'active'`,
      )
      .run(
        sub.agent_id, sub.channel_pubkey.toLowerCase(), sub.admin_pubkey.toLowerCase(),
        sub.access, JSON.stringify(sub.relays),
        sub.guidance ?? "", sub.retention_seconds ?? 7 * 24 * 60 * 60,
        sub.joined_at ?? Date.now(),
      );
  }

  get(agentId: string, channelPubkeyHex: string): ChannelSubscription | null {
    const row = this.#db
      .prepare(
        `SELECT agent_id, channel_pubkey, admin_pubkey, access, relays, moniker, guidance, retention_seconds, delivered_through, processed_through, status
           FROM channel_subscriptions WHERE agent_id = ? AND channel_pubkey = ?`,
      )
      .get(agentId, channelPubkeyHex.toLowerCase()) as Row | undefined;
    return row ? this.#toSubscription(row) : null;
  }

  /** Every channel this daemon should be collecting for. `left` and `ejected` are not collected. */
  active(): ChannelSubscription[] {
    const rows = this.#db
      .prepare(
        `SELECT agent_id, channel_pubkey, admin_pubkey, access, relays, moniker, guidance, retention_seconds, delivered_through, processed_through, status
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

  /**
   * Move the AGENT's position — how far it has actually READ.
   *
   * ⚠️ **A LOWER VALUE THROWS RATHER THAN BEING IGNORED.** Silently refusing would leave a caller
   * that computed a wrong position believing it had been applied, and this number is not
   * recoverable from anywhere else: moving it back re-delivers messages the operator already saw,
   * and moving it forward by mistake skips messages they never did. Equal is a no-op, not an error.
   */
  advanceProcessed(agentId: string, channelPubkeyHex: string, seq: number): void {
    const current = this.get(agentId, channelPubkeyHex);
    if (!current) {
      throw new ChannelSubscriptionError("subscription_unknown", `no subscription for ${channelPubkeyHex.slice(0, 16)}`);
    }
    if (seq < current.processed_through) {
      throw new ChannelSubscriptionError(
        "position_regression",
        `processed_through is ${String(current.processed_through)}; refusing to move it back to ${String(seq)}`,
      );
    }
    if (seq === current.processed_through) return;
    // ⚠️ TOUCHES ONE COLUMN. A read must never move `delivered_through`, or the collector's next
    // pass would start past posts it has not fetched and they would never arrive.
    this.#db
      .prepare(`UPDATE channel_subscriptions SET processed_through = ? WHERE agent_id = ? AND channel_pubkey = ?`)
      .run(seq, agentId, channelPubkeyHex.toLowerCase());
  }

  /**
   * Store a group key for one generation.
   *
   * ⚠️ **IDEMPOTENT, because a re-key can be delivered twice** — the admin retries an undelivered
   * one, and a member that already has it must not end up with two rows or a replaced key.
   */
  addKey(agentId: string, channelPubkeyHex: string, gk: { generation: number; key: Uint8Array }, receivedAt: number): void {
    this.#db
      .prepare(
        `INSERT INTO channel_subscription_keys (agent_id, channel_pubkey, generation, key, received_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (agent_id, channel_pubkey, generation) DO NOTHING`,
      )
      .run(agentId, channelPubkeyHex.toLowerCase(), gk.generation, Buffer.from(gk.key), receivedAt);
    // The GENERATION may be logged; the key may not, ever.
    this.#logger.info("channel.key.stored", {
      agent_id: agentId, channel_pubkey: channelPubkeyHex, generation: gk.generation,
    });
  }

  /**
   * Every group key this subscriber holds, newest generation first.
   *
   * ⚠️ **OLD GENERATIONS ARE NEVER DELETED.** A re-key does not make yesterday's posts unreadable —
   * they are still encrypted under the old key and still in the relay's queue — so dropping it
   * would turn the channel's own history into `unknown_generation` for its own members.
   */
  keysFor(agentId: string, channelPubkeyHex: string): Array<{ generation: number; key: Uint8Array }> {
    const rows = this.#db
      .prepare(
        `SELECT generation, key FROM channel_subscription_keys
          WHERE agent_id = ? AND channel_pubkey = ? ORDER BY generation DESC`,
      )
      .all(agentId, channelPubkeyHex.toLowerCase()) as Array<{ generation: number | bigint; key: Uint8Array }>;
    return rows.map((r) => ({ generation: Number(r.generation), key: new Uint8Array(r.key) }));
  }

  /**
   * The subscriber's OWN decision to stop following. Purely local: nothing is sent, nothing is asked
   * of the publisher, and `active()` stops returning it so the collector stops fetching.
   */
  markLeft(agentId: string, channelPubkeyHex: string): void {
    this.#setStatus(agentId, channelPubkeyHex, "left");
  }

  /**
   * The PUBLISHER's decision. Distinct from `left` on purpose: one the subscriber chose and can undo
   * by rejoining, the other they cannot, and an operator asking why a channel went quiet needs to
   * see which of the two happened.
   */
  markEjected(agentId: string, channelPubkeyHex: string): void {
    this.#setStatus(agentId, channelPubkeyHex, "ejected");
  }

  #setStatus(agentId: string, channelPubkeyHex: string, status: "active" | "left" | "ejected"): void {
    const changed = this.#db
      .prepare(`UPDATE channel_subscriptions SET status = ? WHERE agent_id = ? AND channel_pubkey = ?`)
      .run(status, agentId, channelPubkeyHex.toLowerCase());
    if (Number(changed.changes) === 0) {
      throw new ChannelSubscriptionError("subscription_unknown", `no subscription for ${channelPubkeyHex.slice(0, 16)}`);
    }
    this.#logger.info("channel.subscription.status_changed", {
      agent_id: agentId, channel_pubkey: channelPubkeyHex, status,
    });
  }

  /** A local display label. The pubkey is the identity and naming it changes nothing. */
  setMoniker(agentId: string, channelPubkeyHex: string, moniker: string): void {
    this.#db
      .prepare(`UPDATE channel_subscriptions SET moniker = ? WHERE agent_id = ? AND channel_pubkey = ?`)
      .run(moniker, agentId, channelPubkeyHex.toLowerCase());
  }

  /**
   * Is this pubkey a channel this agent subscribes to?
   *
   * ⚠️ **TRUE FOR `left` AND `ejected` TOO, and that is deliberate.** The one caller is the
   * inbound-session gate: a channel never opens a session, so one arriving from a pubkey we know to
   * be a channel is worth refusing on. Unsubscribing does not stop it being a channel, and
   * answering false here would reopen the hole the moment somebody left.
   */
  isSubscribedChannel(agentId: string, pubkeyHex: string): boolean {
    const row = this.#db
      .prepare(`SELECT 1 AS hit FROM channel_subscriptions WHERE agent_id = ? AND channel_pubkey = ?`)
      .get(agentId, pubkeyHex.toLowerCase()) as { hit: number } | undefined;
    return row !== undefined;
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
      moniker: row.moniker,
      guidance: row.guidance,
      retention_seconds: Number(row.retention_seconds),
      delivered_through: Number(row.delivered_through),
      processed_through: Number(row.processed_through),
      status: row.status as "active" | "left" | "ejected",
    };
  }
}
