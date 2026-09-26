/**
 * M16 043-POSTERS Part D — a member's two positions in each POSTER lane of a channel.
 *
 * The admin lane keeps the existing `delivered_through` / `processed_through` on the subscription
 * row, untouched. Each poster numbers its own posts from 1, so each poster lane needs its own pair —
 * with the same rule as the admin lane: the collector moves `delivered_through`, a read moves
 * `processed_through`, and neither ever goes backwards.
 *
 * Keyed on agent_id, channel pubkey and the poster's pubkey — stable identities, never a name.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_lane_positions (
    agent_id           TEXT    NOT NULL,
    channel_pubkey     TEXT    NOT NULL,
    lane_poster        TEXT    NOT NULL,
    delivered_through  INTEGER NOT NULL DEFAULT 0,
    processed_through  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, channel_pubkey, lane_poster)
  );
`;

export interface LanePosition {
  lane_poster: string;
  delivered_through: number;
  processed_through: number;
}

interface Row {
  lane_poster: string;
  delivered_through: number | bigint;
  processed_through: number | bigint;
}

export class ChannelLanePositionStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_SQL);
  }

  /** Every poster lane this member has a position in, for one channel. */
  lanes(agentId: string, channelHex: string): LanePosition[] {
    const rows = this.#db
      .prepare(`SELECT lane_poster, delivered_through, processed_through FROM channel_lane_positions
                 WHERE agent_id = ? AND channel_pubkey = ? ORDER BY lane_poster`)
      .all(agentId, channelHex) as Row[];
    return rows.map((r) => ({
      lane_poster: r.lane_poster,
      delivered_through: Number(r.delivered_through),
      processed_through: Number(r.processed_through),
    }));
  }

  /** A lane never seen is at 0/0 — nothing fetched, nothing read. */
  get(agentId: string, channelHex: string, posterHex: string): LanePosition {
    return this.lanes(agentId, channelHex).find((l) => l.lane_poster === posterHex)
      ?? { lane_poster: posterHex, delivered_through: 0, processed_through: 0 };
  }

  /** Forward only, like the subscription's own position. */
  setDelivered(agentId: string, channelHex: string, posterHex: string, seq: number): void {
    this.#db
      .prepare(`INSERT INTO channel_lane_positions (agent_id, channel_pubkey, lane_poster, delivered_through)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (agent_id, channel_pubkey, lane_poster)
                DO UPDATE SET delivered_through = MAX(delivered_through, excluded.delivered_through)`)
      .run(agentId, channelHex, posterHex, seq);
    this.#logger.debug("channel.lane.delivered", { agent_id: agentId, channel_pubkey: channelHex, lane_poster: posterHex, seq });
  }

  /** Forward only, and never past what was delivered. */
  advanceProcessed(agentId: string, channelHex: string, posterHex: string, seq: number): void {
    this.#db
      .prepare(`UPDATE channel_lane_positions
                   SET processed_through = MIN(delivered_through, MAX(processed_through, ?))
                 WHERE agent_id = ? AND channel_pubkey = ? AND lane_poster = ?`)
      .run(seq, agentId, channelHex, posterHex);
  }

  /** Posts delivered and not yet read, summed over this channel's poster lanes. */
  unread(agentId: string, channelHex: string): number {
    return this.lanes(agentId, channelHex)
      .reduce((n, l) => n + Math.max(0, l.delivered_through - l.processed_through), 0);
  }
}
