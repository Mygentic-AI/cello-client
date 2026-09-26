/**
 * M16 043-POSTERS — the posting passes THIS daemon's agents hold for channels they do not administer.
 *
 * A pass is the admin's signed, expiring permission for one agent to post on one channel. It arrives
 * over a sealed session from the channel's stored admin (channel-join-exchange.ts), and the agent
 * attaches it to every post it writes there. Keyed on agent_id — the stable identity, never a name.
 *
 * LATEST PASS WINS. The admin re-issues a pass before it expires (the lease); the newer one replaces
 * the older, and an older one arriving late never displaces a newer.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { addColumnIfMissing } from "./column-birth.js";

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_poster_passes (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    pass_cbor       BLOB    NOT NULL,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    members_json    TEXT    NOT NULL DEFAULT '[]',
    PRIMARY KEY (agent_id, channel_pubkey)
  );
`;

export interface HeldPosterPass {
  pass_cbor: Uint8Array;
  issued_at: number;
  expires_at: number;
  /**
   * 044-POSTERBELL: the channel's active members as the admin last sent them with this pass — hex
   * pubkeys. Who this poster rings when it posts. `[]` on a pre-044 row (the column default), which
   * simply means the poster rings nobody until the admin's next renewal fills it.
   */
  members: string[];
}

interface Row {
  pass_cbor: Uint8Array;
  issued_at: number | bigint;
  expires_at: number | bigint;
  members_json: string;
}

export class ChannelPosterPassStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_SQL);
    // 044-POSTERBELL: an operator who held a pass row before 044 has no members column. Birth-gated,
    // so a fresh database (CREATE above already made it) is a no-op.
    addColumnIfMissing(this.#db, this.#logger, {
      table: "channel_poster_passes", column: "members_json",
      sql: "ALTER TABLE channel_poster_passes ADD COLUMN members_json TEXT NOT NULL DEFAULT '[]'",
    });
  }

  /** Store a pass unless one issued at or after it is already held. Returns whether it was stored. */
  put(agentId: string, channelHex: string, pass: HeldPosterPass): boolean {
    const held = this.get(agentId, channelHex);
    if (held !== null && held.issued_at >= pass.issued_at) return false;
    this.#db
      .prepare(
        `INSERT INTO channel_poster_passes (agent_id, channel_pubkey, pass_cbor, issued_at, expires_at, members_json)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (agent_id, channel_pubkey) DO UPDATE SET
           pass_cbor = excluded.pass_cbor, issued_at = excluded.issued_at, expires_at = excluded.expires_at,
           members_json = excluded.members_json`,
      )
      .run(agentId, channelHex, Buffer.from(pass.pass_cbor), pass.issued_at, pass.expires_at, JSON.stringify(pass.members));
    this.#logger.info("channel.poster_pass.stored", {
      agent_id: agentId, channel_pubkey: channelHex, issued_at: pass.issued_at, expires_at: pass.expires_at,
      members: pass.members.length,
    });
    return true;
  }

  get(agentId: string, channelHex: string): HeldPosterPass | null {
    const row = this.#db
      .prepare(`SELECT pass_cbor, issued_at, expires_at, members_json FROM channel_poster_passes WHERE agent_id = ? AND channel_pubkey = ?`)
      .get(agentId, channelHex) as Row | undefined;
    if (!row) return null;
    let members: string[] = [];
    try {
      const parsed = JSON.parse(row.members_json) as unknown;
      if (Array.isArray(parsed)) members = parsed.filter((m): m is string => typeof m === "string");
    } catch { members = []; }
    return {
      pass_cbor: new Uint8Array(row.pass_cbor),
      issued_at: Number(row.issued_at),
      expires_at: Number(row.expires_at),
      members,
    };
  }
}
