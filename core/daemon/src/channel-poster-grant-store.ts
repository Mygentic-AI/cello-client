/**
 * M16 043-POSTERS Part E — the passes an ADMIN has issued for its channels, and their revocations.
 *
 * One row per (channel, poster), keyed on both pubkeys. `issued_at` / `expires_at` are the newest
 * pass the poster was SENT (a pass is recorded only once it was delivered, so an unreached poster is
 * retried on the next tick). `revoked_at` is the time the admin removed the poster (0 = never); the
 * relay treats any pass issued at or before it as dead, and it is published in the channel info
 * record. A later re-add issues a pass AFTER `revoked_at`, which is what makes it live again.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_poster_grants (
    channel_pubkey  TEXT    NOT NULL,
    poster_pubkey   TEXT    NOT NULL,
    issued_at       INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL DEFAULT 0,
    revoked_at      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_pubkey, poster_pubkey)
  );
`;

export interface PosterGrant {
  poster_pubkey: string;
  issued_at: number;
  expires_at: number;
  revoked_at: number;
}

interface Row {
  poster_pubkey: string;
  issued_at: number | bigint;
  expires_at: number | bigint;
  revoked_at: number | bigint;
}

/** A grant is live when it has been issued since its last revocation. */
export function grantIsLive(g: PosterGrant): boolean {
  return g.issued_at > 0 && g.issued_at > g.revoked_at;
}

export class ChannelPosterGrantStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_SQL);
  }

  all(channelHex: string): PosterGrant[] {
    const rows = this.#db
      .prepare(`SELECT poster_pubkey, issued_at, expires_at, revoked_at FROM channel_poster_grants
                 WHERE channel_pubkey = ? ORDER BY poster_pubkey`)
      .all(channelHex) as Row[];
    return rows.map((r) => ({
      poster_pubkey: r.poster_pubkey,
      issued_at: Number(r.issued_at),
      expires_at: Number(r.expires_at),
      revoked_at: Number(r.revoked_at),
    }));
  }

  get(channelHex: string, posterHex: string): PosterGrant | null {
    return this.all(channelHex).find((g) => g.poster_pubkey === posterHex) ?? null;
  }

  recordIssued(channelHex: string, posterHex: string, issuedAt: number, expiresAt: number): void {
    this.#db
      .prepare(`INSERT INTO channel_poster_grants (channel_pubkey, poster_pubkey, issued_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (channel_pubkey, poster_pubkey)
                DO UPDATE SET issued_at = excluded.issued_at, expires_at = excluded.expires_at`)
      .run(channelHex, posterHex, issuedAt, expiresAt);
    this.#logger.info("channel.poster_pass.issued", { channel_pubkey: channelHex, poster_pubkey: posterHex, issued_at: issuedAt, expires_at: expiresAt });
  }

  revoke(channelHex: string, posterHex: string, at: number): void {
    this.#db
      .prepare(`INSERT INTO channel_poster_grants (channel_pubkey, poster_pubkey, revoked_at) VALUES (?, ?, ?)
                ON CONFLICT (channel_pubkey, poster_pubkey) DO UPDATE SET revoked_at = excluded.revoked_at`)
      .run(channelHex, posterHex, at);
    this.#logger.info("channel.poster.revoked", { channel_pubkey: channelHex, poster_pubkey: posterHex, revoked_at: at });
  }

  /** Every revocation ever made for the channel — what the info record publishes. */
  revocations(channelHex: string): Array<{ poster_pubkey: string; revoked_at: number }> {
    return this.all(channelHex).filter((g) => g.revoked_at > 0)
      .map((g) => ({ poster_pubkey: g.poster_pubkey, revoked_at: g.revoked_at }));
  }
}
