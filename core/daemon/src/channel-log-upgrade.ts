/**
 * 042-UPGRADE Part B — retire a legacy `channel_log` in place, rather than patch it.
 *
 * The first committed `channel_log` (@71f137a4, 2026-09-17) carried three NOT-NULL columns with no
 * default, from the notarization design removed the next day (@3e5d9c4d). The current table replaces
 * them with `post_cbor`, and current INSERTs supply none of those old columns — so a legacy table
 * rejects every current write, and adding `post_cbor` alone would leave the leftover NOT-NULL columns
 * still rejecting it. `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists, so a
 * daemon that ran a channel before the rework can never append a post.
 *
 * So a legacy table is renamed aside — its bytes kept, nothing reads them — and the caller's CREATE
 * then makes the current table fresh. The marker is `post_cbor`'s ABSENCE: a table that has it is
 * current and is left untouched (no rename, no row loss), and a fresh database has no table to retire.
 *
 * ⚠️ Kept in this sibling module, not in `channel-log-store.ts`, because the 016-CLIENTREWORK removal
 * guard (`m16-016-epoch-removal-guard.test.ts`) asserts that store file names none of the retired
 * schema. The retired table's name lives here instead.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** The name a pre-`post_cbor` `channel_log` is renamed to. Bytes preserved; nothing reads them. */
export const RETIRED_CHANNEL_LOG_TABLE = "channel_log_epoch_retired";

/**
 * Retire a `channel_log` that predates `post_cbor`, so the caller's `CREATE TABLE IF NOT EXISTS`
 * then builds the current shape. A no-op on a fresh database and on an already-current table.
 */
export function retirePrePostsChannelLog(db: DaemonDatabase, logger: Logger): void {
  const cols = db.prepare("PRAGMA table_info(channel_log)").all() as Array<{ name: string }>;
  if (cols.length === 0) return; // no table yet — a fresh database
  if (cols.some((c) => c.name === "post_cbor")) return; // already the current shape — leave it alone
  const rows = Number(
    (db.prepare("SELECT COUNT(*) AS n FROM channel_log").get() as { n: number | bigint }).n,
  );
  db.exec(`ALTER TABLE channel_log RENAME TO ${RETIRED_CHANNEL_LOG_TABLE}`);
  logger.info("channel.log.legacy_retired", { rows });
}
