/**
 * The relays moved from `*.cello.mygentic.ai` to `*.celloprotocol.com`, keeping their peer ids, and
 * the old domain is expiring. A stored address is dialled as written, so one naming the old domain
 * fails however current the code is.
 *
 * Only the host changes. The `/p2p/<peer id>` tail is what authenticates a relay on connect, so a
 * rewritten address still reaches that same relay or fails the dial.
 *
 * `channel_inbox.from_relay` and `transcript.blob` are deliberately not touched: nothing dials from
 * the first, and the second is a record of what was said.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

const RETIRED_HOST = /^(\/(?:dns|dns4|dns6|dnsaddr)\/[^/]+)\.cello\.mygentic\.ai(?=\/|$)/;

/** Every stored list of relay addresses a dial reads from. */
const RELAY_LIST_COLUMNS = [
  { table: "sessions", column: "relay_addrs" },
  { table: "channel_config", column: "relays" },
  { table: "channel_subscriptions", column: "relays" },
  { table: "channel_join_requests", column: "relays" },
] as const;

/** The same addresses with any retired relay host moved to the current domain. */
export function rewriteRetiredRelayAddrs(addrs: readonly string[]): string[] {
  return addrs.map((addr) => addr.replace(RETIRED_HOST, "$1.celloprotocol.com"));
}

function rewriteStoredList(stored: string): string | null {
  const parsed = JSON.parse(stored) as unknown;
  if (!Array.isArray(parsed) || !parsed.every((a): a is string => typeof a === "string")) return null;
  return JSON.stringify(rewriteRetiredRelayAddrs(parsed));
}

/**
 * Runs on every start, not once. A list can still arrive naming the old domain after this has run,
 * for example from a channel admin who has not upgraded, and a row that needs no change costs nothing.
 *
 * A failure is logged and the daemon carries on: the rows stay as they were, the next start tries
 * again, and refusing to start would take every agent offline over addresses that only affect some
 * dials.
 */
export function migrateRetiredRelayDomain(db: DaemonDatabase, logger: Logger): void {
  let rewritten = 0;
  let malformed = 0;
  db.exec("BEGIN");
  try {
    for (const { table, column } of RELAY_LIST_COLUMNS) {
      const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
      if (!exists) continue;
      const rows = db
        .prepare(`SELECT rowid AS id, ${column} AS list FROM ${table} WHERE ${column} LIKE '%.cello.mygentic.ai%'`)
        .all() as Array<{ id: number | bigint; list: string }>;
      const update = db.prepare(`UPDATE ${table} SET ${column} = ? WHERE rowid = ?`);
      for (const row of rows) {
        let next: string | null;
        try {
          next = rewriteStoredList(row.list);
        } catch {
          next = null;
        }
        if (next === null) {
          malformed += 1;
        } else if (next !== row.list) {
          update.run(next, row.id);
          rewritten += 1;
        }
      }
    }
    db.exec("COMMIT");
  } catch (err: unknown) {
    try {
      db.exec("ROLLBACK");
    } catch {
      /* the failing statement may have already aborted the transaction */
    }
    logger.error("relay.domain.migration.failed", {
      reason: extractErrorMessage(err),
      impact: "stored relay addresses still name the old domain, so dials to them keep failing; the next start tries again",
    });
    return;
  }
  if (malformed > 0) {
    logger.warn("relay.domain.migration.completed", {
      rewritten,
      malformed,
      impact: "rows that are not a list of addresses were left as they were, and any dial reading them keeps failing",
    });
  } else if (rewritten > 0) {
    logger.info("relay.domain.migration.completed", { rewritten, malformed });
  }
}
