/**
 * Backup and restore: write this machine's agent to a file, and put one back.
 *
 * Three dependencies — the handler map, a logger, and where the daemon keeps its data. That is the
 * whole reason this is its own module rather than sitting with the other admin verbs: it touches
 * files and nothing else, so it needs none of the signaling, consortium or ceremony machinery they
 * do, and merging them would push one context over the bound to save one call site.
 *
 * The backup file is as sensitive as a private key. `VACUUM INTO` takes a consistent snapshot with
 * the database still open, which is what makes this safe to run against the daemon serving the call.
 */
import { join } from "node:path";
import { createBackup, inspectBackup } from "./backup-restore.js";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";

export interface BackupRestoreDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  /** Where the daemon keeps its data — the database this writes out and reads back sits under it. */
  celloDir: string;
}

export function registerBackupRestoreHandlers(deps: BackupRestoreDeps): void {
  const { handlers, logger, celloDir } = deps;

  /**
   * DOD-M15-BACKUP-1 — export the agent, so losing the machine does not lose the identity.
   *
   * `VACUUM INTO` takes a consistent snapshot with the database still open, so this is safe to call
   * on a running daemon — which matters, because the daemon is what serves the tool.
   */
  handlers.set("cello_backup", async (params, _connectionId) => {
    const outPath = typeof params?.["path"] === "string" ? (params["path"] as string) : "";
    if (!outPath) {
      return {
        ok: false,
        reason: "missing_path",
        guidance:
          "Give an absolute path to write the backup to, e.g. { path: \"/Users/you/cello-agent.cello-backup\" }. " +
          "It is not written to a default location on purpose: the file contains the key to your agent, " +
          "so where it lands is a decision you should make deliberately.",
      };
    }
    const res = await createBackup({
      dbPath: join(celloDir, "sessions.db"),
      outPath,
      logger,
      ...(params?.["overwrite"] === true ? { overwrite: true } : {}),
    });
    return res.ok
      ? { ok: true, path: res.path, bytes: res.bytes, guidance: res.guidance }
      : { ok: false, reason: res.reason, guidance: res.guidance };
  });

  /**
   * RESTORE IS REFUSED WHILE THIS DAEMON IS RUNNING, and that is not a limitation to apologise for.
   *
   * The daemon holds the database open with a write lock. Overwriting the file underneath an open
   * SQLite handle risks the handle flushing its own pages back over the restored ones — the restore
   * appears to succeed and the database is a hybrid of two identities, which is worse than either
   * failing cleanly.
   *
   * The capability itself lives in `backup-restore.ts` (a daemon module, per the DoD), and the CLI
   * calls it with the daemon stopped. So the honest answer here is the exact sequence, not an
   * attempt.
   */
  handlers.set("cello_restore", async (params, _connectionId) => {
    const archivePath = typeof params?.["path"] === "string" ? (params["path"] as string) : "";
    const inspected = archivePath ? await inspectBackup(archivePath) : null;
    return {
      ok: false,
      reason: "daemon_running",
      ...(inspected?.ok
        ? { archive_verified: true, backup_created_at: new Date(inspected.createdAt).toISOString() }
        : inspected
          ? { archive_verified: false, archive_problem: inspected.reason }
          : {}),
      guidance:
        (inspected?.ok
          ? `That archive is valid (taken ${new Date(inspected.createdAt).toISOString()}). `
          : inspected
            ? `WARNING: that archive did not validate (${inspected.reason}) — fix that before going further. `
            : "") +
        "Restoring REPLACES this machine's agent database, and it cannot be done while the daemon " +
        "is holding it open — the running daemon could flush its own pages back over the restored " +
        "ones and leave a database that is half one identity and half another. Stop the daemon " +
        "first:\n\n  cello logout\n  cello restore " +
        (archivePath || "<archive>") +
        "\n  cello login\n\n" +
        "Anything that happened on this machine since the backup was taken will be gone — restore " +
        "replaces, it does not merge.",
    };
  });
}
