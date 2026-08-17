/**
 * DOD-M12B-RESTART-SEAL-1, the wiring half — the REAL daemon must start the resolver.
 *
 * Every review in this milestone found the same shape: a unit whose class works perfectly and whose
 * call site could be deleted with the whole suite still green. Rank 10 shipped a first build that
 * did nothing at all in production while four tests passed. So this case does not construct a
 * RestartSealResolver at all. It pre-seeds an orphaned session, boots `startDaemon`, and swaps the
 * live `cello_close_session` entry in the handler map for a spy — a spy the resolver can only reach
 * if `startDaemon` actually built it, started it, and resolved the handler lazily.
 *
 * It also pins the SCOPE, which is the safety argument. A session marked `interrupted_by =
 * 'counterparty'` must be left alone: SI-001 ("a daemon that sealed on its own would notarize a
 * conversation nobody chose to end") governs the live case, and only our own stop is exempt.
 *
 * Revert test: delete `restartSealResolver.start()` in daemon.ts and the first case fails — no
 * close is ever attempted. Widen the query to all `interrupted` rows and the second fails.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import type { DaemonConfig, Logger } from "../types.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";

const LOCAL_SID = "11".repeat(32);
const THEIRS_SID = "22".repeat(32);
/** No `interrupted_by` at all — the shape of every row written before the column existed. */
const UNKNOWN_SID = "33".repeat(32);

const NOOP_LOGGER: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** The shape a shutdown leaves behind, plus one the counterparty ended. Old (pre-agent_id) schema
 *  on purpose — `initialize()` re-keys it, which is the upgrade path a real operator's DB takes. */
async function seedOrphans(tempDir: string): Promise<void> {
  const db = openTestDb(join(tempDir, "sessions.db"));
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      agent_name TEXT NOT NULL,
      counterparty_pubkey TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      message_count INTEGER NOT NULL DEFAULT 0,
      interrupted_at TEXT,
      interrupted_by TEXT
    )
  `);
  await seedAgents(db, ["alice"]);
  const now = Date.now();
  const iso = new Date(now).toISOString();
  const ins = db.prepare(
    `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at, interrupted_by)
     VALUES (?, 'alice', ?, 'interrupted', ?, ?, 6, ?, ?)`,
  );
  ins.run(LOCAL_SID, "aa".repeat(32), now, now, iso, "local");
  ins.run(THEIRS_SID, "bb".repeat(32), now, now, iso, "counterparty");
  ins.run(UNKNOWN_SID, "cc".repeat(32), now, now, iso, null);
  db.close();
}

describe("DOD-M12B-RESTART-SEAL-1: startDaemon actually starts the resolver", () => {
  let tempDir = "";
  let handle: Awaited<ReturnType<typeof startDaemon>> | null = null;

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-msg014-")); });
  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already down */ } handle = null; }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function boot(delayMs: number): Promise<void> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: NOOP_LOGGER,
      restartSealInitialDelayMs: delayMs,
      // WITHOUT THIS THE SCOPE TESTS PASS FOR THE WRONG REASON. The default 5 s stagger means the
      // SECOND queue item is not attempted until ~5.4 s, well after these assertions run — so
      // widening the query to every `interrupted` row would leave them green while the safety guard
      // was gone. A short stagger puts every eligible row inside the window.
      restartSealStaggerMs: 40,
    };
    handle = await startDaemon(config);
  }

  it("a session OUR OWN stop orphaned gets a close attempted on it, without anyone asking", async () => {
    await seedOrphans(tempDir);
    // Long enough that the swap below lands before the first attempt, short enough to stay a
    // unit test. The resolver resolves the handler lazily, which is what makes the swap work.
    await boot(400);

    const attempted: string[] = [];
    handle!.getHandlers().set("cello_close_session", async (params) => {
      attempted.push(String(params?.["session_id"]));
      return { ok: true, sealed_root: "00".repeat(32), seal_type: "unilateral" };
    });

    await new Promise((r) => setTimeout(r, 2_500)); // > delay + 3 stagger slots

    expect(
      attempted,
      "the daemon must seal what its own last shutdown orphaned — deleting restartSealResolver.start() makes this empty",
    ).toContain(LOCAL_SID);
  }, 30_000);

  it("a session the COUNTERPARTY ended is left alone — SI-001 still governs the live case", async () => {
    await seedOrphans(tempDir);
    await boot(400);

    const attempted: string[] = [];
    handle!.getHandlers().set("cello_close_session", async (params) => {
      attempted.push(String(params?.["session_id"]));
      return { ok: true, sealed_root: "00".repeat(32), seal_type: "unilateral" };
    });

    await new Promise((r) => setTimeout(r, 2_500)); // > delay + 3 stagger slots

    // EXACT, not `not.toContain`. An exact set is what fails when the query is widened; a
    // negative containment check passes for any number of reasons that are not the guard.
    expect(
      attempted,
      "auto-sealing a session the other party ended would notarize a conversation nobody chose to end",
    ).toEqual([LOCAL_SID]);
  }, 30_000);

  it("a session whose cause is UNKNOWN is left alone — an unlabelled row is not a licence to notarize", async () => {
    // Every row on every database that predates `interrupted_by` is NULL, and that is exactly the
    // population this resolver meets on its first run against a real operator's machine. The safe
    // default for "who ended this?" is NOT "we did". Reading NULL as ours would auto-seal hundreds
    // of historical sessions — including ones the counterparty ended — on a single boot.
    await seedOrphans(tempDir);
    await boot(400);

    const attempted: string[] = [];
    handle!.getHandlers().set("cello_close_session", async (params) => {
      attempted.push(String(params?.["session_id"]));
      return { ok: true, sealed_root: "00".repeat(32), seal_type: "unilateral" };
    });

    await new Promise((r) => setTimeout(r, 2_500)); // > delay + 3 stagger slots

    expect(
      attempted,
      "an unattributable interruption must not be sealed on our own authority — and the exact set is what catches a widened query",
    ).toEqual([LOCAL_SID]);
  }, 30_000);
});
