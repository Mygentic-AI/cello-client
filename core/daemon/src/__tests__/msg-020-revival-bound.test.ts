/**
 * DOD-M12B-REVIVAL-BOUND-1 — an interrupted session must not stay open forever.
 *
 * ANDRE'S RULING, 2026-08-18: *"No peer ID should be used for more than one session. If a session
 * needs to be revived… it should be possible to revive that session on those peer IDs. But after
 * that, those peer IDs and that peer connection needs to be shut down. It is an open connection
 * that a malicious agent can farm for."* And the tenet under it: **leave nothing open that is no
 * longer needed.** The threat model is that the daemon is entirely on the operator's machine and
 * can be reprogrammed, so the guarantee has to hold on the side that is NOT the attacker.
 *
 * WHAT IS ACTUALLY OPEN. `ingestReceivedContent` refuses `sealed`, `seal_interrupted_pending` and
 * `abandoned` with `session_committed` — but deliberately ACCEPTS `interrupted`, because that
 * acceptance is the only reason recovery can work at all. Today nothing ever leaves `interrupted`
 * except by hand, so "accepts while interrupted" means **accepts forever**.
 *
 * MEASURED on Andre's own store, 2026-08-18 05:32 UTC (Entry 41): two rows, one session, 3 messages,
 * `interrupted_by = NULL`. The restart-seal resolver enumerated them and correctly declined — NULL
 * cause is not a licence to notarize. So they are unsealable AND unrevivable AND still writable.
 *
 * THE SPLIT THIS LINE RESTS ON. A receipt asserts a cause, so an unknown cause must not get one.
 * An open write surface asserts nothing; it just has to close. They are different concerns and get
 * different termini:
 *
 *   interrupted_by = 'local'   → the restart-seal resolver SEALS it (we can say what ended it).
 *   anything else, incl. NULL  → past the revival window, ABANDON it. Terminal, refuses ingest,
 *                                claims nothing about cause, spends no ceremony.
 *
 * WHY THE WINDOW IS NOT ZERO. Zero would abandon a laptop-close session while its owner is still
 * asleep — the exact case A/B exist to rescue. The bound is what makes revival safe to add, not a
 * replacement for it.
 *
 * Revert tests, both RUN: drop the `interrupted_by != 'local'` clause and the local-cause case fails;
 * drop the window arithmetic (compare against `now` instead of `now - window`) and TWO fail — the
 * inside-the-window case and the unparseable-timestamp case, which is the pair that together stop
 * the sweep abandoning the whole store.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { startDaemon } from "../daemon.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { DaemonConfig, Logger } from "../types.js";
import { wireContentHash } from "../wire-content-hash.js";

const PEER = "aa".repeat(32);
const HOUR = 3_600_000;

let fx: TwoConnectionFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

/** Insert an interrupted session with an explicit cause and interruption time. */
function seed(
  f: TwoConnectionFixture,
  sessionId: string,
  cause: string | null,
  interruptedAtMs: number | null,
  opts: { messages?: number; updatedAt?: number; agent?: string } = {},
): void {
  const db = f.snm.getDb();
  db.prepare(
    `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                           message_count, interrupted_at, interrupted_by)
     VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = ?), ?, 'interrupted', ?, ?, ?, ?, ?)`,
  ).run(
    sessionId,
    opts.agent ?? "alice",
    PEER,
    1,
    opts.updatedAt ?? 1,
    opts.messages ?? 3,
    // PRODUCTION FORMAT. All three producers write `new Date(now).toISOString()` into this TEXT
    // column, while `updated_at` beside it is epoch millis. A test that seeded a number here would
    // pass against arithmetic that is wrong for every real row — which is exactly what the first
    // build did before the gate caught it.
    interruptedAtMs === null ? null : new Date(interruptedAtMs).toISOString(),
    cause,
  );
}

describe("DOD-M12B-REVIVAL-BOUND-1: an unrevivable session reaches a terminal state", () => {
  it("an unknown-cause session past the window is offered for abandonment", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020a-" });
    const now = 100 * HOUR;
    seed(fx, "01".repeat(32), null, now - 25 * HOUR);

    expect(
      fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR).map((s) => s.sessionId),
      "NULL cause cannot be sealed and cannot be revived — leaving it interrupted leaves it writable",
    ).toEqual(["01".repeat(32)]);
  }, 60_000);

  it("a session still INSIDE the window is left alone — revival must stay possible", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020b-" });
    const now = 100 * HOUR;
    seed(fx, "02".repeat(32), "counterparty", now - 23 * HOUR);

    expect(
      fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR),
      "abandoning inside the window would destroy the laptop-close case that case A exists to rescue",
    ).toEqual([]);
  }, 60_000);

  it("a LOCAL-cause session is never offered here, however old — it belongs to the seal path", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020c-" });
    const now = 100 * HOUR;
    seed(fx, "03".repeat(32), "local", now - 90 * HOUR);

    expect(
      fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR),
      "we know what ended it, so it earns a receipt — abandoning it here would forfeit one it can have",
    ).toEqual([]);
  }, 60_000);

  it("a NULL interrupted_at is STAMPED write-once, then expires one window later", async () => {
    // The rows measured in Entry 41 are this shape: interrupted by a `destroySessionNode` path that
    // wrote the cause and no timestamp. Skipping them would exempt the oldest sessions in the store
    // from the bound permanently — the same "open forever" failure wearing a different NULL.
    //
    // The first build read `updated_at` for these, which the counterparty moves with every message
    // (see the H1 case). The stamp is the fix, and its cost is visible right here: the row gets its
    // full window from the first sweep that sees it rather than from its true interruption. A late
    // close is recoverable; a clock the peer winds is not.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020d-" });
    const t0 = 100 * HOUR;
    const sid = "04".repeat(32);
    seed(fx, sid, null, null, { updatedAt: t0 - 30 * HOUR });

    expect(
      await fx.snm.closeExpiredUnrevivableSessions(t0, 24 * HOUR),
      "the clock starts at the stamp, so an unstamped row is not instantly terminal",
    ).toBe(0);

    const stamped = fx.snm.getDb().prepare("SELECT interrupted_at FROM sessions WHERE session_id = ?").get(sid) as { interrupted_at: string };
    expect(stamped.interrupted_at, "stamped in production format").toBe(new Date(t0).toISOString());

    // Write-once: a second sweep must not move it forward, or the row never expires.
    await fx.snm.closeExpiredUnrevivableSessions(t0 + 5 * HOUR, 24 * HOUR);
    const again = fx.snm.getDb().prepare("SELECT interrupted_at FROM sessions WHERE session_id = ?").get(sid) as { interrupted_at: string };
    expect(again.interrupted_at, "a clock re-stamped on every sweep is a clock that never runs out").toBe(stamped.interrupted_at);

    expect(await fx.snm.closeExpiredUnrevivableSessions(t0 + 25 * HOUR, 24 * HOUR)).toBe(1);
  }, 60_000);

  it("an UNPARSEABLE interrupted_at falls back to updated_at, and is never read as the year 2026", async () => {
    // `CAST('2026-08-18T05:32:04Z' AS INTEGER)` is 2026 — SQLite casts by leading digits. Under that
    // arithmetic every ISO timestamp is older than every epoch bound, so the sweep abandons the whole
    // store on the next boot. This pins the fallback that makes an unreadable value harmless instead.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020f-" });
    const now = 100 * HOUR;
    const db = fx.snm.getDb();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                             message_count, interrupted_at, interrupted_by)
       VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', 1, ?, 3, 'not-a-timestamp', NULL)`,
    ).run("06".repeat(32), PEER, now - 2 * HOUR);

    expect(
      fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR),
      "updated_at is 2h old, so the fallback keeps it INSIDE the window — a garbage value must not " +
      "expire a session that has not expired",
    ).toEqual([]);
  }, 60_000);

  it("closing them flips the status to abandoned, and ingest then refuses", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020e-" });
    const now = 100 * HOUR;
    const sid = "05".repeat(32);
    seed(fx, sid, null, now - 25 * HOUR);

    const closed = await fx.snm.closeExpiredUnrevivableSessions(now, 24 * HOUR);
    expect(closed, "the count is what the boot log reports").toBe(1);

    const row = fx.snm.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(sid) as { status: string };
    expect(row.status, "terminal, so the row stops accepting content").toBe("abandoned");

    // A WELL-FORMED message, deliberately. The first version of this test passed one options object
    // where `content: Uint8Array` goes and nothing where `contentHash` goes, so it only reached
    // `session_committed` because the status guard runs before the hash would have been computed —
    // it proved the guard fires on a MALFORMED call, which is not the claim. The real signature is
    // (agentName, sessionId, content, contentHash, correlationId?, canonicalSeq?).
    const content = new TextEncoder().encode("a message from a peer that should not be accepted");
    const ingest = await fx.snm.ingestReceivedContent("alice", sid, content, wireContentHash(content));
    expect(
      (ingest as { ok: boolean; reason?: string }).reason,
      "this is the whole point of the line — a reprogrammed peer must not be able to write here",
    ).toBe("session_committed");
  }, 60_000);

  it("H1: a peer sending into the interrupted session CANNOT push the deadline out", async () => {
    // THE FINDING THIS PINS. The first build fell back to `updated_at` when `interrupted_at` was
    // NULL. `ingestReceivedContent` accepts content into an interrupted session — that acceptance is
    // this line's whole premise — and a successful ingest writes `updated_at = now`. So the
    // reprogrammed peer held the expiry clock: one message a day and the session never closes.
    // The fix stamps `interrupted_at` write-once and reads only that.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020g-" });
    const t0 = 100 * HOUR;
    const sid = "07".repeat(32);
    seed(fx, sid, null, null, { updatedAt: t0 });

    // First sweep stamps the clock at t0 and closes nothing — the window has not run.
    expect(await fx.snm.closeExpiredUnrevivableSessions(t0, 24 * HOUR)).toBe(0);

    // The peer now does the only thing it can do: send. This moves `updated_at` forward.
    const content = new TextEncoder().encode("keep-alive from a peer that wants the door held open");
    await fx.snm.ingestReceivedContent("alice", sid, content, wireContentHash(content));
    const moved = fx.snm.getDb().prepare("SELECT updated_at FROM sessions WHERE session_id = ?").get(sid) as { updated_at: number };
    expect(moved.updated_at, "the premise of the attack — the peer really can move this column").toBeGreaterThan(t0);

    // 25h after the stamp, it closes anyway.
    expect(
      await fx.snm.closeExpiredUnrevivableSessions(t0 + 25 * HOUR, 24 * HOUR),
      "if this is 0, the counterparty holds the off switch for the control built to stop them",
    ).toBe(1);
  }, 60_000);

  it("H2: a LOCAL session the seal path gave up on is closed — it has no other terminus", async () => {
    // `markRestartSealGaveUp` writes `restart_seal_gave_up_at` and leaves the status `interrupted`,
    // and `listRestartOrphanedSessions` then excludes it forever by `restart_seal_gave_up_at IS
    // NULL`. Excluding it here too left it permanently interrupted and permanently writable.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020h-" });
    const now = 100 * HOUR;
    const sid = "08".repeat(32);
    seed(fx, sid, "local", now - 25 * HOUR);
    fx.snm.markRestartSealGaveUp("alice", sid, "seal_carry_duplicate_own_ctrl_leaf");

    expect(
      fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR).map((r) => r.sessionId),
      "the seal path has finished with it and will never retry — something has to close the door",
    ).toEqual([sid]);
  }, 60_000);

  it("H2: a LOCAL session with ZERO messages is closed — the seal path will never take it", async () => {
    // The resolver requires `message_count > 0`: a dead handshake is not worth a ceremony. Correct,
    // and it still leaves an open write surface that nothing else would ever close.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020i-" });
    const now = 100 * HOUR;
    const sid = "09".repeat(32);
    seed(fx, sid, "local", now - 25 * HOUR, { messages: 0 });

    expect(fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR).map((r) => r.sessionId)).toEqual([sid]);
  }, 60_000);

  it("H2: a LOCAL session the seal path can still take is NOT closed, however old", async () => {
    // The backstop must not race the receipt. This is the case that keeps `RESTART-SEAL-1` first.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020j-" });
    const now = 100 * HOUR;
    seed(fx, "0a".repeat(32), "local", now - 90 * HOUR, { messages: 4 });

    expect(
      fx.snm.listExpiredUnrevivableSessions(now, 24 * HOUR),
      "it can still earn a notarized receipt; abandoning it here forfeits one it can have",
    ).toEqual([]);
  }, 60_000);

  it("the REAL production timestamp — a 2026 ISO string with fractional seconds — is parsed as a date", async () => {
    // Every other case here derives from whole hours off epoch, so they all end `.000` in 1970. The
    // only format production actually writes is `2026-08-18T05:32:04.179Z`, and the bug the gate
    // caught (`CAST(... AS INTEGER)` → 2026) is invisible to a 1970 timestamp.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg020k-" });
    const realNow = Date.parse("2026-08-18T05:32:04.179Z");
    const sid = "0b".repeat(32);
    seed(fx, sid, null, realNow);

    expect(
      fx.snm.listExpiredUnrevivableSessions(realNow + 23 * HOUR, 24 * HOUR),
      "read as the year 2026 this is ancient and closes instantly",
    ).toEqual([]);
    expect(
      fx.snm.listExpiredUnrevivableSessions(realNow + 25 * HOUR, 24 * HOUR).map((r) => r.sessionId),
    ).toEqual([sid]);
  }, 60_000);

  /**
   * THE BLOCKING FINDING FROM REVIEW. Every case above drives `SessionNodeManager` directly, so the
   * entire boot wiring in `daemon.ts` could be deleted and all of them stayed green — the security
   * control could be unwired without a single test noticing. `RESTART-SEAL-1` explicitly refused to
   * leave that gap; this closes the same one.
   *
   * Revert test (RUN): delete the `runRevivalBoundSweep()` call from `daemon.ts` and this fails.
   */
  it("BOOT WIRING: a real daemon start closes an expired session — not just a direct method call", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "cello-msg020boot-"));
    const sid = "0c".repeat(32);
    let handle: Awaited<ReturnType<typeof startDaemon>> | undefined;
    try {
      const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
      const config: DaemonConfig = {
        securityGateway: new PassthroughGatewayClient(),
        celloDir: tempDir,
        socketPath: join(tempDir, "daemon.sock"),
        lockFilePath: join(tempDir, "daemon.lock"),
        maxConnections: 16,
        version: "0.0.1-test",
        logger: silent,
      };

      // FIRST boot builds the schema, exactly as a real install does. Seeding into a hand-rolled
      // table would prove the sweep works against a shape production does not have.
      const first = await startDaemon(config);
      await first.stop?.();

      const db = openTestDb(join(tempDir, "sessions.db"));
      await seedAgents(db, ["alice"]);
      // Interrupted 30 days ago, unknown cause — expired under any window this constant could hold.
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                               message_count, interrupted_at, interrupted_by)
         VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', ?, ?, 3, ?, NULL)`,
      ).run(sid, PEER, Date.now(), Date.now(), new Date(Date.now() - 30 * 24 * HOUR).toISOString());
      db.close();

      handle = await startDaemon(config);

      // The boot sweep is deliberately not awaited, so give the microtask queue a turn to settle.
      for (let i = 0; i < 50; i += 1) {
        await new Promise((r) => setTimeout(r, 20));
        const check = openTestDb(join(tempDir, "sessions.db"));
        const row = check.prepare("SELECT status FROM sessions WHERE session_id = ?").get(sid) as { status: string } | undefined;
        check.close();
        if (row?.status === "abandoned") return;
      }
      throw new Error("the daemon booted and never applied the revival bound — the wiring is dead");
    } finally {
      await handle?.stop?.();
      await rm(tempDir, { recursive: true, force: true });
    }
  }, 60_000);
});
