/**
 * CELLO Daemon — REFUSALS THE OPERATOR CAN ACTUALLY SEE
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE.
 *
 * ⚠️ THE POINT OF THIS MODULE IS THAT A REFUSAL HAS A READER. Every inbound refusal already logged a
 * reason, an impact and a guidance, and they were good — and they had no consumer. From the
 * receiving operator's chair a refused message simply never arrives: the conversation goes quiet
 * with a full explanation sitting in a file they have no reason to open, and they conclude the other
 * person stopped replying.
 *
 * DURABLE, and that is the half that makes it useful — a restart must not lose the notice, because
 * the question it answers ("why did they go quiet?") outlives the process that refused.
 *
 * Moved verbatim, comments included.
 */
import type { Logger } from "./types.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { SessionQueries } from "./session-queries.js";
import { REFUSAL_KINDS, type RefusalKind } from "./refusal-reasons.js";
import { extractErrorMessage } from "./error-message.js";
import { TIER } from "./contacts-tier-migration.js";
import {
  type RefusalNotice,
  MAX_REFUSALS_PER_READ,
  MAX_REFUSAL_READERS,
} from "./session-node-types.js";

/** What the refusal surface needs from the manager. */
export interface RefusalNoticeContext {
  readonly logger: Logger;
  readonly queries: SessionQueries;
  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;
  requireAgentId(agentName: string): string;
  sessionKey(agentName: string, sessionId: string): string;
  unkey(key: string, agentName: string): string | null;
}

export class RefusalNotices {
  readonly #ctx: RefusalNoticeContext;

  constructor(ctx: RefusalNoticeContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * DOD-M15-NO-SILENT-REFUSAL-1 review F6 — refusal notices that could NOT be persisted.
   *
   * Empty in every healthy daemon. It exists so that a database failure costs the restart property
   * and nothing else: without it, the operator-facing surface for a refusal disappears entirely the
   * moment the write fails, which is strictly worse than the in-memory Map this store replaced.
   * `session.refusal.persist.failed` fires at ERROR on every entry that lands here.
   */
  #refusalFallback = new Map<string, Map<string, { kind: RefusalKind; impact: string; guidance: string; count: number; surfacedTo: Map<string, number> }>>();
  /**
   * The one read path behind both doors. `sessionId` narrows it; omitted, it spans the agent.
   *
   * A single implementation on purpose: the per-consumer rule and the order-of-magnitude rule are
   * the two properties this unit must not lose, and two copies of them is two things to keep true.
   */
  drainRefusals(
    agentName: string,
    consumerId: string,
    sessionId?: string,
  ): { notices: RefusalNotice[]; truncated: boolean } {
    const out: RefusalNotice[] = [];
    let truncated = false;
    const now = Date.now();
    let agentId: string | null = null;
    if (this.#db) {
      try {
        agentId = this.#ctx.requireAgentId(agentName);
      } catch {
        // A name that resolves to no active agent has no notices by construction. Already logged by
        // #requireAgentId; re-throwing would fail a read that has nothing to report.
        agentId = null;
      }
    }
    if (agentId !== null && this.#db) {
      /**
       * ⚠️ NEWEST FIRST, AND CAPPED — review F3, and the ordering is the load-bearing half.
       *
       * Read state is keyed on IPC connection id, so every new window and every restart is a
       * consumer that has been told nothing, and the drain returns every notice ever recorded for
       * that agent. Oldest-first and uncapped, the first thing an operator saw after a restart was a
       * chronological archive whose top entry was the oldest refusal on record and whose newest —
       * the one explaining the conversation that just went quiet — was at the bottom. That is a
       * section people learn to scroll past, which is the failure this whole line exists to end.
       *
       * `LIMIT` is `+ 1` so the cap can be DETECTED rather than assumed; the extra row is dropped
       * and `truncated` is reported to the caller, which says so on the list itself.
       *
       * ⚠️ `rowid DESC` is the TIEBREAK and it is load-bearing, not tidiness. `last_at` is
       * `Date.now()`, so notices recorded in the same millisecond have no defined order and "newest
       * first" was true only on average — measured by a test that recorded 30 notices in one tick
       * and got them back in an order SQLite was free to choose. rowid is monotonic per insert, so
       * the tiebreak is insertion order, which for a same-millisecond batch is exactly recency.
       */
      const rows = (
        sessionId === undefined
          ? this.#db
              .prepare(
                `SELECT n.session_id, n.reason, n.kind, n.impact, n.guidance, n.count, r.seen_count,
                        t.total AS lifetime_total, t.seeded AS lifetime_seeded
                   FROM content_refusal_notices n
                   LEFT JOIN content_refusal_reads r
                     ON r.agent_id = n.agent_id AND r.session_id = n.session_id
                    AND r.reason = n.reason AND r.consumer_id = ?
                   LEFT JOIN content_refusal_totals t
                     ON t.agent_id = n.agent_id AND t.session_id = n.session_id
                    AND t.reason = n.reason
                  WHERE n.agent_id = ?
                    AND (r.seen_count IS NULL OR n.count >= r.seen_count * 10)
                  ORDER BY n.last_at DESC, n.rowid DESC LIMIT ?`,
              )
              .all(consumerId, agentId, MAX_REFUSALS_PER_READ + 1)
          : this.#db
              .prepare(
                `SELECT n.session_id, n.reason, n.kind, n.impact, n.guidance, n.count, r.seen_count,
                        t.total AS lifetime_total, t.seeded AS lifetime_seeded
                   FROM content_refusal_notices n
                   LEFT JOIN content_refusal_reads r
                     ON r.agent_id = n.agent_id AND r.session_id = n.session_id
                    AND r.reason = n.reason AND r.consumer_id = ?
                   LEFT JOIN content_refusal_totals t
                     ON t.agent_id = n.agent_id AND t.session_id = n.session_id
                    AND t.reason = n.reason
                  WHERE n.agent_id = ? AND n.session_id = ?
                    AND (r.seen_count IS NULL OR n.count >= r.seen_count * 10)
                  ORDER BY n.last_at DESC, n.rowid DESC LIMIT ?`,
              )
              .all(consumerId, agentId, sessionId, MAX_REFUSALS_PER_READ + 1)
      ) as Array<{
        session_id: string; reason: string; kind: string; impact: string;
        guidance: string; count: number; seen_count: number | null;
        lifetime_total: number | null; lifetime_seeded: number | null;
      }>;
      if (rows.length > MAX_REFUSALS_PER_READ) { truncated = true; rows.length = MAX_REFUSALS_PER_READ; }
      for (const row of rows) {
        const firstTime = row.seen_count === null;
        /**
         * ⚠️ The unseen test is IN THE QUERY (review N4), and this line is a belt, not the gate.
         *
         * Applied only here, the `LIMIT` cut the newest 25 notices and THEN discarded the ones this
         * consumer had already seen — so a consumer holding read rows for the newest 25 got an empty
         * answer forever and a genuinely unseen notice at position 26 could never be reached. The
         * cap has to cut UNSHOWN notices, which means the filter has to run before it.
         *
         * `seen_count` is at least 1 whenever it is set, so this cannot loop on zero.
         */
        if (!firstTime && row.count < row.seen_count! * 10) continue;
        this.#db
          .prepare(
            `INSERT INTO content_refusal_reads
               (agent_id, session_id, reason, consumer_id, seen_count, seen_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id, session_id, reason, consumer_id) DO UPDATE SET
               seen_count = excluded.seen_count, seen_at = excluded.seen_at`,
          )
          .run(agentId, row.session_id, row.reason, consumerId, row.count, now);
        this.#ctx.queries.evictOldestReads(agentId, row.session_id, row.reason);
        out.push({
          sessionId: row.session_id,
          reason: row.reason,
          kind: row.kind as RefusalKind,
          impact: row.impact,
          guidance: row.guidance,
          timesSinceDismissed: row.count,
          /**
           * DOD-M15-REFUSALTERMINAL-1 — three states, and they are three different claims.
           *
           * A counted total is a FIGURE. A seeded row is a FLOOR, and says so by using a different
           * field name (review F1c). `null` means no totals row at all, which after the upgrade
           * backfill can only happen when the notice write itself failed — reported as ABSENT
           * rather than as the smaller number, because substituting it is the defect this unit
           * exists to remove.
           */
          ...(row.lifetime_total === null
            ? {}
            : row.lifetime_seeded === 1
              ? { timesTotalAtLeast: row.lifetime_total }
              : { timesTotal: row.lifetime_total }),
          ...(firstTime ? {} : { repeat: true }),
        });
      }
    }
    /**
     * The unpersisted notices (review F6), under the SAME per-consumer and order-of-magnitude rules.
     * Reading them differently would make a database failure change WHAT the operator is told rather
     * than only how long it survives — and that difference is the thing hardest to notice.
     *
     * Collected separately and REVERSED before joining, not appended in place — review N2. A Map
     * yields insertion order, which is oldest-first, so appending them straight after the DB half
     * (which is newest-first) put the newest notices at the bottom on exactly the daemon where the
     * fallback is the only half there is.
     */
    const fromFallback: typeof out = [];
    for (const [key, perSession] of this.#refusalFallback) {
      const sid = this.#ctx.unkey(key, agentName);
      if (sid === null) continue;
      if (sessionId !== undefined && sid !== sessionId) continue;
      for (const [reason, notice] of perSession) {
        const shownAt = notice.surfacedTo.get(consumerId);
        const firstTime = shownAt === undefined;
        if (!firstTime && notice.count < shownAt * 10) continue;
        notice.surfacedTo.set(consumerId, notice.count);
        // Bounded like the table's read rows are (review N2): a consumer id is an IPC connection id,
        // so without this a long-running daemon grows one entry per reconnect, in memory, on the
        // very path that exists because the disk is already failing.
        if (notice.surfacedTo.size > MAX_REFUSAL_READERS) {
          const oldest = notice.surfacedTo.keys().next();
          if (!oldest.done) notice.surfacedTo.delete(oldest.value);
        }
        // `timesTotal` is deliberately absent: this notice exists because the durable write failed,
        // so there is no lifetime record to report and inventing one from `notice.count` would
        // restore the exact misreading this unit removes.
        fromFallback.push({
          sessionId: sid, reason, kind: notice.kind, impact: notice.impact,
          guidance: notice.guidance, timesSinceDismissed: notice.count,
          ...(firstTime ? {} : { repeat: true }),
        });
      }
    }
    out.push(...fromFallback.reverse());
    /**
     * ONE cap over BOTH halves — review N2.
     *
     * `LIMIT` governs the table only. A persistent database fault (a full disk, which is also the
     * likeliest cause of `transcript_write_failed`) routes EVERY refusal to the fallback, so the cap
     * this unit added was undone for exactly the daemon already in trouble.
     *
     * The truncation keeps the DB half preferentially, and that is the right bias: those rows are
     * the ones that survive a restart, and they are already ordered newest-first.
     */
    if (out.length > MAX_REFUSALS_PER_READ) {
      truncated = true;
      out.length = MAX_REFUSALS_PER_READ;
    }
    return { notices: out, truncated };
  }
  /**
   * ─── DOD-M15-NO-SILENT-REFUSAL-1: refusals the RECEIVING operator can actually see ────────────
   *
   * Every inbound refusal already logs a `reason`, an `impact` and a `guidance` — and they are
   * good. They had no reader. From the receiving operator's chair a refused message simply never
   * arrives: the conversation goes quiet with a full explanation sitting in a file they have no
   * reason to open, and they conclude the other person stopped replying.
   *
   * **DURABLE, and that is the half that makes this useful.** The predecessor kept notices in a
   * `Map` on this instance and drained them on the receive path for one session. So a restart lost
   * them, and an agent NOBODY IS ATTENDING lost them too — the connection is live, the daemon is
   * up, and the notice only ever reaches whoever happens to call `cello_receive` on that exact
   * session. `cello_check_notifications` now reads them as its own inbox category.
   *
   * **DEDUPLICATED PER SESSION PER REASON, and that is the design, not an optimisation.** A skewed
   * peer turns one problem into a flood: the first refusal of a kind is the signal, the ninetieth is
   * noise that trains the operator to ignore the surface. `count` keeps the scale visible without
   * repeating the alert.
   *
   * **NEVER carries the content.** It failed verification; surfacing it is the injection path the
   * cross-check exists to close. The operator learns that a message was refused and why — never
   * what it said.
   */
  /**
   * Record an inbound refusal for the operator. First of its kind per session is the signal.
   *
   * ⚠️ **DOES NOT THROW, and that is a decision with a cost — stated so it is not mistaken for an
   * oversight.** Every call site here has already decided to refuse and is about to return a reason
   * to its caller; a throw would replace that clean refusal with an exception on the ingest path,
   * changing what the SENDER observes because this daemon could not file a note. So a persistence
   * failure is logged at ERROR under `session.refusal.persist.failed`, carrying the reason, the
   * impact and the guidance verbatim — the forensic record survives even when the operator-facing
   * one does not. It is not silent; it is one surface short, and the log says which notice was lost.
   */
  noteContentRefusal(
    agentName: string,
    sessionId: string,
    reason: string,
    /**
     * ALL THREE REQUIRED, and that is the enforcement rather than the convention.
     *
     * The DoD clause is "every reason calls this with an impact and a guidance", and an optional
     * field makes that a thing a reviewer checks by reading thirteen call sites. `kind` is required
     * for the same reason one level up: the header over a list of refusals is composed from it, and
     * a notice that could omit it would silently inherit whichever header happened to be first.
     */
    detail: { kind: RefusalKind; impact: string; guidance: string },
  ): void {
    try {
      if (!this.#db) throw new Error("database is not open");
      const agentId = this.#ctx.requireAgentId(agentName);
      const now = Date.now();
      /**
       * ⚠️ **BOTH WRITES OR NEITHER — review F6, and the comment this replaces was wrong.**
       *
       * It argued that putting the totals insert in the same `try` made the two "fail together".
       * It does not: each `.run()` autocommits, so the notice could persist and the total throw —
       * and the `catch` then ALSO writes an in-memory fallback entry for a notice that is already
       * in the table. The drain unions the two halves without deduplicating on (session, reason),
       * so the operator would see the same refusal TWICE, once with a lifetime figure and once
       * without, one of them blaming a disk fault. Before this unit a single statement made that
       * state impossible; the second statement is what created it.
       *
       * `ROLLBACK` is best-effort because SQLite may have aborted the transaction already — the
       * same shape `agent-id-migration.ts` uses — and it must never mask the original error.
       */
      this.#db.exec("BEGIN");
      try {
      // `count` grows on conflict; impact and guidance are refreshed, because a later refusal of the
      // same reason may know more than the first (the salt branch has four causes and names them).
      this.#db
        .prepare(
          `INSERT INTO content_refusal_notices
             (agent_id, session_id, reason, kind, impact, guidance, count, first_at, last_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
           ON CONFLICT(agent_id, session_id, reason) DO UPDATE SET
             count = count + 1, kind = excluded.kind, impact = excluded.impact,
             guidance = excluded.guidance, last_at = excluded.last_at`,
        )
        .run(agentId, sessionId, reason, detail.kind, detail.impact, detail.guidance, now, now);
      /**
       * DOD-M15-REFUSALTERMINAL-1 — the lifetime tally, in the SAME `try` on purpose.
       *
       * If the notice write failed there is no notice to hang a total off, and the fallback below
       * has no durable counterpart to read — so the two must fail together. A total that survived a
       * failed notice would be a number nobody could see, and one that was written twice for a
       * retried notice would be worse than absent.
       */
      this.#db
        .prepare(
          // `seeded` stays whatever the row already has. A row seeded at upgrade remains a LOWER
          // BOUND for the life of that (session, reason) — counting forward from an incomplete
          // figure does not recover the refusals dismissal already erased, and clearing the flag
          // would turn "at least 58" into a claimed total of 59.
          `INSERT INTO content_refusal_totals
             (agent_id, session_id, reason, total, first_at, last_at, seeded)
           VALUES (?, ?, ?, 1, ?, ?, 0)
           ON CONFLICT(agent_id, session_id, reason) DO UPDATE SET
             total = total + 1, last_at = excluded.last_at`,
        )
        .run(agentId, sessionId, reason, now, now);
        this.#db.exec("COMMIT");
      } catch (inner: unknown) {
        try { this.#db.exec("ROLLBACK"); } catch { /* already aborted by SQLite */ }
        throw inner;
      }
    } catch (err: unknown) {
      this.#ctx.logger.error("session.refusal.persist.failed", {
        agentName, sessionId, reason,
        impact: detail.impact,
        guidance: detail.guidance,
        error: extractErrorMessage(err),
        consequence:
          "this refusal could not be written to the notice store, so it will not survive a restart. It is held in memory for this process instead, so the operator is still told while this daemon runs. The reason, impact and guidance above are the whole notice.",
      });
      /**
       * DOD-M15-NO-SILENT-REFUSAL-1 review F6 — the fallback, and why it is not the silent kind.
       *
       * The store this replaced was an in-memory Map, which could not fail: recording a refusal was
       * a `set`, so the receive door always had the notice for the life of the process. Making the
       * store durable made it, in the failure case, LESS available than before — a DB write failure
       * left no operator-facing surface at all, only a log line.
       *
       * So a failed write falls back to exactly what the Map did. This is not a fallback that hides
       * a fault: the ERROR above fires every time, naming the notice and the cause, and what is lost
       * is only the restart property — which is the property the database was unavailable for
       * anyway. A silent fallback is one that makes a broken system look healthy; this one is
       * announced, and it preserves the surface rather than substituting for it.
       */
      const key = this.#ctx.sessionKey(agentName, sessionId);
      let perSession = this.#refusalFallback.get(key);
      if (!perSession) { perSession = new Map(); this.#refusalFallback.set(key, perSession); }
      const existing = perSession.get(reason);
      if (existing) { existing.count += 1; existing.kind = detail.kind; existing.impact = detail.impact; existing.guidance = detail.guidance; return; }
      perSession.set(reason, { ...detail, count: 1, surfacedTo: new Map<string, number>() });
    }
  }
  /**
   * DOD-M15-NO-SILENT-REFUSAL-1 — the per-session byte cap, from the operator's chair.
   *
   * This is the harshest refusal on the inbound path and the one that reads least like a fault:
   * once the cap is crossed, EVERY later message from that sender on that session is refused, for
   * the life of the session. The counterparty is told nothing either, so from both chairs the other
   * person simply stopped replying.
   *
   * One method rather than two copies because the cap is checked twice — once before the screening
   * await and once after, against freshly-read totals — and a notice that differs between the two
   * would describe a different refusal depending on timing.
   */
  /**
   * DOD-M15-REFUSEDEVIDENCE-1 — **THE BYTE CAP RETAINS NOTHING, and that is a ruling, not an
   * oversight.**
   *
   * Retention is universal everywhere else in this method. Here it is not, because retaining would
   * defeat the very bound it enforces: a session already over its storage budget cannot be given
   * more storage as a reward for exceeding it, and `#getReceivedBytesTotal` counts quarantined bytes
   * precisely so that budget is honest.
   *
   * Andre, 2026-09-03: *"The message limit is the message limit, already handled by the cap. If
   * you're unknown and you have 25 MB and you just tried to send me one gig, well that's it."*
   *
   * The ABUSE is still evidenced — this notice records the reason, the cap and the tier, and every
   * message the session did retain is still there. What is not kept is the oversized payload.
   */
  noteSizeCapRefusal(agentName: string, sessionId: string, cap: number, tier: number): void {
    /**
     * ⚠️ **IN MEGABYTES, WITH THE BYTES BESIDE THEM.** "26214400 bytes" is not a number anyone reads
     * as 25 MB, and the operator being told a conversation just ended deserves to understand the
     * limit that ended it at a glance. The raw figure stays because it is the exact bound.
     */
    const mb = Math.round((cap / 1_048_576) * 10) / 10;
    /**
     * The access level as a QUOTED LOWERCASE LABEL, never a bare word.
     *
     * `their tier is UNKNOWN` reads as "we could not determine their tier" — the opposite of what it
     * says. UNKNOWN is the NAME of the level a sender has before the operator adds them as a
     * contact. Quoting it and lowercasing it makes it a label rather than a failure.
     */
    const level = (Object.entries(TIER).find(([, v]) => v === tier)?.[0] ?? String(tier)).toLowerCase();
    this.noteContentRefusal(agentName, sessionId, "session_size_limit_exceeded", {
      kind: REFUSAL_KINDS.REFUSED,
      impact:
        `This conversation has hit its size limit for this sender: ${mb} MB (${cap} bytes), which is the limit at their access level ("${level}"). The message was not delivered, and neither will anything else they send in this conversation. They were not told — from their side it sent normally.`,
      guidance:
        `The limit is per conversation and does not reset, so waiting will not clear it. Start a NEW conversation with them to keep talking. If you trust them, raising their access level with cello_contact_set_tier gives them a larger limit next time — it does not revive this one. Tell them what happened: they have no way to know.`,
    });
  }
  /**
   * Drain the refusals a GIVEN CONSUMER has not been shown yet, and remember what it was shown.
   *
   * ─── Why this is keyed by consumer, and not by a single flag ──────────────────────────────────
   *
   * It used to set one `surfaced: boolean` on the notice. Two MCP windows attending the same agent
   * is the ordinary case, and under that flag whoever read FIRST consumed the notice — the second
   * window was told nothing, permanently. **That is the same defect `takeReceivedContent` had**, and
   * the comment above the delivery loop in `session-content-handlers.ts` spells out why it was
   * removed: *"reading is non-destructive by construction. Nothing one consumer does mutates state
   * another consumer reads."*
   *
   * ─── Why the count has a reader ───────────────────────────────────────────────────────────────
   *
   * A reason RE-ANNOUNCES to a consumer when its count has grown by an order of magnitude since that
   * consumer last saw it (1 → 10 → 100 → …), marked `repeat: true`. That keeps the first refusal the
   * signal and the ninetieth silent, which is the dedup's point, while still making a skew that has
   * swallowed hundreds of messages visible — at a handful of announcements per session, not one per
   * message.
   *
   * ─── What a restart does, deliberately ────────────────────────────────────────────────────────
   *
   * The notices survive; the read state is keyed by IPC connection id, which does not. So after a
   * restart every notice is unseen again and the next reader is told. That is the correct direction:
   * a fresh window has not been told anything, and re-announcing costs one line where staying silent
   * costs the whole point of storing it.
   */
  takeContentRefusals(
    agentName: string,
    sessionId: string,
    /**
     * REQUIRED, deliberately — no default.
     *
     * It had one (`"default"`), and a default is the defect this method was rewritten to remove,
     * lying in wait: any future call site that omits the argument silently shares ONE bucket across
     * every window, the first reader consumes the notice for all the others, and nothing fails to
     * compile and no test goes red. The parameter existing is not the protection; being unable to
     * forget it is.
     */
    consumerId: string,
  ): Array<Omit<RefusalNotice, "sessionId">> {
    // `sessionId` is dropped from each entry: the caller passed it in and every entry carries the
    // same one, so repeating it back would be a field that can never say anything. The agent-wide
    // door below keeps it, because there it is the only thing that says WHICH conversation.
    //
    // `truncated` is dropped too, and only here: one session's notices cannot reach the cap (the
    // reasons are a bounded set), so a flag that can never be true is a field readers learn to skip.
    return this.drainRefusals(agentName, consumerId, sessionId).notices.map(({ sessionId: _drop, ...rest }) => rest);
  }
  /**
   * DOD-M15-NO-SILENT-REFUSAL-1: the operator has seen these and does not want to see them again.
   *
   * ⚠️ **WITHOUT THIS THE NOTICES ARE PERMANENT, and that is what makes people stop reading the
   * inbox.** "Already shown you" is tracked per WINDOW — a new MCP connection has been told nothing,
   * so it is told everything. Someone on an older build messages you, you sort it out with them,
   * they upgrade, and every new session you ever open still opens with that refusal.
   *
   * Dismissing does NOT turn anything off. If the cause fires again the notice comes back, because
   * a fresh refusal writes a fresh row. The operator is saying "I know", not "stop telling me".
   *
   * Returns how many were cleared, so the caller can say so rather than claiming a silent success.
   */
  dismissContentRefusals(agentName: string, sessionId: string): number {
    if (!this.#db) return 0;
    let agentId: string;
    try { agentId = this.#ctx.requireAgentId(agentName); } catch { return 0; }
    this.#refusalFallback.delete(this.#ctx.sessionKey(agentName, sessionId));
    const res = this.#db
      .prepare("DELETE FROM content_refusal_notices WHERE agent_id = ? AND session_id = ?")
      .run(agentId, sessionId);
    this.#db
      .prepare("DELETE FROM content_refusal_reads WHERE agent_id = ? AND session_id = ?")
      .run(agentId, sessionId);
    return Number(res.changes);
  }
  /**
   * DOD-M15-NO-SILENT-REFUSAL-1: every unshown refusal for an agent, ACROSS its sessions.
   *
   * The inbox's door. `takeContentRefusals` answers for one session because its caller already holds
   * one; `cello_check_notifications` holds an agent and nothing else, and the case this whole line
   * exists for is that nobody is attending any of that agent's sessions — so a per-session read
   * cannot reach it. Same store, same per-consumer rule, same re-announce.
   */
  takeAgentContentRefusals(
    agentName: string,
    consumerId: string,
  ): { notices: RefusalNotice[]; truncated: boolean } {
    return this.drainRefusals(agentName, consumerId);
  }

  /**
   * Drop the IN-MEMORY fallback notices for one session.
   *
   * ⚠️ THE DURABLE ROWS ARE NOT TOUCHED, and the omission is deliberate rather than forgotten. They
   * live in `content_refusal_notices` keyed on agent_id + session_id, and the question they answer —
   * "why did my counterparty go quiet?" — outlives the session that produced it. Only the in-memory
   * fallback, which exists for the case where the write to disk failed, is dropped here; leaving it
   * would let a store that is already in trouble grow without bound in memory as well.
   */
  evictSession(agentName: string, sessionId: string): void {
    this.#refusalFallback.delete(this.#ctx.sessionKey(agentName, sessionId));
  }
}
