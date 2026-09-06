/**
 * CELLO Daemon — READS AND WRITES AGAINST THE SESSION STORE
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. Fifty methods that are SQL and nothing
 * else: they need the database, the logger, and the agent-id lookup, and they hold no state of their
 * own. Grouped by that shape rather than by subject, because "needs only the database" is the
 * property that made them safe to move together.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ EVERY QUERY JOINS ON `agent_id`, NEVER `agent_name`. The name is a mutable display label and is
 * reusable after retirement, so joining on it silently attaches one agent's rows to another's.
 * `requireAgentId` is how a name becomes an id, and it THROWS rather than returning a default —
 * a query that silently read no rows for an unknown agent would look like an empty inbox.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger, SessionRecord } from "./types.js";
import { extractErrorMessage } from "./error-message.js";
import { SessionTree, sessionTreeLeafKindFromDb, type WritableSessionTreeLeafKind } from "./session-tree.js";
import { TIER } from "./contacts-tier-migration.js";
import {
  type QuarantinedRecord,
  CAP_COUNTS,
  CAP_COUNT_SQL,
  capStaleBefore,
  REFUSED_SESSIONS_CAP,
  MAX_REFUSAL_READERS,
} from "./session-node-types.js";

/** What these queries need from the manager. Four things, none of them session state. */
export interface SessionQueryContext {
  readonly logger: Logger;
  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;
  requireAgentId(agentName: string): string;
  sessionKey(agentName: string, sessionId: string): string;
  /** The session id inside a composite key, when it belongs to this agent; null otherwise. */
  unkey(key: string, agentName: string): string | null;
}

export class SessionQueries {
  readonly #ctx: SessionQueryContext;

  constructor(ctx: SessionQueryContext) {
    this.#ctx = ctx;
  }

  /** A getter so every moved query still reads `this.#db` and narrows exactly as it did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * DOD-M12B-REVIVAL-BOUND-1 — interrupted sessions that can no longer be revived, and must close.
   *
   * Andre, 2026-08-18: *"after that, those peer IDs and that peer connection needs to be shut down.
   * It is an open connection that a malicious agent can farm for."* The tenet is **leave nothing
   * open that is no longer needed**, and the threat model is a daemon that has been reprogrammed —
   * so the guarantee has to hold on the side that is not the attacker.
   *
   * WHAT IS OPEN. `ingestReceivedContent` refuses `sealed`, `seal_interrupted_pending` and
   * `abandoned`, but deliberately ACCEPTS `interrupted` — that acceptance is the only reason
   * recovery can work. Nothing else ever leaves `interrupted`, so it means accepts FOREVER.
   *
   * **THIS IS THE BACKSTOP, NOT THE COMPLEMENT.** The seal path gets first refusal on every
   * local-cause session, because a session whose ending we can describe truthfully earns a
   * notarized receipt. But "the seal path owns it" is not the same as "the seal path will finish
   * it", and two populations fall through the gap between those:
   *
   *   - **The resolver gave up.** `markRestartSealGaveUp` writes only `restart_seal_gave_up_at`;
   *     the status stays `interrupted`, and `listRestartOrphanedSessions` then excludes the row by
   *     `restart_seal_gave_up_at IS NULL` so it is never retried. `TERMINAL_SEAL_REFUSALS` has ten
   *     entries and the measured figure is that 59% of seals that start never finish, so this is
   *     the common case, not a corner.
   *   - **Zero-message local sessions.** The resolver requires `message_count > 0` — a dead
   *     handshake is not worth a ceremony. It is still an open write surface.
   *
   * Excluding those left them permanently interrupted and permanently writable, which is the exact
   * condition this line exists to end. And the population is about to become the majority: no row
   * has ever carried `interrupted_by = 'local'` yet, and from the next shutdown onward every
   * shutdown-orphaned session will. So the sweep takes a local-cause session once the seal path
   * has either declined it or exhausted it — never before.
   *
   * **THE CLOCK MUST BE ONE THE COUNTERPARTY CANNOT MOVE.** The obvious fallback for a row with no
   * `interrupted_at` is `updated_at` — and it is exactly wrong. `ingestReceivedContent` accepts
   * content into an `interrupted` session (that acceptance is this whole line's premise), and a
   * successful ingest runs `UPDATE sessions SET message_count = ?, updated_at = <now>`. So
   * `updated_at` is a clock the reprogrammed peer holds: one message every 24 hours and the session
   * never expires, forever. The fallback would have handed the attacker the off switch for the
   * control built to stop them.
   *
   * Instead the missing timestamps are STAMPED ONCE, by `#stampMissingInterruptedAt` immediately
   * before this query runs, and this query reads `interrupted_at` and nothing else. The stamp is
   * written under `WHERE interrupted_at IS NULL`, so it is monotone — set once, never moved, by us
   * and not by a peer. A legacy row therefore gets its full window starting from the first sweep
   * that sees it, which is later than the true interruption but is the only bound that is sound.
   *
   * Same retired-agent INNER JOIN as the sibling query: a retired agent's rows are kept for
   * accountability, are not resumable, and are not writable either.
   *
   * **THE TIME ARITHMETIC IS LOAD-BEARING, AND BOTH OBVIOUS FORMS OF IT ARE WRONG.** These two
   * columns do not hold the same kind of value:
   *
   *   `interrupted_at`  TEXT,    an ISO-8601 string — `new Date(now).toISOString()`.
   *   `updated_at`      INTEGER, epoch milliseconds.
   *
   * There are FOUR writers of `status = 'interrupted'`, not three. The fourth is
   * `destroySessionNode` → `#updateSessionStatus(…, "interrupted", "local")`, which historically
   * wrote `interrupted_by` and **no timestamp at all** — and it is the path that produced the two
   * rows in Entry 41. It now stamps `interrupted_at` like the others, so NULL is a legacy state
   * rather than one production keeps creating.
   *
   * So a bare `interrupted_at <= ?` against a numeric bound is **always false** — the column has
   * TEXT affinity and the bound parameter has none, so SQLite applies TEXT affinity to the
   * parameter and compares them as STRINGS (`'2026-08-18T05:32:04.183Z' <= 1755000000000` → 0).
   * The query silently returns nothing forever and reads as "nothing has expired yet". And
   * `CAST(interrupted_at AS
   * INTEGER)` is worse than useless: SQLite casts by taking the leading digits, so
   * `'2026-08-18T05:32:04Z'` becomes **2026**, which is older than any epoch bound. That form
   * abandons every interrupted session on the next boot, immediately, whatever its age. It was
   * written, and `session-001`/`cello-list-sessions` failed on it in the gate.
   *
   * `strftime('%s', …) * 1000` parses the ISO string properly and returns NULL for anything it
   * cannot parse — so a malformed or differently-formatted value falls through the COALESCE to
   * `updated_at` rather than being read as the year 2026.
   */
  listExpiredUnrevivableSessions(
    nowMs: number,
    windowMs: number,
  ): Array<{ agentName: string; sessionId: string; cause: string | null }> {
    if (!this.#db) {
      // ABSENT IS NOT FINE. An empty array here is indistinguishable from "the store is clean",
      // which is the state this line exists to end — so the one boot where the sweep could not
      // read the store must not look like the boots where it read it and found nothing.
      this.#ctx.logger.error("session.revival_bound.enumerate.failed", {
        error: "db not initialized",
        impact: "no interrupted session was checked against the revival window this boot; any that "
          + "have expired are still accepting content",
      });
      return [];
    }
    const rows = this.#db
      .prepare(
        `SELECT s.session_id AS session_id, s.interrupted_by AS cause, a.agent_name AS agent_name
         FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
         WHERE s.status = 'interrupted' AND a.state != 'retired'
           AND (COALESCE(s.interrupted_by, '') != 'local'
                OR s.restart_seal_gave_up_at IS NOT NULL
                OR s.message_count = 0)
           AND CAST(strftime('%s', s.interrupted_at) AS INTEGER) * 1000 <= ?
         ORDER BY CAST(strftime('%s', s.interrupted_at) AS INTEGER) * 1000 ASC`,
      )
      .all(nowMs - windowMs) as unknown as Array<{ session_id: string; cause: string | null; agent_name: string }>;
    return rows.map((r) => ({ agentName: r.agent_name, sessionId: r.session_id, cause: r.cause }));
  }
  /**
   * DOD-M12B-RESTART-SEAL-1 / DOD-M12B-PENDING-RESOLVE-1 — sessions that need a receipt and have
   * nobody asking for one. TWO populations, one queue, each with its own safety argument.
   *
   * **(2) `seal_interrupted_pending` — a seal commitment nobody notarized.** Measured 2026-08-18 on
   * the live store: 28 sessions, aged 0.3 to 12.8 days, one of them 14 messages long, 26 holding
   * relay-witnessed seal leaves, and **not one with a sealed root**.
   *
   * **HALF OF THEM ARE NOT BILATERAL, and the first version of this comment claimed they were.**
   * Measured split: 14 initiator rows, each carrying the counterparty's signed leaf — and 14
   * responder rows with `counterparty_leaf = NULL`. A responder row is written by
   * `inbound-seal-request.ts` from an UNSIGNED `seal_interrupted_request` frame, before its ack is
   * even sent, so an ordinary send failure produces a one-sided pending row.
   *
   * So the licence is NOT "both parties signed". It is **somebody chose to end this**, on two
   * branches: an initiator row carries the counterparty's signature, and a responder row exists
   * because the counterparty sent a request to seal. And what makes the result VERIFIABLE is
   * neither — it is that the directory rebuilds the tree from relay-witnessed leaves and checks
   * their signatures, never consulting the commitment at all. The commitment is what makes it
   * legitimate to ASK. (`close-session-handler.ts` states this in full; the first draft of this
   * header contradicted it 200 lines away.) `PENDING-EXIT-1` built their exit and it works — but only when an operator runs
   * `cello_close_session` on that session by hand, having somehow deduced they should. Nothing
   * enumerated them, because both sweeps filtered `status = 'interrupted'`. An exit nobody is told
   * about is not an exit.
   *
   * `interrupted_by` is deliberately NOT consulted for that population. It answers "did WE cause
   * this, and may we therefore describe it" — and that is the wrong question once a seal was
   * requested or signed. **SI-001 is not weakened:** it forbids notarizing *"a conversation nobody
   * chose to end"*, and every row here was chosen to be ended by one side or the other. The only
   * thing missing is the request to notarize it.
   *
   * **(1) `interrupted` — sessions our own stop orphaned, and only those.** Here `interrupted_by` is
   * the whole safety argument. `'local'` means the boot sweep, the shutdown
   * sweep, or the operator's own kill switch ended this session — nobody else did, and it cannot be
   * resumed because the transport keypairs died with the process. Those are the ones the resolver
   * may seal on its own.
   *
   * Everything else is excluded and must stay excluded:
   *   'counterparty'        — they hung up. SI-001: the operator may still want to wait.
   *   'relay_stream_close'  — our relay witness link ended; the session itself may be fine.
   *   NULL                  — written before the column existed, so the cause is UNKNOWN. An
   *                           unknown cause is not a licence to notarize; it is the reason not to.
   *
   * Same INNER JOIN discipline as getSessionsByStatus: a retired agent's rows are kept for
   * accountability and are not resumable, so they are not offered for sealing either.
   */
  listRestartOrphanedSessions(): Array<{ agentName: string; sessionId: string; messageCount: number; status: "interrupted" | "seal_interrupted_pending" }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        // `message_count > 0` — a never-messaged interrupted session is a dead HANDSHAKE, which
        // `classifySession` deliberately hides in the "failed" bucket so it does not clutter
        // status. Sealing one spends a directory ceremony to obtain a receipt over nothing, and
        // then moves it into the operator's CLOSED list, making the clutter visible. The whole
        // justification for this work is "3,576 messages produced nothing" — zero messages is
        // nothing to produce.
        //
        // `restart_seal_gave_up_at IS NULL` — a session we have already exhausted. Without it a
        // machine restarting ~6 times a day re-runs five ceremonies against a hopeless session on
        // every boot, forever.
        `SELECT s.session_id AS session_id, s.message_count AS message_count, a.agent_name AS agent_name,
                s.status AS status
         FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
         WHERE a.state != 'retired'
           AND (
                 -- (1) OURS, and we can say so. SI-001 holds: an interrupted session with an
                 -- unknown cause has no signatures behind it and must not be notarized.
                 (s.status = 'interrupted' AND s.interrupted_by = 'local')
                 -- (2) A seal commitment with nobody asking for it. review F5: the EXISTS is
                 -- STRUCTURAL, not decoration. The header's licence is "a commitment was made", and
                 -- a status check alone asserts that in prose while the query checks something
                 -- else. Today status implies an artifact row by construction, which is exactly the
                 -- kind of invariant that holds until someone adds a fourth writer.
                 OR (s.status = 'seal_interrupted_pending'
                     AND EXISTS (SELECT 1 FROM seal_interrupted_artifacts sa
                                 WHERE sa.agent_id = s.agent_id AND sa.session_id = s.session_id))
               )
           AND s.message_count > 0
           AND s.restart_seal_gave_up_at IS NULL
         ORDER BY s.updated_at ASC`,
      )
      .all() as unknown as Array<{ session_id: string; message_count: number; agent_name: string; status: string }>;
    return rows.map((r) => ({
      agentName: r.agent_name,
      sessionId: r.session_id,
      messageCount: r.message_count ?? 0,
      // Carried so a give-up can say something TRUE about this session: the two populations need
      // different words, and force-abandon is right for one and destructive for the other.
      status: r.status === "seal_interrupted_pending" ? "seal_interrupted_pending" as const : "interrupted" as const,
    }));
  }
  /**
   * DOD-M12B-STRAND-1 — write one held frame to the durable store.
   *
   * LOGS LOUD, does not refuse. The caller answers `held: true` either way, and that is correct:
   * held content is never `persisted`-acked, so the sender keeps its copy and retries whether or
   * not this row lands. What a failure costs is the restart case — the frame is memory-only again,
   * exactly as it was before this unit — so it is reported at ERROR here and counted again by the
   * teardown alarm, and never allowed to look like a success.
   */
  persistHeldContent(
    agentName: string,
    sessionId: string,
    canonicalSeq: number,
    deliverContent: Uint8Array,
    originalContent: Uint8Array,
    contentHashHex: string,
    screenedOut: boolean,
    correlationId?: string,
    origin: "received" | "sent" = "received",
    leafKind: WritableSessionTreeLeafKind = "msg",
  ): void {
    if (!this.#db) return;
    try {
      // A position may legitimately be re-written by a redelivery of the SAME frame. Different
      // content at the same relay position means the relay contradicted itself, and destroying the
      // first copy silently is not an option for verified content.
      const existing = this.#db.prepare(
        "SELECT content_hash_hex FROM held_content WHERE agent_id = ? AND session_id = ? AND canonical_seq = ?",
      ).get(this.#ctx.requireAgentId(agentName), sessionId, canonicalSeq) as { content_hash_hex: string } | undefined;
      if (existing && existing.content_hash_hex !== contentHashHex) {
        this.#ctx.logger.error("session.content.held.position_conflict", {
          agentName, sessionId, canonicalSeq, correlationId,
          existingContentHash: existing.content_hash_hex, incomingContentHash: contentHashHex,
          impact: "two different frames claim one canonical position — the earlier held copy is being replaced",
        });
      }
      this.#db.prepare(
        `INSERT OR REPLACE INTO held_content
           (agent_id, session_id, canonical_seq, content_blob, original_blob, content_hash_hex, screened_out, correlation_id, held_at, origin, leaf_kind)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        this.#ctx.requireAgentId(agentName), sessionId, canonicalSeq,
        Buffer.from(deliverContent), Buffer.from(originalContent), contentHashHex,
        screenedOut ? 1 : 0, correlationId ?? null, Date.now(), origin, leafKind,
      );
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.held.persist.failed", {
        agentName, sessionId, canonicalSeq, contentHash: contentHashHex, correlationId,
        impact: "this frame is held IN MEMORY ONLY and will be destroyed if the daemon restarts",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  /**
   * DOD-M15-REFUSEDEVIDENCE-1: read retained refused messages back — all of a session's, or the one
   * at `sequence`.
   *
   * Returns the RAW payload. Every caller that hands it to a reader must frame it first
   * (`frameQuarantinedPayload`); nothing else in the tree may read this without doing so.
   */
  readQuarantined(agentName: string, sessionId: string, sequence?: number): QuarantinedRecord[] {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        `SELECT sequence, blob, created_at, sender_pubkey, sender_sig, attribution, quarantine_reason
         FROM transcript
         WHERE agent_id = ? AND session_id = ? AND direction = 'quarantined'
           ${sequence === undefined ? "" : "AND sequence = ?"}
         ORDER BY sequence ASC`,
      )
      .all(...(sequence === undefined
        ? [this.#ctx.requireAgentId(agentName), sessionId]
        : [this.#ctx.requireAgentId(agentName), sessionId, sequence])) as Array<{
          sequence: number; blob: Uint8Array; created_at: number;
          sender_pubkey: string | null; sender_sig: Uint8Array | null;
          attribution: string; quarantine_reason: string | null;
        }>;
    return rows.map((r) => ({
      sequence: r.sequence,
      /**
       * ⚠️ NOT `?? "refused"` — review F11. A generic default here is a label for a state that
       * cannot occur: the column exists before any `'quarantined'` row can be written and
       * `#quarantineRefusedContent` always supplies a reason. A default reads to the next maintainer
       * as a supported case and would quietly stand in for a real bug. If a NULL ever appears, the
       * empty reason travels to the frame and the caller, which is loud enough to chase.
       */
      reason: r.quarantine_reason as string,
      content: r.blob instanceof Uint8Array ? r.blob : new Uint8Array(r.blob),
      senderPubkeyHex: r.sender_pubkey,
      senderSig: r.sender_sig === null ? null : (r.sender_sig instanceof Uint8Array ? r.sender_sig : new Uint8Array(r.sender_sig)),
      attribution: r.attribution,
      createdAt: r.created_at,
    }));
  }
  /**
   * DOD-M12B-REVIVAL-BOUND-1 — give every timestamp-less interrupted session a clock, once.
   *
   * A row with `interrupted_at IS NULL` has no bound that can be evaluated, and skipping such rows
   * would exempt the oldest sessions in the store from the control permanently — the same "open
   * forever" failure wearing a different NULL. The two rows measured in Entry 41 are exactly this
   * shape, written by a `destroySessionNode` path that set the cause and no timestamp.
   *
   * **`WHERE interrupted_at IS NULL` is the security property, not an optimisation.** It makes the
   * stamp write-once: this can run on every sweep forever and a row's clock still cannot be moved
   * after the first one. That is what disqualifies `updated_at`, which a peer moves with every
   * message it sends into the still-accepting session.
   *
   * The cost is honest and bounded: a legacy row's window starts at the first sweep that sees it
   * rather than at its true interruption, so it survives up to one window longer than it should.
   * A late close is recoverable; a clock the counterparty winds is not.
   *
   * @returns how many rows were stamped.
   */
  stampMissingInterruptedAt(nowMs: number): number {
    if (!this.#db) return 0;
    try {
      const res = this.#db
        .prepare("UPDATE sessions SET interrupted_at = ? WHERE status = 'interrupted' AND interrupted_at IS NULL")
        .run(new Date(nowMs).toISOString()) as unknown as { changes?: number | bigint };
      const stamped = Number(res?.changes ?? 0);
      if (stamped > 0) {
        this.#ctx.logger.info("session.revival_bound.clock.stamped", {
          stamped,
          impact: "these sessions had no interruption timestamp; their revival window starts now",
        });
      }
      return stamped;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.revival_bound.clock.stamp.failed", {
        error: err instanceof Error ? err.message : String(err),
        impact: "sessions with no interruption timestamp cannot be evaluated and stay open",
      });
      return 0;
    }
  }
  /**
   * M7 legibility-TBS-binding (responder verify): record the counterparty's FROST primary (group)
   * pubkey from the FROST-signed SessionAssignment, so the responder can VERIFY the bilateral seal
   * signature locally. Best-effort — a missing row (race) is a no-op; the seal then falls back to
   * accept-without-verify (still sound: the live frame arrives over the authenticated Noise channel).
   */
  /**
   * The counterparty's threshold group key as this agent has seen it BEFORE — trust on first use.
   *
   * DOD-M15-OFFER-SIGNED-1 / RESPONDER-VERIFY-1. The responder does not verify the assignment's
   * signature (deferred to SESSION-004), so every field in it is whatever the directory said. That
   * makes a same-frame check circular: a compromised directory just says the same thing twice.
   *
   * This is the one anchor the responder holds that a directory CANNOT retroactively change — its
   * own memory of previous sessions with this counterparty. A directory that names a different
   * threshold group key for someone you have already talked to is either substituting an identity
   * or has been compromised since; neither is a session to accept quietly.
   *
   * THE BOUND, stated rather than glossed: this is worth nothing on FIRST contact, which is the
   * definition of trust-on-first-use. It hardens every session after it, which is where a long-lived
   * counterparty relationship actually lives.
   *
   * Keyed on `counterparty_pubkey` — the K_local IDENTITY, which is the stable thing — not on a
   * session id or a display name.
   */
  getPinnedCounterpartyPrimary(agentName: string, counterpartyPubkeyHex: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare(
        `SELECT counterparty_primary_pubkey FROM sessions
          WHERE agent_id = ? AND counterparty_pubkey = ? AND counterparty_primary_pubkey IS NOT NULL
          ORDER BY updated_at DESC LIMIT 1`,
      )
      .get(this.#ctx.requireAgentId(agentName), counterpartyPubkeyHex) as
      | { counterparty_primary_pubkey: string }
      | undefined;
    return row?.counterparty_primary_pubkey ?? null;
  }
  /**
   * M7-SESSION-001 (H-1): read back the persisted bilateral commitment artifacts
   * for a session. Returns null when none exist.
   */
  /**
   * M12-P17: durably record verified content that arrived for an ALREADY-ENDED session.
   *
   * Returns true only when the row is committed — the caller confirm-deletes the relay copy on the
   * strength of this answer, and the ORDER is load-bearing: annex first, delete second. A crash
   * between them must lose nothing, so a failure here MUST report false and leave the relay copy
   * alone. Getting that backwards converts a noisy re-pull loop into permanent silent loss, which is
   * the outcome this whole unit exists to prevent.
   */
  recordSealedAnnex(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, senderPubkeyHex: string | null): boolean {
    if (!this.#db) return false;
    try {
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO sealed_session_annex (agent_id, content_hash, session_id, sender_pubkey, content, arrived_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(this.#ctx.requireAgentId(agentName), contentHashHex, sessionId, senderPubkeyHex, Buffer.from(content), Date.now());
      return true;
    } catch (err: unknown) {
      // FAILS LOUD and reports false: the relay copy is the only other one in existence.
      this.#ctx.logger.error("content.annex.write.failed", {
        agentName, sessionId, contentHash: contentHashHex,
        impact: "content NOT annexed — the relay copy must be kept, or the message is lost",
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }
  /**
   * DOD-COATTEND-1 (review F5) — the single next RECEIVED message after `afterSeq`, or null.
   *
   * The delivery path asks this question inside a 20 ms poll, so it is asked ~47 times a second per
   * blocked connection — ~1,400 times over a default 30 s receive. Answering it with
   * `readTranscript()` meant, every single time: SELECT every row of the session with no predicate
   * and no limit, `TextDecoder().decode()` every blob in it, build the array, then `.find()` one
   * row and discard the rest. On a 200-message session with three co-attending connections blocking
   * — which is the M8D use case, not a worst case — that is tens of thousands of blob decodes per
   * second on the daemon's single synchronous SQLCipher handle, contending with the write path.
   *
   * The predicate belongs in SQL. This is O(1) on the existing (agent_id, session_id, sequence)
   * key and decodes exactly the one blob it returns.
   */
  findNextReceivedAfter(
    agentName: string,
    sessionId: string,
    afterSeq: number,
  ): { sequence: number; text: string } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare(
        `SELECT sequence, blob FROM transcript
         WHERE agent_id = ? AND session_id = ? AND direction = 'received' AND sequence > ?
         ORDER BY sequence ASC LIMIT 1`,
      )
      .get(this.#ctx.requireAgentId(agentName), sessionId, afterSeq) as { sequence: number; blob: Uint8Array } | undefined;
    if (!row) return null;
    const blob = row.blob instanceof Uint8Array ? row.blob : new Uint8Array(row.blob);
    return { sequence: row.sequence, text: new TextDecoder().decode(blob) };
  }
  getSealInterruptedArtifacts(agentName: string, sessionId: string): {
    role: string;
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM seal_interrupted_artifacts WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as
      | {
          role: string;
          own_leaf: string;
          counterparty_leaf: string;
          merkle_root: string;
          nonce: string;
        }
      | undefined;
    if (!row) return null;
    return {
      role: row.role,
      ownLeaf: JSON.parse(row.own_leaf),
      counterpartyLeaf: JSON.parse(row.counterparty_leaf),
      merkleRoot: row.merkle_root,
      nonce: row.nonce,
    };
  }
  /**
   * Return all sessions with a given status from SQLite.
   * Used by cello status to surface interrupted sessions.
   */
  getSessionsByStatus(status: "active" | "sealed" | "interrupted"): SessionRecord[] {
    if (!this.#db) return [];
    // Spans EVERY agent (cello_status is daemon-wide), so no single name can be resolved up front —
    // the display name is joined in from `agents`, its one source of truth. `agent_name` is no
    // longer a `sessions` column, so without this join buildActiveSessions/buildInterruptedSessions
    // read `row.agent_name` as undefined.
    //
    // DOD-AGENT-ID-JOINKEY-1 (reviewer Finding 1): INNER JOIN with `state != 'retired'`, NOT a bare
    // LEFT JOIN. This is the LIVE-status + reaper surface, and a retired agent is gone from the
    // runtime — its leftover session rows (kept for accountability, never re-statused) are not
    // resumable and must not appear here. If they did, the half-open reaper would resolve their
    // RETIRED name via #requireAgentId, which throws, taking down cello_status for the whole daemon.
    // Excluding them also guarantees a non-null agent_name on every returned row. The full historical
    // archive (getAllSessions) keeps its LEFT JOIN and still shows retired/orphaned rows.
    return this.#db
      .prepare(
        `SELECT s.*, a.agent_name AS agent_name
         FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
         WHERE s.status = ? AND a.state != 'retired'`,
      )
      .all(status) as unknown as SessionRecord[];
  }
  loadTreeFromDb(agentName: string, sessionId: string): SessionTree {
    if (!this.#db) return SessionTree.empty();
    const rows = this.#db
      .prepare(
        "SELECT leaf_kind, leaf_hash_hex FROM session_tree_leaves WHERE agent_id = ? AND session_id = ? ORDER BY leaf_index ASC",
      )
      .all(this.#ctx.requireAgentId(agentName), sessionId) as Array<{ leaf_kind: string; leaf_hash_hex: string }>;
    return SessionTree.fromLeaves(
      rows.map((r, leafIndex) => {
        const kind = sessionTreeLeafKindFromDb(r.leaf_kind);
        if (kind === "unknown") {
          // A leaf kind written by a newer build. The tree stays intact and sealable (the
          // stored hash carries its own domain), but an operator must be able to see that
          // this daemon is behind the one that wrote the row.
          this.#ctx.logger.error("session.tree.leaf_kind.unrecognized", {
            agentName,
            sessionId,
            leafIndex,
            value: r.leaf_kind,
          });
        }
        return { kind, hashHex: r.leaf_hash_hex };
      }),
    );
  }
  /**
   * M12-P18: record that this agent refused a session, so parked content that later arrives for it
   * (and fails `counterparty_unknown`, because no session row exists) can be swept instead of
   * re-pulled forever. Keeps the most recent REFUSED_SESSIONS_CAP per agent.
   */
  recordRefusedSession(agentName: string, sessionId: string, reason: string): void {
    if (!this.#db) return;
    const agentId = this.#ctx.requireAgentId(agentName);
    try {
      this.#db.prepare(
        `INSERT OR REPLACE INTO refused_sessions (agent_id, session_id, reason, refused_at) VALUES (?, ?, ?, ?)`,
      ).run(agentId, sessionId, reason, Date.now());
      // Prune to the cap — oldest first.
      this.#db.prepare(
        `DELETE FROM refused_sessions WHERE agent_id = ? AND session_id NOT IN (
           SELECT session_id FROM refused_sessions WHERE agent_id = ? ORDER BY refused_at DESC LIMIT ${REFUSED_SESSIONS_CAP}
         )`,
      ).run(agentId, agentId);
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.refused.record.failed", {
        agentName, sessionId, error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  /**
   * DOD-MSG-4 (auto-recover): the DISTINCT relay endpoints this agent has sessions on, so the daemon
   * can pull the agent's parked mailbox from each on reconnect (the relay mailbox is keyed by recipient
   * pubkey, so one pull per relay drains all of the agent's parked content there). Distinct by relay
   * peer id.
   */
  getAgentRelayEndpoints(agentName: string): Array<{ relayPeerId: string; relayAddrs: string[] }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare("SELECT DISTINCT relay_peer_id, relay_addrs FROM sessions WHERE agent_id = ? AND relay_peer_id IS NOT NULL")
      .all(this.#ctx.requireAgentId(agentName)) as Array<{ relay_peer_id?: string | null; relay_addrs?: string | null }>;
    const byPeer = new Map<string, { relayPeerId: string; relayAddrs: string[] }>();
    for (const row of rows) {
      if (!row.relay_peer_id || !row.relay_addrs) continue;
      try {
        const addrs = JSON.parse(row.relay_addrs) as unknown;
        if (!Array.isArray(addrs) || addrs.length === 0) continue;
        if (!byPeer.has(row.relay_peer_id)) byPeer.set(row.relay_peer_id, { relayPeerId: row.relay_peer_id, relayAddrs: addrs as string[] });
      } catch {
        /* skip malformed */
      }
    }
    return [...byPeer.values()];
  }
  /** M8C-ABUSE-1 (anti-swarm) + DOD-TIER-2: non-terminal sessions this agent holds with UNKNOWN-tier
   *  counterparties — the global cap counts across the whole stranger pool. A sender is exempt from
   *  THIS pool iff it is a KNOWN+ contact (tier >= KNOWN); a bare stranger (no row → UNKNOWN) or an
   *  explicitly UNKNOWN-tier contact both count. Keying on `tier >= KNOWN` (bounded to <= VIP so a
   *  corrupt high value cannot grant pool-exemption) replaces the old row-existence proxy, which
   *  would have let a merely-recorded UNKNOWN contact escape the anti-swarm cap. Same
   *  'interrupted'-status fix as countActiveSessionsForCounterparty above. */
  countActiveSessionsFromUnknownSenders(agentName: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS n FROM sessions s
         WHERE s.agent_id = ?
           AND ${CAP_COUNTS("s")}
           AND NOT EXISTS (
             SELECT 1 FROM contacts c
             WHERE c.agent_id = s.agent_id AND c.pubkey = s.counterparty_pubkey
               AND c.tier >= ${TIER.KNOWN} AND c.tier <= ${TIER.VIP}
           )`,
      )
      .get(this.#ctx.requireAgentId(agentName), capStaleBefore()) as { n: number };
    return row.n;
  }
  /**
   * M7-SESSION-004 (AC-005/AC-006): read the persisted seal certificate for a session.
   * Returns the sealed root and the parsed legibility object (JSON-safe, hex pubkeys), or
   * null if the session is unknown or not yet sealed. This is the cert-read surface a
   * reader (operator, agent, arbitrator) — possibly in a DIFFERENT process than the one
   * that built the certificate — uses to determine receipt-not-assent, per-party frontiers,
   * attestation modes, and whether the final message was answered.
   */
  getSealCertificate(agentName: string, sessionId: string): { sealed_root: string; legibility: unknown } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT sealed_root_hex, seal_legibility FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { sealed_root_hex?: string | null; seal_legibility?: string | null } | undefined;
    if (!row || !row.seal_legibility || !row.sealed_root_hex) return null;
    let legibility: unknown;
    try {
      legibility = JSON.parse(row.seal_legibility);
    } catch {
      return null;
    }
    return { sealed_root: row.sealed_root_hex, legibility };
  }
  /**
   * M8C-ABUSE-1: cumulative inbound byte total for a session (anti-drip-feed accounting).
   *
   * ⚠️ DOD-M15-REFUSEDEVIDENCE-1 — QUARANTINED BYTES COUNT, and the bound depends on it.
   *
   * Retaining refused messages puts real bytes on the operator's disk. Left out of this sum,
   * retention would be an UNBOUNDED SIDE CHANNEL: a counterparty who can get messages refused —
   * anyone who can trip the screener, which is anyone — stores against a budget that cannot see
   * what they spent. Counting them makes total retention per session bounded by the same tier cap
   * that bounds delivery, which is the bound the unit's no-truncation rule rests on.
   *
   * No new capability reaches an attacker from this: the counterparty already spends the session's
   * byte budget by sending ordinary messages. Spending it with refused ones costs them the same.
   */
  getReceivedBytesTotal(agentName: string, sessionId: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare("SELECT COALESCE(SUM(LENGTH(blob)), 0) AS total FROM transcript WHERE agent_id = ? AND session_id = ? AND direction IN ('received','quarantined')")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { total: number };
    return row.total;
  }
  ownPubkeyHex(agentName: string): string | null {
    if (!this.#db) return null;
    try {
      // BY agent_id, never by agent_name. The name is a mutable, reuse-freed display label, and
      // scoping on it hands one identity's rows to another keypair (DOD-AGENT-ID-JOINKEY-1).
      const row = this.#db
        .prepare("SELECT k_local_pubkey FROM agents WHERE agent_id = ?")
        .get(this.#ctx.requireAgentId(agentName)) as { k_local_pubkey: string } | undefined;
      return row?.k_local_pubkey ?? null;
    } catch (err: unknown) {
      // An unattributed annex row is truthful; an unattributed row nobody knows about is not. This
      // throws for a retired agent, and without a line here EVERY own held message would land in
      // the record that outlives the session with no sender and no explanation.
      this.#ctx.logger.warn("session.own_pubkey.unresolved", {
        agentName,
        error: err instanceof Error ? err.message : String(err),
        impact: "this agent's own held content will be annexed without a sender",
      });
      return null;
    }
  }
  /**
   * DOD-SESSION-NAME-1: set (string) or clear (null) THIS agent's name for a session.
   *
   * Returns false when the (agent_id, session_id) row does not exist — i.e. the session is not this
   * agent's — so the caller refuses with session_not_found rather than reporting a silent success on
   * a write that landed nowhere. Same contract as setContactMoniker.
   *
   * Ownership is the ONLY scope: the composite key IS the ownership check, and status is deliberately
   * not consulted. A sealed session can be named — naming one long after the fact is the point — and
   * a name is a local column, so writing it cannot touch the seal, a Merkle leaf, or the wire.
   *
   * The caller validates (validateSessionName) before calling; this stores what it is given.
   */
  setSessionName(agentName: string, sessionId: string, sessionName: string | null): boolean {
    if (!this.#db) throw new Error(`setSessionName('${agentName}'): database not initialized`);
    const res = this.#db
      .prepare("UPDATE sessions SET session_name = ? WHERE agent_id = ? AND session_id = ?")
      .run(sessionName, this.#ctx.requireAgentId(agentName), sessionId);
    return res.changes > 0;
  }
  /** DOD-M12B-ABANDON-NOTIFY-1 — durable "they hung up" marker. Not a status: the session stays
   *  sealable, which is the whole point of not making this terminal. */
  markCounterpartyAbandoned(agentName: string, sessionId: string): boolean {
    if (!this.#db) return false;
    try {
      const res = this.#db
        .prepare("UPDATE sessions SET counterparty_abandoned_at = ?, updated_at = ? WHERE agent_id = ? AND session_id = ? AND counterparty_abandoned_at IS NULL")
        .run(Date.now(), Date.now(), this.#ctx.requireAgentId(agentName), sessionId) as unknown as { changes?: number | bigint };
      // No rows changed means it was already marked — a duplicated notice, which must not
      // re-announce. "Did not throw" is not "landed"; the row count is the answer.
      return Number(res?.changes ?? 0) > 0;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.counterparty.abandoned.write.failed", {
        agentName, sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact: "this side will go on trying to reach a counterparty that has hung up",
      });
      return false;
    }
  }
  /**
   * MSG-2 startup-flush: the persisted relay endpoint for a session, or null if none was
   * recorded. Used by the crash-backstop flush, which runs at startup BEFORE the in-memory
   * session entries exist, so it cannot use `entry.relayPeerId`.
   */
  getPersistedRelayEndpoint(agentName: string, sessionId: string): { relayPeerId: string; relayAddrs: string[] } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT relay_peer_id, relay_addrs FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { relay_peer_id?: string | null; relay_addrs?: string | null } | undefined;
    if (!row?.relay_peer_id || !row?.relay_addrs) return null;
    try {
      const addrs = JSON.parse(row.relay_addrs) as unknown;
      if (!Array.isArray(addrs) || addrs.length === 0) return null;
      return { relayPeerId: row.relay_peer_id, relayAddrs: addrs as string[] };
    } catch {
      return null;
    }
  }
  /** Best-effort: a failure to record WHY must never be the thing that breaks a seal. */
  noteCertifiedLeafState(agentName: string, sessionId: string, state: string, detail: string | null): void {
    if (!this.#db) return;
    try {
      this.#db
        .prepare(
          `INSERT OR REPLACE INTO session_certified_leaves_state
             (agent_id, session_id, state, detail, recorded_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .run(this.#ctx.requireAgentId(agentName), sessionId, state, detail, Date.now());
    } catch (err: unknown) {
      this.#ctx.logger.warn("seal.certified_leaves.state.write.failed", {
        agentName, sessionId, state, reason: extractErrorMessage(err),
        impact: "the inclusion-proof surface will not be able to name WHY this session has no certified leaf set; it still refuses rather than proving anything",
      });
    }
  }
  /**
   * DOD-M12B-RESTART-SEAL-1 — record that automatic sealing has exhausted this session.
   *
   * Durable on purpose. The resolver's attempt budget is in memory, so without this the budget
   * resets on every boot and a session that can never seal costs five directory ceremonies a day
   * for the life of the machine.
   *
   * IT IS NOT A DEAD END FOR THE OPERATOR. The row keeps status `interrupted`, so a manual
   * `cello_close_session` still works on it and — since DOD-M12B-INTERRUPTED-ESCALATE-1 — still
   * escalates to a unilateral seal. This column only withdraws the session from AUTOMATIC retries.
   */
  markRestartSealGaveUp(agentName: string, sessionId: string, reason: string): void {
    if (!this.#db) return;
    this.#db
      .prepare("UPDATE sessions SET restart_seal_gave_up_at = ?, restart_seal_gave_up_reason = ? WHERE agent_id = ? AND session_id = ?")
      .run(Date.now(), reason, this.#ctx.requireAgentId(agentName), sessionId);
  }
  /** DOD-SEALED-INBOX-1: mark a terminal session as dismissed — sets read_at to now.
   *  Only valid for terminal sessions; active/interrupted sessions return session_not_terminal. */
  dismissSession(agentName: string, sessionId: string): { ok: true } | { ok: false; reason: string } {
    if (!this.#db) return { ok: false, reason: "db_not_open" };
    const agentId = this.#ctx.requireAgentId(agentName);
    const row = this.#db
      .prepare("SELECT status FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(agentId, sessionId) as { status: string } | undefined;
    if (!row) return { ok: false, reason: "session_not_found" };
    const terminal = ["sealed", "abandoned", "seal_interrupted_pending", "interrupted"];
    if (!terminal.includes(row.status)) return { ok: false, reason: "session_not_terminal" };
    this.#db
      .prepare("UPDATE sessions SET read_at = ? WHERE agent_id = ? AND session_id = ?")
      .run(Date.now(), agentId, sessionId);
    return { ok: true };
  }
  /**
   * Reverse lookup: the display name of a stable agent_id, or null if no such agent.
   *
   * Deliberately INCLUDES retired agents. Its caller (the startup awaiting-content re-park) holds an
   * agent_id read off a durable row and needs a name to find that agent's standing receiver. A
   * retired agent resolves to its name and then has no standing receiver, so the park fails cleanly
   * and loudly — which is correct. Filtering retired agents out here would instead make the row
   * unattributable and the failure mute.
   */
  agentNameForId(agentId: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT agent_name FROM agents WHERE agent_id = ?")
      .get(agentId) as { agent_name: string } | undefined;
    return row?.agent_name ?? null;
  }
  /** DOD-M12B-SEAL-STUCK-1 — how long the oldest held frame for this session has been waiting, or
   *  null when nothing is held. This is what separates "stuck since this morning" from "in flight
   *  40 ms ago", and without it a healthy mid-conversation window reads as a stranded session. */
  oldestHeldMs(agentName: string, sessionId: string): number | null {
    if (!this.#db) return null;
    try {
      const row = this.#db.prepare(
        "SELECT MIN(held_at) AS oldest FROM held_content WHERE agent_id = ? AND session_id = ?",
      ).get(this.#ctx.requireAgentId(agentName), sessionId) as { oldest: number | null } | undefined;
      if (!row || row.oldest === null) return null;
      return Date.now() - row.oldest;
    } catch {
      // A diagnostic detail must not be able to break the surface it decorates.
      return null;
    }
  }
  /** DOD-M12B-STRAND-1 — drop one held frame from the durable store, on release or on a refusal
   *  that supersedes it. A row that outlives its release re-appends on the next boot. */
  deleteHeldContent(agentName: string, sessionId: string, canonicalSeq: number): void {
    if (!this.#db) return;
    try {
      this.#db.prepare(
        "DELETE FROM held_content WHERE agent_id = ? AND session_id = ? AND canonical_seq = ?",
      ).run(this.#ctx.requireAgentId(agentName), sessionId, canonicalSeq);
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.held.delete.failed", {
        agentName, sessionId, canonicalSeq,
        impact: "the released frame's durable row survives and will be re-appended on the next boot",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  /** DOD-RENAME-1: pending rename notices for an agent, oldest first (surfaced in
   *  cello_check_notifications — an INBOX pull, never a real-time push). */
  getRenameNotices(agentName: string): Array<{ pubkey: string; offered_name: string; noticed_at: number; moniker: string | null }> {
    if (!this.#db) return [];
    // JOIN the local pet name so the notice can NAME the contact (AC3) — a notice only ever fires for
    // a personally-named contact, so moniker is expected non-null (LEFT JOIN is defensive).
    return this.#db
      .prepare(
        `SELECT n.pubkey, n.offered_name, n.noticed_at, c.moniker
         FROM contact_rename_notices n
         LEFT JOIN contacts c ON c.agent_id = n.agent_id AND c.pubkey = n.pubkey
         WHERE n.agent_id = ? ORDER BY n.noticed_at ASC`,
      )
      .all(this.#ctx.requireAgentId(agentName)) as Array<{ pubkey: string; offered_name: string; noticed_at: number; moniker: string | null }>;
  }
  /**
   * The certified leaf set, in order, or null when none was stored for this session.
   *
   * Null is a REFUSAL upstream, never a fallback to the local tree: the two cover different leaves
   * and substituting one for the other is how a proof comes to land on a root nobody signed.
   */
  getCertifiedLeafSet(agentName: string, sessionId: string): string[] | null {
    if (!this.#db) return null;
    const rows = this.#db
      .prepare(
        "SELECT content_hash_hex FROM session_certified_leaves WHERE agent_id = ? AND session_id = ? ORDER BY leaf_index ASC",
      )
      .all(this.#ctx.requireAgentId(agentName), sessionId) as Array<{ content_hash_hex: string }>;
    return rows.length > 0 ? rows.map((r) => r.content_hash_hex) : null;
  }
  /** DOD-CAP-SELF-HEAL-1: the sessions with this counterparty that are consuming cap slots, oldest
   *  first. The operator is told to close some — this is WHICH, because "close three of them" with
   *  no list is not an instruction they can follow. */
  sessionsConsumingCap(agentName: string, counterpartyPubkey: string, limit = 10): string[] {
    if (!this.#db) return [];
    try {
      const rows = this.#db.prepare(
        `SELECT session_id FROM sessions WHERE agent_id = ? AND counterparty_pubkey = ? AND ${CAP_COUNTS()}
         ORDER BY updated_at ASC LIMIT ?`,
      ).all(this.#ctx.requireAgentId(agentName), counterpartyPubkey, capStaleBefore(), limit) as Array<{ session_id: string }>;
      return rows.map((r) => r.session_id);
    } catch {
      return [];
    }
  }
  /** Advance the read watermark (delivery marks read). MONOTONIC — never lowers, so a replayed or
   *  out-of-order cello_receive cannot un-read already-read messages. */
  advanceLastDeliveredSeq(agentName: string, sessionId: string, seq: number): void {
    if (!this.#db) return;
    this.#db
      .prepare(
        `INSERT INTO message_watermarks (agent_id, session_id, last_delivered_seq)
         VALUES (?, ?, ?)
         ON CONFLICT(agent_id, session_id)
         DO UPDATE SET last_delivered_seq = MAX(last_delivered_seq, excluded.last_delivered_seq)`,
      )
      .run(this.#ctx.requireAgentId(agentName), sessionId, seq);
    this.#ctx.logger.info("message.watermark.advanced", { agentName, sessionId, sequence: seq });
  }
  /** M8C-ABUSE-1: non-terminal sessions this agent currently holds with the given counterparty.
   *  Reviewer HIGH fix (aeffb82f, D18): counting `status = 'active'` ONLY let a counterparty
   *  evade the bound for free by disconnecting (a trivial, attacker-controlled action that flips
   *  a session to 'interrupted' — markInterruptedWithDetails) and opening a fresh session,
   *  repeated indefinitely. 'interrupted' sessions still accept content (ingestReceivedContent
   *  explicitly allows both statuses) and are NOT terminal (sealed/seal_interrupted_pending are),
   *  so they must still count against the bound. */
  countActiveSessionsForCounterparty(agentName: string, counterpartyPubkey: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare(CAP_COUNT_SQL("agent_id = ? AND counterparty_pubkey = ?"))
      .get(this.#ctx.requireAgentId(agentName), counterpartyPubkey, capStaleBefore()) as { n: number };
    return row.n;
  }
  /**
   * The last thing that happened to this session's certified leaf set, or null if nothing has.
   *
   * Null here and a null from `getCertifiedLeafSet` together mean "no seal has been processed on
   * this side yet" — which is a different sentence again from any of the recorded states.
   */
  getCertifiedLeafSetState(agentName: string, sessionId: string): { state: string; detail: string | null } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT state, detail FROM session_certified_leaves_state WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { state: string; detail: string | null } | undefined;
    return row ? { state: row.state, detail: row.detail } : null;
  }
  /**
   * Return the session record for a specific sessionId, regardless of status.
   * Used by cello_close_session to inspect session state.
   */
  getSessionRecord(agentName: string, sessionId: string): SessionRecord | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as unknown as SessionRecord | undefined;
    // `agent_name` is display-only and no longer stored on the row; stamp back the name whose
    // agent_id scoped this lookup (~50 daemon call sites read `record.agent_name`).
    return row ? { ...row, agent_name: agentName } : null;
  }
  evictOldestReads(agentId: string, sessionId: string, reason: string): void {
    if (!this.#db) return;
    this.#db
      .prepare(
        `DELETE FROM content_refusal_reads
          WHERE agent_id = ? AND session_id = ? AND reason = ? AND consumer_id NOT IN (
            SELECT consumer_id FROM content_refusal_reads
             WHERE agent_id = ? AND session_id = ? AND reason = ?
             ORDER BY seen_at DESC LIMIT ${MAX_REFUSAL_READERS}
          )`,
      )
      .run(agentId, sessionId, reason, agentId, sessionId, reason);
  }
  /**
   * DOD-M15-RELAYONLY-1: is the settings store readable RIGHT NOW?
   *
   * ⚠️ Exists because `getSetting` cannot answer it. That method returns `null` for BOTH "the key is
   * unset" and "there is no database", and a security setting must tell those apart: unset-means-off
   * is correct, db-gone-means-off publishes the operator's real address during the shutdown window.
   * `getDb()` cannot stand in either — it THROWS when there is no database, which on a catch-less
   * ceremony path is worse than the wrong answer.
   */
  hasDatabase(): boolean {
    return this.#db !== null;
  }
  /** M12-P17: read the annex. Operator-initiated ONLY — never wired to a wake path or inbox count. */
  readSealedAnnex(agentName: string, sessionId?: string): Array<{ session_id: string; content_hash: string; sender_pubkey: string | null; text: string; arrived_at: number }> {
    if (!this.#db) return [];
    const rows = (sessionId === undefined
      ? this.#db.prepare("SELECT session_id, content_hash, sender_pubkey, content, arrived_at FROM sealed_session_annex WHERE agent_id = ? ORDER BY arrived_at ASC").all(this.#ctx.requireAgentId(agentName))
      : this.#db.prepare("SELECT session_id, content_hash, sender_pubkey, content, arrived_at FROM sealed_session_annex WHERE agent_id = ? AND session_id = ? ORDER BY arrived_at ASC").all(this.#ctx.requireAgentId(agentName), sessionId)
    ) as Array<{ session_id: string; content_hash: string; sender_pubkey: string | null; content: Buffer; arrived_at: number }>;
    return rows.map((r) => ({
      session_id: r.session_id, content_hash: r.content_hash, sender_pubkey: r.sender_pubkey,
      text: new TextDecoder().decode(new Uint8Array(r.content)), arrived_at: r.arrived_at,
    }));
  }
  /** DOD-M12B-ABANDON-NOTIFY-1: has the counterparty told us they hung up? */
  counterpartyAbandonedAt(agentName: string, sessionId: string): number | null {
    if (!this.#db) return null;
    try {
      const row = this.#db
        .prepare("SELECT counterparty_abandoned_at FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#ctx.requireAgentId(agentName), sessionId) as { counterparty_abandoned_at: number | null } | undefined;
      return row?.counterparty_abandoned_at ?? null;
    } catch {
      return null;
    }
  }
  /**
   * F1-b: the durable sealed root hex for a session (written by recordSealCertificate on the
   * bilateral path), or null if not recorded. Lets cello_receive echo the sealed root in its
   * terminal answer without threading it through destroySessionNode.
   */
  getSealedRootHex(agentName: string, sessionId: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT sealed_root_hex FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { sealed_root_hex?: string | null } | undefined;
    return row?.sealed_root_hex ?? null;
  }
  /** The highest RECEIVED transcript sequence delivered to the operator for (agent, session).
   *  -1 when nothing has been delivered yet (so a seq-0 message reads as unread). */
  getLastDeliveredSeq(agentName: string, sessionId: string): number {
    if (!this.#db) return -1;
    const row = this.#db
      .prepare("SELECT last_delivered_seq FROM message_watermarks WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { last_delivered_seq: number } | undefined;
    return row ? row.last_delivered_seq : -1;
  }
  /** DOD-CAP-SELF-HEAL-1 test seam: the shutdown sweep's effect, without a shutdown. Mirrors the
   *  real UPDATE at gracefulShutdown so a test cannot pass against a label production never sets. */
  markSessionsInterruptedByLocalShutdownForTest(): void {
    // SCOPED TO UNLABELLED ROWS. Unscoped, this would relabel rows already marked
    // `counterparty` — one call excusing every interruption every attacker ever caused, on every
    // agent. Production never relabels; nor does this.
    this.#db?.prepare("UPDATE sessions SET interrupted_by = 'local' WHERE status = 'interrupted' AND interrupted_by IS NULL").run();
  }
  /** M12-P18: did this agent refuse this session? Consulted at drain to sweep orphaned parked content. */
  wasSessionRefused(agentName: string, sessionId: string): boolean {
    if (!this.#db) return false;
    const row = this.#db
      .prepare("SELECT 1 AS present FROM refused_sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { present: number } | undefined;
    return row !== undefined;
  }
  countReceivedMessages(agentName: string, sessionId: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare("SELECT COUNT(*) AS n FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'received'")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { n: number };
    return row.n;
  }
  /** DOD-CAP-SELF-HEAL-1 test seam: the counterparty's stream closing, without a real peer. */
  markInterruptedByCounterpartyForTest(agentName: string, sessionId: string): void {
    this.#db?.prepare(
      "UPDATE sessions SET interrupted_by = 'counterparty' WHERE agent_id = ? AND session_id = ?",
    ).run(this.#ctx.requireAgentId(agentName), sessionId);
  }
  recordSealCertificate(agentName: string, sessionId: string, sealedRootHex: string, legibilityJson: string): void {
    if (!this.#db) return;
    this.#db
      .prepare("UPDATE sessions SET seal_legibility = ?, sealed_root_hex = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
      .run(legibilityJson, sealedRootHex, Date.now(), this.#ctx.requireAgentId(agentName), sessionId);
  }
  recordCounterpartyPrimary(agentName: string, sessionId: string, primaryPubkeyHex: string): void {
    if (!this.#db) return;
    this.#db
      .prepare("UPDATE sessions SET counterparty_primary_pubkey = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
      .run(primaryPubkeyHex, Date.now(), this.#ctx.requireAgentId(agentName), sessionId);
  }
}
