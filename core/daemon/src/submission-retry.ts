/**
 * DOD-M15-ENDORSE-RETRY-1 — a sealed submission survives the directory node going away.
 *
 * An operator mints a trust signal, the one directory node this daemon holds a signaling stream to
 * is down or restarting, and the command fails and it is over: nothing queues the submission,
 * nothing retries it, and the operator has to notice and run it again. The consortium has three
 * nodes, and surviving one of them being unavailable is the entire reason there are three.
 *
 * THIS IS THE RETRY, NOT THE ROUTING, AND THAT DISTINCTION IS RULED. `sendSealedSubmission` says so
 * in its own header: the daemon holds ONE signaling stream, registration already works this way
 * (the client sends to the connected node and the DIRECTORY fans out), and inventing a client-side
 * multi-node write here would duplicate the SignalingManager's reconnect. So the failover mechanism
 * is that existing reconnect — this module never chooses a node, never holds an endpoint, and never
 * learns which node answered. It waits to be told the stream is up again and sends the same bytes.
 *
 * WHY A RETRY IS SAFE, and it is the load-bearing fact for the whole design: `submission_id` is
 * sha256 of the SIGNED PLAINTEXT body, so the same submission produces the same id however many
 * times it is sent. A node stores it once (`ON CONFLICT DO NOTHING` on the id) and the portal mints
 * once (`processed_submissions`, checked before the mint path). Nothing here may ever re-COMPOSE a
 * submission: the sealed bytes are captured at compose time and re-sent verbatim, because a re-seal
 * is randomised and a re-compose could pick up a different `issued_at` — which changes the id, and
 * a changed id is a second endorsement rather than a retry.
 *
 * SERIAL AND STAGGERED, on the `RestartSealResolver`'s pattern, and one of its lessons is carried
 * over wholesale: a refusal that is a precondition OF OURS is not a verdict on the submission, so it
 * must not spend the attempt budget. There the population was `standing_receiver_unavailable` on a
 * fresh boot; here it is a signaling stream that is reconnecting. Production turns that stream over
 * roughly every 70 seconds, so charging each reconnect an attempt would burn a five-attempt budget
 * in six minutes and give up on a submission whose only problem was that the network moved.
 *
 * IN MEMORY, FOR THE LIFE OF THE PROCESS, and stated rather than implied. The queue holds sealed
 * ciphertext, and persisting it would mean a new table, a client-side migration, and a blob at rest
 * whose retention outlives the intake key it is sealed to. A daemon restart therefore loses the
 * pending retries — the operator sees them disappear from `cello_attestations_issued` rather than
 * seeing a lie, and re-submitting is safe by the same content-derived id. The retry window below is
 * far shorter than any manifest validity window, so a queued blob cannot outlive the intake key it
 * was sealed to.
 */
import type { SubmissionOp } from "@cello-protocol/protocol-types";
import type { SendSubmissionResult, SubmissionSendFailure } from "./signal-submission.js";
import type { Logger } from "./types.js";

/**
 * Send failures worth retrying — the ones that are NOT a verdict on the submission.
 *
 *   directory_unreachable / signaling_reconnecting / signaling_lost
 *       Nothing reached anybody. This is the case the unit exists for.
 *   submission_unsupported_by_node
 *       The node never decoded the frame. Nodes deploy independently per region, so the reconnect
 *       this rides may land on one that has the frame kind — which IS the failover case. It is not
 *       a decision about the submission; the node did not get far enough to make one.
 *   submission_write_timeout
 *       The transport handed the frame over and no ack came back. Storage is UNKNOWN, which is
 *       different from refused: re-sending is safe by the content-derived id, so the honest move is
 *       to try again rather than to report a failure the operator cannot resolve either.
 *
 *   submission_refused_by_node
 *       The node decoded it, evaluated it and said no. A retry cannot change that answer, and a
 *       machine asking again is badgering a node that has already decided.
 *   submission_agent_unloaded
 *       Retry-path only, and terminal: nobody on this daemon can sign as the submitting agent any
 *       more, so no amount of waiting produces a sender.
 *
 * A `Record`, NOT a hand-written list, and that is the whole point (review §4). A list is a loop
 * over what the author typed; adding a seventh member to `SubmissionSendFailure` left the old test
 * green while the new member defaulted into "not retried" in silence. A total record fails to
 * COMPILE until someone decides — and it lives here rather than in a test, because
 * `core/daemon/tsconfig.json` excludes `src/__tests__`, so a compile-time pin there is never
 * evaluated and asserts nothing (`signal-submission.ts` calls that "a hollow test wearing
 * compile-time clothing").
 */
const RETRY_DECISION: Readonly<Record<SubmissionSendFailure, boolean>> = {
  directory_unreachable: true,
  signaling_reconnecting: true,
  signaling_lost: true,
  submission_unsupported_by_node: true,
  submission_write_timeout: true,
  submission_refused_by_node: false,
  submission_agent_unloaded: false,
};

const RETRYABLE_SEND_FAILURES: ReadonlySet<SubmissionSendFailure> = new Set(
  (Object.keys(RETRY_DECISION) as SubmissionSendFailure[]).filter((r) => RETRY_DECISION[r]),
);

/**
 * Failures that say something about OUR local preconditions rather than about the submission.
 *
 * These retry on the same backoff but do NOT consume the attempt budget — they are bounded by the
 * retry WINDOW instead, so a genuinely dead network still stops eventually. Straight from
 * `restart-seal-resolver.ts`'s `LOCAL_PRECONDITION_REFUSALS`, for the same reason: without it a
 * flapping stream durably gives up on work that was never in question.
 */
const LOCAL_PRECONDITION_FAILURES: ReadonlySet<SubmissionSendFailure> = new Set<SubmissionSendFailure>([
  "directory_unreachable",
  "signaling_reconnecting",
  "signaling_lost",
]);

export function isRetryableSendFailure(reason: SubmissionSendFailure): boolean {
  return RETRYABLE_SEND_FAILURES.has(reason);
}

/**
 * Why a retry stopped. FOUR names, because they lead to four different operator actions and this is
 * the field a machine consumer branches on.
 *
 * `refused_by_node` and `agent_unloaded` exist because of review H3: a refusal arriving on retry
 * attempt 1 used to be stamped `attempts_exhausted` with `attempts: 0` printed beside it. The
 * node's own words survived in `guidance`, but EVERY machine-readable field said transport — so an
 * operator grepping the log for exhaustion found a quota refusal, and one grepping for refusals
 * found it filed under a transport give-up. The work order's recorded trap is exactly this: *"the
 * operator must be able to tell 'the network is flaky, hold on' from 'the directory said no.'"*
 */
export type SubmissionGiveUpReason =
  /** Failures that REACHED a node and got no usable answer, until the budget ran out. */
  | "attempts_exhausted"
  /** Only ever local preconditions — the stream never came back inside the window. */
  | "retry_window_elapsed"
  /** A node decoded it, evaluated it, and said no. Nothing about waiting changes that. */
  | "refused_by_node"
  /** This daemon can no longer sign as the submitting agent, so nobody can send these bytes. */
  | "agent_unloaded";

/** One submission this daemon composed, sealed, and has not yet handed to a directory node. */
export interface PendingSubmission {
  agentName: string;
  /** The STABLE key. `agentName` is a display label and is reusable after a retire; the surface
   *  that lists these is scoped by id. */
  agentId: string;
  /** Content-derived. Never recomputed here — see the header. */
  submissionId: string;
  intakeKeyId: string;
  /** The sealed blob, re-sent verbatim. */
  ciphertext: Uint8Array;
  op: SubmissionOp;
  subject: string;
}

export type SubmissionDelivery =
  | {
      state: "retrying";
      attempts: number;
      lastReason: SubmissionSendFailure;
      nextAttemptAt: number;
      guidance: string;
    }
  | {
      state: "gave_up";
      attempts: number;
      lastReason: SubmissionSendFailure;
      gaveUpBecause: SubmissionGiveUpReason;
      guidance: string;
    };

export interface PendingSubmissionView {
  submissionId: string;
  op: SubmissionOp;
  subject: string;
  intakeKeyId: string;
  delivery: SubmissionDelivery;
}

export interface ScheduledTask {
  cancel: () => void;
}

export interface SubmissionRetryQueueDeps {
  logger: Logger;
  /**
   * Re-send THESE bytes on whatever stream the agent's SignalingManager currently holds. The queue
   * does not know or care which node that is — that is the point of the ruling in the header.
   */
  send: (item: PendingSubmission) => Promise<SendSubmissionResult>;
  /**
   * A retry landed. The caller writes the same local record a first-pass send writes, or a later
   * withdrawal has no handle to name. Called on the retry path only; the first-pass send records
   * its own.
   */
  onAccepted: (item: PendingSubmission, stored: boolean) => void;
  now?: () => number;
  schedule?: (fn: () => void, ms: number) => ScheduledTask;
  /** Gap between two attempts, so a queue of submissions is not a burst of frames. */
  staggerMs?: number;
  /** Ceiling on attempts that reached a node. */
  maxAttempts?: number;
  /** Wall-clock ceiling for a submission whose failures were all local preconditions. */
  retryWindowMs?: number;
  /** Ceiling on pending submissions held at once, across all agents. */
  queueCap?: number;
}

const DEFAULT_STAGGER_MS = 5_000;
const DEFAULT_MAX_ATTEMPTS = 5;
/**
 * How long to wait before re-trying a LOCAL PRECONDITION failure.
 *
 * Deliberately not the stagger. When the stream is down `sendRaw` returns without touching the
 * network, so a stagger-paced retry would be nearly free and nearly useless — 720 attempts and 720
 * log lines in an hour, none of which could have succeeded. The reconnect callback is the real
 * trigger; this is only the backstop for a reconnect that never fires, so it is paced against the
 * ~70-second stream turnover rather than against impatience.
 */
const LOCAL_PRECONDITION_RETRY_MS = 60_000;
/** Doubles from here, so five attempts span roughly fifteen minutes. */
const BASE_BACKOFF_MS = 30_000;
/**
 * One hour. Chosen against the intake key, not against patience: the queued blob is sealed to the
 * intake key the manifest published at compose time, and a manifest window is measured in weeks.
 *
 * THIS COMMENT USED TO ASSERT THAT AN HOUR "CANNOT OUTLIVE THE KEY", AND THAT WAS AN UNCHECKED
 * CLAIM (review M4). It holds only when the manifest has more than an hour left at compose time.
 * `composeSealedSubmission` refuses an already-expired manifest, but nothing stopped a submission
 * composed one minute before expiry from being held and re-sent for the next fifty-nine — and the
 * portal's rotated-key retention does not cover it either, because that rule keeps a retired key
 * "until no undrained row references it" (M10B-D11) and a HELD submission has no row at any node.
 * The result is exactly the state the expiry gate exists to prevent: a blob the portal cannot open
 * and cannot attribute, arriving as poison with no reply possible — while the operator has been
 * told it is held and needs nothing from them.
 *
 * So the CALLER checks rather than this comment asserting. See the enqueue site in `daemon.ts`,
 * which has the manifest in hand and refuses to hold a submission whose intake key would expire
 * inside this window.
 */
export const DEFAULT_RETRY_WINDOW_MS = 60 * 60_000;
const DEFAULT_QUEUE_CAP = 32;

/** What the operator does about a submission still in flight. Named verb, real parameterless call. */
const RETRYING_GUIDANCE =
  "The daemon is retrying this submission on its own — it is sealed and held, and it goes out as " +
  "soon as the directory signaling stream is back. You do not need to send it again. Run " +
  "cello_attestations_issued to see where it got to. It is held IN MEMORY: if the daemon restarts " +
  "before it lands, it is gone and you will have to write it again — re-sending is safe either way, " +
  "the submission id is derived from the content.";

function gaveUpGuidance(reason: SubmissionGiveUpReason, last: SubmissionSendFailure): string {
  const shared =
    "Nothing was minted and nothing was recorded at a directory. Re-submitting is safe — the " +
    "submission id is derived from the content, so a re-send is stored once, not twice — but the " +
    "text is not kept on this machine, so you have to write it again: run cello_attestations_issue " +
    "with the same subject.";
  switch (reason) {
    case "attempts_exhausted":
      // "ANSWERED" WAS WRONG (review L8). The only reason that normally exhausts this budget is
      // `submission_write_timeout` — where the node answered NOTHING, which is what the reason
      // means — and `submission_unsupported_by_node`, where it answered `not_authenticated`, a
      // frame `sendSealedSubmission` deliberately refuses to treat as an answer.
      return (
        `The daemon retried this submission until it ran out of attempts; the last attempt ended ` +
        `in '${last}'. ${shared}`
      );
    case "retry_window_elapsed":
      return (
        `The daemon held this submission for an hour and the directory signaling stream never came ` +
        `back (last state '${last}'). Check the daemon's directory connection with cello_status ` +
        `first — this is a connectivity problem, not a rejection. ${shared}`
      );
    case "refused_by_node":
      // Reached only when a node refuses mid-retry AND gives no reason of its own; the node's
      // words win whenever it has any. Even here it must not read as a network problem.
      return (
        "A directory node decoded this submission and refused it. That is a decision about the " +
        "submission, not a connectivity problem, so it will not be retried — sending it again " +
        "unchanged will be refused again. " + shared
      );
    case "agent_unloaded":
      return (
        "This daemon can no longer sign as the agent that wrote this submission, so the held bytes " +
        "cannot be sent by anyone. Start the agent with cello_start_agent, then issue it again. " +
        shared
      );
  }
}

interface QueueItem {
  item: PendingSubmission;
  /** Attempts that REACHED a node. Local-precondition failures do not increment this. */
  attempts: number;
  totalSends: number;
  enqueuedAt: number;
  nextAt: number;
  delivery: SubmissionDelivery;
}

function defaultSchedule(fn: () => void, ms: number): ScheduledTask {
  const t = setTimeout(fn, ms);
  // A background retry must never be the reason a daemon will not exit.
  t.unref?.();
  return { cancel: () => clearTimeout(t) };
}

/**
 * The retry queue. One per daemon; keyed by (agentId, submissionId) because two agents on one
 * daemon can each submit about the same subject and the rows are per-agent facts.
 */
export class SubmissionRetryQueue {
  readonly #deps: SubmissionRetryQueueDeps;
  readonly #now: () => number;
  readonly #schedule: (fn: () => void, ms: number) => ScheduledTask;
  readonly #staggerMs: number;
  readonly #maxAttempts: number;
  readonly #retryWindowMs: number;
  readonly #queueCap: number;

  /** Live retries. An entry leaves on acceptance or on give-up. */
  readonly #queue = new Map<string, QueueItem>();
  /**
   * Given-up submissions, kept so the operator surface can SHOW the terminal state. A give-up whose
   * only consumer is a log line is indistinguishable from the submission never having existed,
   * which is exactly the silence this unit exists to end. Bounded by the same cap.
   */
  readonly #gaveUp: QueueItem[] = [];

  #timer: ScheduledTask | null = null;
  #running = false;
  #stopped = false;

  constructor(deps: SubmissionRetryQueueDeps) {
    this.#deps = deps;
    this.#now = deps.now ?? (() => Date.now());
    this.#schedule = deps.schedule ?? defaultSchedule;
    this.#staggerMs = deps.staggerMs ?? DEFAULT_STAGGER_MS;
    this.#maxAttempts = deps.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.#retryWindowMs = deps.retryWindowMs ?? DEFAULT_RETRY_WINDOW_MS;
    this.#queueCap = deps.queueCap ?? DEFAULT_QUEUE_CAP;
  }

  /**
   * Take ownership of a submission whose send failed for a retryable reason.
   *
   * Returns `false` when the queue is full, and the caller then reports the plain failure — an
   * operator who is told "the daemon has it" about a submission the daemon dropped is worse off
   * than one who is told it failed, because only the second knows to act.
   */
  enqueue(item: PendingSubmission, lastReason: SubmissionSendFailure): boolean {
    if (this.#stopped) return false;
    const key = `${item.agentId}:${item.submissionId}`;
    // Idempotent on the content-derived id: re-submitting the same body while a retry is pending is
    // the SAME submission, not a second one.
    if (this.#queue.has(key)) return true;

    if (this.#queue.size >= this.#queueCap) {
      this.#deps.logger.warn("signal.submission.retry.queue_full", {
        agentName: item.agentName,
        submissionId: item.submissionId,
        cap: this.#queueCap,
        impact: "this submission is NOT held for retry — the operator is told it failed and must re-send",
      });
      return false;
    }

    const now = this.#now();
    this.#queue.set(key, {
      item,
      attempts: 0,
      totalSends: 0,
      enqueuedAt: now,
      // Deliberately NOT now: the stream is down, and an immediate attempt spends the stagger on a
      // connection that does not exist. The reconnect is what makes it due.
      nextAt: now + this.#staggerMs,
      delivery: {
        state: "retrying",
        attempts: 0,
        lastReason,
        nextAttemptAt: now + this.#staggerMs,
        guidance: RETRYING_GUIDANCE,
      },
    });
    this.#deps.logger.info("signal.submission.retry.enqueued", {
      agentName: item.agentName,
      submissionId: item.submissionId,
      op: item.op,
      reason: lastReason,
      pending: this.#queue.size,
    });
    this.#arm(this.#staggerMs);
    return true;
  }

  /**
   * The agent's directory signaling stream reached 'connected' — the first connect and every
   * reconnect after a drop. THIS IS THE FAILOVER. Which node it landed on is not this module's
   * business and is deliberately not read.
   */
  onSignalingConnected(agentName: string): void {
    if (this.#stopped) return;
    const now = this.#now();
    let woke = 0;
    for (const entry of this.#queue.values()) {
      if (entry.item.agentName !== agentName) continue;
      entry.nextAt = now;
      // Only live entries are in `#queue`, so this is always the retrying shape — written out
      // rather than spread, so a later member of the union cannot be silently mangled by a cast.
      entry.delivery = {
        state: "retrying",
        attempts: entry.attempts,
        lastReason: entry.delivery.lastReason,
        nextAttemptAt: now,
        guidance: RETRYING_GUIDANCE,
      };
      woke += 1;
    }
    if (woke === 0) return;
    this.#deps.logger.info("signal.submission.retry.woken", { agentName, count: woke });
    this.#arm(0);
  }

  /**
   * What this agent still has in flight, and what was given up on. Read by `wallet_list_issued`,
   * which is the surface behind `cello_attestations_issued` — the verb whose whole question is
   * "what happened to what I sent?".
   */
  list(agentId: string): PendingSubmissionView[] {
    const views: PendingSubmissionView[] = [];
    for (const entry of [...this.#queue.values(), ...this.#gaveUp]) {
      if (entry.item.agentId !== agentId) continue;
      views.push({
        submissionId: entry.item.submissionId,
        op: entry.item.op,
        subject: entry.item.subject,
        intakeKeyId: entry.item.intakeKeyId,
        delivery: entry.delivery,
      });
    }
    return views;
  }

  /**
   * Stop, and start nothing further.
   *
   * EVERY DROPPED SUBMISSION IS NAMED (review H2). The queue is in memory by design, but the
   * operator was told in as many words "you do NOT need to run this again" — and before this, a
   * restart left no durable trace anywhere naming what had been lost. A comment in the composition
   * root asserting "in memory by design" is not a record; these lines are.
   *
   * The SUBJECT is logged and the body is not: the subject is a pubkey or a signal hash, and the
   * body is the operator's own words about a third party, which this whole path exists to keep out
   * of the clear on disk.
   */
  stop(): void {
    this.#stopped = true;
    this.#timer?.cancel();
    this.#timer = null;
    for (const entry of this.#queue.values()) {
      this.#deps.logger.warn("signal.submission.retry.dropped_on_shutdown", {
        agentName: entry.item.agentName,
        submissionId: entry.item.submissionId,
        op: entry.item.op,
        subject: entry.item.subject,
        attempts: entry.attempts,
        sends: entry.totalSends,
        impact: "it reached no directory node and the daemon is stopping — it must be issued again",
      });
    }
    this.#queue.clear();
  }

  #arm(delayMs: number): void {
    if (this.#stopped) return;
    if (this.#queue.size === 0) return;
    this.#timer?.cancel();
    this.#timer = this.#schedule(() => {
      this.#timer = null;
      void this.#pump();
    }, delayMs);
  }

  #armIfWork(): void {
    if (this.#queue.size === 0) return;
    this.#arm(this.#staggerMs);
  }

  async #pump(): Promise<void> {
    if (this.#stopped || this.#running || this.#queue.size === 0) return;

    const now = this.#now();
    let due: QueueItem | null = null;
    for (const entry of this.#queue.values()) {
      if (entry.nextAt <= now && (due === null || entry.nextAt < due.nextAt)) due = entry;
    }
    if (due === null) {
      let earliest = Infinity;
      for (const entry of this.#queue.values()) earliest = Math.min(earliest, entry.nextAt);
      if (earliest !== Infinity) this.#arm(Math.max(0, earliest - now));
      return;
    }

    const entry = due;
    const key = `${entry.item.agentId}:${entry.item.submissionId}`;
    entry.totalSends += 1;
    this.#running = true;

    let result: SendSubmissionResult;
    try {
      result = await this.#deps.send(entry.item);
    } catch (err: unknown) {
      // A thrown send is not a decision about the submission either — it is our own transport
      // falling over. Treated as the local precondition it is.
      this.#deps.logger.warn("signal.submission.retry.threw", {
        agentName: entry.item.agentName,
        submissionId: entry.item.submissionId,
        error: err instanceof Error ? err.message : String(err),
      });
      result = { ok: false, reason: "directory_unreachable", guidance: "" };
    } finally {
      this.#running = false;
    }

    /**
     * AN ACCEPTANCE IS RECORDED EVEN IF WE ARE SHUTTING DOWN, and the `#stopped` check sits BELOW
     * this branch for that reason (review H1).
     *
     * `stop()` does not await the send in flight. Checking `#stopped` first meant a node that
     * accepted the submission during shutdown produced no `onAccepted`, no log line, and no row in
     * `issued_submissions` — while the portal went on to mint it. The endorsement is real and the
     * operator holds no handle to it, so it can never be withdrawn: `recordIssuedSubmission`'s own
     * comment is "KEEP THE HANDLE, or a withdrawal has nothing to name."
     *
     * The log line goes out FIRST and carries the subject, so even if the database is already
     * closed the handle survives in `daemon.log`. A bare `return` here was the worst of the three
     * available options.
     */
    if (result.ok) {
      this.#queue.delete(key);
      this.#deps.logger.info("signal.submission.retry.accepted", {
        agentName: entry.item.agentName,
        submissionId: entry.item.submissionId,
        op: entry.item.op,
        // The SUBJECT, so this line alone is enough to reconstruct the handle if the write below
        // cannot run. It is a pubkey or a signal hash — never the operator's words.
        subject: entry.item.subject,
        intakeKeyId: entry.item.intakeKeyId,
        sends: entry.totalSends,
        stored: result.stored,
        ...(this.#stopped ? { duringShutdown: true } : {}),
      });
      try {
        this.#deps.onAccepted(entry.item, result.stored);
      } catch (err: unknown) {
        // Best-effort, exactly as the first-pass record write is: the submission IS accepted, and
        // failing over a local bookkeeping write would invite a re-send of something already queued.
        this.#deps.logger.error("signal.submission.retry.record_failed", {
          agentName: entry.item.agentName,
          submissionId: entry.item.submissionId,
          subject: entry.item.subject,
          error: err instanceof Error ? err.message : String(err),
        });
      }
      if (!this.#stopped) this.#armIfWork();
      return;
    }

    // Below here everything is bookkeeping for a FUTURE attempt, and a stopped queue makes none.
    if (this.#stopped) return;

    // A NON-RETRYABLE FAILURE ARRIVING MID-RETRY IS TERMINAL, AND IT KEEPS ITS OWN NAME (review
    // H3). Stamping these `attempts_exhausted` printed a transport story — with `attempts: 0` beside
    // it — for a quota refusal, in the one field a machine consumer branches on.
    if (!isRetryableSendFailure(result.reason)) {
      this.#giveUp(
        key,
        entry,
        result.reason,
        result.reason === "submission_agent_unloaded" ? "agent_unloaded" : "refused_by_node",
        result.guidance,
      );
      return;
    }

    const localPrecondition = LOCAL_PRECONDITION_FAILURES.has(result.reason);
    if (!localPrecondition) entry.attempts += 1;

    const windowElapsed = this.#now() - entry.enqueuedAt >= this.#retryWindowMs;
    if (windowElapsed) {
      this.#giveUp(key, entry, result.reason, "retry_window_elapsed");
      return;
    }
    if (!localPrecondition && entry.attempts >= this.#maxAttempts) {
      this.#giveUp(key, entry, result.reason, "attempts_exhausted");
      return;
    }

    const waitMs = localPrecondition
      ? LOCAL_PRECONDITION_RETRY_MS
      : BASE_BACKOFF_MS * 2 ** Math.max(0, entry.attempts - 1);
    entry.nextAt = this.#now() + waitMs;
    entry.delivery = {
      state: "retrying",
      attempts: entry.attempts,
      lastReason: result.reason,
      nextAttemptAt: entry.nextAt,
      guidance: RETRYING_GUIDANCE,
    };
    this.#deps.logger.info("signal.submission.retry.waiting", {
      agentName: entry.item.agentName,
      submissionId: entry.item.submissionId,
      attempts: entry.attempts,
      sends: entry.totalSends,
      reason: result.reason,
      localPrecondition,
      retryInMs: waitMs,
    });
    this.#arm(waitMs);
  }

  #giveUp(
    key: string,
    entry: QueueItem,
    lastReason: SubmissionSendFailure,
    because: SubmissionGiveUpReason,
    nodeGuidance?: string,
  ): void {
    this.#queue.delete(key);
    entry.delivery = {
      state: "gave_up",
      attempts: entry.attempts,
      lastReason,
      gaveUpBecause: because,
      // The NODE'S OWN words survive when it gave any — a refusal on the merits names something
      // this module cannot know. Ours is the fallback, never the replacement.
      guidance: nodeGuidance && nodeGuidance.length > 0 ? nodeGuidance : gaveUpGuidance(because, lastReason),
    };
    this.#gaveUp.push(entry);
    while (this.#gaveUp.length > this.#queueCap) this.#gaveUp.shift();
    this.#deps.logger.warn("signal.submission.retry.gave_up", {
      agentName: entry.item.agentName,
      submissionId: entry.item.submissionId,
      op: entry.item.op,
      attempts: entry.attempts,
      sends: entry.totalSends,
      reason: lastReason,
      // WHY it stopped, not just that it did — "we ran out of tries" and "the network never came
      // back" lead to different operator actions.
      stoppedBecause: because,
      impact: "this trust signal reached no directory node; it is visible as gave_up in cello_attestations_issued",
    });
    this.#armIfWork();
  }
}
