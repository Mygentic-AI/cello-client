/**
 * DOD-COATTEND-VISIBLE-1 (M8D Tier 0) — co-attendance bookkeeping.
 *
 * Several sessions may attend one agent. That is DELIBERATE and permanent (spec §3: co-attendance,
 * not exclusivity — connections die constantly, exclusivity buys no cryptographic property, and it
 * forecloses listener mode). What was missing is not a restriction; it is VISIBILITY.
 *
 * Two facts live here, and nothing in this module changes delivery:
 *
 *  1. HOW MANY sessions attend an agent. `daemon.ts`'s `isAttended()` answers a boolean on first
 *     match and deliberately never counts — M8C-AWAY-1's auto-ack suppression hangs off it, so it is
 *     left exactly as it is. `countAttendance` is ADDITIVE and shares its one source of truth: the
 *     same `currentAgent` map the doorbell routes on. A private second counter could disagree with
 *     who actually gets woken; this cannot.
 *
 *  2. WHICH connection consumed a message. The delivery buffer is keyed `(agentName, sessionId)` and
 *     drained with `buf.shift()`, so when two sessions are woken by the same multicast doorbell the
 *     faster one REMOVES the message from the other's view. Tier 0 does not fix that (Tier 1's
 *     DOD-COATTEND-1 does). It records it, so the session that got nothing can be told the
 *     difference between "your counterparty is quiet" and "your sibling took it".
 *
 * WHY HERE AND NOT IN SessionNodeManager. The ledger's subject is connection identity, which is an
 * IPC-layer concept. `SessionNodeManager` is deliberately connection-agnostic — `#receivedContent`
 * being keyed by (agent, session) and NOT by connection IS the Tier-1 defect — so teaching it about
 * connections inside the launch-gate slice would start the redesign early. This sits beside the
 * per-connection read cursor, which is the same kind of state for the same reason.
 */

/** The slice of per-connection state attendance depends on. Structural, so both call sites fit. */
export interface AttendanceConnState {
  readonly currentAgent: string | null;
}

/**
 * How many live connections currently attend `agentName`.
 *
 * NOT a replacement for `isAttended()`. That function's early return drives the away-response
 * decision; this one only ever reports. Both read the same map, so they cannot disagree.
 */
export function countAttendance(
  perConnectionState: ReadonlyMap<string, AttendanceConnState>,
  agentName: string,
): number {
  let attending = 0;
  for (const state of perConnectionState.values()) {
    if (state.currentAgent === agentName) attending += 1;
  }
  return attending;
}

/** One consumption of buffered content: which connection took which leaf. No content, ever. */
export interface ContentTake {
  readonly connectionId: string;
  readonly sequenceNumber: number;
}

/** What a caller MISSED: content a sibling consumed that this connection has not read. */
export interface SiblingTakes {
  readonly count: number;
  readonly lastSequence: number;
  /** The connections that took it — so the daemon log alone reconstructs the race. */
  readonly connections: readonly string[];
  /**
   * The per-session cap discarded older takes, so `count` is a FLOOR, not the total. Stated on the
   * answer rather than only in a constant: an unstated cap is a silent truncation, and a caller
   * reading `count: 64` deserves to know the real number may be larger.
   */
  readonly truncated: boolean;
}

/**
 * Bounds. A daemon runs for days across many sessions, so an unbounded map is a leak — and a cap
 * that is not stated is a silent truncation. Both numbers are generous relative to the question
 * being asked ("did a sibling take something I have not read?"), which only ever looks at takes
 * above the caller's cursor.
 */
const MAX_TAKES_PER_SESSION = 64;
const MAX_TRACKED_SESSIONS = 512;

export class ContentTakeLedger {
  /** `(agentName, sessionId)` → recent takes, oldest first. Insertion order doubles as the LRU. */
  readonly #takes = new Map<string, ContentTake[]>();
  /** Sessions whose per-session cap has discarded at least one take. */
  readonly #truncated = new Set<string>();

  static #key(agentName: string, sessionId: string): string {
    // NUL cannot appear in either component, so the join is unambiguous.
    return `${agentName}\u0000${sessionId}`;
  }

  /** Record that `connectionId` consumed the leaf at `sequenceNumber`. */
  record(agentName: string, sessionId: string, connectionId: string, sequenceNumber: number): void {
    const key = ContentTakeLedger.#key(agentName, sessionId);
    const existing = this.#takes.get(key);
    const takes = existing ?? [];
    takes.push({ connectionId, sequenceNumber });
    if (takes.length > MAX_TAKES_PER_SESSION) {
      takes.splice(0, takes.length - MAX_TAKES_PER_SESSION);
      this.#truncated.add(key);
    }
    // Re-insert so this session moves to the young end of the eviction order.
    if (existing !== undefined) this.#takes.delete(key);
    this.#takes.set(key, takes);
    while (this.#takes.size > MAX_TRACKED_SESSIONS) {
      const oldest = this.#takes.keys().next();
      if (oldest.done === true) break;
      this.#takes.delete(oldest.value);
      this.#truncated.delete(oldest.value);
    }
  }

  /**
   * Drop everything `connectionId` took. Called from the daemon's `onDisconnect`, beside
   * `connectionCursors.delete` — this state is connection-scoped for the same reason and must have
   * the same lifetime.
   *
   * WHY IT IS NOT OPTIONAL (review HIGH). A fresh connection presents cursor -1, so without this
   * every take a dead connection ever recorded sits above the bar and reads as a live sibling
   * stealing mail. The `cello` CLI opens a fresh connection PER COMMAND, so that fired on ordinary
   * single-operator use and never cleared — the catch-up dead end in mirror image. Once a
   * connection is gone its takes are history, and history is not "another session took it".
   *
   * Bounded by construction: at most MAX_TRACKED_SESSIONS × MAX_TAKES_PER_SESSION entries.
   */
  forget(connectionId: string): void {
    for (const [key, takes] of this.#takes) {
      const kept = takes.filter((t) => t.connectionId !== connectionId);
      if (kept.length === takes.length) continue;
      if (kept.length === 0) {
        this.#takes.delete(key);
        this.#truncated.delete(key);
      } else {
        this.#takes.set(key, kept);
      }
    }
  }

  /**
   * Content another connection consumed that `connectionId` has not read, or `null` when there is
   * none.
   *
   * TWO conditions, and both are load-bearing.
   *
   * 1. The take is above the caller's own read cursor — NOT inside a wall-clock window. A window
   *    would have to guess how long ago a theft still counts for, and would miss the ordinary case
   *    where the sibling's take lands microseconds before this caller's handler even starts. A
   *    cursor is exact: it reports content this connection genuinely has not seen, and it CLEARS by
   *    itself once the caller catches up. A discriminator that never clears is one nobody reads.
   *
   * 2. The taking connection is STILL ALIVE — guaranteed by `forget()` on disconnect, which is why
   *    that call is not housekeeping. A take by a connection that has since died is history, and
   *    reporting history as a live theft is what made this fire on every CLI command.
   */
  missedBy(agentName: string, sessionId: string, connectionId: string, cursor: number): SiblingTakes | null {
    const key = ContentTakeLedger.#key(agentName, sessionId);
    const takes = this.#takes.get(key);
    if (takes === undefined) return null;
    const missed = takes.filter((t) => t.connectionId !== connectionId && t.sequenceNumber > cursor);
    if (missed.length === 0) return null;
    return {
      count: missed.length,
      lastSequence: missed.reduce((max, t) => (t.sequenceNumber > max ? t.sequenceNumber : max), missed[0].sequenceNumber),
      connections: [...new Set(missed.map((t) => t.connectionId))],
      truncated: this.#truncated.has(key),
    };
  }
}
