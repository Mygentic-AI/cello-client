/**
 * DOD-COATTEND-VISIBLE-1 (M8D Tier 0) — co-attendance bookkeeping.
 *
 * Several sessions may attend one agent. That is DELIBERATE and permanent (spec §3: co-attendance,
 * not exclusivity — connections die constantly, exclusivity buys no cryptographic property, and it
 * forecloses listener mode). What was missing is not a restriction; it is VISIBILITY.
 *
 * HOW MANY sessions attend an agent. `daemon.ts`'s `isAttended()` answers a boolean on first match
 * and deliberately never counts — M8C-AWAY-1's auto-ack suppression hangs off it, so it is left
 * exactly as it is. `countAttendance` is ADDITIVE and shares its one source of truth: the same
 * `currentAgent` map the doorbell routes on. A private second counter could disagree with who
 * actually gets woken; this cannot.
 *
 * The ledger of WHICH connection consumed a message is gone (2026-09-13). `cello_receive` now reads
 * against one bookmark per agent, so "another window read it" is no longer a different state from
 * "it was read" — the message was read by this agent, and `cello_transcript` shows it.
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
