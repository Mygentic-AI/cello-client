/**
 * DOD-M9C-SCREENINSTALL-1 — which screening layers are actually running, for `cello_status`.
 *
 * Its own module because `daemon-status-report.ts` is at its line cap, and because the answer has
 * exactly one source: the gateway's `screenerState`, the same function the CLI prints and the
 * gateway's startup line carries. Three surfaces computing this three ways is how "installed" came
 * to mean three different things.
 */
import { screenerState, screenerModelDir, runtimeAvailable, describeScreenerState } from "@cello-protocol/gateway";
import type { ScreeningStatusInfo } from "./types.js";

/**
 * Never throws: a screener check that could break `cello status` would be a worse defect than the
 * gap it reports. Absence is reported as absence — the field is omitted, not faked.
 */
export async function screeningStatus(): Promise<ScreeningStatusInfo | undefined> {
  try {
    const s = await screenerState({ dir: screenerModelDir(), runtimePresent: await runtimeAvailable() });
    return { classifier: s.state, summary: describeScreenerState(s), ...(s.problem ? { problem: s.problem } : {}) };
  } catch {
    return undefined;
  }
}
