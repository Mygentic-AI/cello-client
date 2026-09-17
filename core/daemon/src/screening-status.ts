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
 * Verifying digests means hashing 131 MB. That is right for `cello status`, which an operator runs
 * deliberately, and wrong for a notification poll that fires on a timer — so the answer is cached
 * for a minute and the poll path asks the cheap question (are the files there, is the runtime
 * there) rather than the expensive one.
 */
const CACHE_MS = 60_000;
let cached: { at: number; value: ScreeningStatusInfo | undefined } | undefined;

/**
 * Never throws: a screener check that could break `cello status` would be a worse defect than the
 * gap it reports. Absence is reported as absence — the field is omitted, not faked.
 *
 * @param opts.quick skip digest verification (the notification path). A quick check can say
 * "installed" of files it has not hashed, so `cello status` and the CLI never use it.
 */
export async function screeningStatus(opts: { quick?: boolean } = {}): Promise<ScreeningStatusInfo | undefined> {
  const now = Date.now();
  if (!opts.quick && cached && now - cached.at < CACHE_MS) return cached.value;
  try {
    const s = await screenerState({
      dir: screenerModelDir(),
      runtimePresent: await runtimeAvailable(),
      ...(opts.quick ? { verifyDigests: false } : {}),
    });
    const value = { classifier: s.state, summary: describeScreenerState(s), ...(s.problem ? { problem: s.problem } : {}) };
    if (!opts.quick) cached = { at: now, value };
    return value;
  } catch {
    return undefined;
  }
}

/**
 * The line an agent sees on a session while the classifier is absent — essential when the caller is
 * a stranger. Empty when both layers are running, so a healthy inbox stays quiet.
 */
export async function screeningSessionNotice(): Promise<string | undefined> {
  return screeningSessionNoticeFrom(() => screeningStatus({ quick: true }));
}

/** The decision, with its source injected — so the states can be tested without a model on disk. */
export async function screeningSessionNoticeFrom(
  read: () => Promise<ScreeningStatusInfo | undefined>,
): Promise<string | undefined> {
  const s = await read();
  if (!s || s.classifier === "ready") return undefined;
  return "Screening: 1 of 2 layers active (classifier not installed). Recommended: cello screener install";
}
