/**
 * DOD-M9C-SCREENINSTALL-1 — which screening layers are actually running, for `cello_status`.
 *
 * Its own module because `daemon-status-report.ts` is at its line cap, and because the answer has
 * exactly one source: the gateway's `screenerState`, the same function the CLI prints and the
 * gateway's startup line carries. Three surfaces computing this three ways is how "installed" came
 * to mean three different things.
 */
import { screenerState, screenerModelDir, runtimeAvailable, describeScreenerState, type ScreenerStatus } from "@cello-protocol/gateway";
import type { ScreeningStatusInfo } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

/**
 * Verifying digests means hashing 131 MB, which is too much for a poll that fires on a timer — so
 * the VERDICT is cached for a minute and every surface serves the cached one.
 *
 * What it must never do is compute a CHEAPER answer for the poll. It did: the notification path
 * skipped digests, so five right-sized, wrong-byte files read as `ready` and the inbox stayed
 * silent while `cello status` called the same install `broken`. A surface that answers a question
 * it did not ask is worse than one that stays quiet.
 */
const CACHE_MS = 60_000;
let cached: { at: number; value: ScreeningStatusInfo | undefined } | undefined;

/**
 * What the running gateway reported about Layer 2 on its READY line (080-SCREENERCPU):
 * `active:native`, `active:wasm` or `off:<reason>`. Files on disk prove the bytes; only the
 * gateway's self-check proves the scores, so the summary is built from this.
 */
let gatewayLayer2: string | undefined;

/** Called by the daemon each time a gateway sidecar reports ready. */
export function recordGatewayLayer2(layer2: string): void {
  gatewayLayer2 = layer2;
  cached = undefined;
}

/** The status block from the file state AND the gateway's report. Pure, so T5 needs no sidecar. */
export function screeningInfoFrom(s: ScreenerStatus, layer2: string | undefined): ScreeningStatusInfo {
  if (s.state === "ready" && layer2?.startsWith("off:")) {
    return { classifier: "broken", summary: describeScreenerState(s, layer2), problem: layer2.slice(4) };
  }
  return { classifier: s.state, summary: describeScreenerState(s, layer2), ...(s.problem ? { problem: s.problem } : {}) };
}

/**
 * Never throws: a screener check that could break `cello status` would be a worse defect than the
 * gap it reports. A failure is REPORTED as `unknown` with its cause, never omitted.
 *
 */
export async function screeningStatus(): Promise<ScreeningStatusInfo> {
  const now = Date.now();
  if (cached && now - cached.at < CACHE_MS && cached.value) return cached.value;
  try {
    const s = await screenerState({ dir: screenerModelDir(), runtimePresent: await runtimeAvailable() });
    const value = screeningInfoFrom(s, gatewayLayer2);
    cached = { at: now, value };
    return value;
  } catch (err) {
    // ABSENT IS NOT FINE. Omitting the block made a permissions error on ~/.cello/screener render
    // exactly like a build that does not report screening at all — and this block exists precisely
    // so that absence cannot be read as health.
    const message = extractErrorMessage(err);
    return { classifier: "unknown", summary: `Screening: state UNKNOWN — the screener check failed: ${message}`, problem: message };
  }
}

/**
 * The line an agent sees on a session while the classifier is absent — essential when the caller is
 * a stranger. Empty when both layers are running, so a healthy inbox stays quiet.
 */
export async function screeningSessionNotice(): Promise<string | undefined> {
  return screeningSessionNoticeFrom(() => screeningStatus());
}

/** The decision, with its source injected — so the states can be tested without a model on disk. */
export async function screeningSessionNoticeFrom(
  read: () => Promise<ScreeningStatusInfo | undefined>,
): Promise<string | undefined> {
  const s = await read();
  if (!s || s.classifier === "ready") return undefined;
  if (s.classifier === "broken" && s.problem?.includes("self-check")) {
    // No --repair: reinstalling the same verified files cannot change what this CPU computes.
    return `Screening: the classifier gives wrong scores on this machine and did NOT judge this content: ${s.problem}. The pattern layer still ran.`;
  }
  if (s.classifier === "broken") {
    return `Screening: the classifier is BROKEN and did NOT judge this content: ${s.problem ?? "unknown fault"}. Fix it with: cello screener install --repair`;
  }
  if (s.classifier === "unknown") {
    return `Screening: state UNKNOWN — ${s.problem ?? "the check failed"}. This content may have been judged by one layer only.`;
  }
  return "Screening: 1 of 2 layers active (classifier not installed). Recommended: cello screener install";
}
