/**
 * DOD-DOC-WATCH-1 — the selective nudge: matching what changed against what an agent is waiting on.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────────
 *
 * A document update raises no doorbell (§11.3), deliberately: a collaborator typing produces a stream
 * of updates, and one doorbell each interrupts continuously for something with no deadline. That
 * decision stands. What it costs is that the only thing shortening the gap between an agent reading a
 * document and writing to it is the agent happening to re-read.
 *
 * `DOD-DOC-STALE-WRITE-1` made that gap SAFE — a stale write is refused rather than destroying the
 * peer's work — and safe is not short. An actor who reads at 09:00 and writes at 11:00 composes a
 * whole edit against a document that moved at 09:04, and learns it at the refusal.
 *
 * And the larger half: **silence currently means three different things** — nothing happened, the
 * peer is offline, or their update was refused — so quiet carries no information and no deadline can
 * rest on it. Once an agent declares what it is waiting for, "no nudge by 11:00" becomes a fact worth
 * acting on. That is an escalation rule becoming evaluable instead of prose in a runbook.
 *
 * ── RECEIVER-LOCAL, WHICH IS THE SECURITY PROPERTY ───────────────────────────────────────────────
 *
 * The watch list is declared by the receiving agent, on its own machine, and never goes on the wire.
 * A sender cannot make your agent wake by claiming a field matters, and cannot suppress a wake by
 * omitting one. There is no schema to enforce and no dependence on the peer describing the document
 * honestly — the receiver decides, from what actually changed in its own copy.
 */

/** The watch that means "any change at all" — for text documents, which have no key paths. */
export const WATCH_ALL = "*";

const SEPARATOR = ".";

/**
 * True when `changed` is `watched` itself or a descendant of it.
 *
 * SEGMENT-AWARE, never a raw string prefix: `status` must not match `status_line`. That mistake
 * surfaces as a false wake, which is the failure mode that gets a notification feature switched off.
 */
function covers(watched: string, changed: string): boolean {
  if (watched === WATCH_ALL) return true;
  if (changed === watched) return true;
  return changed.startsWith(watched + SEPARATOR);
}

/**
 * The changed paths this agent asked to be told about.
 *
 * An empty watch list matches NOTHING. "I am waiting on nothing" must never be read as "everything" —
 * defaulting to all is exactly how a selective nudge turns back into the per-update doorbell §11.3
 * rejected.
 */
export function matchWatchedPaths(watches: readonly string[], changed: readonly string[]): string[] {
  if (watches.length === 0) return [];
  return changed.filter((path) => watches.some((w) => covers(w, path)));
}

/**
 * Canonicalise a watch list: trimmed, non-empty, de-duplicated, and with any path already covered by
 * a broader one removed.
 *
 * Dropping the redundant child matters beyond tidiness — keeping both `blocking_flags` and
 * `blocking_flags.insufficient_funds` would report one change under two watches and make the nudge's
 * own path list misleading about what fired it.
 *
 * A malformed path THROWS rather than being silently repaired. A watch that was quietly rewritten
 * into something else would fail to fire, and a notification that does not arrive is indistinguishable
 * from nothing having happened — which is the very ambiguity this feature exists to remove.
 */
export function normalizeWatchPaths(paths: readonly string[]): string[] {
  const cleaned: string[] = [];
  for (const raw of paths) {
    const path = raw.trim();
    if (path.length === 0) continue;
    if (path === WATCH_ALL) return [WATCH_ALL];
    if (
      path.startsWith(SEPARATOR) ||
      path.endsWith(SEPARATOR) ||
      path.includes(SEPARATOR + SEPARATOR)
    ) {
      throw new Error(
        `invalid watch path '${raw}': a watch path is dot-separated segments, e.g. ` +
          `'blocking_flags.insufficient_funds', or '${WATCH_ALL}' for any change`,
      );
    }
    if (!cleaned.includes(path)) cleaned.push(path);
  }
  // Drop anything a broader sibling already covers.
  return cleaned.filter((p) => !cleaned.some((other) => other !== p && covers(other, p)));
}
