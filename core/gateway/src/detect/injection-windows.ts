/**
 * DOD-M9C-SCREENWIRE-1 — reading the whole message.
 *
 * One pipeline call truncates at the model's window, so an attack past the cut is never screened and
 * nothing says so — a gap that looks exactly like coverage. A long message is split into overlapping
 * windows instead, every window is scored, and the message takes the worst one.
 *
 * Pure functions, no model: the windowing is the part that can be wrong in a way nobody notices, so
 * it is testable without loading 96 MB of weights.
 */

/**
 * Split token ids into windows of `size` that overlap by `overlap`.
 *
 * The overlap is what keeps an attack that straddles a boundary intact in at least one window:
 * Patronus' card specifies 2,048-token windows with 64 tokens of overlap, and the manifest carries
 * both numbers so this never reads them from the model's `config.json` (which advertises 8,192
 * positions the model was never benchmarked at).
 */
export function buildWindows(tokens: readonly number[], size: number, overlap: number): number[][] {
  if (size <= 0) throw new Error(`window size must be positive (got ${size})`);
  if (overlap >= size) {
    // Each step would advance zero tokens — an infinite loop on adversary-controlled content.
    throw new Error(`window overlap ${overlap} must be smaller than the window size ${size}`);
  }
  if (tokens.length <= size) return [[...tokens]];

  const stride = size - overlap;
  const windows: number[][] = [];
  for (let start = 0; start < tokens.length; start += stride) {
    windows.push(tokens.slice(start, start + size));
    if (start + size >= tokens.length) break; // the tail is covered; another window would repeat it
  }
  return windows;
}

/**
 * The message's score, from its windows.
 *
 * The MAXIMUM, deliberately. Patronus aggregates with normalised Smooth-Max; the maximum is the
 * conservative form of the same idea, and it is what CELLO's own measurements are taken against — so
 * the numbers we publish are ours, not the card's. Averaging is the wrong shape here: a long benign
 * preamble would bury the injection it carries, which is precisely how a padded attack is built.
 */
export function aggregateWindowScores(scores: readonly number[]): number {
  if (scores.length === 0) {
    // ABSENT IS NOT FINE. A fabricated 0 reads as "screened and clean" for content nothing looked at.
    throw new Error("cannot score a message with no windows — refusing to report an unscanned message as clean");
  }
  return Math.max(...scores);
}
