/**
 * THE CLAIMS LEDGER, as code — `DOD-M15-LEDGER-1`.
 *
 * ─── Why the ledger moved out of prose ─────────────────────────────────────────────────────────
 *
 * `DOD-M15-LEDGER-1` first produced a markdown table, and its review found it incomplete: the
 * completeness rested on one grep vocabulary at one moment. `DOD-M15-CLAIM-SCANNER-1` then made
 * discovery mechanical — surfaces enumerated from `package.json#files`, the plugin tree, the repo
 * root and the CLI's own strings — and the two artifacts immediately disagreed about what a claim
 * was. Two records of the same thing is how they drift; this repo has paid for that shape twice.
 *
 * ─── The specific defect this file fixes ───────────────────────────────────────────────────────
 *
 * The scanner counts **unadjudicated** claims and the count may only shrink. But adjudicating a
 * claim honestly often means writing MORE claim-shaped words, not fewer:
 *
 *   before   "End a session. Both sides sign off and get a tamper-proof receipt."
 *   after    "…Both sides sign off where they can, and each gets a tamper-evident receipt."
 *            plus three lines explaining that a seal may be unilateral and what that means.
 *
 * That correction removed a false absolute and added real disclosure — and made the count go UP,
 * so the guard failed the build for an edit that made the product more honest. A guard that
 * punishes disclosure teaches people to delete the disclosure.
 *
 * So a claim has three states, not two: unadjudicated (in the baseline), **adjudicated** (here,
 * with its verdict and the evidence), or gone. Adjudicating moves a claim from the first to the
 * second, and the baseline shrinks by what the entry accounts for — which is what the DoD line
 * asked for all along: *"every hit appears in the claims table with a disposition and a reason."*
 *
 * ─── What an entry has to carry ────────────────────────────────────────────────────────────────
 *
 * `evidence` is the field that matters and the one to be strict about. It names the code that makes
 * the claim true, or the change that made it true. "It looks right" is not a disposition — the prose
 * ledger's whole failure was rows that recorded a belief rather than a check.
 */

export interface AdjudicatedClaim {
  /** The surface it lives on, exactly as the scanner names it. */
  surface: string;
  /** The claim text, verbatim enough to find. */
  claim: string;
  /** How many claim-vocabulary matches this entry accounts for on that surface. */
  matches: number;
  verdict: "true" | "corrected" | "withdrawn";
  /** The code or change that settles it. Never a belief. */
  evidence: string;
}

export const ADJUDICATED: AdjudicatedClaim[] = [
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "close-session: 'Both sides sign off where they can, and each gets a tamper-evident receipt.'",
    matches: 1,
    verdict: "corrected",
    evidence:
      "Said 'tamper-PROOF' and 'Both sides sign off'. Both were wrong. A hash chain plus a Merkle " +
      "root plus a threshold signature makes alteration DETECTABLE, not impossible — and the help " +
      "text three lines below already said 'tamper-evident', so the summary was overclaiming what " +
      "its own help disclaimed. 'Both sides sign off' is the good case, not the guarantee: " +
      "`seal-escalation.ts:219` returns `seal_type: \"unilateral\"` when the counterparty never " +
      "comes back.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "sealed-receipt: 'what was said, and who signed off on it.'",
    matches: 1,
    verdict: "corrected",
    evidence:
      "Said 'proof both sides signed off on the conversation'. False for a unilateral seal — and " +
      "that is exactly the receipt an operator is most likely to be holding when something went " +
      "wrong, so the sentence failed precisely where it mattered most. The receipt now reports " +
      "which kind it is rather than promising the stronger kind.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "sealed-receipt help: 'BILATERAL or UNILATERAL, and the receipt says which.'",
    matches: 3,
    verdict: "true",
    evidence:
      "New disclosure, not a claim inherited from anywhere. `close-session-handler.ts:350` and " +
      "`seal-escalation.ts:70` both carry `seal_type` on the success variant, so the distinction is " +
      "on the wire and the receipt can state it. Counted here because saying 'tamper-evident' and " +
      "'notarized' accurately still spends claim vocabulary — and a guard that charges for honest " +
      "disclosure would teach people to delete it.",
  },
];

/** How many matches on a surface are accounted for by an adjudicated entry. */
export function adjudicatedMatches(surface: string): number {
  return ADJUDICATED.filter((a) => a.surface === surface).reduce((n, a) => n + a.matches, 0);
}
