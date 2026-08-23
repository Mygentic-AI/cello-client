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

/**
 * ─── WHY `excerpts` EXISTS, AND WHY `matches` IS NO LONGER A NUMBER SOMEBODY TYPES ─────────────
 *
 * The first version of this file carried a hand-written `matches: N` per row, guarded by two tests:
 * the count may only shrink, and no surface may account for more matches than it contains. A review
 * of `DOD-M15-LEDGER-1` demonstrated in ONE attempt that both guards are strictly weaker than they
 * read. This entry passed them and zeroed an entire unswept surface:
 *
 *   { surface: "plugins/cello/skills/documents/SKILL.md",
 *     claim: "the documents skill's safety properties",
 *     matches: 18,
 *     evidence: "Verified against document-handlers.ts and document-inbound.ts, whose guards are
 *                structural rather than conventional and hold on every apply path." }
 *
 * Nothing checked that the claim text existed on the surface, that the cited files existed, or that
 * 18 corresponded to any real vocabulary hit. The shrink-only test then drove that baseline to zero
 * PERMANENTLY. The guards constrained the ledger's internal consistency, never its correspondence to
 * reality — which is the same defect class this milestone exists to remove, reproduced inside the
 * mechanism built to police it.
 *
 * So a row now carries the **verbatim text it accounts for**, and the number is DERIVED from that
 * text by the same regex the scanner uses. Three consequences worth stating because they are the
 * point rather than side effects:
 *
 *   1. A row for text that is not on the surface fails. Laundering needs the words to exist.
 *   2. Double-counting is impossible to hide: two rows quoting the same sentence are visible as the
 *      same string, and the arithmetic they produce is no longer a matter of opinion.
 *   3. The judgement calls that used to live in comments ("ONE, not three", "ZERO, and that is the
 *      honest number") become arithmetic. Those comments were arguments where they should have been
 *      code, and both of them were written to correct my own over-counting.
 */
export interface AdjudicatedClaim {
  /** The surface it lives on, exactly as the scanner names it. */
  surface: string;
  /** The claim text, as a human reads it. Display only — `excerpts` is what counts. */
  claim: string;
  /**
   * VERBATIM slices of the surface this row accounts for. Each must appear in the surface text
   * exactly, and the row's match count is the sum of the vocabulary hits inside them.
   *
   * An array rather than one string because a single claim is often stated in several places (the
   * "encrypted database" phrasing appears four times in the README), and because a claim split
   * across a wrapped line needs both halves.
   */
  excerpts: readonly string[];
  verdict: "true" | "corrected" | "withdrawn";
  /**
   * WHO ENFORCES IT — carried onto this line by `DOD-M15-CLAIM-SCANNER-1` and load-bearing for
   * Invariant 1. Without it, a claim held up by the operator's own rewritable client and a claim
   * held up by the absence of a wire field are indistinguishable rows.
   *
   *   `structural`   — nothing has to run. There is no field to carry it, no branch to skip.
   *   `daemon-local` — the operator's own daemon checks it. Ergonomics, not a guarantee: they can
   *                    rewrite it. Honest for a claim about what YOUR machine does for YOU.
   *   `directory`    — a party other than the claimant enforces it (directory, relay, portal).
   *   `nobody-yet`   — the claim is not enforced anywhere. A row may only be `true` with this if
   *                    the claim asserts an ABSENCE or is a disclaimer.
   */
  enforcedBy: "structural" | "daemon-local" | "directory" | "nobody-yet";
  /** The code or change that settles it. Never a belief. */
  evidence: string;
}

/** Vocabulary hits inside one string — the SAME regex the scanner applies to a whole surface. */
export function countClaimWords(text: string): number {
  return (
    text.match(
      /\b(never|cannot|impossible|tamper-proof|tamper-evident|independently verify|verifiable|verified|notarized|zero-knowledge|no one can|nobody can|only you|guarantee[ds]?|encrypted|screened|proof|ACTIVE)\b/g,
    ) ?? []
  ).length;
}

export const ADJUDICATED: AdjudicatedClaim[] = [
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "close-session: 'Both sides sign off where they can, and each gets a tamper-evident receipt.'",
    excerpts: ["each gets a tamper-evident receipt."],
    enforcedBy: "directory",
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
    excerpts: ["notarized receipt — what was said, and who signed off on it."],
    enforcedBy: "directory",
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
    excerpts: [
      "unilateral means the counterparty never returned to sign",
      "conversation, notarized and tamper-evident, but not their agreement that it is complete.",
    ],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "New disclosure, not a claim inherited from anywhere. `close-session-handler.ts:350` and " +
      "`seal-escalation.ts:70` both carry `seal_type` on the success variant, so the distinction is " +
      "on the wire and the receipt can state it. Counted here because saying 'tamper-evident' and " +
      "'notarized' accurately still spends claim vocabulary — and a guard that charges for honest " +
      "disclosure would teach people to delete it.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "refresh: 'CELLO never holds your whole signing key in one place — it is split into shares held with the directory nodes.'",
    excerpts: ["CELLO never holds your whole signing key in one place"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Verified, and the verification matters because the WEAKER implementation exists in the tree. " +
      "`frost-threshold-signer.ts` has a `trustedDealer` path where one party does hold the whole " +
      "key momentarily — but `bootstrapKeyShares` THROWS unless `NODE_ENV === \"test\"` " +
      "(\"bootstrapKeyShares is a test-only shortcut. Real DKG (M3) is required in production\"). " +
      "Production registration runs a real distributed key generation across the consortium " +
      "(`register-handler.ts`, `network-directory-node.ts` frost_dkg_round1), so no whole key is " +
      "ever assembled anywhere. The claim would have been FALSE under the dealer path, which is why " +
      "the guard is the evidence rather than the comment.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "attestations: 'It is sealed to the CELLO portal (the directory cannot read it)'",
    excerpts: ["cannot read it)"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "`signal-submission.ts:239` calls `sealToRecipient(intakeKey.pubkey, encoded)` — an anonymous " +
      "public-key seal to the PORTAL's intake key. The directory stores and replicates ciphertext " +
      "it holds no private key for. Consistent with the no-PII-in-the-directory rule: directories " +
      "are federated and possibly public, so they hold hashes and sealed blobs, never plaintext.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "restore: 'a corrupt or truncated file cannot destroy the agent you still have'",
    excerpts: ["file cannot destroy the agent you still have."],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Built and tested as part of DOD-M15-BACKUP-1. `restoreBackup` calls `parseArchive` FIRST, " +
      "which gunzips, parses, checks the magic and version, requires a 32-byte key and verifies a " +
      "SHA-256 over the database payload — entirely in memory. Nothing reaches the disk until all " +
      "of that passes. Two tests cover it: a garbage file and a half-length truncation, each " +
      "asserting afterwards that the pre-existing database still reads its original marker.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "backup: 'a database without its key restores to something nobody can read — including you' / 'whoever holds it can sign as you'",
    // ONE, not two — F10 on review. The second match this row used to buy is `never` in "the
    // snapshot is taken through SQLite, so it is never a half-written copy", a DIFFERENT claim that
    // this row's evidence says nothing about. It has its own row below. A row paying for a sentence
    // it does not discuss is how a match leaves the backlog unexamined.
    excerpts: ["key restores to something nobody can read — including you."],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Both are properties of the artifact built in DOD-M15-BACKUP-1. The database is SQLCipher- " +
      "encrypted and its key is a separate 32-byte file at `<db>.key` — `sqlcipher-db.ts` calls it " +
      "'the ONE plaintext key file on disk' — and a fresh daemon mints its own, which cannot open a " +
      "database encrypted under a different one. The round-trip test proves the archive carries the " +
      "key by restoring into a directory whose key differs. The second half follows: the archive " +
      "contains that key in the clear, so possession of the file is possession of the agent. Saying " +
      "so at the moment one is written is the affordance, not decoration.",
  },
  {
    surface: "plugins/cello/skills/cello/SKILL.md",
    claim: "doorbell: 'a new kind of message must never be silently ignored because this table is older than the daemon'",
    excerpts: ["a new kind of message must never be silently"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The default direction is implemented and tested (DOD-M15-DOORBELL-1). `buildChannelParams` " +
      "sets `wake_action` to `none` only for names in HOUSEKEEPING_TYPES and `read_inbox` for " +
      "everything else, including a type it has never seen — `dod-m15-doorbell-1.test.ts` asserts " +
      "exactly that with a fabricated future doorbell name. Defaulting the other way would make a " +
      "new message-bearing type silently ignored, which is a conversation that never gets answered " +
      "with nothing reporting a problem.",
  },
  {
    surface: "core/adapter-claude-code/SKILL.md",
    claim: "doorbell: 'a new kind of message must never be silently ignored because this table is older than the daemon'",
    excerpts: ["a new kind of message must never be silently"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The same sentence as the plugin skill's, and the same evidence: `buildChannelParams` marks " +
      "only HOUSEKEEPING_TYPES as `none` and everything else — including an unrecognised type — as " +
      "`read_inbox`, asserted with a fabricated future doorbell name in " +
      "`dod-m15-doorbell-1.test.ts`. Carried on BOTH surfaces because the tarball SKILL.md is the " +
      "one every previous audit missed (it is not source and was on nobody's list), which is why " +
      "the scanner enumerates package.json#files rather than trusting a list.",
  },
  {
    surface: "core/adapter-claude-code/SKILL.md",
    claim: "backup: 'a database without its key restores to something nobody can read, including you' / 'anyone holding that file can sign as this agent'",
    // NOT the "nobody can read" sentence, which is what this row used to be counted against. The
    // scanner's `\bnobody can\b` cannot match it: the two words straddle a line break in the
    // markdown, so the phrase is `nobody\ncan` and the regex never fires. The row was therefore
    // paying for a match that does not exist, and the surface's real hit here is `encrypted`.
    excerpts: ["It contains the agent's encrypted database"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Replaces a claim that had become FALSE — both shipped skills still said backup and restore " +
      "return `not_implemented`, which stopped being true when DOD-M15-BACKUP-1 landed. The new " +
      "text states properties of the artifact that unit builds: the archive carries the SQLCipher " +
      "key alongside the database (round-trip test restores into a directory with a different key " +
      "to prove it), so possession of the file is possession of the agent.",
  },
  {
    surface: "plugins/cello/skills/cello/SKILL.md",
    claim: "backup: same sentence, plugin copy",
    // NOT the "nobody can read" sentence, which is what this row used to be counted against. The
    // scanner's `\bnobody can\b` cannot match it: the two words straddle a line break in the
    // markdown, so the phrase is `nobody\ncan` and the regex never fires. The row was therefore
    // paying for a match that does not exist, and the surface's real hit here is `encrypted`.
    excerpts: ["It contains the agent's encrypted database"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Same text and same evidence as the tarball SKILL.md row above. Carried on BOTH surfaces " +
      "because the tarball copy is the one every previous audit missed — it is not source and was " +
      "on nobody's list, which is why the scanner enumerates package.json#files.",
  },
  {
    surface: "core/adapter-claude-code/SKILL.md",
    claim: "seal_failed: 'Your commitment is durable and the conversation is intact — the receipt was simply not produced.'",
    excerpts: ["a directory it cannot reach"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "DOD-M15-SEAL-FAILED-TERMINAL-1. Both halves are properties of code, not reassurance. " +
      "DURABLE: the close only reaches the background ceremony after `submitSealLeaf` succeeds — " +
      "the SEAL ctrl leaf is posted to the relay witness before the caller is answered, and a " +
      "re-close recovers that same leaf rather than posting a second one " +
      "(`#recoverOwnSealCtrlLeaf`), which is why a retry is safe. INTACT: a failed ceremony writes " +
      "nothing to the transcript and does not change session status — the session stays `active` " +
      "with its leaves, which is exactly why the restart seal resolver can still notarize it on a " +
      "later boot. The one operation that DOES destroy the receipt is force-abandon, and the same " +
      "guidance names it as the thing not to do.",
  },
  {
    surface: "plugins/cello/skills/cello/SKILL.md",
    claim: "seal_failed: same sentence, plugin copy",
    excerpts: ["a directory it cannot reach"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Same text and same evidence as the tarball SKILL.md row above. Carried on BOTH surfaces for " +
      "the same reason the backup rows are: the tarball copy is the one every hand-kept audit " +
      "missed, so an entry that covers only the source copy leaves the shipped one unadjudicated.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "backup: 'the snapshot is taken through SQLite, so it is never a half-written copy'",
    // Split out of the backup row above on review (F10). It was being PAID FOR by a row whose
    // evidence discusses key material and says nothing about snapshot atomicity — the claim is
    // true, which is exactly why it survived unexamined for a pass.
    excerpts: ["the snapshot is taken through SQLite, so it is never"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "`backup-restore.ts:158` performs the copy with SQLite's `VACUUM INTO`, which writes a " +
      "transactionally consistent snapshot of the database — so a backup taken while the daemon " +
      "holds the write lock cannot capture a torn page or a half-applied transaction. That is what " +
      "makes 'safe to run while the daemon is up' true rather than optimistic, and it matters " +
      "because the alternative an operator would otherwise reach for is copying the file, which " +
      "has none of that property.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "restore: 'Refusing without proof is deliberate — this operation replaces your agent.'",
    excerpts: ["Refusing without proof is "],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Review F4. The guard now uses `probeSingletonLock`, the kernel-authoritative check, and " +
      "refuses on BOTH `held` and `unknown`. It previously used readLock + isProcessAlive, which " +
      "returns null for absent AND unparseable and took the permissive branch on both — so a " +
      "stale, deleted or corrupt lock let a restore overwrite the database under a LIVE daemon. " +
      "`singleton-lock.ts` states the rule the old version broke: every stale-lock heuristic is an " +
      "attempt to guess what only the kernel knows.",
  },

  // ─── README.md — the public repo's front page. Swept by DOD-M15-LEDGER-1, → Entry S1. ─────────
  //
  // The most exposed surface in the milestone now that AUDIT-ME.md is deleted: it is the first
  // thing an evaluator with a coding agent reads, and every claim in it is checkable in minutes.

  {
    surface: "README.md",
    claim: "Headline: 'relayed as encrypted blobs the relay cannot read'",
    excerpts: ["relayed as encrypted blobs the relay cannot read"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "The relay is a blind witness by construction, not by policy. It is bound to a session with " +
      "both participants' pubkeys and receives signed content HASHES, and verifying a signature " +
      "against a known pubkey never requires reading content — which is why the corroboration work " +
      "in `DOD-M15-CORROBORATE-1` can be added without weakening this. Live content additionally " +
      "travels inside libp2p's Noise session, so the relay is carrying ciphertext it holds no key " +
      "for. Scope kept honest: this says the relay cannot read CONTENT. It does see who talks to " +
      "whom, when, how often and how big — disclosed as a bounded property by `DOD-M15-DISCLOSE-1` " +
      "rather than left for a reader to discover.",
  },
  {
    surface: "README.md",
    claim: "'ONE encrypted database' / 'the encrypted database' / 'inside the encrypted DB' (four places)",
    excerpts: [
      "encrypted database); **`connect`**",
      "**Creates ONE encrypted database**",
      "inside the encrypted DB",
      "key material, and the encrypted database",
    ],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Whole-file SQLCipher, and the claim is stronger than it looks because there is no second " +
      "home for key material to leak into: `db-identity-store.ts` keeps the Ed25519 seed, the " +
      "FROST share, the ML-DSA keypair and the registration record in the `agents` table and its " +
      "header states 'There is no flat-file home for any of it.' The daemon opens the file through " +
      "`sqlcipher-db.ts`, and this project forbids `node:sqlite` repo-wide precisely because it " +
      "stores plaintext — the eslint rule is the enforcement, not the comment.",
  },
  {
    surface: "README.md",
    claim: "Close produces 'a tamper-evident seal.'",
    excerpts: ["tamper-evident seal."],
    enforcedBy: "directory",
    verdict: "corrected",
    evidence:
      "Said 'a tamper-evident bilateral seal', which promises the good case as the guarantee. " +
      "`seal-escalation.ts:219` returns `seal_type: \"unilateral\"` when the counterparty never " +
      "comes back, and `close-session-handler.ts:379` carries that variant on the success type — " +
      "so the wire already distinguishes them and the README was the only surface still " +
      "universalising. The IDENTICAL overclaim was corrected at the CLI surface by an earlier " +
      "entry in this file; leaving the public front page contradicting `cello --help` is worse " +
      "than either wording alone. Two further instances of the same word fixed in the same pass: " +
      "the tools list's 'close and bilaterally seal' and the sealed-receipt description.",
  },
  {
    surface: "README.md",
    claim: "sealed-receipt: 'the notarized seal'",
    excerpts: ["— the notarized seal"],
    enforcedBy: "directory",
    verdict: "corrected",
    evidence:
      "Said 'the notarized bilateral seal' — false for exactly the receipt an operator is most " +
      "likely to be holding when something went wrong, which is the same failure mode the CLI's " +
      "own sealed-receipt summary was corrected for earlier in this file. `seal_type` is present " +
      "on both the escalation and close-handler success variants, so the receipt can state which " +
      "kind it is rather than the description promising the stronger kind.",
  },
  {
    surface: "README.md",
    claim: "'Not yet implemented — registered but the daemon returns not_implemented': inclusion-proof",
    excerpts: ["inclusion-proof <session-id>"],
    enforcedBy: "daemon-local",
    verdict: "corrected",
    evidence:
      "THE CLAIM WAS FALSE IN THE UNDERSTATING DIRECTION, which is the case a claims audit is " +
      "least likely to look for — and it was the most consequential instance in the file. The " +
      "block listed `backup · restore · inclusion-proof`, but the daemon's not_implemented stub " +
      "loop at `daemon.ts:3926` covers exactly ONE tool, `cello_get_inclusion_proof`. `backup` and " +
      "`restore` are fully built (`registry.ts:345,375` call `createBackup`/`restoreBackup`; " +
      "`DOD-M15-BACKUP-1` is closed and reviewed). So the README told operators 'Don't build on " +
      "these yet' about the only feature that prevents permanent identity loss — five lines under " +
      "its own sentence 'losing them means losing your identity', which also still said automated " +
      "backup was unimplemented. Both places corrected; inclusion-proof stays listed because it " +
      "genuinely is the one tool in that stub loop.",
  },
  {
    surface: "README.md",
    claim: "Read-before-write: \"You can't reply to something you never saw.\"",
    excerpts: ["never saw."],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "`session-content-handlers.ts:246` returns `reason: \"session_not_current\"` on the send " +
      "path when unread inbound content exists, so the refusal is real code and not a convention. " +
      "`vocabulary.ts:297` records that the reason string is a stable contract scripts branch on. " +
      "The adapter's own `_fetch_content` docstring documents the live consequence of the gate " +
      "(session 9bc456f6, 2026-08-07: a reply refused and lost because the connection had not " +
      "drained), which is evidence the gate fires in production rather than only in tests.",
  },
  {
    surface: "README.md",
    claim: "'the cello_* tools remain available for the things a conversation cannot do'",
    excerpts: ["the things a conversation cannot do"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Not a security claim — an operational statement about which verbs exist outside the bridge's " +
      "delivery path, and it is checkable because it names them. All four are registered MCP tools " +
      "in `cello-mcp.ts`: `cello_initiate_session`, `cello_close_session`, `cello_status`, " +
      "`cello_sessions`. Counted rather than waved through because 'cannot' is claim vocabulary " +
      "wherever it appears, and because a list of verbs is exactly the kind of prose that goes " +
      "stale silently when a tool is renamed — the defect that shipped in the connect tarball's " +
      "SKILL.md once already.",
  },
  {
    surface: "README.md",
    claim: "Bridge: 'the daemon's security gateway screens inbound content on the same path either way… not whether they are screened.'",
    excerpts: ["The bridge changes which door the screened bytes", "not whether they are screened."],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The claim is COMPARATIVE — the bridge does not change whether screening happens — and that " +
      "is what holds. The Hermes adapter reaches content only by calling `cello_receive` on its " +
      "own daemon socket (`assets.ts` `_fetch_content`, docstring: 'the peer's screened words'), " +
      "so it is downstream of whatever the daemon already did; it adds no ingest path of its own. " +
      "The gateway is also non-optional — `daemon.ts:365` refuses to start without one (INV-9) " +
      "rather than defaulting to a permissive stub. **CORRECTED ON REVIEW: an earlier version of " +
      "this row said `session-node-manager.ts:6326` is the routine 'every inbound message passes " +
      "through'. That is false and the row must not rest on it.** There are three `screenInbound` " +
      "call sites (`session-node-manager.ts:6326`, `daemon.ts:4454`, `content-park.ts:200`), and " +
      "at `session-node-manager.ts:6316` a DOCUMENT FRAME skips screening entirely " +
      "(`isDocFrame ? { disposition: \"allow\", content } : await screenInbound(...)`). The " +
      "conclusion survived on evidence that did not support it, which is the laundering shape this " +
      "ledger exists to prevent — a row whose premise is false is a row nobody can re-check.",
  },
  {
    surface: "README.md",
    claim: "session_scope peer: 'two customers must never end up in one context'",
    excerpts: ["two customers must never end up in one"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "`assets.ts` `_chat_id_for` returns `agent_name + \"/\" + counterparty` under `peer` scope, " +
      "and its docstring states the counterparty key is the PUBKEY, 'Never the moniker: a moniker " +
      "is a mutable display label and reusable after retirement' — the project's stable-key rule " +
      "applied in the one place where getting it wrong silently MERGES two customers' contexts, " +
      "which is the exact harm the sentence promises against. Correctly scoped in the README too: " +
      "the default `agent` scope deliberately shares one conversation and the text says so.",
  },
  {
    surface: "README.md",
    claim: "'a setting you cannot see in the command you just typed is a setting you will be surprised by later'",
    excerpts: ["a setting you cannot see in the command you just"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Design rationale, and the behaviour it describes is real: `install-hermes.ts:171` calls " +
      "`upsertEnvLine(envPath, \"CELLO_SESSION_SCOPE\", sessionScope)` on every run with the " +
      "resolved value, so omitting a flag rewrites the default rather than preserving a previous " +
      "install's value. The adapter also refuses a typo instead of falling back — `_invalid_settings` " +
      "rejects an unknown scope, whose docstring says 'session_scope: pear' must not quietly run " +
      "as the default.",
  },
  {
    surface: "README.md",
    claim: "'A session name is private to you — never sent to the counterparty, the relay, or the directory'",
    excerpts: ["**private to you** — never sent to the counterparty"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Verified STRUCTURALLY rather than by inspection of send sites, which is what makes it hold " +
      "against future edits: `session_name` appears in no wire type in `core/protocol-types/src`, " +
      "so there is no field for it to travel in. It is a local column on the sessions table " +
      "(`session-node-manager.ts`), documented as never entering a frame, the transcript, the seal " +
      "or a Merkle leaf. Re-confirmed here rather than inherited from the earlier prose ledger row.",
  },
  {
    surface: "README.md",
    claim: "contact set-moniker: 'YOUR pet name for THEM (they cannot spoof it)'",
    excerpts: ["YOUR pet name for THEM (they cannot spoof it)"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The claim needs checking precisely because a peer's OWN moniker does cross the wire — " +
      "`protocol-types/src/moniker.ts` calls it 'a WIRE CONTRACT: the moniker crosses the wire on " +
      "the session offer'. What makes the sentence true is that the two are separate columns and " +
      "the inbound path cannot reach the local one: `recordOfferedMoniker` " +
      "(`session-node-manager.ts:2413`) writes only `last_offered_moniker` and the notice queue, " +
      "under a docstring stating 'The stored local pet name (contacts.moniker) is SACROSANCT'. A " +
      "peer renaming itself raises a NOTICE to the operator; it never edits what they see.",
  },

  // ─── core/cli/src/registry.ts — the sentences printed at the moment an operator acts. ─────────
  // Swept by DOD-M15-LEDGER-1, → Entry S1. Higher stakes than a README: a claim read at the point
  // of action is acted on harder than one read while browsing.

  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "close-session help: 'Each gets a notarized receipt.'",
    excerpts: ["Each gets a notarized receipt"],
    enforcedBy: "directory",
    verdict: "corrected",
    evidence:
      "THE CORRECTION HAD BEEN MADE ONE LINE ABOVE AND NOT PROPAGATED. An earlier entry in this " +
      "file corrected close-session's SUMMARY off 'tamper-proof'/'both sides sign off', and its " +
      "reasoning cited the help text as the thing the summary was overclaiming against — but the " +
      "help itself still read 'Both parties sign off on the whole conversation', the identical " +
      "universal. `seal-escalation.ts:219` returns `seal_type: \"unilateral\"`. A partial " +
      "correction inside one command is worse than none: the summary and the help now disagreed, " +
      "so whichever the operator read, one of them was lying.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "contact set-tier: screening 'runs on inbound and outbound content at every tier. Its semantic layer… needs a classifier model that is not installed by default, so what runs today is the pattern layer.'",
    // NO EXCERPTS, and that is now arithmetic rather than an argument. The correction DELETED the
    // vocabulary word it was made for: the line reads "It does NOT change content screening." and
    // "screening" is not in the vocabulary ("screened" is). A row that accounts for nothing
    // subtracts nothing. It stays because the REASONING is the durable record — see the evidence.
    excerpts: [],
    enforcedBy: "daemon-local",
    verdict: "corrected",
    evidence:
      "Said 'that is ACTIVE at every tier, in both directions' — the unqualified form " +
      "`DOD-M15-CLAIM-SCREEN-1` withdrew from the MCP tool description and the two shipped " +
      "SKILL.md copies, left standing on the CLI. `installModel` (`gateway/src/detect/" +
      "model-installer.ts:83`) is exported and has no production caller, so the semantic layer " +
      "cannot be installed on any operator's machine (`DOD-M15-SCREENINSTALL-1`). Partially true " +
      "is false. Scope copied from the README's already-adjudicated wording rather than invented, " +
      "so the two surfaces now say the same thing. NOTE what the replacement deliberately does " +
      "NOT say: an earlier draft of this correction ended '…cello status reports which layers " +
      "loaded'. `cello_status`'s handler (`daemon.ts:3688`) reports no such thing — the only " +
      "record is a `security.gateway.connected` log line at `daemon.ts:378`, and a log is not a " +
      "control. Naming it would have been Invariant 4's blocking defect (guidance naming a " +
      "surface that does not exist), written INSIDE the unit that audits claims.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "The ledger's own correction note: \"This said 'proof both sides signed off'\"",
    excerpts: ["proof both sides signed off"],
    enforcedBy: "nobody-yet",
    verdict: "corrected",
    evidence:
      "Not a live claim — it is the SOURCE COMMENT recording a claim this ledger already " +
      "withdrew, quoting the old false text so a later reader knows it was believed. It is " +
      "counted because the extractor takes any string literal of three or more words, including " +
      "inside comments, and its docstring says over-including is the right direction to err. " +
      "Worth recording as a shape rather than waving through: the scanner CHARGES A CLAIM for " +
      "keeping the audit trail of a withdrawn claim, which is the same pressure as charging for " +
      "disclosure — it rewards deleting the correction note. Left in place and paid for here.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "sealed-receipt help: unilateral 'carries YOUR account… but not their agreement' / 'attests RECEIPT, never agreement (implies_assent: false)… never as consent.'",
    excerpts: [
      "It attests RECEIPT, never agreement (implies_assent: false)",
      "reads as delivered-but-unanswered, never as consent.",
    ],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "The strongest disclosure in the CLI and it holds: `implies_assent: false` is a real field, " +
      "not a turn of phrase, and the unilateral variant is a distinct type " +
      "(`close-session-handler.ts:379`, `seal-escalation.ts:70`) rather than a flag on the " +
      "bilateral one — so a caller cannot read a unilateral receipt as bilateral by ignoring a " +
      "boolean. This matters more than it reads: a receipt that silently implied consent would " +
      "turn an unanswered message into evidence of agreement, which is the one thing a " +
      "notarization product must never do.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "close-session --force: 'abandons a half-open session that can never be sealed… It FORFEITS the receipt — never use it on a healthy session.'",
    excerpts: [
      "a half-open session that can never be sealed",
      "never joined). It FORFEITS the receipt — never use it on a healthy session.",
    ],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Accurate and load-bearing: an operator who read a slow close as a hang force-abandoned " +
      "SEVENTEEN sessions on 2026-08-17, forfeiting every receipt the wait was earning — the " +
      "incident behind `DOD-M15-CLOSEWAIT-1`. The warning is therefore not boilerplate; it " +
      "describes a loss that has actually happened. 'can never be sealed' is correctly narrow: it " +
      "names the half-open handshake case, and `DOD-M15-INTERRUPTED-1` covers the separate case " +
      "of an interrupted session that CAN still seal, so the two are not conflated here.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "--session-name / name-session: 'PRIVATE — never sent to the counterparty, the relay, or the directory' and 'cannot change anything the protocol does' (three places)",
    excerpts: [
      "It is PRIVATE — never sent to the counterparty",
      "The name is PRIVATE: never sent to the counterparty",
      "cannot change anything the protocol does",
    ],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Verified structurally, which is what makes it survive future edits: `session_name` appears " +
      "in NO wire type in `core/protocol-types/src`, so there is no field it could travel in. It " +
      "is a local column on the sessions table whose comment records that it never enters a frame, " +
      "the transcript, the seal or a Merkle leaf. The same three sentences appear on close-session, " +
      "name-session and the README, and all three say the same thing — consistency checked rather " +
      "than assumed, because the close-session/help divergence above shows this repo can correct " +
      "one copy and leave another.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "dismiss: 'Sets a local read_at timestamp — never propagated, never part of the seal or hash chain.'",
    excerpts: ["never propagated, never part of the seal or hash chain."],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Structural again: `read_at` appears in no type under `core/protocol-types/src`, so it " +
      "cannot be propagated — there is no wire field for it. It is an epoch-ms column on the " +
      "sessions table added by `DOD-SEALED-INBOX-1`, whose own comment states it is never part of " +
      "the seal ceremony or hash chain and is distinct from the read watermark (it records " +
      "'operator acknowledged via dismiss', not 'operator received via cello_receive').",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "inbox: 'pending session requests and unread message COUNTS — never message content'",
    excerpts: ["unread message COUNTS — never message content"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The distinction is the whole point of the command and it is real: reading content is what " +
      "advances the per-connection cursor that the read-before-send gate " +
      "(`session-content-handlers.ts:246`, `session_not_current`) tracks, so an inbox that " +
      "returned content would silently consume the unread state an operator was trying to inspect " +
      "without consuming. The README states the same property in the same words.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "set-agent-offline: 'The agent becomes UNREACHABLE: inbound sessions are refused and it cannot even send an away message.'",
    excerpts: ["inbound sessions are refused and it cannot even send an away"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The claim's value is the CONTRAST it draws, and the contrast is real: away messages are " +
      "sent by a running agent's own daemon path (`daemon.ts:1489` screens the away draft through " +
      "`screenOutbound`), so an agent that is not started has nothing to send them with — " +
      "`daemon.ts:2990` refuses with `agent_offline` rather than falling back to an away reply. " +
      "The help names the right alternative for the softer case, `cello stop-using-agent`, which " +
      "is a real command in this same registry.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "doc remove: 'You cannot remove a fellow admin this way, and there is no demote command to reach for: demotion needs every other admin's signature and that verb is not built.'",
    excerpts: ["You cannot remove a fellow admin this way"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Verified by attempted falsification, because 'that verb is not built' is exactly the kind " +
      "of sentence that goes stale silently: grep for `demote(` across `core/**` returns nothing " +
      "outside comments, and `document-handlers.ts:1131` documents the refusal with the same " +
      "reasoning ('demote first, under remove_admin's all-others rule — whose cross-daemon " +
      "signature gathering is a parked design note'). This is a claim about an ABSENCE and it " +
      "names its own remedy's absence too, which is rarer and better than the usual shape.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "doc propose --retry: 'Re-send an offer that was created but never reached them'",
    excerpts: ["Re-send an offer that was created but never reached them"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Operational, and the flag it describes exists rather than being aspirational prose: " +
      "`registry.ts:1235` declares `{ name: \"--retry\", consumesValue: true }` and " +
      "`registry.ts:1296` reads it with `takeValueFlag(rest, \"--retry\")`. Checked because a " +
      "help string naming a flag that was renamed or dropped is the precise defect that shipped " +
      "in the connect tarball's SKILL.md, which named three tools that no longer existed.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "'Quoting is only needed if a value contains spaces (agent names and tokens never do).'",
    excerpts: ["(agent names and tokens never do)"],
    enforcedBy: "structural",
    verdict: "true",
    evidence:
      "Enforced by a shared charset rule rather than by convention: `protocol-types/src/moniker.ts` " +
      "is the single home of `MONIKER_RE`, which governs agent names and monikers alike and is " +
      "described there as a WIRE CONTRACT, and `validateMoniker` is applied on the write paths " +
      "(`addContact`/`setContactMoniker` throw on a non-matching value). A space cannot reach a " +
      "stored agent name, so the parenthetical is a property of the code and not advice.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "doc propose: 'for a running log; it does NOT make the document tamper-evident.'",
    excerpts: ["it does NOT make the document tamper-evident"],
    enforcedBy: "nobody-yet",
    verdict: "true",
    evidence:
      "A DISCLAIMER rather than a claim, and the right one — it withdraws a property a reader " +
      "would otherwise import from the seal vocabulary used everywhere else in this CLI. Recorded " +
      "here rather than skipped because the ledger's job is both directions: `DOD-M15-LEDGER-1`'s " +
      "review found the costly miss was a claim false in the UNDERSTATING direction, so a sentence " +
      "that correctly declines a property is exactly as much a ledger row as one that asserts it.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "relay fallback: 'When a message cannot go directly to the other agent (they are offline, or the network is in the way)…'",
    excerpts: ["When a message cannot go directly to the other agent"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Describes the content-park path, which is real and is deliberately unauthenticated on " +
      "deposit — safe because a sender signature sits inside the seal, as the relay audit records. " +
      "The sentence is careful in a way worth preserving: it names two causes (peer offline, " +
      "network in the way) rather than asserting which one applies, and Invariant 3 exists " +
      "because a single string, `counterparty_offline`, was once returned for three unrelated " +
      "causes and cost most of a day.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "set-tier: 'A higher tier RAISES their limits; it never removes the caps.' / set-signal: 'Can only narrow: it never presents something you have not accepted.'",
    excerpts: ["it never removes the caps", "Can only narrow: it never"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "The set-signal half is enforced positively, which is why the universal is safe: every read " +
      "path selects on `consent_state = 'accepted'` (`trust-signal-store.ts:695,810,843`, the " +
      "`consented` check at :558, and `daemon.ts:2885`). A positive predicate cannot be widened by " +
      "a per-contact override — the override can only subtract from an already-accepted set. Had " +
      "the gate been written negatively (`<> 'refused'`) the same sentence would have been false.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "attestation-consent refuse: 'it stays inert and is never presented' / 'a refused signal is indistinguishable from one that was never issued, everywhere it is checked.'",
    excerpts: [
      "it stays inert and is never presented",
      "is indistinguishable from one that was never issued, everywhere it is checked",
    ],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "'Everywhere it is checked' is a universal, so it was checked as one rather than sampled. It " +
      "holds for a structural reason: every consumer gates POSITIVELY on " +
      "`consent_state = 'accepted'` — `trust-signal-store.ts:695,810,843` in SQL, :558 in code, " +
      "and `daemon.ts:2885` — so a `refused` row fails the same predicate a `pending` row and a " +
      "missing row fail. There is no path that tests for refusal, which is what makes the " +
      "indistinguishability total instead of a list someone must keep complete.",
  },
  /**
   * WITHDRAWN FROM THE LEDGER ON REVIEW — `registry.ts`: *"You cannot attest about yourself."*
   *
   * It was adjudicated `true`, and the evidence I wrote for it described the CONSENT gate
   * (`consent_state = 'accepted'`, signals born `pending` for `issuerKind === "agent"`). That is a
   * real mechanism and it makes an unaccepted attestation invisible — **it says nothing about who
   * may issue one.** Evidence establishing X for a claim about Y is the shape a review of this unit
   * caught twice elsewhere, and this is the third.
   *
   * Searching for the enforcement point finds **only the sentence itself**. There is no
   * self-attestation refusal anywhere in `core/`: the nearest authorization check,
   * `trust-signal-store.ts:588`, compares an envelope's issuer against the signal's recorded issuer,
   * which is a different question. Either the PORTAL refuses it — a repo this lane has not read —
   * or nothing does.
   *
   * So the match goes BACK IN THE BACKLOG and the registry baseline rises by one. That is the whole
   * point of the three states: a claim I cannot settle is unadjudicated, not quietly true. Settling
   * it needs someone to read the portal's issuance path.
   */
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "trust-signals: 'verifiable claims about you… issued by the CELLO portal, notarized by the directory, and held in your local encrypted wallet.'",
    excerpts: [
      "Trust signals are verifiable claims about you",
      "agent presents to contacts during sessions. They are issued by the CELLO portal, notarized by",
      "the directory, and held in your local encrypted wallet",
    ],
    enforcedBy: "directory",
    verdict: "true",
    evidence:
      "Three separate properties, each with a home. 'Held in your local encrypted wallet' is the " +
      "`wallet_trust_signals` table inside the SQLCipher database (`trust-signal-store.ts:207`), " +
      "so 'encrypted' is whole-file encryption and not a claim about a separate envelope. " +
      "'Notarized by the directory' is consistent with the no-PII rule: the directory holds and " +
      "replicates a sealed blob it has no private key for (`signal-submission.ts:239` seals to the " +
      "PORTAL's intake key, per the earlier attestations row). 'Verifiable' is the weakest word " +
      "here and is scoped by its own examples — GitHub account age, phone, email — which are " +
      "claims the portal attests to, not properties CELLO proves.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "moniker: 'the one thing they cannot spoof' / 'It is a HINT, not proof — like caller ID… shown it as self-declared'",
    excerpts: ["name they offer — the one thing they cannot spoof", "It is a HINT, not proof"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "These two sentences are about DIFFERENT monikers and both are right, which is why they can " +
      "sit near each other without contradiction. The peer's self-declared moniker crosses the " +
      "wire (`protocol-types/src/moniker.ts`: 'a WIRE CONTRACT: the moniker crosses the wire on " +
      "the session offer') and is correctly called a hint. The operator's own pet name for them " +
      "cannot be touched from the wire: `recordOfferedMoniker` " +
      "(`session-node-manager.ts:2413`) writes only `last_offered_moniker` and a rename notice, " +
      "under a docstring stating the local `contacts.moniker` is SACROSANCT.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "doc write: 'your offsets cannot go stale under an edit the peer made while you were typing' / 'editing a shared document never depends on the peer being reachable'",
    excerpts: ["so your offsets cannot go stale", "editing a shared document never depends on the"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "Both are consequences of the same design rather than two promises: edits are applied " +
      "against local state and forwarded by a background worker when the peer is reachable " +
      "(`document-handshake.ts` and the doc handlers), so reachability is a delivery property and " +
      "not an editing precondition. The offsets claim is the stronger of the two and is the one " +
      "an evaluator would test, because 'cannot go stale' is absolute — it holds because the " +
      "offset is resolved against the caller's own state at apply time, not against a shared " +
      "cursor the peer can move.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "policy log: 'Every screened message and what happened to it: clean, redacted, blocked or warned… chainValid: false means the log itself was tampered with'",
    excerpts: ["Every screened message and what happened to it"],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "'Every' is a completeness claim, and CORRECTED ON REVIEW: an earlier version of this row " +
      "rested it on there being ONE ingest path (`session-node-manager.ts:6326`). That premise is " +
      "false — there are three `screenInbound` call sites and a document frame skips screening " +
      "entirely at `session-node-manager.ts:6316`. The claim survives for a BETTER reason, which " +
      "is why the citation had to move: recording does not happen at any ingest path at all. " +
      "`cello-gateway.ts:184,199` call `recordOutcome` for outbound and inbound inside the gateway " +
      "itself, synchronously before the verdict is returned (`gateway/src/server.ts:13` states " +
      "exactly that ordering) — so anything the gateway screens is recorded by construction, " +
      "however many callers there are. The `chainValid` half is the " +
      "sharper sentence and it is the right instruction — it tells the reader to STOP reasoning " +
      "from the log rather than to interpret it, which is the correct response to a hash-chain " +
      "break and the opposite of the 'detection that does not act' pattern this milestone exists " +
      "to remove. `DOD-M15-CHAINHEALTH-1` is the line that makes this checkable without SSH.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "bridge hermes: 'where two customers must never share a context.'",
    excerpts: ["where two customers must never share a context."],
    enforcedBy: "daemon-local",
    verdict: "true",
    evidence:
      "`assets.ts` `_chat_id_for` returns `agent_name + \"/\" + counterparty` under `peer` scope, " +
      "keyed on the PUBKEY — its docstring says 'Never the moniker: a moniker is a mutable display " +
      "label and reusable after retirement', applying the project's stable-key rule in the one " +
      "place where getting it wrong silently MERGES two customers' contexts. The adapter also " +
      "refuses an unrecognised scope rather than falling back to the default, so a typo cannot " +
      "quietly deliver the shared-context behaviour the sentence warns against.",
  },
];

/**
 * DELIBERATELY NOT ADJUDICATED, and worth saying why rather than leaving a silent gap.
 *
 * The same attestation sentence also says the submission is **"screened"**. That screening happens
 * in the PORTAL, a different repo and a different component from the daemon's security gateway, and
 * I have not read it. `DOD-M15-CLAIM-SCREEN-1` was opened precisely because a screening claim was
 * being repeated on surfaces nobody had checked against the code, in both directions.
 *
 * So it stays in the unadjudicated backlog. Moving it here without reading the portal would be the
 * prose ledger's original defect — a row recording that somebody looked, rather than what they
 * found — reproduced inside the mechanism built to replace it.
 */

/** Vocabulary hits a single row accounts for — derived from its verbatim text, never typed. */
export function rowMatches(a: AdjudicatedClaim): number {
  return a.excerpts.reduce((n, e) => n + countClaimWords(e), 0);
}

/** How many matches on a surface are accounted for by adjudicated entries. */
export function adjudicatedMatches(surface: string): number {
  return ADJUDICATED.filter((a) => a.surface === surface).reduce((n, a) => n + rowMatches(a), 0);
}
