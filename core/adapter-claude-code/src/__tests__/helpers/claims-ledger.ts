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
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "refresh: 'CELLO never holds your whole signing key in one place — it is split into shares held with the directory nodes.'",
    matches: 1,
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
    matches: 1,
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
    matches: 1,
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
    matches: 2,
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
    matches: 1,
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
    matches: 1,
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
    matches: 1,
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
    matches: 1,
    verdict: "true",
    evidence:
      "Same text and same evidence as the tarball SKILL.md row above. Carried on BOTH surfaces " +
      "because the tarball copy is the one every previous audit missed — it is not source and was " +
      "on nobody's list, which is why the scanner enumerates package.json#files.",
  },
  {
    surface: "core/adapter-claude-code/SKILL.md",
    claim: "seal_failed: 'Your commitment is durable and the conversation is intact — the receipt was simply not produced.'",
    matches: 1,
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
    matches: 1,
    verdict: "true",
    evidence:
      "Same text and same evidence as the tarball SKILL.md row above. Carried on BOTH surfaces for " +
      "the same reason the backup rows are: the tarball copy is the one every hand-kept audit " +
      "missed, so an entry that covers only the source copy leaves the shipped one unadjudicated.",
  },
  {
    surface: "core/cli/src/registry.ts (operator-facing strings)",
    claim: "restore: 'Refusing without proof is deliberate — this operation replaces your agent.'",
    matches: 1,
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
    matches: 2,
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
    matches: 4,
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
    claim: "Close produces 'a tamper-evident seal — bilateral when the counterparty is there to co-sign, unilateral when they are not, and the receipt says which.'",
    matches: 1,
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
    claim: "sealed-receipt: 'the notarized seal, and whether it is bilateral or unilateral'",
    matches: 1,
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
    matches: 1,
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
    matches: 1,
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
    matches: 1,
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
    matches: 2,
    verdict: "true",
    evidence:
      "The bridge does not introduce a second ingest path. `session-node-manager.ts:6326` calls " +
      "`securityGateway.screenInbound(content, …)` inside the content-ingest routine every inbound " +
      "message passes through, and the Hermes adapter reaches content only by calling " +
      "`cello_receive` on its own daemon socket (`assets.ts` `_fetch_content`, whose docstring " +
      "calls them 'the peer's screened words'). The gateway is also non-optional: `daemon.ts:365` " +
      "refuses to start without one (INV-9) rather than defaulting to a permissive stub. NOTE the " +
      "bound this row does NOT assert: it says screening RUNS on this path, not that screening is " +
      "complete — the semantic layer is still uninstallable (`DOD-M15-SCREENINSTALL-1`) and that " +
      "scope is stated separately in the Contacts section.",
  },
  {
    surface: "README.md",
    claim: "session_scope peer: 'two customers must never end up in one context'",
    matches: 1,
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
    matches: 1,
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
    matches: 1,
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
    matches: 1,
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

/** How many matches on a surface are accounted for by an adjudicated entry. */
export function adjudicatedMatches(surface: string): number {
  return ADJUDICATED.filter((a) => a.surface === surface).reduce((n, a) => n + a.matches, 0);
}
