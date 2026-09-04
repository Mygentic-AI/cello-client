/**
 * 024-ORPHANTRIAGE — what an operator is told when a message arrives for a conversation this
 * machine has no record of.
 *
 * ─── What was wrong, from the operator's chair ─────────────────────────────────────────────────
 *
 * The notice used to end *"ask the counterparty to start a NEW session"*. Somebody sends a message
 * naming a conversation you have never had, we refuse it, and we advise you to go and talk to them.
 * If that message came from a stranger who guessed or harvested your peer id, **making contact is
 * the thing they sent it for**: it confirms somebody is home and that your agent answers. The
 * refusal was correct and the advice handed the sender the one thing the refusal denied them.
 *
 * ─── There are exactly TWO actions, and never a third ──────────────────────────────────────────
 *
 * **Report it** — the default, and the only action unless every condition below holds. **Reach out
 * in a SEPARATE conversation** — only when the message carries a signature that verifies, against a
 * key the operator has deliberately vouched for, in a conversation this machine still holds part
 * of. Waiting, replying into the named conversation, deleting and ignoring are not offered, because
 * an affordance list is a menu and a menu is how the wrong option gets picked.
 *
 * ─── Why the signals are read the way they are ─────────────────────────────────────────────────
 *
 * Every input here is anchored on something the sender does NOT control:
 *
 *  - the signature is checked against the key carried inside the sender's own signed bytes, so it
 *    proves **possession of a private key** and nothing else — never an identity;
 *  - "known" is a TIER, not a row: an inbound offer writes an `UNKNOWN`-tier contact row from the
 *    wire with no operator action, so a row means "somebody dialled", and only `KNOWN` or above
 *    means the operator vouched;
 *  - "ongoing" is read from the operator's own transcript rows, never from the sequence number the
 *    sender chose to write.
 *
 * ─── Deliberately a pure function ──────────────────────────────────────────────────────────────
 *
 * Same reason as `parkRefusalGuidance`: a guidance string is a decision about what a person does
 * next, and the branch that is WRONG is the one nothing cheap can reach. Every sentence below is
 * assertable without a database, a daemon or a socket.
 */

/** The only two actions this triage ever names. A third would be a menu. */
export const ORPHAN_ACTIONS = {
  /** Tell CELLO. The default, and the whole answer whenever the sender cannot be established. */
  REPORT: "report",
  /** Open a SEPARATE conversation with the key — never the one the message names. */
  REACH_OUT_NEW_CONVERSATION: "reach_out_new_conversation",
} as const;
export type OrphanAction = (typeof ORPHAN_ACTIONS)[keyof typeof ORPHAN_ACTIONS];

/**
 * A signal that was never measured, kept apart from one measured `false`.
 *
 * Review F6: these two used to be `false` on every path that did not look, and the orphan log event
 * then published them as readings. Somebody filtering that event days later would read
 * `ongoingConversation: false` and conclude there was no local trace, when nothing had been asked.
 */
export const NOT_CHECKED = "not_checked";
export type Signal = boolean | typeof NOT_CHECKED;

/**
 * The three signals, computed at the orphan branch from evidence the daemon already holds.
 *
 * `signerPubkeyHex` is the gate: `null` means no signature could be checked at all, and everything
 * below it is then meaningless — a claimed key is a string anyone can type.
 */
export interface OrphanEvidence {
  /**
   * The key whose signature over the sender's own signed bytes VERIFIED — full hex, never
   * truncated. `null` when the frame carried no readable signed record, which is a finding and not
   * a missing field.
   */
  signerPubkeyHex: string | null;
  /**
   * Has the operator VOUCHED for that key — tier `KNOWN` or above? Read from OUR store, not from
   * the message, and never from the mere existence of a row: an inbound offer writes an
   * `UNKNOWN`-tier row from the wire, and blocking a contact leaves its row in place at `BLOCKED`.
   */
  knownContact: Signal;
  /** The operator's own pet name for that key, when they have set one. */
  contactMoniker: string | null;
  /**
   * Do we still hold part of this conversation locally? Anchored on OUR transcript rows — never on
   * the sequence number the sender supplied, which they are free to invent.
   */
  ongoingConversation: Signal;
}

export interface OrphanTriage {
  action: OrphanAction;
  impact: string;
  guidance: string;
}

/**
 * The sentence that catches the operator who is unsure, and it is in EVERY case.
 *
 * The three signals are probabilistic: a vouched key can be stolen, a local trace can belong to a
 * conversation someone has taken over mid-flight, and an operator standing here has no way to
 * resolve it. Reporting costs them nothing and costs an attacker their anonymity, so uncertainty
 * resolves to report — and it is needed most in the reach-out case, where the temptation to act
 * alone is highest.
 */
export const WHEN_IN_DOUBT = "When in doubt, report it: reporting costs you nothing and costs whoever sent this their anonymity.";

/**
 * ⛔ REPORTING IS NOT REACHABLE YET, AND SAYING SO IS THE POINT.
 *
 * The destination is meant to be a CELLO agent — `CELLO_Reporting` — that any operator's agent
 * opens a session with, which is the product demonstrating its own use. It does not exist: it needs
 * a registered identity, somewhere to run, and a pubkey published in shipped guidance, and that
 * last part is outward-facing wording. Naming a verb that resolves to nothing is exactly what
 * Invariant 4 forbids, so this says plainly that there is nowhere to send it and names the one
 * thing the operator CAN do — keep the evidence.
 *
 * ⚠️ **THE EVIDENCE DIFFERS BY CASE, AND SAYING "the public key" ALWAYS WAS WRONG** — review F4.
 * In the unsigned case the impact has just finished explaining that any key on the message is a
 * string somebody typed; telling the operator to write it down as evidence in the next breath asks
 * them to record an unverified claim in the one case the paragraph above taught them not to.
 *
 * ⚠️ **"the time" IS NOT ON THE SURFACE** — review F9. The inbox projection carries session, reason,
 * kind, impact, guidance and count; `first_at`/`last_at` exist in the table and are not selected. So
 * the sentence names the time the reader has, which is the time they are reading.
 *
 * ⛔ TRIGGER: when `CELLO_Reporting` is provisioned and its pubkey is published, this becomes the
 * session-open verb and its pubkey. Do not soften it before then.
 */
export function reportingNotYetAvailable(signerPubkeyHex: string | null): string {
  const evidence = signerPubkeyHex === null
    // No key is named, deliberately. The only key-shaped thing here is the one the message claimed,
    // and the impact has just said that claim proves nothing.
    ? "the conversation id above, the time you are reading this, and the fact that the message carried no signature anyone could check"
    : `the public key above, the conversation id, and the time you are reading this`;
  return `CELLO has no agent to receive reports yet, so there is no command here that would send one. Write down ${evidence} — that IS the report — and keep it until there is somewhere to send it.`;
}

/**
 * ✅ **THE TRIGGER FIRED, AND THE SENTENCE MOVED RATHER THAN BEING REWRITTEN IN PLACE.**
 *
 * This module used to define `MESSAGE_NOT_RETAINED`: *"The message itself was not kept — this build
 * discards what it refuses."* `023-REFUSEDEVIDENCE` made that false, and 024's own note asked for a
 * rewrite rather than a deletion so a reader can see the claim changed. Recorded here; the
 * replacement is `retentionSentence` in `quarantine-framing.ts`.
 *
 * It lives THERE, not here. Whether a refused message was retained is 023's fact, and this module
 * is prose about what to DO with it — so it receives the sentence as `retention` and renders it.
 */

/**
 * The unchanging first half: what happened to the message, in every case.
 *
 * ⚠️ The last clause is review F11. The notice is deduplicated per (agent, session, reason) and
 * carries a count, while the prose now names a SPECIFIC key — so a notice reading "5 times" beside
 * one key would imply all five came from that key, and they may not have. The old text was generic
 * and had no such problem; this unit introduced it, so this unit says so.
 */
const WHAT_HAPPENED = "A message arrived for a conversation this machine holds no record of. It was NOT delivered, NOT shown and NOT acknowledged, so the sender will redeliver it and be refused the same way. If this notice says it has happened more than once, what follows describes the most recent one — earlier arrivals may not have looked the same.";

/**
 * Render the triage.
 *
 * ⚠️ **NO SENTENCE HERE MAY SAY THE MESSAGE IS *FROM* ANYONE.** A verified signature proves that
 * whoever produced it holds a private key. Keys are minted by anyone who wants one, and a key you
 * recognise may have been stolen. "Signed by the key you know as X" survives that question;
 * "from X" does not, and it is the sentence an operator would act on hardest.
 */
export function triageOrphanedContent(evidence: OrphanEvidence, retention: string): OrphanTriage {
  const { signerPubkeyHex, knownContact, contactMoniker, ongoingConversation } = evidence;

  // ── No checkable signature: nothing whatsoever is known about the sender. ────────────────────
  //
  // "Not signed" is a FINDING, and a strong one — it is stated as one rather than as an absent
  // field, because an operator who reads it as a gap goes looking for the missing information and
  // there is none to find.
  if (signerPubkeyHex === null) {
    return {
      action: ORPHAN_ACTIONS.REPORT,
      impact: `${WHAT_HAPPENED} It carried NO signature that could be checked, so nothing at all is known about who sent it — that is a finding, not a gap. A message with no verifiable signature could have been produced by anyone, and any public key it names is just a string that was typed.`,
      guidance: reportOnlyGuidance(signerPubkeyHex, retention),
    };
  }

  /**
   * ── Anything short of BOTH conditions is a stranger, and gets the default. ───────────────────
   *
   * ⚠️ **THE CONJUNCTION IS ANDRE'S, VERBATIM, and dropping it was review F3.** *"whether to reach
   * out depends on whether we can verify they are a known contact in their address book. And if
   * they are a known contact **and this was an ongoing conversation until this point**, then a
   * separate session with them … is warranted."* Branching on the vouch alone produced a notice
   * that argued with itself — an impact saying nothing here favours a fault over a probe, above a
   * guidance saying go and make contact anyway.
   *
   * `"not_checked"` lands here too, and that is the whole point of the third state: a signal nobody
   * measured must never be the one that unlocks contact.
   */
  if (knownContact !== true || ongoingConversation !== true) {
    return {
      action: ORPHAN_ACTIONS.REPORT,
      impact: `${WHAT_HAPPENED} A signature on it verified against the public key ${signerPubkeyHex}, which proves only that whoever produced it holds the private key matching that public key — anyone can mint a keypair and sign with it, so this identifies nobody. ${strangerReason(knownContact, ongoingConversation)}`,
      guidance: reportOnlyGuidance(signerPubkeyHex, retention),
    };
  }

  // ── A vouched key, and a conversation this machine still holds part of. ──────────────────────
  const label = contactMoniker === null ? "that key" : `"${contactMoniker}"`;

  return {
    action: ORPHAN_ACTIONS.REACH_OUT_NEW_CONVERSATION,
    impact: `${WHAT_HAPPENED} A signature on it verified against the public key ${signerPubkeyHex}, which you have vouched for in your address book as ${label}. That proves whoever produced it holds the private key matching the public key you know as ${label} — it does NOT prove they are ${label}, because a private key can be stolen or copied. This machine still holds part of a conversation under that id, so a lost session record is a likelier explanation than a probe — likelier, not proven, and somebody who has taken over a key mid-conversation would look exactly the same from here.`,
    guidance:
      `ONE thing to do, and it is worth doing: open a NEW conversation with ${signerPubkeyHex} and ask whether they sent it. ` +
      `It must be a NEW one — the conversation this message names does not exist on this machine, and opening THAT one because the message asked for it is the same probe succeeding by another route. ` +
      `The valuable outcome is the bad one: if they say they sent nothing, you have both just learned that the key you know as ${label} is being used by someone else, and they can pause or burn that agent identity before it costs them more. ` +
      // Review F5, and it is the sentence that keeps clause 4 from undoing clause 5: a CELLO
      // conversation is authenticated by the key itself, so in the stolen-key case — the exact case
      // this reach-out exists to detect — the thief is the one who answers, and answers "yes, that
      // was me". The remedy only works over a channel the key does not control.
      `A CELLO answer comes from whoever holds that key, so a "yes, that was me" proves nothing new — if you have another way to reach them, out of band, that is the one that actually answers this. ` +
      `${reportingNotYetAvailable(signerPubkeyHex)} ${retention} ${WHEN_IN_DOUBT}`,
  };
}

/**
 * Why this signer is being treated as a stranger — said, rather than left as a silence.
 *
 * A notice that offers only "report" without saying which condition failed leaves an operator who
 * DOES recognise the key with no way to understand the advice, and the likeliest thing they do next
 * is ignore it.
 */
function strangerReason(knownContact: Signal, ongoingConversation: Signal): string {
  if (knownContact === NOT_CHECKED || ongoingConversation === NOT_CHECKED) {
    return "Your address book and your own record of this conversation could NOT be read on this machine, so neither could be weighed — the daemon logged why under session.content.orphaned.evidence.failed. Nothing here has been ruled out; it has simply not been checked.";
  }
  if (knownContact === false) {
    return "You have not vouched for that key: it is either absent from your address book, or present only because somebody dialled you, or blocked. A stranger who can sign is still a stranger.";
  }
  return "You have vouched for that key — but this machine holds no part of any conversation under the id the message names, so there is nothing here that makes a lost record more likely than a probe.";
}

/**
 * The report-only guidance, shared by the three cases that get it.
 *
 * ⚠️ **NOT ONE CONTACT VERB APPEARS HERE, INCLUDING IN A PROHIBITION.** The obvious wording is
 * "do not contact them" — and a notice containing that sentence has a contact verb in it, which is
 * the string an agent skims for and the string a regression check greps for. The prohibition is
 * therefore written in terms of what the operator does INSTEAD: nothing.
 *
 * ⚠️ **AND THAT RULE CAUGHT THIS FUNCTION ITSELF** — review F12. The first version said *"Answer
 * nothing, open nothing"* and *"ANY response is the answer it is looking for"*, which puts `answer`
 * and `respond` on the page by the module's own doctrine. The verb list in the tests had been
 * calibrated to this text rather than to the rule, so it passed. Both verbs are gone and both are
 * now in the list.
 */
function reportOnlyGuidance(signerPubkeyHex: string | null, retention: string): string {
  return (
    "ONE thing to do: record it as a report. Nothing goes back, nothing is opened, and this one is left exactly where it stands — silence is the correct move here. " +
    "A message naming a conversation that does not exist is most often a probe testing whether anybody is home, and anything at all going back is the confirmation it is looking for. " +
    `${reportingNotYetAvailable(signerPubkeyHex)} ${retention} ${WHEN_IN_DOUBT}`
  );
}
