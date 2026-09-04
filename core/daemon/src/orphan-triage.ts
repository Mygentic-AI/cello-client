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
 * **Report it** — the default, and the only action when nothing can be established about the
 * sender. **Reach out in a SEPARATE conversation** — only when the message carries a signature that
 * verifies against a key already in the operator's address book. Waiting, replying into the named
 * conversation, deleting and ignoring are not offered, because an affordance list is a menu and a
 * menu is how the wrong option gets picked.
 *
 * ─── Why the signals are read the way they are ─────────────────────────────────────────────────
 *
 * Every input here is anchored on something the sender does NOT control:
 *
 *  - the signature is checked against the key carried inside the sender's own signed bytes, so it
 *    proves **possession of a private key** and nothing else — never an identity;
 *  - "known" is read from the operator's own address book;
 *  - "ongoing" is read from the operator's own transcript rows, never from the sequence number the
 *    sender chose to write.
 *
 * A sender who wants the reach-out branch would have to already be in the receiver's address book.
 * They cannot cause that from the wire.
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
  /** Is that key in this agent's address book? Read from OUR store, not from the message. */
  knownContact: boolean;
  /** The operator's own pet name for that key, when they have set one. */
  contactMoniker: string | null;
  /**
   * Do we still hold part of this conversation locally? Anchored on OUR transcript rows — never on
   * the sequence number the sender supplied, which they are free to invent.
   */
  ongoingConversation: boolean;
}

export interface OrphanTriage {
  action: OrphanAction;
  impact: string;
  guidance: string;
}

/**
 * The sentence that catches the operator who is unsure, and it is in EVERY case.
 *
 * The three signals are probabilistic: a known key can be stolen, a consistent position can be
 * forged mid-conversation, and an operator standing here has no way to resolve it. Reporting costs
 * them nothing and costs an attacker their anonymity, so uncertainty resolves to report — and it is
 * needed most in the reach-out case, where the temptation to act alone is highest.
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
 * ⛔ TRIGGER: when `CELLO_Reporting` is provisioned and its pubkey is published, this sentence is
 * replaced by the session-open verb and its pubkey. Do not soften it before then.
 */
export const REPORTING_NOT_YET_AVAILABLE = "CELLO has no agent to receive reports yet, so there is no command here that would send one. Write down the public key, the conversation id and the time — that IS the report — and keep it until there is somewhere to send it.";

/**
 * ⛔ WHAT WAS REFUSED IS NOT KEPT, and this sentence is true only until `023-REFUSEDEVIDENCE` lands.
 *
 * That unit retains refused messages, flagged as quarantined. Until it does, a report can carry the
 * metadata above and nothing else, and an operator told to report something must not be left to
 * discover on their own that there is no artifact behind it.
 *
 * ⛔ TRIGGER: when refused content is retained, this sentence becomes false — rewrite it to name
 * where the retained message is, rather than deleting it.
 */
export const MESSAGE_NOT_RETAINED = "The message itself was not kept — this build discards what it refuses — so nothing but those details exists to attach.";

/** The unchanging first half: what happened to the message, in every case. */
const WHAT_HAPPENED = "A message arrived for a conversation this machine holds no record of. It was NOT delivered, NOT shown and NOT acknowledged, so the sender will redeliver it and be refused the same way.";

/**
 * Render the triage.
 *
 * ⚠️ **NO SENTENCE HERE MAY SAY THE MESSAGE IS *FROM* ANYONE.** A verified signature proves that
 * whoever produced it holds a private key. Keys are minted by anyone who wants one, and a key you
 * recognise may have been stolen. "Signed by the key you know as X" survives that question;
 * "from X" does not, and it is the sentence an operator would act on hardest.
 */
export function triageOrphanedContent(evidence: OrphanEvidence): OrphanTriage {
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
      guidance: reportOnlyGuidance(),
    };
  }

  // ── A stranger who can sign is still a stranger. ─────────────────────────────────────────────
  if (!knownContact) {
    return {
      action: ORPHAN_ACTIONS.REPORT,
      impact: `${WHAT_HAPPENED} A signature on it verified against the public key ${signerPubkeyHex}, which proves only that whoever produced it holds the private key for that key — anyone can mint a keypair and sign with it, so this identifies nobody. That key is not in your address book.`,
      guidance: reportOnlyGuidance(),
    };
  }

  // ── Known key + verified signature: reaching out is warranted, in a NEW conversation. ────────
  const label = contactMoniker === null ? "that key" : `"${contactMoniker}"`;
  const position = ongoingConversation
    ? "This machine still holds part of a conversation under that id, so a lost session record is a likelier explanation than a probe — likelier, not proven, and someone who has taken over a key mid-conversation would look the same from here."
    : "This machine holds no part of any conversation under that id, so there is nothing here that makes a technical fault more likely than a probe.";

  return {
    action: ORPHAN_ACTIONS.REACH_OUT_NEW_CONVERSATION,
    impact: `${WHAT_HAPPENED} A signature on it verified against the public key ${signerPubkeyHex}, which is in your address book as ${label}. That proves whoever produced it holds the private key you know as ${label} — it does NOT prove they are ${label}, because a private key can be stolen or copied. ${position}`,
    guidance:
      `ONE thing to do, and it is worth doing: open a NEW conversation with ${signerPubkeyHex} and ask whether they sent it. ` +
      `It must be a NEW one — the conversation this message names does not exist on this machine, and opening THAT one because the message asked for it is the same probe succeeding by another route. ` +
      `The valuable outcome is the bad one: if they say they sent nothing, you have both just learned that the key you know as ${label} is being used by someone else, and they can pause or burn that agent identity before it costs them more. ` +
      `${REPORTING_NOT_YET_AVAILABLE} ${MESSAGE_NOT_RETAINED} ${WHEN_IN_DOUBT}`,
  };
}

/**
 * The report-only guidance, shared by the two cases that get it.
 *
 * ⚠️ **NOT ONE CONTACT VERB APPEARS HERE, INCLUDING IN A PROHIBITION.** The obvious wording is
 * "do not contact them" — and a notice containing that sentence has a contact verb in it, which is
 * the string an agent skims for and the string a regression check greps for. The prohibition is
 * therefore written in terms of what the operator does INSTEAD: nothing.
 */
function reportOnlyGuidance(): string {
  return (
    "ONE thing to do: report it. Answer nothing, open nothing, and let it stand unremarked — silence is the correct response here. " +
    "A message naming a conversation that does not exist is most often a probe testing whether anybody is home, and ANY response is the answer it is looking for. " +
    `${REPORTING_NOT_YET_AVAILABLE} ${MESSAGE_NOT_RETAINED} ${WHEN_IN_DOUBT}`
  );
}
