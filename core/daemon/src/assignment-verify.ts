/**
 * assignment-verify.ts — DOD-M15-ASSIGN-1.
 *
 * `session-assignment-parser.ts` shape-validates a session assignment. Its header said the
 * signature "is verified downstream by the transport/session layer against the directory's pinned
 * key" — and that site did not exist: `buildSessionEstablishmentTbs` was called to SIGN, and
 * nowhere to verify. This module is the downstream the comment promised.
 *
 * SEPARATE FROM THE PARSER on purpose. Parsing answers "is this the right shape"; verifying answers
 * "did the right party say it". Keeping them apart means the second cannot be quietly skipped by a
 * caller that only wanted the first — which is how the gap existed.
 */
// `verify` (plain Ed25519) is deliberately NOT imported: the single-key branch that used it was
// removed with the downgrade refusal (review F1). Verifying `directory_signature` against the
// `directory_pubkey` riding beside it in the same unsigned frame checks a key against itself, and
// having that call available is how a future edit reintroduces the bypass.
import { verifyFrostSignature, verifyKeyBinding, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { DbRegistrationPersistence } from "./db-identity-store.js";
import type { Logger } from "./types.js";

/**
 * DOD-M15-ASSIGN-1 — verify a session assignment's signature before anything trusts it.
 *
 * REFUSES, never logs-and-continues. The whole finding here is a comment naming a verification the
 * tree does not perform, so a check that ran and then let the session proceed anyway would be the
 * same defect with more code. `DOD-M15-ASSIGN-1`'s receiver gate reads this assignment; gating on a
 * document nobody verified relocates trust rather than closing it.
 */
export async function verifyAssignmentSignature(
  assignment: SessionAssignment,
  persistence: DbRegistrationPersistence,
  logger: Logger,
  agentName: string,
  correlationId: string,
): Promise<
  | {
      ok: true;
      /**
       * 038-KEYBIND. The COUNTERPARTY's FROST group public key, hex, having been proved theirs by a
       * signature under their own K_local. Returned rather than left on the frame so the caller
       * cannot pin a value that was never checked — the only way to hold this string is to have
       * come through the binding check below.
       */
      counterpartyPrimaryHex: string;
    }
  | { ok: false; reason: string; guidance: string }
> {
  // RECOMPUTED, not taken from the frame — and that is a strengthening rather than a workaround.
  // `genesis_prev_root` is not on the wire at all: the directory derives it from
  // (pubA, pubB, session_id, timestamp) and so must we. A value we derive cannot be chosen for us,
  // so the TBS we verify against is anchored to the assignment's own participants and id.
  const genesisPrevRoot = computeGenesisPrevRoot(
    assignment.participant_a.pubkey,
    assignment.participant_b.pubkey,
    assignment.session_id,
    assignment.session_timestamp,
  );
  const tbs = buildSessionEstablishmentTbs(
    assignment.session_id,
    assignment.participant_a.pubkey,
    assignment.participant_b.pubkey,
    genesisPrevRoot,
    assignment.session_timestamp,
    assignment.initiator_session_peer_id,
    assignment.initiator_session_addrs,
    assignment.counterparty_session_peer_id,
    assignment.counterparty_session_addrs,
    assignment.transport_mode,
    assignment.high_stakes,
    assignment.prior_relay_id,
  );

  /**
   * LOAD THE REGISTRATION BEFORE BRANCHING ON `signature_type` — review F1, and this ordering is
   * the entire fix.
   *
   * `signature_type` rides in the frame and is covered by no signature. The parser reads any value
   * that is not the string "frost" — including an ABSENT field — as "single". So while this load
   * lived inside the frost branch, a hostile directory disabled every check below by omitting one
   * field: it put its own freshly-minted key in `directory_pubkey`, signed a TBS naming an
   * impostor as the counterparty, and the single-key branch verified that signature against that
   * same key and returned ok. The anti-circularity comparison, the threshold verify and the
   * fail-closed were all simply stepped over.
   *
   * Reading the registration first closes it: an agent that HAS a threshold registration knows its
   * assignments are FROST-signed, so a non-FROST one is a downgrade attempt and is refused by
   * name — never quietly routed to a weaker check.
   */
  const reg = await persistence.loadRegistrationState();
  if (!reg) {
    // FAIL CLOSED. Without our own registration we cannot know whose quorum should have signed,
    // so the signature is unverifiable — which is not the same as valid.
    logger.warn("session.assignment.verify.no_identity", {
      agentName, correlationId,
      impact: "this agent has no persisted registration, so the signer of its own session assignment cannot be established; the session was refused rather than accepted unverified",
    });
    return {
      ok: false,
      reason: "assignment_unverifiable_no_registration",
      guidance: "This agent has no registration on record, so the directory's session assignment cannot be checked against the key that should have signed it. Re-register with cello register-agent, then try again.",
    };
  }

  if (assignment.signature_type !== "frost") {
    /**
     * THE DOWNGRADE REFUSAL. Checked against the producer, not assumed: the directory constructs
     * `signature_type: "frost"` unconditionally at a single site (`directory-node.ts`), with no
     * branch that can emit anything else. There is no legitimate producer of a single-key session
     * assignment for a registered agent, so this is not a compatibility path being closed — it is
     * a shape that only an attacker or a broken directory can send.
     */
    logger.error("session.assignment.signature_type_downgraded", {
      agentName, correlationId,
      offeredType: assignment.signature_type,
      impact: "the assignment claimed a weaker signature type than this agent's registration can produce, which would have routed it to a check that verifies a key against itself; it was refused, and no session was established",
    });
    return {
      ok: false,
      reason: "assignment_signature_type_downgraded",
      guidance: "The directory returned a session assignment that does not carry a threshold signature, though this agent is registered with one. Nothing was established and no message was sent. Retry the session; if it repeats, the directory you reached is not producing valid assignments and cello status will show which one that is.",
    };
  }

  {
    // THE ANTI-CIRCULARITY CHECK. `signer_pubkey` comes from the frame; `reg.primaryPubkey` comes
    // from this machine's own registration. Comparing them is what makes verifying against
    // `signer_pubkey` mean anything at all.
    const expected = reg.primaryPubkey.toLowerCase();
    const offered = Buffer.from(assignment.signer_pubkey).toString("hex").toLowerCase();
    if (offered !== expected) {
      logger.error("session.assignment.signer_mismatch", {
        agentName, correlationId,
        expectedPrefix: expected.slice(0, 16), offeredPrefix: offered.slice(0, 16),
        impact: "the assignment was signed by a key that is not this agent's own threshold group key; it was refused, and no session was established",
      });
      return {
        ok: false,
        reason: "assignment_signer_not_this_agent",
        guidance: "The directory returned a session assignment signed by a key that is not this agent's own. Nothing was established and no message was sent. This is refused rather than reported as an error because the observation cannot distinguish a directory fault from an attempt to broker a session on your behalf; cause undetermined.",
      };
    }
    if (!verifyFrostSignature(assignment.directory_signature, tbs, CONTEXT_SESSION_ESTABLISHMENT, assignment.signer_pubkey)) {
      logger.error("session.assignment.signature_invalid", {
        agentName, correlationId, signatureType: "frost",
        impact: "the assignment's threshold signature did not verify over its own contents; it was refused, and no session was established",
      });
      return {
        ok: false,
        reason: "assignment_signature_invalid",
        guidance: "The directory's session assignment did not verify against the key that should have signed it. Nothing was established. Retry the session; if it repeats, the directory you reached is not producing valid assignments and cello status will show which one that is.",
      };
    }

    /**
     * 038-KEYBIND — LEARN THE COUNTERPARTY'S GROUP KEY, AND ONLY IF THEY VOUCHED FOR IT.
     *
     * The initiator never used to learn the responder's group key at all. The cost was concrete and
     * one-directional: when the RESPONDER closed the conversation first, the seal certificate came
     * back signed by their group key, this daemon held no copy, and it accepted the certificate
     * with `verified:false` / `signer_key_not_held`. The receipt for a conversation you had was
     * taken on faith in the channel it arrived on.
     *
     * `participant_b_primary_pubkey` alone would not fix that — it would move the same circularity
     * to the other side, where a directory names a group key and we write it down. The BINDING is
     * what makes it a fact: a signature under `participant_b`'s K_local, which is the value the
     * operator typed and which this function's caller has already compared against `target_pubkey`.
     * No directory holds that key, so no directory can put a group key of its choosing here.
     */
    const counterpartyBinding = assignment.participant_b_key_binding;
    const counterpartyPrimary = assignment.participant_b_primary_pubkey;
    if (!counterpartyBinding || !counterpartyPrimary) {
      // ABSENT AND MALFORMED TAKE THIS PATH TOGETHER (the parser maps a wrong-length value to
      // undefined). An attacker who cannot forge a binding evades a mismatch check by supplying
      // none, so "we could not tell" must cost exactly what "it was wrong" costs.
      logger.error("session.assignment.counterparty_binding_absent", {
        agentName, correlationId,
        hasBinding: !!counterpartyBinding, hasPrimary: !!counterpartyPrimary,
        impact: "the assignment carried no proof that the counterparty's threshold group key is theirs, so this agent could not learn a key it would later have to trust for their seal; the session was refused before any dial and nothing was sent",
      });
      return {
        ok: false,
        reason: "assignment_counterparty_binding_absent",
        guidance: "The directory returned a session assignment without the counterparty's key binding — the signature that proves their threshold key belongs to the identity you asked for. Nothing was opened and nothing you wrote was sent. Retry cello_initiate_session; a different directory node will serve it. If it repeats on every node, the counterparty registered against a directory that predates this proof and they need to re-register before you can reach them.",
      };
    }
    if (!verifyKeyBinding(counterpartyBinding, assignment.participant_b.pubkey, counterpartyPrimary)) {
      logger.error("session.assignment.counterparty_binding_invalid", {
        agentName, correlationId,
        counterpartyPrefix: Buffer.from(assignment.participant_b.pubkey).toString("hex").slice(0, 16),
        impact: "the assignment named a threshold group key for the counterparty that their own identity key has not vouched for; it was refused before any dial, so no conversation was opened and nothing was sent",
      });
      return {
        ok: false,
        reason: "assignment_counterparty_binding_invalid",
        guidance: "The directory named a threshold key for your counterparty that their own identity key has not signed for. This is refused rather than reported because the observation cannot tell a directory fault from an attempt to put a key it controls in their place; cause undetermined. Run cello_status to see which node answered and retry — if it repeats across nodes, confirm the counterparty's pubkey with their operator out of band before trying again.",
      };
    }

    return { ok: true, counterpartyPrimaryHex: Buffer.from(counterpartyPrimary).toString("hex") };
  }
}


/**
 * DOD-M15-RESPONDER-VERIFY-1 — the RESPONDER's half, which until now did not exist.
 *
 * The initiator verifies its assignment against its own threshold group key (above). The responder
 * did not verify at all: it logged `session.inbound.assignment.unverified` and proceeded, so every
 * field it then acted on — the dialer it opens its receiver to, the `signer_pubkey` it persists as
 * the seal trust anchor — was whatever the directory said.
 *
 * ─── Why this could not simply reuse the function above ────────────────────────────────────────
 *
 * That one compares `signer_pubkey` against the agent's OWN persisted `primaryPubkey`. The responder
 * is not the signer — the assignment is signed by the INITIATOR's quorum — so it has no equivalent
 * value, and verifying a frame's signature against a key from the same frame is circular: mint a
 * key, sign with it, name it. That circularity is why the check was deferred rather than written.
 *
 * ─── What breaks the circle ────────────────────────────────────────────────────────────────────
 *
 * The TOFU pin. For a counterparty this agent has completed a session with, `expectedSignerHex` is
 * what THIS daemon recorded then — a value no directory can retroactively change. Verifying against
 * that is a real check: a compromised directory can produce a signature, but not one that verifies
 * under a key it does not hold.
 *
 * ─── 038-KEYBIND CLOSED THE CIRCLE, AND THIS PARAGRAPH REPLACES THE ONE THAT ADMITTED IT ───────
 *
 * ⚠️ THE OLD TEXT HERE IS KEPT AS EVIDENCE RATHER THAN DELETED, because it is the record of a real
 * bound that someone reasoned their way to and wrote down. It said: *"UNPINNED (first contact):
 * there is nothing independent to verify against, so this checks INTERNAL CONSISTENCY only… That
 * does NOT authenticate the directory, and it is not claimed to."* That was true of the code as it
 * stood, and the `verifyAgainst` line below really did fall back to `assignment.signer_pubkey` — a
 * field of the very document under verification. The signature therefore always verified, and the
 * key it verified under was then PINNED as the counterparty's identity forever.
 *
 * It is no longer true, and the thing that changed is not a stronger check on the same evidence —
 * it is NEW evidence on the wire. `participant_a_key_binding` is a signature by the INITIATOR's own
 * K_local naming their group key. No directory holds that key, so no directory can name a group key
 * of its choosing. The group key stops being something the frame ASSERTS and becomes something a
 * signature PROVES.
 *
 * ─── The order of the two checks is the fix, not an optimisation ───────────────────────────────
 *
 * The binding is verified FIRST, and the threshold signature is then verified under the key the
 * binding proved. There is no path to the signature check that does not pass through it: `signer`
 * is not used as a verification key anywhere below, and a missing or bad binding returns before the
 * TBS is even built.
 *
 * ─── Two modes, and neither is circular any more ───────────────────────────────────────────────
 *
 * PINNED (`expectedSignerHex` given): the signature must verify under the PINNED key — a value THIS
 * daemon recorded in an earlier session, which no directory can retroactively change. The binding
 * still runs; the pin is now a consistency check ACROSS TIME rather than the sole authority.
 *
 * FIRST CONTACT: the signature verifies under the group key `participant_a`'s identity key vouched
 * for. What it still cannot tell you is whether `participant_a` is who you think they are — that is
 * the operator's out-of-band problem and always was — but a directory can no longer substitute a
 * group key, which is what this function existed to be unable to say.
 */
export function verifyInboundAssignment(
  assignment: SessionAssignment,
  expectedSignerHex: string | null,
): { ok: true; mode: "pinned" | "bound" } | { ok: false; reason: string; detail: string } {
  if (assignment.signature_type !== "frost") {
    return {
      ok: false,
      reason: "inbound_assignment_not_frost",
      detail: `signature_type was ${String(assignment.signature_type)}; the directory produces frost for every session assignment`,
    };
  }
  const signer = assignment.signer_pubkey;
  if (!signer || signer.length !== 32) {
    return { ok: false, reason: "inbound_assignment_no_signer", detail: "signer_pubkey missing or not 32 bytes" };
  }

  /**
   * 038-KEYBIND — PLACE THE GROUP KEY BEFORE VERIFYING ANYTHING UNDER IT.
   *
   * `participant_a.pubkey` is the counterparty's K_local: the 64-hex identity their operator was
   * given out of band, and the value this daemon keys its contacts and its pin on. The binding is a
   * signature under THAT key naming `signer_pubkey` as its group key.
   *
   * ABSENT IS A REFUSAL. Tolerating a missing binding would reproduce exactly the state this exists
   * to end — and worse, it would hand the choice to the party the check exists to catch: a
   * directory that cannot forge a binding simply omits one, and every session goes back to
   * verifying a key against itself. The parser maps a malformed value to `undefined`, so missing
   * and malformed take this same path.
   */
  const binding = assignment.participant_a_key_binding;
  if (!binding) {
    return {
      ok: false,
      reason: "inbound_assignment_no_key_binding",
      detail:
        "the assignment carried no key binding for the initiator, so the threshold key it names could not be placed against their identity",
    };
  }
  if (!verifyKeyBinding(binding, assignment.participant_a.pubkey, signer)) {
    return {
      ok: false,
      reason: "inbound_assignment_key_binding_invalid",
      detail:
        "the initiator's identity key has not signed for the threshold key this assignment names as theirs",
    };
  }
  /**
   * The key the BINDING proved — not the key the frame supplied.
   *
   * Textually these are the same bytes, and that is worth being precise about rather than glossing:
   * what changed is that this value is now unreachable without a signature by `participant_a`'s
   * K_local having verified over it three lines above. A directory that names a group key it holds
   * cannot get here at all.
   */
  const boundGroupKey = signer;

  // PINNED beats bound. When we hold a value from an earlier session, that is the stronger anchor —
  // it survives the counterparty's own key material changing, which a fresh binding would not
  // reveal on its own.
  const verifyAgainst = expectedSignerHex !== null ? Buffer.from(expectedSignerHex, "hex") : boundGroupKey;
  if (expectedSignerHex !== null && Buffer.from(signer).toString("hex").toLowerCase() !== expectedSignerHex.toLowerCase()) {
    return {
      ok: false,
      reason: "inbound_assignment_signer_not_pinned",
      detail: "the assignment names a different signer than this agent recorded for this counterparty",
    };
  }

  const genesisPrevRoot = computeGenesisPrevRoot(
    assignment.participant_a.pubkey,
    assignment.participant_b.pubkey,
    assignment.session_id,
    assignment.session_timestamp,
  );
  const tbs = buildSessionEstablishmentTbs(
    assignment.session_id,
    assignment.participant_a.pubkey,
    assignment.participant_b.pubkey,
    genesisPrevRoot,
    assignment.session_timestamp,
    assignment.initiator_session_peer_id,
    assignment.initiator_session_addrs,
    assignment.counterparty_session_peer_id,
    assignment.counterparty_session_addrs,
    assignment.transport_mode,
    assignment.high_stakes,
    assignment.prior_relay_id,
  );

  if (!verifyFrostSignature(assignment.directory_signature, tbs, CONTEXT_SESSION_ESTABLISHMENT, new Uint8Array(verifyAgainst))) {
    return {
      ok: false,
      reason: "inbound_assignment_signature_invalid",
      detail:
        expectedSignerHex !== null
          ? "the signature did not verify under the key this agent recorded for this counterparty"
          : "the signature did not verify under the threshold key the initiator's identity key vouched for — the frame is tampered or malformed",
    };
  }
  // `bound` was `internal`, and the rename is the claim changing rather than the label.
  // `internal` meant "internally consistent only — this proves nothing about the signer".
  // A first contact now verifies under a group key the counterparty's own identity key signed
  // for, so the old word would assert a weaker property than the code holds and send the next
  // reader looking for a gap that has been closed.
  return { ok: true, mode: expectedSignerHex !== null ? "pinned" : "bound" };
}
