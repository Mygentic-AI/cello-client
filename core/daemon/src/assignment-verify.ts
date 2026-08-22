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
import { verifyFrostSignature, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
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
): Promise<{ ok: true } | { ok: false; reason: string; guidance: string }> {
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
    return { ok: true };
  }
}
