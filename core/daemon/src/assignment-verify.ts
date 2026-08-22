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
import { verify, verifyFrostSignature, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
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

  if (assignment.signature_type === "frost") {
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

  // Single-key assignments verify against the directory's own key, which rides the assignment as
  // `directory_pubkey`. NOTE the asymmetry, stated rather than glossed: there is no independent
  // value to compare that against here the way `primaryPubkey` anchors the FROST case, so this
  // branch proves internal consistency only. It exists for legacy and direct-mode assignments;
  // production registration produces FROST.
  if (!verify(assignment.directory_pubkey, tbs, assignment.directory_signature)) {
    logger.error("session.assignment.signature_invalid", {
      agentName, correlationId, signatureType: "single",
      impact: "the assignment's signature did not verify over its own contents; it was refused, and no session was established",
    });
    return {
      ok: false,
      reason: "assignment_signature_invalid",
      guidance: "The directory's session assignment did not verify against the key it names. Nothing was established. Retry the session; if it repeats, cello status will show which directory answered.",
    };
  }
  return { ok: true };
}
