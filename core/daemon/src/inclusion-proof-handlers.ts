/**
 * `cello_get_inclusion_proof` and `cello_verify_inclusion_proof` — the two halves of proving that
 * ONE sentence is in a sealed conversation.
 *
 * Until `DOD-M15-INCLUSION-1` the first of these was a registered tool that returned
 * `not_implemented`. That was honest, and it cost the product its central claim: an operator could
 * say *"this conversation was notarized"* and could not say *"and here is the proof the sentence you
 * are disputing is in it, unaltered."*
 *
 * ─── THE TWO THINGS THAT MAKE THIS A PROOF ────────────────────────────────────────────────────
 *
 * **The path is built over the CERTIFIED leaf set, not the local tree.** They are different trees.
 * `SessionTree` holds content leaves; the certified root covers the seal's CONTROL leaves too. A
 * path built from the local tree lands on a root no certificate names — proving only that this
 * machine agrees with itself, which is worth nothing to the third party the proof is for. The
 * certified set is stored at seal time only after it reproduces the FROST-signed root
 * (`sealed-leaf-set.ts`), so it is the consortium's leaf set and not the directory's word for it.
 *
 * **The leaf is recomputed from the operator's message.** The daemon's own `contentHashFor` derives
 * it; the proof carries the algorithm name and the session salt so a stranger can repeat the
 * derivation. Change one byte of the message and the leaf changes and the proof fails, which is the
 * assertion this feature exists to make.
 *
 * ─── WHY THE VERIFY HALF IS A TOOL AND NOT A DOCUMENT ─────────────────────────────────────────
 *
 * A proof nobody can check is a data structure. `cello_verify_inclusion_proof` reads no session, no
 * certificate store and no tree — proof, message, root, and nothing else — so it answers for a
 * session this daemon has never seen, on a machine that has never spoken to the counterparty.
 */

import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { ConnState } from "./contact-handlers.js";
import type { Logger } from "./types.js";
import { CONTENT_HASH_ALGS, contentHashFor } from "./wire-content-hash.js";
import {
  proofPathFor,
  rootOverLeafHashes,
  verifyInclusionProof,
  type InclusionProof,
} from "./inclusion-proof.js";

export interface InclusionProofDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  NO_CURRENT_AGENT_RESPONSE: unknown;
}

/** How a caller checks a proof — named in every success response, because a proof nobody runs is inert. */
const VERIFY_AFFORDANCE =
  "To check this, call cello_verify_inclusion_proof with { proof, message, certified_root }, where " +
  "certified_root is the sealed_root from cello_sealed_receipt — NOT the root inside the proof. It " +
  "needs no access to this daemon, so a third party can run it against the certificate you give them.";

export function registerInclusionProofHandlers(deps: InclusionProofDeps): void {
  const { handlers, logger, sessionNodeManager, getConnState, resolveCurrentAgent, NO_CURRENT_AGENT_RESPONSE } = deps;

  handlers.set("cello_get_inclusion_proof", async (params, connectionId) => {
    const sessionId = params?.["session_id"] as string | undefined;
    if (!sessionId || typeof sessionId !== "string") {
      return {
        ok: false,
        reason: "missing_session_id",
        guidance: "Provide the session_id (hex) of the sealed session. cello_sessions lists the full ids.",
      };
    }
    const message = params?.["message"];
    if (typeof message !== "string" || message.length === 0) {
      return {
        ok: false,
        reason: "missing_message",
        guidance:
          "Provide { message } — the EXACT text of the message you want to prove, copied from " +
          `cello_transcript ${sessionId}. The proof is over the message's bytes, so a paraphrase, a ` +
          "trimmed quote, or added whitespace produces a different message and will not be found.",
      };
    }

    const connState = getConnState(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.["agent"] as string | undefined);
    if (!agentName) return NO_CURRENT_AGENT_RESPONSE;

    // ─── Is there a certificate at all? "not sealed" and "unknown" are different situations ─────
    const cert = sessionNodeManager.getSealCertificate(agentName, sessionId);
    if (!cert) {
      if (!sessionNodeManager.getSessionRecord(agentName, sessionId)) {
        return {
          ok: false,
          reason: "unknown_session",
          guidance: "No session with this id belongs to the current agent. Run cello_sessions to see the full ids.",
        };
      }
      return {
        ok: false,
        reason: "not_sealed_yet",
        guidance:
          "There is no certificate for this session yet, so there is no notarized root for a proof to " +
          `land on. Close it with cello_close_session ${sessionId} and retry once cello_sealed_receipt ` +
          "reports a sealed_root. A proof against this machine's own record would prove only that this " +
          "machine agrees with itself, so none is issued.",
      };
    }

    // ─── The certified leaf set: the tree the signature actually covers ─────────────────────────
    const certifiedLeaves = sessionNodeManager.getCertifiedLeafSet(agentName, sessionId);
    if (!certifiedLeaves) {
      return missingLeafSetRefusal(
        logger,
        sessionNodeManager.getCertifiedLeafSetState(agentName, sessionId),
        agentName,
        sessionId,
        cert.sealed_root,
      );
    }

    /**
     * RE-PROVE THE STORED SET AGAINST THE CERTIFICATE ON EVERY READ.
     *
     * It was already proved at seal time, and that check ran against the seal frame. This one runs
     * against the DATABASE — the two are not the same claim. The local store is a SQLCipher file on
     * the operator's own disk, which is the thing a sceptic is entitled to doubt, and re-deriving
     * costs one Merkle build over an already-sealed session.
     */
    const storedRoot = rootOverLeafHashes(certifiedLeaves);
    if (storedRoot !== cert.sealed_root.toLowerCase()) {
      logger.error("inclusion.certified_leaves.root_mismatch", {
        agentName,
        sessionId,
        storedRoot,
        certifiedRoot: cert.sealed_root,
        impact:
          "the leaf set held for this session no longer hashes to the certified root, so no proof " +
          "can be issued from it — the local copy has changed since the seal",
      });
      return {
        ok: false,
        reason: "certified_leaves_root_mismatch",
        sealed_root: cert.sealed_root,
        guidance:
          "The leaf set stored on this machine no longer reproduces the root in the certificate, so " +
          "nothing here can be proved against it. The certificate itself is untouched and still valid " +
          "— take it and the counterparty's copy of the conversation to establish what was said. Do " +
          "not treat any proof from this machine as reliable until that is resolved.",
      };
    }

    /**
     * DOES THIS AGENT'S OWN RECORD AGREE WITH WHAT WAS CERTIFIED? — and a disagreement REFUSES.
     *
     * The certified set opens with the content leaves in canonical order and ends with the seal's
     * control leaves, so this side's tree should be a prefix of it. When it is not, the operator's
     * transcript and the notarized record are two different conversations. Emitting a proof anyway
     * would be true about the certified leaf and misleading about the message the operator is
     * reading, which is worse than refusing.
     */
    const tree = sessionNodeManager.getSessionTree(agentName, sessionId);
    const localSize = tree.size();
    if (localSize > certifiedLeaves.length) {
      return divergenceRefusal(logger, agentName, sessionId, cert.sealed_root, {
        detail: `this side holds ${localSize} content leaves and the certificate covers only ${certifiedLeaves.length} leaves in total`,
      });
    }
    for (let i = 0; i < localSize; i++) {
      const local = tree.hashAt(i);
      if (local !== certifiedLeaves[i]) {
        return divergenceRefusal(logger, agentName, sessionId, cert.sealed_root, {
          detail: `leaf ${i} of this side's record is ${local ?? "absent"} and the certified leaf at that position is ${certifiedLeaves[i]}`,
        });
      }
    }

    /**
     * ─── The salt, without which a proof is about a number rather than a sentence ───────────────
     *
     * `getSessionContentSaltState`, NOT `getSessionContentSalt` — fallback-finder finding 2. The
     * plain accessor answers `null` for a session that never agreed a salt AND for one whose salt
     * row is corrupt or unreadable, and those need opposite sentences: the first is a fact about the
     * conversation, the second is damage to this operator's own database, and telling them the
     * second is the first sends them to their counterparty over a local disk problem.
     */
    const saltState = sessionNodeManager.getSessionContentSaltState(agentName, sessionId);
    if (saltState.salt === null && saltState.reason === "unreadable") {
      logger.error("inclusion.salt.unreadable", {
        agentName,
        sessionId,
        impact:
          "this session HOLDS a salt that could not be read, so its messages cannot be re-hashed and " +
          "no inclusion proof can be issued — the conversation and its receipt are unaffected",
      });
      return {
        ok: false,
        reason: "session_salt_unreadable",
        sealed_root: cert.sealed_root,
        guidance:
          "This session DOES have a salt and this machine could not read it, so the message cannot be " +
          "re-hashed and no proof can be issued. THIS IS A PROBLEM WITH THIS MACHINE'S DATABASE, not " +
          "with the session, the counterparty or their build — do not ask them to upgrade and do not " +
          "start a new session to fix it. Look for session.salt.read.failed in the daemon log; it " +
          "names the row. The receipt itself is unaffected and still proves the conversation sealed.",
      };
    }
    if (saltState.salt === null) {
      return {
        ok: false,
        reason: "session_unsalted",
        sealed_root: cert.sealed_root,
        guidance:
          "This session's content hashes are UNSALTED, and no proof is issued over one. An unsalted " +
          "leaf is sha256 of the message, which anyone holding a copy of the text can recompute — so " +
          "it links this message to every other record carrying the same words, which is what the " +
          "session salt exists to prevent. cello_sealed_receipt reports a session's salt state; a " +
          "session opened while both agents are connected agrees one at open.",
      };
    }
    const salt = saltState.salt;

    const messageBytes = new TextEncoder().encode(message);
    const leafHash = Buffer.from(
      contentHashFor(messageBytes, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt }),
    ).toString("hex");

    /**
     * WHICH LEAF — and identical text twice is two messages, not one.
     *
     * `SessionTree.indexOfHash` answers "is this content anywhere", and `DOD-FRONTIER-STRAND-1`
     * already paid for treating that as "is this content at THIS position": a session stranded
     * because a genuine second send of the same words was dropped as a redelivery. So a repeated
     * message is not resolved by picking the first — it is refused with the candidate positions, and
     * the caller says which one they mean.
     */
    const matches: number[] = [];
    for (let i = 0; i < certifiedLeaves.length; i++) if (certifiedLeaves[i] === leafHash) matches.push(i);

    const requestedIndex = params?.["leaf_index"];
    let leafIndex: number;
    if (requestedIndex !== undefined && requestedIndex !== null) {
      if (typeof requestedIndex !== "number" || !Number.isInteger(requestedIndex) || requestedIndex < 0) {
        return {
          ok: false,
          reason: "invalid_leaf_index",
          guidance: `leaf_index must be a whole number 0 or greater. Omit it unless a previous call reported this message at more than one position.`,
        };
      }
      if (certifiedLeaves[requestedIndex] !== leafHash) {
        return {
          ok: false,
          reason: "leaf_index_mismatch",
          leaf_index: requestedIndex,
          candidate_leaf_indices: matches,
          guidance:
            matches.length > 0
              ? `The certified leaf at position ${requestedIndex} is not this message. This message is at ${matches.join(", ")} — retry with one of those.`
              : `The certified leaf at position ${requestedIndex} is not this message, and this message is not at any position in this session. Copy the text exactly from cello_transcript ${sessionId}.`,
        };
      }
      leafIndex = requestedIndex;
    } else if (matches.length === 0) {
      return {
        ok: false,
        reason: "message_not_in_session",
        sealed_root: cert.sealed_root,
        leaf_count: certifiedLeaves.length,
        guidance:
          `No leaf in this session's notarized record is this message. Copy the text exactly from ` +
          `cello_transcript ${sessionId} — the proof is over the bytes, so a changed character, a ` +
          "trimmed quote or a trailing newline is a different message. If the text IS exact, this " +
          "message is genuinely not in this sealed conversation.",
      };
    } else if (matches.length > 1) {
      return {
        ok: false,
        reason: "message_ambiguous",
        candidate_leaf_indices: matches,
        guidance:
          `This exact text was sent ${matches.length} times in this session, at positions ` +
          `${matches.join(", ")} — they are different messages that happen to read the same, and a ` +
          "proof names one of them. Retry with { leaf_index } set to the one you mean.",
      };
    } else {
      leafIndex = matches[0];
    }

    const proof: InclusionProof = {
      version: 1,
      session_id: sessionId,
      certified_root: cert.sealed_root.toLowerCase(),
      leaf_index: leafIndex,
      leaf_count: certifiedLeaves.length,
      leaf_hash: leafHash,
      proof_path: proofPathFor(certifiedLeaves, leafIndex),
      content_hash_alg: CONTENT_HASH_ALGS.HMAC_SALT_V1,
      content_salt: Buffer.from(salt).toString("hex"),
    };

    /**
     * RUN THE VERIFIER BEFORE HANDING THE PROOF OVER.
     *
     * Not belt-and-braces: a proof that does not verify is worse than no proof, because it is
     * presented as evidence and fails in front of the person it was shown to. This is the same
     * derivation a third party will run, against the same certificate root, so it fails HERE — where
     * it can be named — rather than in the dispute.
     */
    const selfCheck = verifyInclusionProof(proof, messageBytes, cert.sealed_root);
    if (!selfCheck.ok) {
      logger.error("inclusion.proof.self_check_failed", {
        agentName,
        sessionId,
        leafIndex,
        reason: selfCheck.reason,
        detail: selfCheck.detail,
        impact: "a proof was constructed for this message and did not verify against the certified root, so it was NOT returned",
      });
      return {
        ok: false,
        reason: "proof_self_check_failed",
        detail: selfCheck.detail,
        guidance:
          "This daemon built a proof for that message and it failed its own check against the " +
          "certified root, so nothing was returned rather than handing you evidence that would fail " +
          "in front of whoever you showed it to. Report the session id and this reason; the receipt " +
          "itself is unaffected and still valid.",
      };
    }

    logger.info("inclusion.proof.issued", {
      agentName,
      sessionId,
      leafIndex,
      leafCount: certifiedLeaves.length,
      contentHashAlg: proof.content_hash_alg,
    });

    return {
      ok: true,
      session_id: sessionId,
      proof,
      // Repeated outside the proof so a caller reading the response does not have to open it.
      certified_root: proof.certified_root,
      leaf_index: leafIndex,
      leaf_count: certifiedLeaves.length,
      guidance: VERIFY_AFFORDANCE,
    };
  });

  /**
   * THE THIRD-PARTY VERIFIER. Touches no session, no certificate store, no tree.
   *
   * Registered on the daemon because that is where the tool surface lives, not because it needs
   * anything the daemon holds — which is exactly the property that lets someone who has never spoken
   * to either party check the proof on their own machine.
   */
  handlers.set("cello_verify_inclusion_proof", async (params) => {
    const rawProof = params?.["proof"];
    if (rawProof === undefined || rawProof === null) {
      return {
        ok: false,
        reason: "missing_proof",
        guidance: "Provide { proof } — the object cello_get_inclusion_proof returned, verbatim.",
      };
    }
    // Accepted as an object OR as the JSON text of one: a proof travels between people by paste, and
    // refusing a pasted string would send the reader to reformat evidence by hand, which is the one
    // step most likely to alter it.
    let proof: unknown = rawProof;
    if (typeof rawProof === "string") {
      try {
        proof = JSON.parse(rawProof);
      } catch {
        return {
          ok: false,
          reason: "proof_malformed",
          guidance:
            "The proof was supplied as text and is not valid JSON. Paste the whole object " +
            "cello_get_inclusion_proof returned, braces included, with nothing trimmed.",
        };
      }
    }

    const message = params?.["message"];
    if (typeof message !== "string" || message.length === 0) {
      return {
        ok: false,
        reason: "missing_message",
        guidance:
          "Provide { message } — the exact text being proved. Verification recomputes the message's " +
          "hash, so this is what makes the answer about a sentence rather than about a number.",
      };
    }

    const certifiedRoot = params?.["certified_root"];
    if (typeof certifiedRoot !== "string" || certifiedRoot.length === 0) {
      return {
        ok: false,
        reason: "missing_certified_root",
        guidance:
          "Provide { certified_root } — the sealed_root from the certificate (cello_sealed_receipt " +
          "reports it). It is REQUIRED and it must come from the certificate, never from the proof: a " +
          "proof checked against its own root proves only that whoever wrote it was consistent.",
      };
    }

    const result = verifyInclusionProof(proof, new TextEncoder().encode(message), certifiedRoot);
    if (!result.ok) {
      logger.info("inclusion.proof.verify.refused", { reason: result.reason, detail: result.detail });
      return { ok: false, reason: result.reason, detail: result.detail, guidance: result.guidance };
    }

    logger.info("inclusion.proof.verify.ok", {
      sessionId: result.session_id,
      leafIndex: result.leaf_index,
      leafCount: result.leaf_count,
    });
    return {
      ok: true,
      verified: true,
      session_id: result.session_id,
      leaf_index: result.leaf_index,
      leaf_count: result.leaf_count,
      certified_root: result.certified_root,
      content_hash_alg: result.content_hash_alg,
      // Carried through so a caller cannot read `session_id` above as something that was checked.
      // The anchor is the ROOT; nothing here binds a session id (fallback-finder finding 6).
      session_id_verified: result.session_id_verified,
      // WHAT THIS DOES AND DOES NOT ESTABLISH. The proof binds a message to a root; it says nothing
      // about whether that root is the one a directory signed. Claiming more here would be the
      // "partially true is false" failure the claims ledger exists to catch.
      means:
        "This exact message is at position " + result.leaf_index + " of the " + result.leaf_count +
        " leaves under root " + result.certified_root + ". It has not been altered by a single byte. " +
        "This does NOT by itself establish that the root is genuine — verify the certificate's own " +
        "signature (cello_sealed_receipt) to establish that, then this proof binds the message to it. " +
        "The session_id above is copied from the proof and was NOT checked: nothing here binds a " +
        "session id, so treat it as a label rather than as a finding.",
    };
  });
}

/**
 * WHY there is no certified leaf set — one reason string per cause, never one for all four.
 *
 * ⚠️ THIS USED TO BE A SINGLE `certified_leaves_unavailable` WHOSE GUIDANCE ASSERTED THE MOST BENIGN
 * OF FOUR CAUSES — fallback-finder finding 1, and it is the defect this milestone is named for.
 *
 * `getCertifiedLeafSet` answers null when: no seal frame carried the leaves, the DIRECTORY shipped a
 * set that does not reproduce the root its own FROST signature covers, a leaf was malformed, or the
 * write failed. The text said *"the normal state for the party that was ABSENT at seal time … ask
 * your counterparty."* So an operator who was present throughout, whose directory had just
 * contradicted its own signature — the strongest misbehaviour signal this client can produce — was
 * told they had been absent, and sent to a counterparty who has nothing to give them. The detection
 * was correct and its only consumer was a log line.
 *
 * `session_certified_leaves_state` is written at every one of those four points, so the cause
 * survives to here. A state this build does not recognise is named as such rather than folded into
 * the nearest familiar one.
 */
function missingLeafSetRefusal(
  logger: Logger,
  recorded: { state: string; detail: string | null } | null,
  agentName: string,
  sessionId: string,
  sealedRoot: string,
): Record<string, unknown> {
  const base = { ok: false as const, sealed_root: sealedRoot, ...(recorded?.detail ? { detail: recorded.detail } : {}) };

  switch (recorded?.state) {
    case "sealed_leaves_root_disagrees":
      // THE LOUD ONE. Not a degradation — a party that signed one thing and shipped another.
      logger.error("inclusion.certified_leaves.directory_disagreed", {
        agentName, sessionId, detail: recorded.detail,
        impact:
          "the leaf set delivered with this seal does not reproduce the root the consortium signed, " +
          "so it was refused and no message in this session can be proved from this side",
      });
      return {
        ...base,
        reason: "certified_leaves_root_disagrees",
        guidance:
          "THIS IS NOT THE ORDINARY 'no leaves' CASE. The leaf set delivered with this seal does not " +
          "hash to the root the directory consortium signed — the same party gave two answers that " +
          "cannot both be true, so it was refused rather than stored. Your receipt is unaffected and " +
          "still proves this conversation was sealed; what is unavailable is proof about an " +
          "individual message. Keep the receipt, note the session id, and raise this with the " +
          "operator — a directory contradicting its own signature is worth investigating, not " +
          "retrying.",
      };
    case "sealed_leaves_malformed":
      return {
        ...base,
        reason: "certified_leaves_malformed",
        guidance:
          "The signed leaves delivered with this seal could not be read, so none were stored and no " +
          "message in this session can be proved from this side. The receipt is unaffected. This is " +
          "a version or transport problem rather than a dispute — nothing local repairs it, and " +
          "re-closing the session will not re-deliver them.",
      };
    case "persist_failed":
      return {
        ...base,
        reason: "certified_leaves_persist_failed",
        guidance:
          "The leaf set for this session arrived and verified, and this machine failed to write it. " +
          "THE FAULT IS LOCAL — do not ask your counterparty for anything. Look for " +
          "seal.certified_leaves.persist.failed in the daemon log; it names the write. Your " +
          "counterparty's copy can still issue a proof for the same messages in the meantime.",
      };
    case "not_carried_present_party":
      // The false-remedy case: on this path the counterparty is the ABSENT one, who has less.
      return {
        ...base,
        reason: "certified_leaves_not_carried",
        guidance:
          "This seal completed with your counterparty absent, and the directory sent no signed leaves " +
          "with it — so NEITHER side can prove an individual message in this session. Do not ask them " +
          "for a proof; they were not there and hold even less than you do. Your receipt is complete " +
          "and still proves the conversation was sealed. Nothing local repairs this.",
      };
    case "not_carried_absent_party":
      return {
        ...base,
        reason: "certified_leaves_unavailable",
        guidance:
          "You were the ABSENT party when this session sealed, and the signed leaves only ever reach " +
          "the party that was present — so this side can never prove an individual message here, and " +
          "re-closing will not change that. Ask your counterparty to issue the proof; their copy can. " +
          "Your receipt is unaffected and still proves the conversation was sealed.",
      };
    default:
      // Includes `recorded === null`: no seal has been processed on this side at all, which is a
      // different sentence again — and an unrecognised state, which is named rather than guessed.
      return {
        ...base,
        reason: "certified_leaves_unavailable",
        ...(recorded ? { recorded_state: recorded.state } : {}),
        guidance:
          "This side holds the receipt for this session but not the leaf set it is signed over, and " +
          "no cause was recorded for that — most often because the seal was processed by a build " +
          "older than this one. No message-level proof can be built here. Ask your counterparty to " +
          "issue the proof; their copy may still be able to. The receipt itself is unaffected.",
      };
  }
}

/**
 * The refusal for a local record that does not match what was certified.
 *
 * One function because both callers must produce the SAME reason string: the operator's next step is
 * identical either way, and two spellings of one situation is how a reason code stops being usable
 * as a signal.
 */
function divergenceRefusal(
  logger: Logger,
  agentName: string,
  sessionId: string,
  sealedRoot: string,
  args: { detail: string },
): Record<string, unknown> {
  logger.error("inclusion.local_tree.diverged", {
    agentName,
    sessionId,
    sealedRoot,
    detail: args.detail,
    impact:
      "this side's own record of the conversation is not the record that was notarized, so no " +
      "message-level proof is issued from it",
  });
  return {
    ok: false,
    reason: "local_tree_diverged",
    detail: args.detail,
    sealed_root: sealedRoot,
    guidance:
      "This machine's record of the conversation does not match the one the certificate covers, so " +
      "any proof built here could be true about the certified record and wrong about the messages " +
      "you are reading. Read cello_transcript " + sessionId + " and compare it with your " +
      "counterparty's copy out of band. The certificate is unaffected and still proves the " +
      "conversation was sealed; what is in doubt is this side's copy of it.",
  };
}
