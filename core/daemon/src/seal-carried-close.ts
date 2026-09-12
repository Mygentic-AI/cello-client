/**
 * `DOD-M15-CARRIEDSEAL-1` — THE CLOSE THAT DOES NOT NEED ANYONE ELSE TO BE AWAKE.
 *
 * Extracted from `session-seal.ts` rather than written beside it, for the reason that file's own
 * ratchet exists: a seal path that keeps growing in one place is how the second implementation of a
 * seal gets written next to the first. There is exactly one caller.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { buildLocalSealTerminus } from "./seal-local-terminus.js";
import { RELAY_GAVE_NO_ANSWER, relayRefusedUs } from "./seal-relay-silence.js";
import { SessionSealLeafStore, type SealCarryLeaf } from "./session-seal-leaf-store.js";
import type { SessionSealContext } from "./session-seal.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";

/** What the carried close needs from the seal path, and nothing more. */
export interface CarriedCloseDeps {
  readonly ctx: SessionSealContext;
  readonly db: DaemonDatabase | null;
  readonly getSealCarry: (agentPubkeyHex: string, sessionIdHex: string) => SealCarryLeaf[];
}

/**
 * ═══ 070-CARRIEDSEAL — THE CLOSE THAT DOES NOT NEED ANYONE ELSE TO BE AWAKE ═══
 *
 * Returns the escalation values for a seal closed over evidence this side already holds, or
 * `null` when this is not that situation and the caller should fail exactly as it did before.
 *
 * ⚠️ `null` IS THE DEFAULT, AND THAT IS THE SAFETY PROPERTY. Every way out of here that is not a
 * successfully written terminus returns `null`, so the caller's original refusal stands with its
 * original reason. A bug in this method costs the receipt this order was written to save; it
 * cannot turn a relay's ruling into a seal.
 *
 * The first gate is the important one: `RELAY_GAVE_NO_ANSWER` separates a relay that was not there
 * from one that considered the leaf and declined it. Routing around a ruling is the thing a trust
 * layer must never do, and "the submit failed" alone does not tell the two apart.
 */
export async function closeOverCarriedEvidence(
  deps: CarriedCloseDeps,
  agentName: string,
  sessionId: string,
  cause: string,
  correlationId?: string,
  /**
   * The relay's standing verdict about THIS AGENT, when there is a relay client to ask. The reason
   * string cannot carry it — see `relayRefusedUs` — so it is passed alongside.
   */
  standingRefusal?: { reason: string } | null,
): Promise<{ ok: true; sequenceNumber: number; reportedRootHex: string } | null> {
  if (!RELAY_GAVE_NO_ANSWER.has(cause)) return null;
  if (relayRefusedUs(standingRefusal)) {
    /**
     * THE RELAY ANSWERED, AND THE ANSWER WAS NO. Sealing over carried evidence here would be
     * routing around a ruling — the relay authenticated this agent and then refused it, and that
     * refusal is a decision about us rather than an absence of anyone to ask.
     */
    deps.ctx.logger.warn("session.seal.local_terminus.relay_refused", {
      agentName, sessionId, cause, relayReason: standingRefusal?.reason, correlationId,
      impact: "the relay REFUSED this agent rather than being unreachable, so this side did not sign its own closing leaf. No receipt was produced and the session is untouched — closing around a refusal would put a record on the chain that the witness declined to witness.",
      guidance: "Fix what the relay refused (cello status names it — an expired credential, a rate limit, or a capacity cap), then close again. If the relay is genuinely gone rather than refusing, the close will proceed on its own.",
    });
    return null;
  }

  const kp = deps.ctx.getKeyProvider(agentName);
  if (!kp) {
    // Not a silent skip: without this agent's key nothing here can be signed, and the operator's
    // action ("start the agent") is different from every other reason a close fails.
    deps.ctx.logger.warn("session.seal.local_terminus.key_unavailable", {
      agentName, sessionId, cause, correlationId,
      impact: "the relay could not be reached and this agent's key is not loaded, so the closing leaf could not be signed here either. No receipt was produced and nothing about the session changed.",
      guidance: "Start the agent (cello_start_agent) and close again.",
    });
    return null;
  }
  const ownPubkey = new Uint8Array(await kp.getPublicKey());
  const ownPubkeyHex = Buffer.from(ownPubkey).toString("hex");
  const carry = deps.getSealCarry(ownPubkeyHex, sessionId);

  /**
   * The session id comes out of the LEAVES, not out of the caller's argument. The directory checks
   * the terminus against the same session the carried leaves name, so reading it from anywhere
   * else would let the two disagree — and this path exists precisely for the case where no live
   * relay registration is around to be consulted.
   */
  const first = carry[0] ? decodeStructure1(carry[0].structure1Cbor) : null;
  if (!first?.ok) {
    /**
     * TWO DIFFERENT FACTS, AND THEY SEND THE OPERATOR TO DIFFERENT PLACES. An empty carry means the
     * conversation was never witnessed; an undecodable first leaf means the record IS here and is
     * damaged. Reporting the second as the first sends someone looking for something that is not
     * missing.
     */
    const empty = carry.length === 0;
    deps.ctx.logger.info("session.seal.local_terminus.no_carry", {
      agentName, sessionId, cause, carryLength: carry.length,
      reason: empty ? "seal_carry_empty" : "seal_carry_unreadable", correlationId,
      impact: empty
        ? "no witnessed leaf is held for this session, so there is no record to close over and no receipt to produce."
        : "this session's first recorded leaf is on disk and cannot be decoded, so the record cannot be chained onto. The conversation is NOT missing — cello_transcript still shows it — but no receipt can be produced from this side.",
    });
    return null;
  }

  /**
   * ⚠️ NO GENESIS, NO TERMINUS — and this used to be `?? new Uint8Array(32)`.
   *
   * The genesis is the session's agreed starting point, and it is what BOTH chain links fall back to
   * for a party that has not spoken yet. Substituting thirty-two zero bytes does not fail: the
   * directory's walk skips `prev_own_hash` for a sender's first leaf and never checks
   * `last_seen_hash` at all, so the leaf notarizes and the counterparty — verifying against the real
   * starting point — is the one who finds a link that does not reconcile. A silent substitution
   * whose cost lands on the other party.
   *
   * The send path already refuses for exactly this reason ("no seed means no send… the honest
   * outcome is to refuse rather than sign a chain anchored to nothing"). So does this.
   */
  const genesis = deps.ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId);
  if (!genesis) {
    deps.ctx.logger.warn("session.seal.local_terminus.no_genesis", {
      agentName, sessionId, cause, correlationId,
      impact: "this session has no recorded starting point on this machine, so a closing leaf written here could not link to anything and its place in the conversation could never be proven. Nothing was signed and the session is untouched.",
      guidance: "Close WITH your counterparty instead — a bilateral close does not need this value. cello_transcript still shows the conversation either way.",
    });
    return null;
  }

  const built = await buildLocalSealTerminus({
    carry,
    ownPubkeyHex,
    ownPubkey,
    sessionIdBytes: first.fields.sessionId,
    genesis,
    finalRootHex: deps.ctx.getSessionTreeRootHex(agentName, sessionId),
    closeTimestamp: Date.now(),
    sign: async (bytes) => new Uint8Array(await kp.sign(bytes)),
  });
  if (!built.ok) {
    /**
     * ⚠️ AN ALREADY-PLACED TERMINUS IS A SUCCESS BEING REPORTED AS A FAILURE — review MEDIUM-3.
     *
     * `seal_carry_own_ctrl_present` means a previous close already wrote our closing leaf. Returning
     * `null` sent the caller to its original refusal, so an operator who closed successfully and then
     * closed again — or whose reconnect retried for them — was told the RELAY was unavailable, for a
     * session whose closing leaf is on their own disk. The terminus builder's own docblock says the
     * caller must reuse the one that is there; nobody did.
     *
     * Reused rather than rebuilt: the leaf on disk is the one whose bytes were signed, and rebuilding
     * would produce a different timestamp and therefore a different record.
     */
    if (built.reason === "seal_carry_own_ctrl_present") {
      const existing = carry.find((l) => l.leafKind === 0x02 && l.senderPubkeyHex === ownPubkeyHex);
      const priorS1 = existing ? decodeStructure1(existing.structure1Cbor) : null;
      if (existing && priorS1?.ok) {
        const priorRootHex = deps.ctx.getSessionTree(agentName, sessionId)
          .rootWithAppendedHex(Buffer.from(priorS1.fields.contentHash).toString("hex"));
        deps.ctx.logger.info("session.seal.local_terminus.reused", {
          agentName, sessionId, cause, sequenceNumber: existing.sequenceNumber, correlationId,
          impact: "this side had already signed its closing leaf for this session, so the earlier one is carried again rather than a second being written. A second closing leaf would make the session unsealable by any directory, permanently.",
        });
        return { ok: true, sequenceNumber: existing.sequenceNumber, reportedRootHex: priorRootHex };
      }
    }
    deps.ctx.logger.warn("session.seal.local_terminus.refused", {
      agentName, sessionId, cause, reason: built.reason, correlationId,
      impact: "the relay could not be reached and the record this side holds cannot be closed over as it stands, so no receipt was produced.",
    });
    return null;
  }

  if (!deps.ctx.sealLeafStore && deps.db) {
    deps.ctx.sealLeafStore = new SessionSealLeafStore(deps.db, deps.ctx.logger);
  }
  const wrote = deps.ctx.sealLeafStore?.store(ownPubkeyHex, sessionId, built.leaf, Date.now()) ?? false;
  if (!wrote) {
    /**
     * The store is INSERT OR IGNORE on the position, so a false means something already occupies
     * it. Refusing is the only safe answer: carrying a leaf that is not the one on disk would
     * present a record this daemon does not actually hold.
     */
    deps.ctx.logger.warn("session.seal.local_terminus.position_taken", {
      agentName, sessionId, sequenceNumber: built.leaf.sequenceNumber, correlationId,
      impact: "a leaf is already recorded at the position the closing leaf would take, so it was not written and no receipt was produced.",
    });
    return null;
  }

  // The reported root is the certified-root domain — content hashes, this leaf appended. The same
  // derivation the relay path uses one method down, so both close paths report the same value for
  // the same leaf set.
  const reportedRootHex = deps.ctx.getSessionTree(agentName, sessionId).rootWithAppendedHex(built.contentHashHex);
  deps.ctx.logger.info("session.seal.local_terminus.placed", {
    agentName, sessionId, cause,
    sequenceNumber: built.leaf.sequenceNumber,
    carryLength: carry.length,
    correlationId,
    impact: "the relay did not answer, so this side signed its own closing leaf over the record it already holds. The seal proceeds on carried evidence and needs no relay.",
  });
  return { ok: true, sequenceNumber: built.leaf.sequenceNumber, reportedRootHex };
}

