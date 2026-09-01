/**
 * The seal cluster: bilateral seal, unilateral escalation, and the returning-absent-party upgrade.
 *
 * Five pieces of mutable state and the four signaling listeners that drive them. They were already
 * seal-private inside startDaemon — nothing else touched them — but "private" was a convention you
 * had to verify by reading 6,000 lines. Here it is the module boundary.
 *
 * What the cluster actually needs from the daemon is five things: the session store, a logger, the
 * per-agent FROST persistence, the per-agent key provider, and a way to recover parked content
 * before ratifying a seal. Notably NOT the signaling hub — a SignalingManager is passed in per
 * listener registration, so the coordinator never reaches for the daemon's nervous system.
 *
 * The state objects (the waiter maps, the in-progress sets) are returned as-is rather than hidden
 * behind accessors: cello_close_session drives them directly from ~30 sites and stays in daemon.ts
 * (it inlines the cursor gate, governance, transcript append and retry enqueue — see the refactor
 * plan's DO-NOT-CUT list). Preserving behavior beats tightening encapsulation in the same move;
 * the encapsulation is a later, separate change with its own tests.
 */
import { Buffer } from "node:buffer";
import { SignalingManager } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import { attemptSealUpgrade as attemptSealUpgradeImpl, verifyUpgradeConfirmedCert } from "./seal-upgrade.js";
import { upgradeAbsentToRecovered, hasAbsentParticipant } from "./seal-receipt-upgrade.js";
import { verifyUnilateralCertificate, verifyBilateralSealCertificate } from "./session-ceremony.js";
import { reDeriveFrontiers, findInflatedFrontier, checkUnilateralFrontier, type SealFrontierLeaf } from "./seal-frontier-verify.js";
import type { LegibilityForHash } from "./seal-legibility-tbs.js";
import { frameValueToHex, normalizeLegibility } from "./frame-values.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { DbRegistrationPersistence } from "./db-identity-store.js";
import type { Logger } from "./types.js";

/**
 * M7-SESSION-004: the bilateral seal resolves with the sealed_root AND the legibility certificate.
 *
 * DOD-M15-SEALWIRE-1 bullet 2 (review F4) added the REFUSED shape. A root mismatch used to log and
 * `return`, leaving the waiter unresolved — so the close sat out its eleven-minute wait, escalated,
 * and told the operator *"the counterparty has not closed"* about a counterparty who had closed and
 * whose certificate this daemon had just refused. Three failures in one sentence: it names a party
 * the code never checked, the remedy cannot work (the seal frame is delivered once), and the one
 * thing actually detected appears nowhere the operator looks.
 *
 * A detection whose only consumer is a log line is not a control.
 */
export type SealCompletion =
  | { rootHex: string; legibility?: unknown }
  | { refused: true; reason: string; detail: string; ownRootHex: string | null };

/**
 * The signed leaves a seal frame carried, or undefined when it carried none.
 *
 * Shape-only: every caller re-checks the signatures (`reDeriveFrontiers` / `checkUnilateralFrontier`)
 * or the root (`recordCertifiedLeafSet`) before believing anything in here.
 */
function parseFrontierLeaves(raw: unknown): SealFrontierLeaf[] | undefined {
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  const toU8 = (v: unknown): Uint8Array => (v instanceof Uint8Array ? v : new Uint8Array(v as ArrayLike<number>));
  return (raw as unknown[]).map((l) => {
    const o = l as Record<string, unknown>;
    return {
      structure1_cbor: toU8(o["structure1_cbor"]),
      sender_pubkey: toU8(o["sender_pubkey"]),
      sender_signature: toU8(o["sender_signature"]),
    };
  });
}

/**
 * DOD-M15-INCLUSION-1: keep the leaf set this certificate is signed over, so a single message can
 * later be proved to sit under it.
 *
 * The local `SessionTree` cannot stand in — it holds content leaves only, while the certified root
 * covers the seal's CONTROL leaves too, so a path built from it lands on a root no certificate names.
 * These are the only frames that ever carry the full set.
 *
 * `recordCertifiedLeafSet` refuses anything that does not reproduce `sealedRootHex`, so a failure
 * here costs the SESSION its inclusion proofs and costs the RECEIPT nothing — hence a warn that says
 * so, and no `return` that would abandon a seal over it.
 */
function keepCertifiedLeafSet(
  deps: { logger: Logger; sessionNodeManager: SessionNodeManager },
  agentName: string,
  sidHex: string,
  frame: Record<string, unknown>,
  sealedRootHex: string,
  path: "bilateral" | "unilateral" | "unilateral_notification",
): void {
  const leaves = parseFrontierLeaves(frame["frontier_leaves"]);
  if (!leaves) {
    /**
     * ABSENT IS NOT FINE — it is just not fatal. And WHICH absence this is decides what the operator
     * should do, so it is recorded rather than flattened (fallback-finder findings 1 and 3).
     *
     * ⚠️ THIS GUIDANCE USED TO END *"The other party, whose confirm frame carries the leaves, can
     * still issue proofs."* That is true on the `unilateral_notification` path and FALSE on
     * `unilateral`: there, WE are the present party and the other party is the ABSENT one, who holds
     * strictly less. So the one string sent each side to ask the other for something neither has —
     * a remedy that reads actionable and is not, which spends the reader's trust as well as their
     * time.
     */
    const state = path === "unilateral_notification" ? "not_carried_absent_party" : "not_carried_present_party";
    deps.sessionNodeManager.noteCertifiedLeafSetUnavailable(agentName, sidHex, state, `no frontier_leaves on the ${path} seal frame`);
    deps.logger.warn("seal.certified_leaves.not_carried", {
      sessionId: sidHex,
      agentName,
      path,
      state,
      impact:
        "this seal frame carried no signed leaves, so this side holds no certified leaf set for the " +
        "session and cannot issue an inclusion proof for any message in it; the sealed receipt itself " +
        "is complete and unaffected",
      guidance:
        state === "not_carried_absent_party"
          ? "cello_get_inclusion_proof refuses this session by name (certified_leaves_unavailable). This side was the ABSENT party, so the counterparty — whose confirm frame carries the leaves — can still issue proofs."
          : "cello_get_inclusion_proof refuses this session by name (certified_leaves_not_carried). This side was PRESENT and the directory sent no leaves, so NEITHER side can prove an individual message here; do not send the operator to the counterparty for one.",
    });
    return;
  }
  try {
    deps.sessionNodeManager.recordCertifiedLeafSet(agentName, sidHex, leaves, sealedRootHex);
  } catch (error) {
    deps.logger.warn("seal.certified_leaves.persist.failed", {
      sessionId: sidHex,
      agentName,
      path,
      reason: error instanceof Error ? error.message : String(error),
      impact: "no inclusion proof can be issued for this session; the sealed receipt is unaffected",
    });
  }
}

/**
 * SESSION-002 / M8B FINDING-3: a unilateral seal carries the legibility certificate so the close
 * returns it inline — the same RESPONSE SHAPE as a bilateral close, but NOT cryptographic parity:
 * this cert is directory-attested (FINDING-5). `remainingSeconds` carries the directory's
 * seal_unilateral_too_early countdown, so the close can tell the operator WHEN a unilateral seal
 * becomes available.
 */
export type UnilateralResult =
  | { ok: true; sealedRootHex: string; legibility?: unknown }
  | { ok: false; reason: string; remainingSeconds?: number };

export interface SealCoordinatorDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** PERSIST-002: the agent's encrypted FROST-share persistence seam. */
  getPersistence: (agentName: string) => DbRegistrationPersistence;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  /**
   * Recover parked content for an agent. THE KERNEL of DOD-UP-1 depends on this: the absent party
   * ratifies a seal ONLY after it has recovered and integrity-verified the content behind the
   * sealed root. It never co-signs content it could not verify.
   */
  recoverContent: (agentName: string) => Promise<void>;
}

export function createSealCoordinator(deps: SealCoordinatorDeps) {
  const { logger, sessionNodeManager, getPersistence, getKeyProvider, recoverContent } = deps;

  // DOD-LOOP-1: daemon-level seal bookkeeping is keyed by (agentName, sessionId), NOT sessionId
  // alone — two of the operator's agents can hold both ends of the same session_id on one daemon
  // (loopback), and each end seals independently. Keying by session_id alone would let A's close
  // block B's (false seal_interrupted_in_progress) and make their seal waiters collide.
  const sealKey = (agentName: string, sessionId: string): string => `${agentName}\x1f${sessionId}`;

  // M7-SESSION-001: tracks seal-interrupted flows currently in progress.
  // Prevents duplicate concurrent seal-interrupted attempts for the same (agent, session) (AC-011).
  const sealInterruptedInProgress = new Set<string>();

  // M7 DOD-SPINE-7: relay-mediated bilateral seal. cello_close_session registers a waiter
  // per session_id (hex); the directory's session_sealed frame — delivered over the agent's
  // signaling stream after FROST notarization, once BOTH parties have submitted their SEAL
  // ctrl leaf — resolves it with the sealed_root.
  // M7-SESSION-004: the bilateral seal resolves with the sealed_root AND the legibility
  // certificate (receipt-not-assent, per-party frontiers, attestation modes, final_message).
  const pendingSealWaiters = new Map<string, (completion: SealCompletion) => void>();

  // M7 DOD-SPINE-7: register the session_sealed completion handler on a signaling manager — per-agent
  // in production (the directory routes session_sealed to the session-owning agent's authenticated
  // stream), or the shared manager on the test path. Function declaration so getAgentSignaling
  // (defined earlier, called at runtime) can wire it per-agent.
  function registerSessionSealedListener(signaling: SignalingManager, agentName: string, agentPubkeyHex: string): () => void {
    return signaling.registerInboundHandler((frame) => {
      if (frame["type"] !== "session_sealed") return;
      const sidHex = frameValueToHex(frame["session_id"]);
      const rootHex = frameValueToHex(frame["sealed_root"]);
      if (!sidHex || !rootHex) return;
      void (async () => {
        const toU8 = (v: unknown): Uint8Array | null =>
          v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;

        // M7 legibility-TBS-binding: when THIS party is the seal's signer (the initiator, whose
        // group key produced the FROST signature), verify the signature over the legibility-bound
        // TBS. A tampered legibility (answered / content_frontier_seq / attestation_mode, carried
        // unsigned on the frame) changes the hash → the signature fails → the seal is REJECTED. The
        // non-initiator does not hold the signer's key, so it accepts (verified:false): the frame
        // arrived over the authenticated Noise channel, and the binding lets any out-of-band holder
        // of the initiator's primary verify an exported cert.
        if (frame["signature_type"] === "frost") {
          const sessionIdBytes = toU8(frame["session_id"]);
          const sealedRootBytes = toU8(frame["sealed_root"]);
          const frostSig = toU8(frame["frost_signature"]);
          const signerPubkey = toU8(frame["signer_pubkey"]);
          const leafCount = typeof frame["leaf_count"] === "number" ? frame["leaf_count"] : null;
          const ctRaw = frame["close_timestamp"];
          const closeTs = typeof ctRaw === "number" ? ctRaw : typeof ctRaw === "bigint" ? Number(ctRaw) : null;
          if (!sessionIdBytes || !sealedRootBytes || !frostSig || !signerPubkey || leafCount === null || closeTs === null) {
            logger.error("session.sealed.signature.invalid", { sessionId: sidHex, reason: "missing_certificate_fields" });
            return;
          }
          const record = sessionNodeManager.getSessionRecord(agentName, sidHex);
          const verdict = await verifyBilateralSealCertificate(
            { persistence: getPersistence(agentName), agentPubkeyHex, logger, counterpartyPrimaryHex: record?.counterparty_primary_pubkey ?? null },
            {
              sessionId: sessionIdBytes,
              sealedRoot: sealedRootBytes,
              leafCount,
              closeTimestamp: closeTs,
              frostSignature: frostSig,
              signerPubkey,
              signatureType: "frost",
              legibility:
                frame["legibility"] && typeof frame["legibility"] === "object"
                  ? (frame["legibility"] as LegibilityForHash)
                  : null,
            },
          );
          if (!verdict.ok) {
            // tamper-evidence: do NOT mark sealed, do NOT resolve the waiter as success.
            logger.error("session.sealed.signature.invalid", { sessionId: sidHex, reason: verdict.reason });
            return;
          }

          /**
           * IS THIS A ROOT OVER *OUR* CONVERSATION? — `DOD-M15-SEALWIRE-1` bullet 2.
           *
           * The signature check above proves the directory signed these bytes. It does not prove the
           * bytes describe this session. Until bullet 1 the client could not tell: the certified root
           * was the relay/directory internal root, which carries relay-assigned fields this daemon
           * never sees for the counterparty's leaves. So the root computed one step earlier was
           * discarded, and at co-signing time this key signed a root it had never checked.
           *
           * Now both live in the content-hash domain and it is a comparison.
           *
           * THE COUNTERBALANCE, and why this is not simply "refuse on any difference": a wrong
           * comparison makes every session unsealable, leaving force-abandon — no receipt — as the
           * only exit. That is worse than the defect it guards. So the daemon distinguishes "the
           * roots disagree" from "I cannot judge": the carry is this daemon's own view and may be
           * legitimately short at this instant, because the counterparty's SEAL leaf is what
           * TRIGGERS the seal and may not have been witnessed here yet. Only a provably complete
           * carry can accuse.
           */
          const rootCheck = sessionNodeManager.verifyCertifiedRoot(
            agentPubkeyHex, sidHex, sealedRootBytes, leafCount,
          );
          if (rootCheck.verdict === "mismatch") {
            /**
             * RESOLVE THE WAITER AS REFUSED — review F4. Dropping it left the caller to time out and
             * be told something false. The close now answers with what actually happened.
             */
            const waiter = pendingSealWaiters.get(sealKey(agentName, sidHex));
            if (waiter) {
              pendingSealWaiters.delete(sealKey(agentName, sidHex));
              waiter({
                refused: true,
                reason: "seal_root_mismatch",
                detail: rootCheck.detail,
                ownRootHex: rootCheck.ownRootHex,
              });
            }
            logger.error("session.sealed.root.mismatch", {
              /**
               * `agentName` — review pass 1 on bullet 8, H2. Both verdict events carried only
               * `sessionId`, and ONE DAEMON CAN HOST BOTH ENDS OF ONE SESSION (`DOD-LOOP-1`
               * loopback). Two verdicts then land under the same key, indistinguishable, and a
               * reader — or a journey scraping the log — attributes one end's answer to the other.
               * It is also why `j-loopback` could not use the new journey assertion at all.
               */
              agentName,
              sessionId: sidHex,
              certifiedRoot: rootHex,
              ownRoot: rootCheck.ownRootHex,
              detail: rootCheck.detail,
              leafCount,
              impact:
                "the directory signed a root over a leaf set this daemon does not hold. The signature " +
                "is valid, so this is not a forged certificate — it is a certificate over a DIFFERENT " +
                "conversation, or over this one with leaves added, dropped or reordered. Refusing: " +
                "storing it would produce a receipt that proves nothing about what was actually said.",
              guidance:
                "The session is NOT marked sealed and the transcript is untouched. Compare the leaf " +
                "count with the counterparty, and check the relay and directory logs for this session id.",
            });
            return;
          }
          logger.info("session.sealed.root.checked", {
            agentName,
            sessionId: sidHex,
            verdict: rootCheck.verdict,
            ...(rootCheck.verdict === "cannot_judge" ? { reason: rootCheck.reason } : {}),
            ...(rootCheck.verdict === "cannot_judge"
              ? {
                  impact:
                    "the certified root was accepted WITHOUT being checked against this daemon's own " +
                    "leaves, because this daemon cannot yet prove it holds the same leaf set. The " +
                    "signature was verified; the CONTENT was not.",
                }
              : {}),
          });
          // F2-a: on verified:false, surface WHY (signer_key_not_held / no_frost_share / …) so this
          // event can never be mistaken for a tolerated failed check. A real failure took the early
          // return above (session.sealed.signature.invalid) and never reaches here.
          logger.info("session.sealed.signature.checked", {
            sessionId: sidHex,
            verified: verdict.verified,
            ...(verdict.verified ? {} : { reason: verdict.reason }),
          });
        }

        // M7-SESSION-004 (AC-005): normalise the wire legibility (Uint8Array pubkeys → hex) into a
        // JSON-safe certificate and persist it with the sealed record so it survives a restart and
        // is readable via cello_get_sealed_receipt — receipt-not-assent, per-party frontiers,
        // attestation modes, and final_message.answered.
        const legibility = normalizeLegibility(frame["legibility"]);
        logger.info("session.sealed.received", {
          sessionId: sidHex,
          sealedRoot: rootHex,
          hasLegibility: legibility !== undefined,
          finalMessageAnswered:
            legibility && typeof legibility === "object" && "final_message" in legibility
              ? (legibility as { final_message?: { answered?: boolean } }).final_message?.answered
              : undefined,
        });
        // DOD-LEG-2 (SI-002): independently re-derive each party's content_frontier_seq from the
        // signed leaves the directory shipped, and REJECT the certificate if any published frontier
        // is inflated beyond what the signed leaves support. The client does NOT trust the directory
        // for the frontier VALUE — only for transporting signed bytes it re-checks itself. When no
        // frontier_leaves are present (a pre-LEG-2 directory), the guard is skipped (backward-compat).
        const frontierLeavesRaw = frame["frontier_leaves"];
        if (legibility !== undefined) {
          const rawParticipants =
            (legibility as { participants?: Array<{ pubkey?: unknown; content_frontier_seq?: unknown }> }).participants ?? [];
          // Any party claiming to have received content (frontier > 0) MUST be backed by signed leaves.
          const anyClaimedFrontier = rawParticipants.some(
            (p) => typeof p.content_frontier_seq === "number" && p.content_frontier_seq > 0,
          );
          const haveLeaves = Array.isArray(frontierLeavesRaw) && frontierLeavesRaw.length > 0;
          // HIGH (fail-closed): a malicious directory must not bypass the guard by OMITTING the leaves
          // while still publishing a frontier. No leaves + a claimed frontier → reject.
          if (anyClaimedFrontier && !haveLeaves) {
            logger.error("seal.certificate.frontier.unverifiable", { sessionId: sidHex, reason: "frontier_leaves_missing" });
            return;
          }
          // LOW (robustness): a malformed/malicious legibility (null pubkey or non-numeric frontier)
          // must be rejected, never crash the guard.
          for (const p of rawParticipants) {
            if (typeof p.pubkey !== "string" || typeof p.content_frontier_seq !== "number") {
              logger.error("seal.certificate.frontier.unverifiable", { sessionId: sidHex, reason: "participant_malformed" });
              return;
            }
          }
          const participants = rawParticipants as Array<{ pubkey: string; content_frontier_seq: number }>;

          if (haveLeaves) {
          const toU8 = (v: unknown): Uint8Array => (v instanceof Uint8Array ? v : new Uint8Array(v as ArrayLike<number>));
          const leaves: SealFrontierLeaf[] = (frontierLeavesRaw as unknown[]).map((l) => {
            const o = l as Record<string, unknown>;
            return {
              structure1_cbor: toU8(o["structure1_cbor"]),
              sender_pubkey: toU8(o["sender_pubkey"]),
              sender_signature: toU8(o["sender_signature"]),
            };
          });
          // Session-bound re-derivation (BLOCKING fix): leaves must be from THIS session, so a
          // malicious directory cannot replay a party's leaves from another session to inflate.
          const rederived = reDeriveFrontiers(leaves, toU8(frame["session_id"]));
          if (!rederived.ok) {
            logger.error("seal.certificate.frontier.unverifiable", { sessionId: sidHex, reason: rederived.reason });
            return;
          }
          const inflated = findInflatedFrontier(participants, rederived.frontiers);
          if (inflated) {
            // The directory published a frontier higher than the signed leaves support — refuse the
            // seal (do NOT persist, do NOT resolve the close as success), exactly like a bad signature.
            logger.error("seal.certificate.frontier.unverifiable", {
              sessionId: sidHex,
              party: inflated.party,
              publishedFrontier: inflated.publishedFrontier,
              derivedFrontier: inflated.derivedFrontier,
            });
            return;
          }
          logger.info("seal.certificate.frontier.verified", {
            sessionId: sidHex,
            parties: participants.length,
          });
          }
        }

        if (legibility !== undefined) {
          try {
            sessionNodeManager.recordSealCertificate(agentName, sidHex, rootHex, JSON.stringify(legibility));
          } catch (error) {
            logger.warn("seal.certificate.persist.failed", {
              sessionId: sidHex,
              reason: error instanceof Error ? error.message : String(error),
            });
          }
          keepCertifiedLeafSet({ logger, sessionNodeManager }, agentName, sidHex, frame, rootHex, "bilateral");
        }
        const waiter = pendingSealWaiters.get(sealKey(agentName, sidHex));
        if (waiter) {
          pendingSealWaiters.delete(sealKey(agentName, sidHex));
          waiter({ rootHex, legibility });
        }
        // STATUS FIRST AND SYNCHRONOUS, teardown second. The comment here used to read "mark the
        // session sealed + tear the node down (idempotent — safe if already gone)" — it asserted the
        // property the code lacked, which is why the gap survived. `destroySessionNode` returns
        // early at `if (!entry) return` and writes the status BELOW that guard, so for a session
        // with no live node the receipt landed and the row never moved.
        try { sessionNodeManager.markSealed(agentName, sidHex); }
        catch (err: unknown) {
          logger.error("session.seal.status.write.threw", {
            sessionId: sidHex, agentName,
            error: err instanceof Error ? err.message : String(err),
            impact: "the seal COMPLETED and the certificate is stored, but this row still reads interrupted",
          });
        }
        void sessionNodeManager.destroySessionNode(agentName, sidHex, "sealed");
      })();
    });
  }

  // SESSION-002 (DOD-SEAL): cello_close_session escalates to a UNILATERAL seal when the
  // counterparty never co-closes. The waiter is resolved by the seal_unilateral_confirmed
  // listener AFTER it verifies the certificate signature (channel-independent), or by
  // seal_unilateral_too_early (grace not elapsed). Keyed by session_id hex.
  // F20: `remainingSeconds` carries the directory's seal_unilateral_too_early countdown so the
  // close result can tell the operator WHEN a unilateral seal becomes available.
  // M8B FINDING-3 (cascade-2): a successful unilateral seal now carries the legibility certificate
  // (normalized, JSON-safe) so cello_close_session returns it inline — the same RESPONSE SHAPE as the
  // bilateral close (not cryptographic parity: this cert is directory-attested, see FINDING-5). undefined
  // when the directory shipped none (a pre-cascade-2 directory): the seal still completes, but no
  // retrievable receipt is produced (the pre-fix behavior).
  // KEYED `agent\x1f session`, like `sealInterruptedInProgress` — NOT by session id alone.
  //
  // Two agents on one daemon is a supported topology (and the one the operator actually runs), and
  // the away-path one-shot escalation can overlap a manual close. Keyed by session id, whichever
  // registered second CLOBBERED the first's resolver: the loser waited out the full 30 s and
  // reported `seal_unilateral_timeout` for a seal that SUCCEEDED — the operator is then told the
  // directory could not verify their root, for a session that is notarized.
  const pendingUnilateralWaiters = new Map<string, (r: UnilateralResult) => void>();

  // SESSION-002: per-agent listener for the unilateral certificate. Verifies the FROST
  // signature over the rebuilt TBS against the agent's own primary_pubkey BEFORE resolving
  // the close as sealed (SI-003: a channel-swapped sealed_root fails the signature check).
  function registerUnilateralConfirmedListener(
    signaling: SignalingManager,
    agentName: string,
    agentPubkeyHex: string,
  ): () => void {
    return signaling.registerInboundHandler((frame) => {
      const ftype = frame["type"];
      if (ftype !== "seal_unilateral_confirmed" && ftype !== "seal_unilateral_too_early") return;
      const sidHex = frameValueToHex(frame["session_id"]);
      if (!sidHex) return;
      const waiter = pendingUnilateralWaiters.get(sealKey(agentName, sidHex));
      if (!waiter) return;

      if (ftype === "seal_unilateral_too_early") {
        pendingUnilateralWaiters.delete(sealKey(agentName, sidHex));
        // F20: thread the directory's remaining_seconds through so the close guidance can
        // say when the unilateral seal becomes available.
        const rs = frame["remaining_seconds"];
        waiter({
          ok: false,
          reason: "seal_unilateral_too_early",
          ...(typeof rs === "number" ? { remainingSeconds: rs } : {}),
        });
        return;
      }

      void (async () => {
        const toU8 = (v: unknown): Uint8Array | null =>
          v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;
        const sessionId = toU8(frame["session_id"]);
        const sealedRoot = toU8(frame["sealed_root"]);
        const frostSig = toU8(frame["frost_signature"]);
        const leafCount = typeof frame["leaf_count"] === "number" ? frame["leaf_count"] : null;
        const tsRaw = frame["close_timestamp"];
        const closeTs = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
        const sigType = frame["signature_type"];
        if (!sessionId || !sealedRoot || !frostSig || leafCount === null || closeTs === null ||
            (sigType !== "frost" && sigType !== "single")) {
          logger.warn("session.unilateral.certificate.invalid", { sessionId: sidHex, reason: "malformed_certificate" });
          pendingUnilateralWaiters.delete(sealKey(agentName, sidHex));
          waiter({ ok: false, reason: "malformed_certificate" });
          return;
        }
        const result = await verifyUnilateralCertificate(
          { persistence: getPersistence(agentName), agentPubkeyHex, logger },
          { sessionId, sealedRoot, leafCount, closeTimestamp: closeTs, frostSignature: frostSig, signatureType: sigType },
        );
        pendingUnilateralWaiters.delete(sealKey(agentName, sidHex));
        if (!result.ok) {
          // SI-003: do NOT mark sealed when the certificate signature does not verify.
          logger.warn("session.unilateral.certificate.invalid", { sessionId: sidHex, reason: result.reason, signatureType: sigType });
          waiter({ ok: false, reason: `certificate_invalid:${result.reason}` });
          return;
        }
        logger.info("session.unilateral.certificate.verified", { sessionId: sidHex, signatureType: sigType, party: "present" });

        // M8B FINDING-3 (cascade-2): normalise + PERSIST the legibility certificate the directory
        // now ships on this frame — the SAME store the bilateral session_sealed handler writes
        // (recordSealCertificate → read back by cello_get_sealed_receipt). Without this a unilateral
        // close returned ok+root but sealed_receipt_not_found forever: the whole point of sealing
        // when your counterparty vanished is walking away with a DURABLE, RETRIEVABLE receipt.
        // Persist BEFORE destroying the node (bilateral ordering) so the sessions row still exists
        // for the UPDATE. undefined legibility (a pre-cascade-2 directory) → nothing persisted; the
        // seal still completes — surfaced loudly so this can never masquerade as a produced receipt.
        const rootHex = Buffer.from(sealedRoot).toString("hex");
        const legibility = normalizeLegibility(frame["legibility"]);

        // M8B FINDING-5 (SI-002): before persisting, INDEPENDENTLY re-derive each CLIENT-VERIFIABLE
        // ('live', the present party) frontier from the signed frontier_leaves and OVERRIDE an inflated
        // directory-published value DOWN to the provable one (the directory cannot forge signed leaves,
        // so the re-derived value is truth). We OVERRIDE, never reject — the unilateral seal has a
        // directory-side dedup guard that makes a client rejection unrecoverable (a retry close is
        // silently ignored → no receipt ever, worse than FINDING-3; cascade-2 reviewer Critical 2). The
        // absent party's frontier stays directory-attested (its remainder is not re-derivable here). No
        // frontier_leaves (pre-FINDING-5 directory) → the cert stays directory-attested (FINDING-3).
        // A receipt is ALWAYS persisted; the close never dead-ends here.
        if (legibility !== undefined) {
          const rawParticipants =
            (legibility as { participants?: Array<{ pubkey?: unknown; content_frontier_seq?: unknown; attestation_mode?: unknown }> }).participants ?? [];
          const guardParticipants = rawParticipants
            .filter((p): p is { pubkey: string; content_frontier_seq: unknown; attestation_mode: string } =>
              typeof p.pubkey === "string" && typeof p.attestation_mode === "string")
            .map((p) => ({
              pubkey: p.pubkey,
              content_frontier_seq: typeof p.content_frontier_seq === "number" ? p.content_frontier_seq : 0,
              attestation_mode: p.attestation_mode,
            }));
          const frontierLeavesRaw = frame["frontier_leaves"];
          const toU8f = (v: unknown): Uint8Array => (v instanceof Uint8Array ? v : new Uint8Array(v as ArrayLike<number>));
          const parsedFrontierLeaves: SealFrontierLeaf[] | undefined =
            Array.isArray(frontierLeavesRaw) && frontierLeavesRaw.length > 0
              ? (frontierLeavesRaw as unknown[]).map((l) => {
                  const o = l as Record<string, unknown>;
                  return {
                    structure1_cbor: toU8f(o["structure1_cbor"]),
                    sender_pubkey: toU8f(o["sender_pubkey"]),
                    sender_signature: toU8f(o["sender_signature"]),
                  };
                })
              : undefined;
          const check = checkUnilateralFrontier(guardParticipants, parsedFrontierLeaves, sessionId);
          // Apply any frontier corrections to the object we persist — override inflated 'live'
          // frontier(s) DOWN to the provable value, so the stored receipt never claims more than the
          // signed leaves support. Runs for both 'corrected' (valid leaves) and 'leaves_invalid'
          // (forged leaves → corrected to 0). Never rejects → the close never dead-ends.
          if (check.corrections.size > 0) {
            for (const p of rawParticipants) {
              if (typeof p.pubkey === "string" && check.corrections.has(p.pubkey.toLowerCase())) {
                (p as { content_frontier_seq?: unknown }).content_frontier_seq = check.corrections.get(p.pubkey.toLowerCase());
              }
            }
          }
          if (check.status === "corrected") {
            logger.error("seal.certificate.frontier.overridden", {
              sessionId: sidHex,
              corrections: [...check.corrections.entries()].map(([party, seq]) => ({ party, correctedTo: seq })),
              path: "unilateral",
            });
          } else if (check.status === "verified") {
            logger.info("seal.certificate.frontier.verified", {
              sessionId: sidHex,
              parties: guardParticipants.filter((p) => p.attestation_mode === "live").length,
              path: "unilateral",
            });
          } else if (check.status === "leaves_invalid") {
            // Forged / cross-session leaves — a tamper signal. The 'live' frontier(s) have been
            // corrected to 0 above (zero trustworthy evidence); persist that (never reject → never
            // dead-end). Surfaced loudly for audit.
            logger.error("seal.certificate.frontier.leaves_invalid", {
              sessionId: sidHex,
              reason: check.reason,
              corrections: [...check.corrections.entries()].map(([party, seq]) => ({ party, correctedTo: seq })),
              path: "unilateral",
            });
          } else {
            // directory_attested: no frontier_leaves shipped (pre-FINDING-5 directory). Frontiers stay
            // DIRECTORY-attested (already marked per-participant) — visible/auditable, never silently
            // presented as client-verified.
            logger.warn("seal.certificate.frontier.directory_attested", {
              sessionId: sidHex,
              reason: "no_frontier_leaves",
              path: "unilateral",
            });
          }
        }

        if (legibility !== undefined) {
          try {
            sessionNodeManager.recordSealCertificate(agentName, sidHex, rootHex, JSON.stringify(legibility));
            logger.info("session.unilateral.receipt.persisted", {
              sessionId: sidHex,
              sealedRoot: rootHex,
              finalMessageAnswered:
                legibility && typeof legibility === "object" && "final_message" in legibility
                  ? (legibility as { final_message?: { answered?: boolean } }).final_message?.answered
                  : undefined,
            });
          } catch (error) {
            logger.warn("seal.certificate.persist.failed", {
              sessionId: sidHex,
              reason: error instanceof Error ? error.message : String(error),
            });
          }
          keepCertifiedLeafSet({ logger, sessionNodeManager }, agentName, sidHex, frame, rootHex, "unilateral");
        } else {
          // The seal is valid, but no receipt is retrievable — a directory that predates cascade-2.
          logger.warn("session.unilateral.receipt.absent", { sessionId: sidHex, reason: "no_legibility_on_frame" });
        }
        // THE WAITER IS ANSWERED FIRST. `markSealed` is SYNCHRONOUS and reaches `#requireAgentId`,
        // which throws for a retired agent or a closed database — and a throw here would escape
        // this frame, leave the waiter unresolved, and make the close sit out its full timeout and
        // report `seal_unilateral_timeout` for a seal that COMPLETED and whose certificate is
        // already on disk. That is the error-substitution defect this milestone was opened on,
        // reproduced on the path that fixes it. The old line was an async `void`, whose throw
        // became a discarded rejection and could not do this.
        waiter({ ok: true, sealedRootHex: rootHex, legibility });
        // STATUS THEN TEARDOWN — and on THIS path the node is gone by construction. A unilateral
        // seal is what an interrupted session escalates to, and every producer of `interrupted`
        // deletes the `#activeNodes` entry, so `destroySessionNode` alone would return before the
        // status write every single time.
        try {
          sessionNodeManager.markSealed(agentName, sidHex);
        } catch (err: unknown) {
          logger.error("session.seal.status.write.threw", {
            sessionId: sidHex, agentName,
            error: err instanceof Error ? err.message : String(err),
            impact: "the seal COMPLETED and the certificate is stored, but this row still reads interrupted",
          });
        }
        void sessionNodeManager.destroySessionNode(agentName, sidHex, "sealed");
      })();
    });
  }

  // ─── DOD-UP-1: returning-absent-party seal upgrade (unilateral → bilateral) ───
  // Per-session idempotency guard so a notification burst (reconnect re-delivery) cannot launch
  // concurrent upgrade attempts. Keyed `${agentName}:${sessionIdHex}`; cleared after each attempt.
  const sealUpgradeInFlight = new Set<string>();

  /**
   * DOD-UP-1: B (the absent party) ratifies a unilateral seal it learns about on reconnect.
   *
   * THE KERNEL: B signs the ratification ONLY after it has recovered + integrity-verified the
   * content behind the sealed root. We (0) verify the unilateral cert so R1 is provably authentic
   * (SI-003 — a channel-swapped root fails); (1) recover any parked content from the relay; (2) gate
   * on getSealUpgradeReadiness — refuse content_unrecoverable (session unknown) or content_tamper
   * (cross-check mismatch, AC-003); only then (3) sign the ack over R1 with B's OWN K_local and send
   * seal_upgrade_request. B never co-signs content it could not verify.
   */
  // Thin wrapper over the extracted, unit-tested seal-upgrade.ts module (the KERNEL + AC-008 + H1/M1
  // hardening live there so the refusal/reject bodies run under adversarial tests). This wrapper owns
  // only the per-session in-flight guard and the real-dep injection.
  async function attemptSealUpgrade(
    signaling: SignalingManager,
    agentName: string,
    agentPubkeyHex: string,
    sidHex: string,
    frame: Record<string, unknown>,
  ): Promise<void> {
    const key = `${agentName}:${sidHex}`;
    if (sealUpgradeInFlight.has(key)) return;
    sealUpgradeInFlight.add(key);
    try {
      const result = await attemptSealUpgradeImpl(
        {
          logger, agentName, agentPubkeyHex,
          getReadiness: (a, s) => sessionNodeManager.getSealUpgradeReadiness(a, s),
          getContentLeafCount: (a, s) => sessionNodeManager.getSessionTree(a, s).size(),
          recoverContent: (a) => recoverContent(a),
          getKeyProvider: (a) => getKeyProvider(a),
          sendRaw: (f) => signaling.sendRaw(f),
        },
        sidHex,
        frame,
      );
      // M8B FINDING-6 (3b): the ABSENT party (B) persists its UNILATERAL receipt from the
      // notification's legibility — but ONLY after the KERNEL content-recovery/verify gate passed.
      // `result.sent` is true iff attemptSealUpgradeImpl recovered + integrity-verified the content
      // behind R1 and sent the ratification request; a tampered/unrecoverable/incomplete case returns
      // sent:false → NO receipt (never a receipt for content B could not verify). B may hold no local
      // `sessions` row (recordSealCertificateEnsuringRow inserts a stub, counterparty = A's pubkey).
      // The notification carries no frontier_leaves (FINDING-5 ships those only on the present party's
      // confirm frame), so B's legibility is directory-attested — consistent with FINDING-5's
      // directory_attested path; B trusts its own KERNEL-verified content, not a re-derivation.
      if (result.sent) {
        try {
          // ONE-WAY RATCHET (cascade-2 FINDING-6 review): a re-delivered seal_unilateral_notification
          // (reconnect burst) re-runs this path and would re-persist the notification's ORIGINAL
          // legibility (counterparty 'absent'). If a prior upgrade already flipped the stored receipt
          // to 'recovered' (no 'absent' participant), re-persisting would REGRESS it — and no later
          // event restores 'recovered' (the directory dedups the duplicate as already_bilateral →
          // seal_upgrade_rejected, which only logs). So skip the re-persist once the cert is upgraded.
          const existing = sessionNodeManager.getSealCertificate(agentName, sidHex);
          if (existing && !hasAbsentParticipant(existing.legibility)) {
            logger.debug("session.unilateral.receipt.persist.skipped", { sessionId: sidHex, reason: "already_upgraded" });
          } else {
            const legibility = normalizeLegibility(frame["legibility"]);
            const rootHex = frameValueToHex(frame["sealed_root"]);
            const counterpartyHex = frameValueToHex(frame["present_pubkey"]); // A — the present party
            if (legibility !== undefined && rootHex && counterpartyHex) {
              sessionNodeManager.recordSealCertificateEnsuringRow(agentName, sidHex, counterpartyHex, rootHex, JSON.stringify(legibility));
              logger.info("session.unilateral.receipt.persisted", { sessionId: sidHex, sealedRoot: rootHex, party: "absent" });
              keepCertifiedLeafSet({ logger, sessionNodeManager }, agentName, sidHex, frame, rootHex, "unilateral_notification");
            } else if (legibility === undefined) {
              logger.warn("session.unilateral.receipt.absent", { sessionId: sidHex, reason: "no_legibility_on_notification" });
            }
          }
        } catch (error) {
          logger.warn("seal.certificate.persist.failed", { sessionId: sidHex, reason: error instanceof Error ? error.message : String(error) });
        }
      }
    } finally {
      // Clear the guard so a later reconnect can retry if the request never reached the directory;
      // the directory dedups a repeat with already_bilateral.
      sealUpgradeInFlight.delete(key);
    }
  }

  // Thin wrapper: verify the dual-attestation cert (module, AC-008 + H1), then APPLY — mark bilateral
  // ONLY on ok. Never trust the directory's "bilateral" claim.
  async function verifyAndApplyUpgradeConfirmed(
    agentName: string,
    agentPubkeyHex: string,
    sidHex: string,
    frame: Record<string, unknown>,
  ): Promise<void> {
    const result = await verifyUpgradeConfirmedCert(
      {
        logger, agentName, agentPubkeyHex, persistence: getPersistence(agentName),
        getCounterpartyHex: (a, s) => sessionNodeManager.getSessionRecord(a, s)?.counterparty_pubkey ?? null,
      },
      sidHex,
      frame,
    );
    if (!result.ok) return; // cert.invalid already logged inside; do NOT accept as bilateral.
    logger.info("session.seal.upgraded", { sessionId: sidHex, agentName, party: result.party });
    // M8B FINDING-6 (3a): the seal is now BILATERAL (verified) — upgrade THIS party's own stored
    // receipt so the counterparty recorded 'absent' becomes 'recovered'. Client-side: the directory
    // ships no bilateral legibility at upgrade time (the seal leaves aren't persisted there), so each
    // party rebuilds from the cert it already holds — the present party's from its unilateral close
    // (FINDING-3), the returning party's from the notification it persisted after the KERNEL gate
    // (3b). The seal signatures do not bind the (unsigned) legibility, so mutating it is sound; only
    // the attestation flips (frontiers unchanged — never overstated). No-op if no cert is stored yet.
    const stored = sessionNodeManager.getSealCertificate(agentName, sidHex);
    if (stored) {
      try {
        const upgraded = upgradeAbsentToRecovered(stored.legibility);
        sessionNodeManager.recordSealCertificate(agentName, sidHex, stored.sealed_root, JSON.stringify(upgraded));
        logger.info("session.seal.receipt.upgraded", { sessionId: sidHex, agentName, party: result.party });
      } catch (error) {
        logger.warn("seal.certificate.persist.failed", { sessionId: sidHex, reason: error instanceof Error ? error.message : String(error) });
      }
    }
    // STATUS FIRST — same reason as the two sites above.
    try { sessionNodeManager.markSealed(agentName, sidHex); }
    catch (err: unknown) {
      logger.error("session.seal.status.write.threw", {
        sessionId: sidHex, agentName,
        error: err instanceof Error ? err.message : String(err),
        impact: "the seal COMPLETED and the certificate is stored, but this row still reads interrupted",
      });
    }
    void sessionNodeManager.destroySessionNode(agentName, sidHex, "sealed");
  }

  /**
   * DOD-UP-1: per-agent listener for the absent-party seal upgrade. On reconnect the directory
   * delivers a queued seal_unilateral_notification to B (the absent party) — that triggers the
   * ratification attempt. The directory's seal_upgrade_confirmed / seal_upgrade_rejected responses
   * are observed here too (B marks the session bilaterally sealed / logs the refusal).
   */
  function registerUnilateralUpgradeListener(
    signaling: SignalingManager,
    agentName: string,
    agentPubkeyHex: string,
  ): () => void {
    return signaling.registerInboundHandler((frame) => {
      const ftype = frame["type"];
      if (ftype === "seal_upgrade_confirmed") {
        const sidHex = frameValueToHex(frame["session_id"]);
        if (!sidHex) return;
        // AC-008: do NOT accept "bilateral" on the directory's word — verify the dual attestation.
        void verifyAndApplyUpgradeConfirmed(agentName, agentPubkeyHex, sidHex, frame);
        return;
      }
      if (ftype === "seal_upgrade_rejected") {
        const sidHex = frameValueToHex(frame["session_id"]);
        if (!sidHex) return;
        logger.warn("session.seal.upgrade.rejected", { sessionId: sidHex, agentName, reason: frame["reason"] });
        return;
      }
      if (ftype !== "seal_unilateral_notification") return;
      const sidHex = frameValueToHex(frame["session_id"]);
      if (!sidHex) return;
      // Only the ABSENT party receives this frame — B reacts by attempting the ratification.
      void attemptSealUpgrade(signaling, agentName, agentPubkeyHex, sidHex, frame);
    });
  }
  /**
   * Wire the WHOLE seal listener set onto an authenticated signaling stream.
   *
   * A BUNDLE, deliberately — the three listeners are NOT exported individually, because being able
   * to register two of the three is what caused the bug this replaced. The daemon's VISITING stream
   * registered `session_sealed` + `seal_unilateral_confirmed` but not the upgrade listener, and that
   * looked intentional. It was not: the directory drains its DURABLE notification queue on any
   * stream that authenticates — visiting included — and DELETES each row once sent. So a
   * `seal_unilateral_notification` pushed down a visiting stream hit no handler, was dropped, and
   * its durable row was gone. The absent party never ratified, and the seal stayed unilateral
   * forever: silent, permanent loss of a notarized receipt.
   *
   * Every stream that can carry a seal frame gets every seal listener. Making the partial case
   * impossible to express is the fix; a comment asking future callers to remember all three is not.
   *
   * Safe to call on any stream, including transient ones: `attemptSealUpgrade` holds a per-session
   * in-flight guard, the receipt persist is behind the one-way ratchet, and the directory dedups a
   * repeated ratification with `already_bilateral`.
   */
  function registerSealListeners(signaling: SignalingManager, agentName: string, agentPubkeyHex: string): () => void {
    const unregisterSealed = registerSessionSealedListener(signaling, agentName, agentPubkeyHex);
    const unregisterUnilateral = registerUnilateralConfirmedListener(signaling, agentName, agentPubkeyHex);
    const unregisterUpgrade = registerUnilateralUpgradeListener(signaling, agentName, agentPubkeyHex);
    return () => {
      unregisterSealed();
      unregisterUnilateral();
      unregisterUpgrade();
    };
  }

  return {
    sealKey,
    sealInterruptedInProgress,
    pendingSealWaiters,
    pendingUnilateralWaiters,
    registerSealListeners,
  };
}
