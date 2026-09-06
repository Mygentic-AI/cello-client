/**
 * Session-signing FROST ceremony participation — daemon side (DOD-SPINE-5, increment 3).
 *
 * When an initiator's `cello_initiate_session` reaches the directory, the directory
 * FROST-signs the SessionAssignment by DELEGATING to the initiator: its
 * `ClientDelegatedSigner.participateInCeremony` sends a `ceremony_request`
 * {ceremony_id, tbs, context} over the initiator's authenticated signaling stream and
 * awaits a `ceremony_result` {ceremony_id, signature}. The initiator (coordinator) runs
 * the FROST ceremony with its share + the directory's K_server_X shares, and replies.
 *
 * This wires that handler onto a PER-AGENT signaling stream (the same per-agent routing used for
 * registration).
 *
 * The threshold signer is reconstructed lazily from the agent's persisted
 * `frost-share.json` (the daemon holds no FrostThresholdSigner after registration —
 * the registration-time signer was on the disposed RegistrationContext).
 */

import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { createHash } from "node:crypto";
import { buildSealTbs } from "@cello-protocol/protocol-types";
import { bindLegibilityToTbs, type LegibilityForHash } from "./seal-legibility-tbs.js";
import { reDeriveFrontiers, findInflatedFrontier, type SealFrontierLeaf } from "./seal-frontier-verify.js";
import { FrostThresholdSigner } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { storeDkgResult } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import type { IThresholdSigner } from "@cello-protocol/crypto";
import type { FrostContext } from "@cello-protocol/crypto/frost/types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { NetworkDirectoryNode, runNetworkRefresh } from "./network-directory-node.js";
import type { FrostKeyShareRecord } from "./registration-persistence.js";
import type { ConsortiumEndpoint } from "./directory-bootstrap.js";
import type { DaemonRegistrationPersistence } from "./registration-persistence.js";
import type { SignalingSeam } from "./registration-context.js";
import type { Logger } from "./types.js";

/**
 * WIRE-002: answer the directory's `session_offer` on a per-agent signaling stream. When an
 * initiator's session_request names this agent as the target, the directory sends a
 * `session_offer {session_id}` before it builds the FROST-signed assignment; the agent must
 * reply `session_offer_accept` advertising its SESSION endpoint (its standing receiver, which
 * `acceptSession` reuses as the receiver-side session node) so the directory can fold the
 * counterparty endpoint into the assignment and the initiator can reach it. Without this, the
 * assignment carries an empty counterparty endpoint and content delivery can never connect.
 */
export function wireSessionOfferHandler(deps: {
  agentName: string;
  getStandingReceiverEndpoint: () => { peerId: string; addrs: string[] } | null;
  /**
   * DOD-M15-ASSIGN-1: name the one peer allowed to dial this agent's standing receiver. Called
   * with the offer's `initiator_session_peer_id` BEFORE the accept advertises our address, so the
   * gate is already narrowed by the time anyone could know where to dial. Returns false when
   * there is no receiver or the offer named nobody.
   */
  admitOfferedDialer: (initiatorSessionPeerId: string, sessionIdHex: string) => "narrowed" | "no_receiver" | "no_peer_named";
  /**
   * DOD-M15-RELAYONLY-1: is relay-only on for this agent? Optional, defaulting to FALSE, so every
   * existing caller and test keeps its exact behaviour — the guard below must only fire when the
   * setting is what emptied the address list, never when a receiver simply has none yet.
   */
  isRelayOnly?: () => boolean;
  signaling: SignalingSeam;
  logger: Logger;
}): () => void {
  // DOD-OFFER-REJECT-1 (D1): answer, never vanish. A silent abort left the directory waiting
  // 2 s for an accept that would never come, after which it FROST-signed an assignment with an
  // EMPTY counterparty endpoint and pushed it to both parties — the phantom session's origin.
  // The reject lets the directory fail fast (D2 resolves its waiter on this frame; until the
  // directory understands it, the frame is inert and the timeout path still applies). This is
  // the Generic Reject of the inbound-state matrix, arriving as a protocol necessity.
  // session_id is echoed when present; a no_session_id offer has nothing to echo, so the field
  // is omitted (never an empty value on the wire — same rule as the directory's encoder).
  async function sendOfferReject(sessionId: Uint8Array | null, reason: string): Promise<void> {
    const rejectFrame: Record<string, unknown> = { type: "session_offer_reject", reason };
    if (sessionId) rejectFrame["session_id"] = sessionId;
    try {
      // The production seam (transport SignalingManager.sendRaw) NEVER throws — it resolves
      // {ok:false, reason} on every failure (reconnecting, lost, stream throw). Discarding the
      // result would log reject.sent while nothing left the machine (D1 review F1). The catch
      // stays as belt-and-braces for a seam that does throw.
      const res = await deps.signaling.sendRaw(rejectFrame);
      if (res.ok) {
        deps.logger.info("session.offer.reject.sent", { agentName: deps.agentName, reason });
      } else {
        deps.logger.warn("session.offer.reject.failed", {
          agentName: deps.agentName,
          reason,
          detail: res.reason ?? "send_not_ok",
          ...(res.guidance ? { guidance: res.guidance } : {}),
        });
      }
    } catch (err: unknown) {
      deps.logger.warn("session.offer.reject.failed", {
        agentName: deps.agentName,
        reason,
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return deps.signaling.registerInboundHandler((frame) => {
    if (frame["type"] !== "session_offer") return;
    void (async () => {
      const sidRaw = frame["session_id"];
      const sessionId = sidRaw instanceof Uint8Array ? sidRaw : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;
      if (!sessionId) {
        deps.logger.warn("session.offer.abort", { agentName: deps.agentName, reason: "no_session_id" });
        await sendOfferReject(null, "no_session_id");
        return;
      }
      const sr = deps.getStandingReceiverEndpoint();
      if (!sr) {
        deps.logger.warn("session.offer.abort", { agentName: deps.agentName, reason: "standing_receiver_unavailable" });
        await sendOfferReject(sessionId, "standing_receiver_unavailable");
        return;
      }
      // DOD-M15-RELAYONLY-1: ANSWER, never publish an empty address list — **but only when
      // relay-only is what emptied it.**
      //
      // ⚠️ An empty `addrs` is NOT exclusively a relay-only condition, and the first version of this
      // guard refused unconditionally — which broke the pre-existing accept path for a receiver that
      // legitimately has no addresses yet, a case `session-ceremony-verify` covers on purpose. A
      // privacy control that changes behaviour when it is switched OFF is its own defect.
      //
      // ⚠️ Under relay-only the endpoint is already filtered to circuit addresses, and with no relay
      // reservation that set is EMPTY. The directory folds an accept only
      // `if (counterparty_session_addrs.length > 0)` — **with no `else`** — so an empty accept is
      // dropped in silence, the offer waiter never resolves, and the INITIATOR's operator is told
      // `counterparty_unavailable`: a lie about our state, produced by our setting. Rejecting
      // explicitly keeps the failure attributable to the side that caused it, and is the same
      // answer-never-vanish contract the reject path above already implements.
      if (sr.addrs.length === 0 && (deps.isRelayOnly?.() ?? false)) {
        deps.logger.warn("session.offer.abort", {
          agentName: deps.agentName,
          reason: "relay_only_no_reservation",
          impact:
            "relay-only is on and this agent holds no relay reservation, so it has no circuit " +
            "address to advertise and will not reveal its own — the offer is refused rather than " +
            "answered with an empty endpoint the directory would silently drop",
        });
        await sendOfferReject(sessionId, "relay_only_no_reservation");
        return;
      }
      /**
       * DOD-M15-ASSIGN-1 — open the door to the named dialer, and ONLY then publish our address.
       *
       * The ordering is the whole mechanism. Our receiver admits nobody until this line runs; the
       * accept below is what tells the directory (and through it, the initiator) where we listen.
       * Narrowing first means the gate names the initiator before the initiator can possibly know
       * where to dial, so there is no interval in which the address is reachable by anyone else.
       *
       * REFUSED WHEN THE OFFER NAMES NOBODY. The directory rejects any session_request that omits
       * `initiator_session_peer_id` (`session_request_missing_peer_id`), so a well-formed request
       * cannot produce a nameless offer — one here means a directory that is broken or lying.
       * Advertising anyway would be the worse failure: the initiator would dial an address whose
       * gate refuses them, and the session would die at the transport with no one able to say why.
       * Rejecting names the cause on the frame the directory is already waiting for.
       */
      const offeredDialerRaw = frame["initiator_session_peer_id"];
      const offeredDialer = typeof offeredDialerRaw === "string" ? offeredDialerRaw : "";
      // Keyed by SESSION (review F1): two overlapping offers to one agent must not overwrite
      // each other's record, or a legitimate session is refused and the check disarms itself.
      const narrowed = deps.admitOfferedDialer(offeredDialer, Buffer.from(sessionId).toString("hex"));
      if (narrowed !== "narrowed") {
        /**
         * Review F6 — ONE REASON PER CAUSE. This branch used to report `offer_named_no_dialer` for
         * both outcomes, and its guidance sent the operator to "the directory is not populating
         * initiator_session_peer_id" even when the truth was that this agent had no standing
         * receiver. That is a local problem wearing a remote label, which is the exact shape that
         * costs days. `standing_receiver_unavailable` already exists two branches above and is the
         * correct name for it.
         */
        const isLocal = narrowed === "no_receiver";
        const reason = isLocal ? "standing_receiver_unavailable" : "offer_named_no_dialer";
        deps.logger.warn("session.offer.abort", {
          agentName: deps.agentName,
          reason,
          impact: isLocal
            ? "this agent has no standing receiver to open, so it cannot serve the session; the session was refused rather than accepted with nowhere to be dialled"
            : "the directory's offer did not say who would dial, so this agent could not open its receiver to exactly one peer; the session was refused rather than served behind a door open to anyone",
          guidance: isLocal
            ? "the receiver is created when the agent comes online — check that cello_start_agent reached this daemon, then have the initiator retry"
            : "the initiator should retry; a repeat means the directory is not populating initiator_session_peer_id and the session cannot be established safely",
        });
        await sendOfferReject(sessionId, reason);
        return;
      }
      try {
        // Same production contract as the reject above (D1 review F3, pre-existing): sendRaw
        // resolves {ok:false, reason} instead of throwing. Logging "accepted" on {ok:false}
        // pointed the operator away from the exact failure that fabricates phantom sessions —
        // the directory hears nothing, stalls 2 s, and signs an endpoint-less assignment.
        const res = await deps.signaling.sendRaw({
          type: "session_offer_accept",
          session_id: sessionId,
          counterparty_session_peer_id: sr.peerId,
          counterparty_session_addrs: sr.addrs,
        });
        if (res.ok) {
          deps.logger.info("session.offer.accepted", {
            agentName: deps.agentName,
            sessionPeerId: sr.peerId,
          });
        } else {
          deps.logger.warn("session.offer.accept.failed", {
            agentName: deps.agentName,
            detail: res.reason ?? "send_not_ok",
            ...(res.guidance ? { guidance: res.guidance } : {}),
          });
        }
      } catch (err: unknown) {
        deps.logger.warn("session.offer.accept.failed", {
          agentName: deps.agentName,
          detail: err instanceof Error ? err.message : String(err),
        });
      }
    })();
  });
}

export interface CeremonyWiringDeps {
  agentName: string;
  /**
   * PERSIST-002: the agent's identity persistence (DB-backed) — the FROST share is loaded from the
   * encrypted `agents` row, not a `frost-share.json` file.
   */
  persistence: DaemonRegistrationPersistence;
  agentPubkeyHex: string;
  /**
   * DOD-M15-SEALWIRE-1 bullet 2 — THE CO-SIGNING HALF, which the line calls the worst moment:
   * *"your key signs a root you never checked."*
   *
   * Review F1: the first cut installed the root check only on the RECEIVING path
   * (`seal-coordinator.ts`), and left this one — where this agent's FROST key actually endorses the
   * root — untouched. A directory certifying a root over a different leaf set still got the
   * initiator's signature on it, and the resulting artifact is durable, valid and non-repudiable.
   * The receiving-side check then runs AFTER that signature already exists.
   *
   * Required, not optional: an unwired check here is the defect this bullet exists to close.
   */
  verifyCertifiedRoot: (
    agentPubkeyHex: string,
    sessionIdHex: string,
    certifiedRoot: Uint8Array,
    certifiedLeafCount: number,
  ) => { verdict: "match" } | { verdict: "mismatch"; ownRootHex: string | null; detail: string } | { verdict: "cannot_judge"; reason: string };
  /**
   * SEC-2: the agent's K_local signer — authenticates every FROST commit/sign request the ceremony
   * sends to the directory (the directory verifies it against agentPubkeyHex before touching its share).
   */
  keyProvider: KeyProvider;
  /** The agent's directory-connected libp2p node (the per-agent signaling node). */
  getNode: () => CelloNode | null;
  /** Resolve the directory endpoint to open FROST streams on (single-node / primary). */
  getDirectoryEndpoint: () => Promise<{ peerId: string; multiaddr?: string } | null>;
  /**
   * DOD-SIGN-1: resolve the FULL consortium directory-node roster from the verified manifest at
   * ceremony time, or NULL when no consortium manifest is configured. A non-null roster ⇒ the
   * threshold signer coordinates the FROST ceremony across ALL these nodes (T-of-N — it excludes
   * a node that's down and reaches any T). Null ⇒ single-node (M6/M7 back-compat).
   */
  getConsortiumEndpoints: () => Promise<ConsortiumEndpoint[] | null>;
  /** The agent's per-agent signaling seam (where ceremony_request arrives + result is sent). */
  signaling: SignalingSeam;
  logger: Logger;
  /**
   * DOD-M15-SEALPARTIES-1: leave a mark when the seal ceremony dies, so the answer outlives it.
   *
   * `if (!frostSignature) return;` was the whole handling of a ceremony that produced no signature
   * — no log line, no record, nothing. Requiring the co-signing directories to judge the leaves adds
   * a NEW way to land there (they refuse), and a refusal nobody hears is indistinguishable from the
   * seal simply never happening. It also covers the paths that were already silent: a root this
   * agent cannot confirm, an inflated frontier, a share it cannot load.
   *
   * REQUIRED rather than optional, deliberately: an optional sink is one a call site forgets, and
   * the whole class of defect this unit is closing is a check that quietly stopped being wired.
   */
  recordSealFailure: (agentName: string, sessionId: string, reason: string) => void;
}

/**
 * Reconstruct the agent's FROST threshold signer from its persisted share, configured to
 * drive the ceremony's `/cello/frost/1.0.0` round-trips on the agent's directory node.
 * Returns null when no share is persisted or the share is unreadable.
 */
async function hydrateShareAndStubs(
  deps: CeremonyWiringDeps,
): Promise<{ share: FrostKeyShareRecord; stubs: NetworkDirectoryNode[] | undefined } | null> {
  const share = await deps.persistence.loadActiveFrostKeyShare();
  if (!share) return null;

  const frostSecret = { identifier: share.identifier, signingShare: new Uint8Array(share.signingShare) };
  let commitments: Uint8Array[] = [];
  const verifyingShares: Record<string, Uint8Array> = {};
  try {
    const dc = decode(Buffer.from(share.commitmentsCbor)) as unknown;
    if (Array.isArray(dc)) {
      commitments = dc.map((c) =>
        c instanceof Uint8Array ? c : Buffer.isBuffer(c) ? new Uint8Array(c as Buffer) : new Uint8Array(0),
      );
    }
    const dvs = decode(Buffer.from(share.verifyingSharesCbor)) as unknown;
    if (dvs && typeof dvs === "object" && !Array.isArray(dvs)) {
      for (const [k, v] of Object.entries(dvs as Record<string, unknown>)) {
        verifyingShares[k] = v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : new Uint8Array(0);
      }
    }
  } catch (err: unknown) {
    deps.logger.error("session.ceremony.share.load.failed", {
      agentName: deps.agentName,
      reason: "cbor_deserialize_failed",
      detail: err instanceof Error ? err.message : String(err),
    });
    return null;
  }

  const frostPublic = { signers: { min: share.threshold, max: share.participants + 1 }, commitments, verifyingShares };
  try {
    // SI-001: storeDkgResult does not log the secret. Cast via the function's own param
    // types (the daemon has no direct @noble/curves dependency).
    storeDkgResult(
      deps.agentPubkeyHex,
      frostSecret as unknown as Parameters<typeof storeDkgResult>[1],
      frostPublic as unknown as Parameters<typeof storeDkgResult>[2],
    );
  } catch (err: unknown) {
    deps.logger.error("session.ceremony.share.load.failed", {
      agentName: deps.agentName,
      reason: "storeDkgResult_failed",
      detail: err instanceof Error ? err.message : String(err),
    });
    return null;
  }

  // DOD-SIGN-1: build a directory-node stub PER consortium node so the FROST threshold signer
  // can run the signing ceremony across ALL N nodes (it reaches any T and excludes a node that's
  // down — "kill a node, still signs"). With no consortium manifest configured the roster is null
  // → the single primary endpoint (M6/M7 single-node back-compat). NOTE: the share's threshold T
  // (from the multi-node DKG) is FIXED — a degraded roster (fewer than T reachable) makes signing
  // FAIL, it can never forge a lower-threshold signature, so a single-stub fallback is safe.
  let directoryNodeStubs: NetworkDirectoryNode[] | undefined;
  const node = deps.getNode();
  const roster = await deps.getConsortiumEndpoints();
  // Use the share's CURRENT epoch (advances after a proactive refresh) — NOT a hardcoded epoch:1, else
  // post-refresh signing would target the now-EXPIRED epoch and fail (DOD-REFRESH-1). For an un-refreshed
  // agent share.epochId IS "…:epoch:1", so this is identical to the prior behavior.
  const epochId = share.epochId;
  // The stub's FROST identifier (`id`) MUST be the node's DKG label, NOT its libp2p peerId. The directory
  // derives each node's FROST participant identifier as derive(nodeId), where nodeId = the node's region
  // (frost-handler.ts:23 `nodeIdentifier = derive(nodeId)`; the bin sets nodeId = region). So the group's
  // node shares are bound to derive(region), and the node SIGNS under derive(region). If the client verifies
  // /aggregates partials under derive(peerId) instead, every verifyShare fails → all nodes excluded →
  // ceremony_exhausted. `id` feeds Identifier.derive() in the signer; `directoryPeerId` is the network dial
  // and stays the libp2p peerId. (nodeId and peerId coincide only for legacy single-node agents whose DKG
  // predates the region-as-nodeId change — the single-node fallback below passes peerId for that reason.)
  const mkStub = (nodeId: string, peerId: string, multiaddr: string): NetworkDirectoryNode => {
    const stub = new NetworkDirectoryNode({
      id: nodeId,
      node: node!,
      directoryPeerId: peerId,
      directoryMultiaddrs: [multiaddr],
      logger: deps.logger,
    });
    stub.setBootstrapContext(deps.agentPubkeyHex, epochId, (h) => deps.keyProvider.sign(h)); // SEC-2
    return stub;
  };
  if (node && roster !== null && roster.length > 0) {
    // M8B quorum: filter the live roster to the SHARE-HOLDER quorum Q the agent registered with
    // (share.directoryNodeIds), so the seal targets holders — not nodes that came back online after a
    // quorum registration but hold NO share for this agent (they'd pad the count via isReachable()===true
    // and burn the retry budget). Absent Q (pre-quorum agent / single-node) → full roster (unchanged
    // DOD-SIGN-1). Defensive: if every Q node has vanished from the roster, fall back to the full roster
    // rather than an empty signer set (the ceremony's own below-threshold pre-check then applies).
    const q = share.directoryNodeIds;
    const filtered = q && q.length > 0 ? roster.filter((ep) => q.includes(ep.nodeId)) : roster;
    const holders = filtered.length > 0 ? filtered : roster;
    // FROST id = ep.nodeId (region — the DKG label); network dial = ep.peerId.
    directoryNodeStubs = holders.map((ep) => mkStub(ep.nodeId, ep.peerId, ep.multiaddr));
  } else if (node) {
    // No consortium manifest (roster null) or a configured manifest that resolved EMPTY → the single
    // primary endpoint. INTENTIONAL asymmetry with DKG-1 (which REFUSES a configured-but-empty roster
    // because DKG needs all N): for SIGNING the share's threshold T is FIXED, so a degraded/single
    // stub makes participateInCeremony fail the `reachable < T-1` pre-check rather than forge a weaker
    // seal — safe. WARN distinctly on the configured-but-unreachable case so the operator sees "your
    // consortium was unreachable" rather than a generic below-threshold error (fallback-finder F3).
    if (roster !== null && roster.length === 0) {
      deps.logger.warn("session.ceremony.consortium_unreachable", { agentName: deps.agentName });
    }
    const ep = await deps.getDirectoryEndpoint();
    if (ep && ep.multiaddr) {
      // Single-node back-compat: no region is available from getDirectoryEndpoint, and legacy single-node
      // agents' DKG labeled the node by peerId (pre region-as-nodeId), so the FROST id stays the peerId here.
      directoryNodeStubs = [mkStub(ep.peerId, ep.peerId, ep.multiaddr)];
    }
  }
  return { share, stubs: directoryNodeStubs };
}

export async function reconstructThresholdSigner(
  deps: CeremonyWiringDeps,
  /**
   * DOD-M15-SEALPARTIES-1: the signed leaves this ceremony's TBS is a root over, forwarded to every
   * directory node so each reaches its own verdict instead of signing a claim. Supplied on the seal
   * ceremony and on nothing else — a co-signer requires it under the seal context and ignores it
   * everywhere else.
   */
  sealEvidence?: import("./network-directory-node.js").SealCeremonyEvidence,
): Promise<IThresholdSigner | null> {
  const h = await hydrateShareAndStubs(deps);
  if (!h) return null;
  if (sealEvidence) for (const stub of h.stubs ?? []) stub.setSealEvidence(sealEvidence);
  return new FrostThresholdSigner(
    { threshold: h.share.threshold, participants: h.share.participants, directoryNodeStubs: h.stubs },
    Buffer.from(deps.agentPubkeyHex, "hex"),
  );
}

/**
 * M8B DOD-REFRESH-1: run a proactive share refresh for an already-registered agent. Rotates the client's
 * + every directory node's share to the next epoch (group public key unchanged), then persists the
 * client's new share as the active one so subsequent signing uses the new epoch and old-epoch shares die.
 */
export async function runAgentRefresh(
  deps: CeremonyWiringDeps,
): Promise<{ ok: true; toEpochN: number; primaryPubkey: string; verifyingSharesDigest: string } | { ok: false; reason: string }> {
  const h = await hydrateShareAndStubs(deps);
  if (!h) return { ok: false, reason: "no_active_share" };
  if (!h.stubs || h.stubs.length === 0) return { ok: false, reason: "no_directory_nodes" };
  const fromEpochN = Number(/:epoch:(\d+)$/.exec(h.share.epochId)?.[1] ?? "1");
  let result: Awaited<ReturnType<typeof runNetworkRefresh>>;
  try {
    result = await runNetworkRefresh(Buffer.from(deps.agentPubkeyHex, "hex"), {
      threshold: h.share.threshold,
      participants: h.share.participants,
      directoryNodes: h.stubs,
      fromEpochN,
      signAuth: (hash) => deps.keyProvider.sign(hash), // SEC-2
    });
  } catch (err: unknown) {
    deps.logger.error("refresh.ceremony.failed", {
      agentName: deps.agentName,
      detail: err instanceof Error ? err.message : String(err),
    });
    return { ok: false, reason: "ceremony_failed" };
  }
  const primaryPubkeyHex = Buffer.from(result.primaryPubkey).toString("hex");
  // M2 (defense-in-depth): the group public key MUST be byte-identical to the PRE-refresh key. The
  // cross-node check inside runNetworkRefresh only proves all parties AGREE post-refresh — a uniform
  // secret-shift (a crypto-core regression) would move the key on every party identically and pass it,
  // while silently diverging from the registered key counterparties verify seals against. Assert against
  // the KNOWN pre-refresh key (h.share.primaryPubkey) and abort WITHOUT persisting on mismatch.
  if (primaryPubkeyHex !== h.share.primaryPubkey) {
    deps.logger.error("refresh.ceremony.group_key_changed", {
      agentName: deps.agentName,
      expected: h.share.primaryPubkey.slice(0, 16),
      got: primaryPubkeyHex.slice(0, 16),
    });
    return { ok: false, reason: "group_key_changed" };
  }
  // verifyingShares are PUBLIC (s_j·G per participant) and MOVE on a real refresh while commitments[0]
  // (the group key) does not — so their digest is the one observable that distinguishes a genuine
  // rotation from a no-op "relabel" (the spine asserts it changes across two refreshes). SI-001-safe.
  const verifyingSharesDigest = createHash("sha256")
    .update(
      Object.keys(result.verifyingShares)
        .sort()
        .map((k) => `${k}:${Buffer.from(result.verifyingShares[k]).toString("hex")}`)
        .join("|"),
    )
    .digest("hex");
  // L7: a persist failure here is the most dangerous point (directories already advanced) — surface it
  // as a STRUCTURED reason rather than letting a raw throw escape the handler.
  try {
    await deps.persistence.persistFrostKeyShare({
      epochId: `${deps.agentPubkeyHex}:epoch:${result.toEpochN}`,
      primaryPubkey: primaryPubkeyHex,
      identifier: result.identifier,
      signingShare: result.signingShare,
      threshold: h.share.threshold,
      participants: h.share.participants,
      commitmentsCbor: encodeCbor(result.commitments),
      verifyingSharesCbor: encodeCbor(result.verifyingShares),
      dkgMethod: "network_dkg",
      // M8B quorum: a proactive refresh re-randomizes shares among the SAME membership — carry the
      // quorum Q forward, else this UPDATE wipes frost_directory_node_ids to NULL and the next restart's
      // seal falls back to the full roster (reintroducing the padding/retry-budget bug the persist fixed).
      directoryNodeIds: h.share.directoryNodeIds,
    });
  } catch (err: unknown) {
    deps.logger.error("refresh.ceremony.persist_failed", {
      agentName: deps.agentName,
      detail: err instanceof Error ? err.message : String(err),
    });
    return { ok: false, reason: "persist_failed" };
  }
  deps.logger.info("refresh.ceremony.complete", {
    agentName: deps.agentName,
    toEpoch: result.toEpochN,
    primaryPubkey: primaryPubkeyHex.slice(0, 16),
  });
  return { ok: true, toEpochN: result.toEpochN, primaryPubkey: primaryPubkeyHex, verifyingSharesDigest };
}

/**
 * Register a `ceremony_request` handler on the agent's signaling seam. On the directory's
 * delegated-signing request, run the agent's threshold signer's participateInCeremony and
 * reply with `ceremony_result`. The signer is reconstructed lazily and cached. Returns the
 * unregister function. SI-001: tbs/signature never logged.
 */
/**
 * DOD-SPINE-7: register a `seal_verified` handler on the agent's signaling seam. After the
 * directory rebuilds + verifies the bilateral seal's signed Merkle chain (relay-mediated
 * processSeal FROST path), it sends the SEAL INITIATOR a `seal_verified` {session_id,
 * sealed_root, leaf_count, timestamp} and waits for the initiator to COORDINATE the seal FROST
 * ceremony. This handler reconstructs the agent's threshold signer (same machinery as the
 * session ceremony), runs participateInCeremony over buildSealTbs with context
 * "cello-frost-seal-v1", and replies `seal_frost_signature` {session_id, frost_signature}. The
 * directory's #processSealFrostSignature then completes notarization and delivers
 * `session_sealed` (the byte-identical sealed_root) to both parties.
 *
 * SI-001: tbs/signature never logged.
 */
export function wireSealCeremonyHandler(deps: CeremonyWiringDeps): () => void {
  return deps.signaling.registerInboundHandler((frame) => {
    if (frame["type"] !== "seal_verified") return;
    void (async () => {
      const toU8 = (v: unknown): Uint8Array | null =>
        v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;
      const sessionId = toU8(frame["session_id"]);
      const sealedRoot = toU8(frame["sealed_root"]);
      const leafCountRaw = frame["leaf_count"];
      const leafCount = typeof leafCountRaw === "number" ? leafCountRaw : null;
      const tsRaw = frame["timestamp"];
      const timestamp = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
      if (!sessionId || !sealedRoot || leafCount === null || timestamp === null) {
        deps.logger.warn("session.seal.ceremony.abort", {
          agentName: deps.agentName,
          reason: !sessionId ? "no_session_id" : !sealedRoot ? "no_sealed_root" : leafCount === null ? "no_leaf_count" : "no_timestamp",
        });
        return;
      }
      const sidHex = Buffer.from(sessionId).toString("hex");

      /**
       * DOD-M15-SEALPARTIES-1: forward the raw signed leaves to every co-signing directory.
       *
       * They arrive on `seal_verified` and are already re-verified on this side (the frontier
       * re-derivation below reads the same array). Forwarding them is what lets a node that did NOT
       * run the verification rebuild the root itself and refuse a certificate over a leaf set the
       * participants never produced — the difference between three signatures that mean three
       * independent judgements and three that rest on one node's reading.
       *
       * Absent here means the frame carried none, and the directories refuse on that: it is not
       * this side's place to decide the evidence was optional.
       */
      const sealEvidenceLeaves = Array.isArray(frame["frontier_leaves"]) && frame["frontier_leaves"].length > 0
        ? (frame["frontier_leaves"] as unknown[])
        : undefined;
      // Reconstruct a FRESH signer per ceremony (same rationale as the session ceremony:
      // fresh directory endpoint, no shared FROST state across concurrent ceremonies).
      /**
       * ⚠️ ABSENT IS PASSED AS ABSENT — fallback hunt, finding 4. This used to send `[]`, which the
       * co-signer classified as MALFORMED ("compare builds") rather than MISSING ("someone is asking
       * for a signature without showing the record"). The seal failed either way; the diagnosis the
       * module exists to produce was the one case it could never reach.
       */
      /**
       * Review F6: what each holder SAID, kept so the recorded failure can name it. "Threshold not
       * met" is a count; `SEAL_ROOT_UNSUPPORTED` from a holder is an accusation against the
       * verifying directory, and the operator surface should be able to tell them apart.
       */
      const cosignRefusals = new Set<string>();
      const signer = await reconstructThresholdSigner(
        deps,
        sealEvidenceLeaves
          ? { leaves: sealEvidenceLeaves, closeTimestamp: timestamp, onRefused: (r) => cosignRefusals.add(r) }
          : undefined,
      );
      if (!signer) {
        deps.logger.warn("session.seal.ceremony.abort", { agentName: deps.agentName, sessionId: sidHex, reason: "no_signer" });
        deps.recordSealFailure(deps.agentName, sidHex, "seal_ceremony_no_signer");
        return;
      }
      // M7 legibility-TBS-binding: when the directory's seal_verified carries `legibility` (the
      // bilateral seal), fold its canonical hash into the TBS we co-sign — so the FROST signature
      // covers the legibility and a MITM cannot tamper answered/frontier/attestation_mode in
      // transit. The directory binds the IDENTICAL hash (it built the TBS it verifies against);
      // the receiving client re-binds and verifies. Unilateral seal_verified carries no legibility
      // → plain TBS (bindLegibilityToTbs is a no-op), matching the directory's unilateral TBS.
      const legibility = frame["legibility"];
      const legForHash = legibility && typeof legibility === "object" ? (legibility as LegibilityForHash) : null;

      // DOD-LEG-2 (SI-002): the INITIATOR must not co-sign an inflated certificate — otherwise a
      // validly-FROST-signed inflated cert would exist as a durable artifact. Re-derive each party's
      // content_frontier_seq from the signed leaves the directory ships on seal_verified and ABORT
      // the ceremony (no signature) if any published frontier is inflated. Same logic the receiver
      // applies at session_sealed; doing it here means a lying directory gets NO signature at all.
      const wireParts = legForHash && Array.isArray((legForHash as { participants?: unknown }).participants)
        ? ((legForHash as { participants: Array<{ pubkey?: unknown; content_frontier_seq?: unknown }> }).participants)
        : null;
      if (wireParts) {
        // Wire pubkeys are Uint8Array; normalise to hex for comparison with the re-derived map.
        const parts = wireParts.map((p) => ({
          pubkey: p.pubkey instanceof Uint8Array
            ? Buffer.from(p.pubkey).toString("hex")
            : (typeof p.pubkey === "string" ? p.pubkey : null),
          content_frontier_seq: typeof p.content_frontier_seq === "number" ? p.content_frontier_seq : null,
        }));
        const malformed = parts.some((p) => p.pubkey === null || p.content_frontier_seq === null);
        const anyClaimed = parts.some((p) => (p.content_frontier_seq ?? 0) > 0);
        const flRaw = frame["frontier_leaves"];
        const haveLeaves = Array.isArray(flRaw) && flRaw.length > 0;
        if (malformed || (anyClaimed && !haveLeaves)) {
          const abortReason = malformed ? "frontier_participant_malformed" : "frontier_leaves_missing";
          deps.logger.warn("session.seal.ceremony.abort", {
            agentName: deps.agentName, sessionId: sidHex, reason: abortReason,
          });
          deps.recordSealFailure(deps.agentName, sidHex, abortReason);
          return;
        }
        if (haveLeaves) {
          const toLeaf = (v: unknown): Uint8Array => (v instanceof Uint8Array ? v : new Uint8Array(v as ArrayLike<number>));
          const leaves: SealFrontierLeaf[] = (flRaw as unknown[]).map((l) => {
            const o = l as Record<string, unknown>;
            return { structure1_cbor: toLeaf(o["structure1_cbor"]), sender_pubkey: toLeaf(o["sender_pubkey"]), sender_signature: toLeaf(o["sender_signature"]) };
          });
          const rederived = reDeriveFrontiers(leaves, sessionId);
          const inflated = rederived.ok
            ? findInflatedFrontier(parts as Array<{ pubkey: string; content_frontier_seq: number }>, rederived.frontiers)
            : null;
          if (!rederived.ok || inflated) {
            const inflatedReason = rederived.ok ? "frontier_unverifiable" : rederived.reason;
            deps.logger.warn("session.seal.ceremony.abort", {
              agentName: deps.agentName, sessionId: sidHex,
              reason: inflatedReason,
              ...(inflated ? { party: inflated.party, publishedFrontier: inflated.publishedFrontier, derivedFrontier: inflated.derivedFrontier } : {}),
            });
            deps.recordSealFailure(deps.agentName, sidHex, inflatedReason);
            return; // refuse to co-sign — the directory gets no signature for an inflated cert
          }
        }
      }

      /**
       * DO NOT SIGN A ROOT THIS AGENT HAS NOT CHECKED — bullet 2's co-signing half (review F1).
       *
       * Same predicate as the receiving path, deliberately: one implementation, so the two halves
       * cannot drift into disagreeing about what counts as a mismatch.
       *
       * `cannot_judge` REFUSES here, where the accept path tolerates it — and the asymmetry is the
       * point. Accepting an unverifiable certificate keeps a receipt that already exists; SIGNING an
       * unverifiable one manufactures a new, durable, non-repudiable claim with this agent's key on
       * it. The safe default is opposite in each direction: tolerate on the way in, refuse on the way
       * out.
       */
      const rootCheck = deps.verifyCertifiedRoot(deps.agentPubkeyHex, sidHex, sealedRoot, leafCount);
      if (rootCheck.verdict !== "match") {
        deps.logger.error("session.seal.ceremony.abort", {
          agentName: deps.agentName, sessionId: sidHex,
          reason: rootCheck.verdict === "mismatch" ? "root_mismatch" : "root_unverifiable",
          detail: rootCheck.verdict === "mismatch" ? rootCheck.detail : rootCheck.reason,
          ...(rootCheck.verdict === "mismatch" && rootCheck.ownRootHex ? { ownRoot: rootCheck.ownRootHex } : {}),
          impact:
            "this agent REFUSED to co-sign. Signing would have put its key on a notarization it " +
            "cannot confirm describes this conversation — a durable, valid, non-repudiable claim " +
            "about a transcript it never checked. The session is not sealed; nothing is lost.",
          guidance:
            "Compare the leaf count with the counterparty and check the directory and relay logs for " +
            "this session id. Do NOT force-abandon: that forfeits the receipt permanently.",
        });
        deps.recordSealFailure(
          deps.agentName,
          sidHex,
          rootCheck.verdict === "mismatch" ? "seal_root_mismatch" : "seal_root_unverifiable",
        );
        return; // refuse to co-sign — the directory gets no signature for a root we cannot verify
      }

      const tbs = bindLegibilityToTbs(buildSealTbs(sessionId, sealedRoot, leafCount, timestamp), legForHash);
      let frostSignature: Uint8Array | null = null;
      try {
        // The initiator COORDINATES the seal FROST ceremony (its signer drives the
        // /cello/frost round-trips with the directory's K_server shares via directoryNodeStubs).
        const result = await signer.participateInCeremony(`seal:${sidHex}`, tbs, "cello-frost-seal-v1" as FrostContext);
        frostSignature = result.ok ? new Uint8Array(result.signature) : null;
        deps.logger.info("session.seal.ceremony.participated", { agentName: deps.agentName, sessionId: sidHex, ok: result.ok });
      } catch (err: unknown) {
        deps.logger.warn("session.seal.ceremony.failed", {
          agentName: deps.agentName,
          sessionId: sidHex,
          detail: err instanceof Error ? err.message : String(err),
        });
        deps.recordSealFailure(deps.agentName, sidHex, "seal_ceremony_threw");
        return;
      }
      if (!frostSignature) {
        /**
         * ⚠️ THIS WAS `if (!frostSignature) return;` WITH NO LOG AND NO RECORD —
         * `DOD-M15-SEALPARTIES-1`.
         *
         * It is where a seal lands when the FROST ceremony produces nothing, and requiring the
         * co-signing directories to judge the leaves makes it reachable for a NEW and important
         * reason: a holder looked at the record, decided it does not support the root, and declined.
         * That is the strongest signal this system produces, and its entire trace was a bare return.
         *
         * The refusing node's own reason is on the coordinating side too — `network-directory-node`
         * logs `frost.directory.sign.refused` per node with what that node said — because a
         * threshold failure is a count, and the count does not say WHY any particular holder said
         * no.
         */
        deps.logger.error("session.seal.ceremony.no_signature", {
          agentName: deps.agentName,
          sessionId: sidHex,
          cosignRefusals: [...cosignRefusals].sort(),
          impact:
            "the seal FROST ceremony ended with no signature, so this session has no certificate " +
            "and nothing was signed with this agent's key. Enough share-holding directories " +
            "declined or were unreachable that the threshold was not met.",
          guidance:
            "Look for frost.directory.sign.refused in this daemon's log — each line names one " +
            "directory and the reason it gave. A SEAL_ROOT_UNSUPPORTED there means a holder rebuilt " +
            "the root from the leaves and got a different answer, which is a fault in the verifying " +
            "directory or the relay, not in this agent. Do NOT force-abandon: that forfeits the " +
            "receipt permanently.",
        });
        deps.recordSealFailure(
          deps.agentName,
          sidHex,
          cosignRefusals.size > 0
            ? `seal_cosigners_refused:${[...cosignRefusals].sort().join(",")}`
            : "seal_ceremony_threshold_not_met",
        );
        return;
      }

      await sendSealFrostSignature(deps, sessionId, sidHex, frostSignature);
    })();
  });
}

/**
 * DOD-SENDRAW-1: deliver the co-signed seal FROST signature to the directory, branching on the
 * seam's RESOLVED result. The production seam (transport SignalingManager.sendRaw) never throws —
 * it resolves {ok:false, reason} on every failure — so the old try/catch logged `.sent` for a
 * signature that never left the machine, inside the non-repudiation ceremony, and the failure
 * event was unreachable. Exported so the send contract is testable without a live FROST ceremony.
 */
export async function sendSealFrostSignature(
  deps: { agentName: string; signaling: SignalingSeam; logger: Logger },
  sessionId: Uint8Array,
  sidHex: string,
  frostSignature: Uint8Array,
): Promise<void> {
  try {
    const res = await deps.signaling.sendRaw({ type: "seal_frost_signature", session_id: sessionId, frost_signature: frostSignature });
    if (res.ok) {
      deps.logger.info("session.seal.frost.signature.sent", { agentName: deps.agentName, sessionId: sidHex });
    } else {
      deps.logger.warn("session.seal.frost.signature.send.failed", {
        agentName: deps.agentName,
        sessionId: sidHex,
        detail: res.reason ?? "send_not_ok",
        ...(res.guidance ? { guidance: res.guidance } : {}),
      });
    }
  } catch (err: unknown) {
    deps.logger.warn("session.seal.frost.signature.send.failed", {
      agentName: deps.agentName,
      sessionId: sidHex,
      detail: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * SESSION-002 (DOD-SEAL-3): verify a unilateral seal certificate WITHOUT trusting the
 * channel. Rebuilds the canonical seal TBS from the cert fields and verifies the signature
 * against a key trusted independently of the delivering frame: the session primary_pubkey
 * (commitments[0] of this agent's FROST share) for 'frost'. A channel-swapped sealed_root
 * (or any TBS-bound field) fails this check (SI-003). The 'single' (pre-DKG) variant verifies
 * against the directory node key from the consortium manifest — not yet wired on the daemon;
 * surfaced honestly rather than accepted on faith.
 */
export async function verifyUnilateralCertificate(
  deps: { persistence: DaemonRegistrationPersistence; agentPubkeyHex: string; logger: Logger },
  cert: {
    sessionId: Uint8Array;
    sealedRoot: Uint8Array;
    leafCount: number;
    closeTimestamp: number;
    frostSignature: Uint8Array;
    signatureType: "frost" | "single";
  },
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const tbs = buildSealTbs(cert.sessionId, cert.sealedRoot, cert.leafCount, cert.closeTimestamp);

  if (cert.signatureType !== "frost") {
    // 'single' (pre-DKG) — verify vs the directory node key from the manifest. Not wired yet.
    return { ok: false, reason: "single_key_verification_unsupported" };
  }

  const share = await deps.persistence.loadActiveFrostKeyShare();
  if (!share) return { ok: false, reason: "no_frost_share" };

  let primaryPubkey: Uint8Array | null = null;
  try {
    const dc = decode(Buffer.from(share.commitmentsCbor)) as unknown;
    if (Array.isArray(dc) && dc.length > 0) {
      const c0 = dc[0];
      primaryPubkey = c0 instanceof Uint8Array ? c0 : Buffer.isBuffer(c0) ? new Uint8Array(c0 as Buffer) : null;
    }
  } catch (err: unknown) {
    deps.logger.warn("session.unilateral.certificate.share.decode.failed", {
      agentPubkey: deps.agentPubkeyHex,
      detail: err instanceof Error ? err.message : String(err),
    });
    return { ok: false, reason: "share_decode_failed" };
  }
  if (!primaryPubkey || primaryPubkey.length !== 32) return { ok: false, reason: "no_primary_pubkey" };

  const verifier = new FrostThresholdSigner({ threshold: 1, participants: 1 }, Buffer.from(deps.agentPubkeyHex, "hex"));
  const valid = verifier.verifySignature(cert.frostSignature, tbs, "cello-frost-seal-v1" as FrostContext, primaryPubkey);
  return valid ? { ok: true } : { ok: false, reason: "signature_invalid" };
}

/**
 * M7 legibility-TBS-binding: verify a BILATERAL session_sealed certificate's signature over the
 * legibility-bound TBS, channel-independently.
 *
 * KEY STRUCTURE (why verifiability is asymmetric TODAY): the seal's FROST signature is produced by
 * the group key (commitments[0] of the DKG share) of whichever party CLOSED THE SESSION FIRST — the
 * directory designates the sender of the first SEAL ctrl leaf as the "seal initiator" and signs
 * against that party's primary (directory-node.ts). This is NOT a fixed initiator/responder role:
 * either the session initiator or the responder can be the first closer.
 *
 * A party can channel-independently verify here only against a group primary it HOLDS locally:
 *  - its OWN primary — loaded from its own DKG share (`signer_pubkey === own primary`); or
 *  - the counterparty's primary — recorded via recordCounterpartyPrimary (see below).
 * It then verifies the FROST signature over `buildSealTbs ‖ legibilityHash`. A tampered legibility
 * (answered / content_frontier_seq / attestation_mode — carried unsigned on the frame) changes the
 * hash → the signature fails → REJECT.
 *
 * When the signer's key is NOT held locally, the party ACCEPTS (`verified:false`, with a `reason`).
 * This is sound for the LIVE path: session_sealed arrives over the daemon↔directory libp2p Noise
 * channel (authenticated + encrypted), so it is not MITM-tamperable in transit; the binding's
 * primary value is OUT-OF-BAND (any holder of the signer's primary — e.g. an arbitrator — can verify
 * an exported cert's legibility).
 *
 * SYMMETRY STATUS: SYMMETRIC as of 038-KEYBIND, and the old text is worth stating because it names
 * what was broken. It read: *"The missing half is the INITIATOR-records-RESPONDER direction: an
 * initiator never learns the responder's primary, so when the responder closes first, the initiator
 * cannot verify locally and accepts with reason `signer_key_not_held`."* That was exactly right,
 * and it is now closed: the session assignment carries `participant_b_primary_pubkey` alongside a
 * binding signed by participant_b's own K_local, the initiator verifies that binding before it will
 * accept the assignment at all, and `initiate-session-handler.ts` records the result. Both closing
 * orders verify locally.
 *
 * `signer_key_not_held` therefore no longer describes an ordinary responder-first close. It remains
 * reachable — a session row that predates the recording, or one whose assignment never reached this
 * path — and it is still the honest answer in those cases, which is why the branch stays.
 *
 * `legibility` MUST be the AS-RECEIVED wire object (not a normalised copy) — the directory signed
 * over the canonical hash of exactly what it sent.
 */
export async function verifyBilateralSealCertificate(
  deps: { persistence: DaemonRegistrationPersistence; agentPubkeyHex: string; logger: Logger; counterpartyPrimaryHex?: string | null },
  cert: {
    sessionId: Uint8Array;
    sealedRoot: Uint8Array;
    leafCount: number;
    closeTimestamp: number;
    frostSignature: Uint8Array;
    signerPubkey: Uint8Array;
    signatureType: "frost" | "single";
    legibility: LegibilityForHash | null;
  },
): Promise<{ ok: true; verified: boolean; reason?: string } | { ok: false; reason: string }> {
  // F2-a: every verified:false branch carries a `reason` so the daemon's
  // session.sealed.signature.checked log can never read as a silently-tolerated FAILED check.
  // A genuinely failed check takes the { ok:false, reason:"signature_invalid" } path, which the
  // caller REJECTS (never marks sealed). verified:false is always "no key held to verify → accepted
  // on the authenticated Noise channel", never "a check ran and failed".
  if (cert.signatureType !== "frost") return { ok: true, verified: false, reason: "non_frost_certificate" };
  if (cert.signerPubkey.length !== 32) return { ok: false, reason: "no_signer_pubkey" };
  const signerHex = Buffer.from(cert.signerPubkey).toString("hex");

  const share = await deps.persistence.loadActiveFrostKeyShare();
  if (!share) return { ok: true, verified: false, reason: "no_frost_share" }; // no share to verify with — accept (Noise-delivered)

  let ownPrimary: Uint8Array | null = null;
  try {
    const dc = decode(Buffer.from(share.commitmentsCbor)) as unknown;
    if (Array.isArray(dc) && dc.length > 0) {
      const c0 = dc[0];
      ownPrimary = c0 instanceof Uint8Array ? c0 : Buffer.isBuffer(c0) ? new Uint8Array(c0 as Buffer) : null;
    }
  } catch {
    return { ok: true, verified: false, reason: "commitments_decode_failed" };
  }
  if (!ownPrimary || ownPrimary.length !== 32) return { ok: true, verified: false, reason: "own_primary_unavailable" };

  // The seal is signed by the INITIATOR's primary (group) key. This party can verify against a
  // key it holds independently: its OWN primary (when it is the initiator) or the counterparty's
  // primary from the FROST-signed SessionAssignment (when it is the responder). SI-003: the signer
  // must be one of these — never a key supplied only by the (untrusted) cert frame.
  const cpHex = deps.counterpartyPrimaryHex ?? null;
  if (signerHex === Buffer.from(ownPrimary).toString("hex")) {
    // initiator path — verify against own primary.
  } else if (cpHex && signerHex === cpHex.toLowerCase()) {
    // responder path — verify against the known counterparty primary.
  } else if (cpHex) {
    // We know the counterparty primary and the signer is NEITHER participant → unknown signer.
    return { ok: false, reason: "signer_not_a_session_participant" };
  } else {
    // We do not hold the signer's key (no counterparty primary recorded) → cannot verify; accept
    // (the live frame arrived over the authenticated Noise channel; the binding aids out-of-band).
    // This is the initiator-when-responder-closed-first case F2-b would close.
    return { ok: true, verified: false, reason: "signer_key_not_held" };
  }

  const tbs = bindLegibilityToTbs(buildSealTbs(cert.sessionId, cert.sealedRoot, cert.leafCount, cert.closeTimestamp), cert.legibility);
  const verifier = new FrostThresholdSigner({ threshold: 1, participants: 1 }, Buffer.from(deps.agentPubkeyHex, "hex"));
  const valid = verifier.verifySignature(cert.frostSignature, tbs, "cello-frost-seal-v1" as FrostContext, cert.signerPubkey);
  return valid ? { ok: true, verified: true } : { ok: false, reason: "signature_invalid" };
}

export function wireSessionCeremonyHandler(deps: CeremonyWiringDeps): () => void {
  return deps.signaling.registerInboundHandler((frame) => {
    if (frame["type"] !== "ceremony_request") return;
    void (async () => {
      const ceremonyId = typeof frame["ceremony_id"] === "string" ? (frame["ceremony_id"] as string) : undefined;
      const tbsRaw = frame["tbs"];
      const tbs = tbsRaw instanceof Uint8Array ? tbsRaw : Buffer.isBuffer(tbsRaw) ? new Uint8Array(tbsRaw as Buffer) : null;
      const context = typeof frame["context"] === "string" ? (frame["context"] as string) : undefined;

      // L3: the reply send is best-effort — a throw here must not become an unhandled
      // rejection in this fire-and-forget handler. DOD-SENDRAW-1: the production seam never
      // throws — it resolves {ok:false, reason} — so the failure must be read off the RESULT;
      // catch-only made session.ceremony.reply.failed unreachable in production.
      const reply = async (signature: Uint8Array | null): Promise<void> => {
        if (!ceremonyId) return;
        try {
          const res = await deps.signaling.sendRaw({ type: "ceremony_result", ceremony_id: ceremonyId, signature });
          if (!res.ok) {
            deps.logger.warn("session.ceremony.reply.failed", {
              agentName: deps.agentName,
              detail: res.reason ?? "send_not_ok",
              ...(res.guidance ? { guidance: res.guidance } : {}),
            });
          }
        } catch (err: unknown) {
          deps.logger.warn("session.ceremony.reply.failed", {
            agentName: deps.agentName,
            detail: err instanceof Error ? err.message : String(err),
          });
        }
      };

      // L1: a request with no addressable ceremony_id cannot be replied to (the reply is
      // keyed by it) — log and drop rather than send an unkeyed result.
      if (!ceremonyId) {
        deps.logger.warn("session.ceremony.abort", { agentName: deps.agentName, reason: "no_ceremony_id" });
        return;
      }
      if (!tbs || !context) {
        deps.logger.warn("session.ceremony.abort", { agentName: deps.agentName, reason: !tbs ? "no_tbs" : "no_context" });
        await reply(null);
        return;
      }

      // H1 / M1 / concurrency: reconstruct a FRESH signer (fresh directory endpoint +
      // NetworkDirectoryNode) PER ceremony. No caching — so signaling reconnecting to a
      // different directory node is picked up, a transient reconstruction failure retries
      // on the next request, and concurrent ceremonies never share one signer's FROST
      // state. (storeDkgResult is idempotent for the same share; reconstruction is cheap.)
      const signer = await reconstructThresholdSigner(deps);
      if (!signer) {
        deps.logger.warn("session.ceremony.abort", { agentName: deps.agentName, reason: "no_signer" });
        await reply(null);
        return;
      }
      try {
        const result = await signer.participateInCeremony(ceremonyId, tbs, context as FrostContext);
        deps.logger.info("session.ceremony.participated", {
          agentName: deps.agentName,
          ceremonyId: ceremonyId.slice(0, 16),
          ok: result.ok,
        });
        await reply(result.ok ? new Uint8Array(result.signature) : null);
      } catch (err: unknown) {
        deps.logger.warn("session.ceremony.failed", {
          agentName: deps.agentName,
          detail: err instanceof Error ? err.message : String(err),
        });
        await reply(null);
      }
    })();
  });
}
