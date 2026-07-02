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
 * This wires that handler onto a PER-AGENT signaling stream (the same per-agent routing
 * SPINE-4 established for registration). It is a faithful port of
 * core/client `SealManager.handleCeremonyRequest` + `client-startup` signer
 * reconstruction — the daemon must NOT import the dead core/client stack.
 *
 * The threshold signer is reconstructed lazily from the agent's persisted
 * `frost-share.json` (the daemon holds no FrostThresholdSigner after registration —
 * the registration-time signer was on the disposed RegistrationContext).
 */

import { decode, encode } from "cbor-x";
import { createHash } from "node:crypto";
import { buildSealTbs } from "@cello-protocol/protocol-types";
import { bindLegibilityToTbs, type LegibilityForHash } from "./seal-legibility-tbs.js";
import { reDeriveFrontiers, findInflatedFrontier, type SealFrontierLeaf } from "./seal-frontier-verify.js";
import { FrostThresholdSigner } from "@cello-protocol/crypto";
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
  signaling: SignalingSeam;
  logger: Logger;
}): () => void {
  return deps.signaling.registerInboundHandler((frame) => {
    if (frame["type"] !== "session_offer") return;
    void (async () => {
      const sidRaw = frame["session_id"];
      const sessionId = sidRaw instanceof Uint8Array ? sidRaw : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;
      if (!sessionId) {
        deps.logger.warn("session.offer.abort", { agentName: deps.agentName, reason: "no_session_id" });
        return;
      }
      const sr = deps.getStandingReceiverEndpoint();
      if (!sr) {
        deps.logger.warn("session.offer.abort", { agentName: deps.agentName, reason: "standing_receiver_unavailable" });
        return;
      }
      try {
        await deps.signaling.sendRaw({
          type: "session_offer_accept",
          session_id: sessionId,
          counterparty_session_peer_id: sr.peerId,
          counterparty_session_addrs: sr.addrs,
        });
        deps.logger.info("session.offer.accepted", {
          agentName: deps.agentName,
          sessionPeerId: sr.peerId,
        });
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
  const mkStub = (peerId: string, multiaddr: string): NetworkDirectoryNode => {
    const stub = new NetworkDirectoryNode({
      id: peerId,
      node: node!,
      directoryPeerId: peerId,
      directoryMultiaddrs: [multiaddr],
      logger: deps.logger,
    });
    stub.setBootstrapContext(deps.agentPubkeyHex, epochId);
    return stub;
  };
  if (node && roster !== null && roster.length > 0) {
    // Consortium configured → one stub per resolved directory node (T-of-N signing).
    directoryNodeStubs = roster.map((ep) => mkStub(ep.peerId, ep.multiaddr));
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
      directoryNodeStubs = [mkStub(ep.peerId, ep.multiaddr)];
    }
  }
  return { share, stubs: directoryNodeStubs };
}

export async function reconstructThresholdSigner(deps: CeremonyWiringDeps): Promise<IThresholdSigner | null> {
  const h = await hydrateShareAndStubs(deps);
  if (!h) return null;
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
      commitmentsCbor: encode(result.commitments),
      verifyingSharesCbor: encode(result.verifyingShares),
      dkgMethod: "network_dkg",
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
 * Faithful port of core/client `SealManager.handleSealVerified` (the dead stack); the daemon
 * must NOT import that stack. SI-001: tbs/signature never logged.
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

      // Reconstruct a FRESH signer per ceremony (same rationale as the session ceremony:
      // fresh directory endpoint, no shared FROST state across concurrent ceremonies).
      const signer = await reconstructThresholdSigner(deps);
      if (!signer) {
        deps.logger.warn("session.seal.ceremony.abort", { agentName: deps.agentName, sessionId: sidHex, reason: "no_signer" });
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
          deps.logger.warn("session.seal.ceremony.abort", {
            agentName: deps.agentName, sessionId: sidHex,
            reason: malformed ? "frontier_participant_malformed" : "frontier_leaves_missing",
          });
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
            deps.logger.warn("session.seal.ceremony.abort", {
              agentName: deps.agentName, sessionId: sidHex,
              reason: rederived.ok ? "frontier_unverifiable" : rederived.reason,
              ...(inflated ? { party: inflated.party, publishedFrontier: inflated.publishedFrontier, derivedFrontier: inflated.derivedFrontier } : {}),
            });
            return; // refuse to co-sign — the directory gets no signature for an inflated cert
          }
        }
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
        return;
      }
      if (!frostSignature) return; // ceremony failed (threshold not met) — no signature to send

      try {
        await deps.signaling.sendRaw({ type: "seal_frost_signature", session_id: sessionId, frost_signature: frostSignature });
        deps.logger.info("session.seal.frost.signature.sent", { agentName: deps.agentName, sessionId: sidHex });
      } catch (err: unknown) {
        deps.logger.warn("session.seal.frost.signature.send.failed", {
          agentName: deps.agentName,
          sessionId: sidHex,
          detail: err instanceof Error ? err.message : String(err),
        });
      }
    })();
  });
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
 * SYMMETRY STATUS: the counterparty-primary branch (below) IS built — the RESPONDER records the
 * session initiator's primary from the FROST-signed SessionAssignment at accept time
 * (recordCounterpartyPrimary, daemon.ts). The missing half is the INITIATOR-records-RESPONDER
 * direction: an initiator never learns the responder's primary, so when the responder closes first,
 * the initiator cannot verify locally and accepts with reason `signer_key_not_held`. Making the
 * directory hand EACH party the other's primary (so both closing orders verify) is F2-b — a
 * cross-repo protocol addition, not done here.
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
      // rejection in this fire-and-forget handler.
      const reply = async (signature: Uint8Array | null): Promise<void> => {
        if (!ceremonyId) return;
        try {
          await deps.signaling.sendRaw({ type: "ceremony_result", ceremony_id: ceremonyId, signature });
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
