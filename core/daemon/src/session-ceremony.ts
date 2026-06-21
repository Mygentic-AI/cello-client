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

import { decode } from "cbor-x";
import { buildSealTbs } from "@cello-protocol/protocol-types";
import { FrostThresholdSigner } from "@cello-protocol/crypto";
import { storeDkgResult } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import type { IThresholdSigner } from "@cello-protocol/crypto";
import type { FrostContext } from "@cello-protocol/crypto/frost/types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { NetworkDirectoryNode } from "./network-directory-node.js";
import { FileRegistrationPersistence } from "./registration-persistence.js";
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
  /** `${celloDir}/agents/<name>` — holds frost-share.json. */
  agentDir: string;
  agentPubkeyHex: string;
  /** The agent's directory-connected libp2p node (the per-agent signaling node). */
  getNode: () => CelloNode | null;
  /** Resolve the directory endpoint to open FROST streams on. */
  getDirectoryEndpoint: () => Promise<{ peerId: string; multiaddr?: string } | null>;
  /** The agent's per-agent signaling seam (where ceremony_request arrives + result is sent). */
  signaling: SignalingSeam;
  logger: Logger;
}

/**
 * Reconstruct the agent's FROST threshold signer from its persisted share, configured to
 * drive the ceremony's `/cello/frost/1.0.0` round-trips on the agent's directory node.
 * Returns null when no share is persisted or the share is unreadable.
 */
export async function reconstructThresholdSigner(deps: CeremonyWiringDeps): Promise<IThresholdSigner | null> {
  const persistence = new FileRegistrationPersistence({ agentDir: deps.agentDir, logger: deps.logger });
  const share = await persistence.loadActiveFrostKeyShare();
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

  let directoryNodeStubs: NetworkDirectoryNode[] | undefined;
  const ep = await deps.getDirectoryEndpoint();
  const node = deps.getNode();
  if (ep && ep.multiaddr && node) {
    const stub = new NetworkDirectoryNode({
      id: ep.peerId,
      node,
      directoryPeerId: ep.peerId,
      directoryMultiaddrs: [ep.multiaddr],
      logger: deps.logger,
    });
    stub.setBootstrapContext(deps.agentPubkeyHex, `${deps.agentPubkeyHex}:epoch:1`);
    directoryNodeStubs = [stub];
  }
  return new FrostThresholdSigner(
    { threshold: share.threshold, participants: share.participants, directoryNodeStubs },
    Buffer.from(deps.agentPubkeyHex, "hex"),
  );
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
      const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, timestamp);
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
  deps: { agentDir: string; agentPubkeyHex: string; logger: Logger },
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

  const persistence = new FileRegistrationPersistence({ agentDir: deps.agentDir, logger: deps.logger });
  const share = await persistence.loadActiveFrostKeyShare();
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
