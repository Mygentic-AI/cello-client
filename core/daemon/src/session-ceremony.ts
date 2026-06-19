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
import { FrostThresholdSigner } from "@cello-protocol/crypto";
import { storeDkgResult } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import type { IThresholdSigner } from "@cello-protocol/crypto";
import type { FrostContext } from "@cello-protocol/crypto/frost/types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { NetworkDirectoryNode } from "./network-directory-node.js";
import { FileRegistrationPersistence } from "./registration-persistence.js";
import type { SignalingSeam } from "./registration-context.js";
import type { Logger } from "./types.js";

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
  } catch {
    deps.logger.error("session.ceremony.share.load.failed", { agentName: deps.agentName, reason: "cbor_deserialize_failed" });
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
  } catch {
    deps.logger.error("session.ceremony.share.load.failed", { agentName: deps.agentName, reason: "storeDkgResult_failed" });
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
export function wireSessionCeremonyHandler(deps: CeremonyWiringDeps): () => void {
  let signerPromise: Promise<IThresholdSigner | null> | null = null;
  const getSigner = (): Promise<IThresholdSigner | null> => {
    if (!signerPromise) signerPromise = reconstructThresholdSigner(deps);
    return signerPromise;
  };

  return deps.signaling.registerInboundHandler((frame) => {
    if (frame["type"] !== "ceremony_request") return;
    void (async () => {
      const ceremonyId = typeof frame["ceremony_id"] === "string" ? (frame["ceremony_id"] as string) : undefined;
      if (!ceremonyId) return;
      const tbsRaw = frame["tbs"];
      const tbs = tbsRaw instanceof Uint8Array ? tbsRaw : Buffer.isBuffer(tbsRaw) ? new Uint8Array(tbsRaw as Buffer) : null;
      const context = typeof frame["context"] === "string" ? (frame["context"] as string) : undefined;

      const replyNull = async (): Promise<void> => {
        await deps.signaling.sendRaw({ type: "ceremony_result", ceremony_id: ceremonyId, signature: null });
      };

      const signer = await getSigner();
      if (!signer || !tbs || !context) {
        deps.logger.warn("session.ceremony.abort", {
          agentName: deps.agentName,
          reason: !signer ? "no_signer" : !tbs ? "no_tbs" : "no_context",
        });
        await replyNull();
        return;
      }
      try {
        const result = await signer.participateInCeremony(ceremonyId, tbs, context as FrostContext);
        const sig = result.ok ? result.signature : null;
        deps.logger.info("session.ceremony.participated", {
          agentName: deps.agentName,
          ceremonyId: ceremonyId.slice(0, 16),
          ok: result.ok,
        });
        await deps.signaling.sendRaw({
          type: "ceremony_result",
          ceremony_id: ceremonyId,
          signature: sig ? new Uint8Array(sig) : null,
        });
      } catch (err: unknown) {
        deps.logger.warn("session.ceremony.failed", {
          agentName: deps.agentName,
          error: err instanceof Error ? err.message : String(err),
        });
        await replyNull();
      }
    })();
  });
}
