/**
 * A REAL FROST group for a test agent, and a seal signed by it the way the directory signs one.
 *
 * Every `session_sealed` is verified now (the M9D purge removed the path that skipped verification
 * when `signature_type` was absent), so a test that drives the seal handler needs a certificate that
 * genuinely verifies: a 2-of-3 FROST group from in-process stubs, the agent's persistence answering
 * with that group's commitments, and a signature over the production seal TBS
 * (`buildSealTbs` ‖ `bindLegibilityToTbs`) under the production context. Real crypto, no doubles.
 */
import { randomBytes } from "node:crypto";
import { encode } from "cbor-x";
import { FrostThresholdSigner, CONTEXT_SEAL } from "@cello-protocol/crypto";
import { bootstrapKeyShares } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import { createInProcessStubs } from "@cello-protocol/crypto/frost/stubs.js";
import { buildSealTbs } from "@cello-protocol/protocol-types";
import { bindLegibilityToTbs, type LegibilityForHash } from "../../seal-legibility-tbs.js";

export interface FrostSealer {
  /** The group key — the seal's `signer_pubkey`, and commitments[0] of the agent's share. */
  primary: Uint8Array;
  /** What `getPersistence(agent)` must return so the verifier finds its own primary. */
  persistence: { loadActiveFrostKeyShare(): Promise<{ commitmentsCbor: Uint8Array }> };
  /** A FROST signature over the legibility-bound seal TBS. */
  sign(cert: { sessionId: Uint8Array; sealedRoot: Uint8Array; leafCount: number; closeTimestamp: number; legibility: LegibilityForHash | null }): Promise<Uint8Array>;
}

export async function frostSealer(agentPubkey: Uint8Array): Promise<FrostSealer> {
  const config = { threshold: 2, participants: 3, directoryNodeStubs: createInProcessStubs(3) };
  const { primaryPubkey } = await bootstrapKeyShares(agentPubkey, config);
  const signer = new FrostThresholdSigner(config, agentPubkey);
  const commitmentsCbor = new Uint8Array(encode([primaryPubkey]));
  return {
    primary: primaryPubkey,
    persistence: { loadActiveFrostKeyShare: async () => ({ commitmentsCbor }) },
    async sign(c) {
      const tbs = bindLegibilityToTbs(buildSealTbs(c.sessionId, c.sealedRoot, c.leafCount, c.closeTimestamp), c.legibility);
      const r = await signer.participateInCeremony(`seal-${randomBytes(4).toString("hex")}`, tbs, CONTEXT_SEAL);
      if (!r.ok) throw new Error(`frostSealer: ceremony failed ${JSON.stringify(r.error)}`);
      return r.signature;
    },
  };
}
