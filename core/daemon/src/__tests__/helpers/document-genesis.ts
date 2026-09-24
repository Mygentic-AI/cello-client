/**
 * A document's GENESIS for tests that build the document layer directly.
 *
 * Every production document starts from a recorded proposal, and membership is derived from it:
 * the proposer is a participant by their signature, the peer only after their own consent entry.
 * A document row with no genesis cannot answer "who may write here", and the inbound gate refuses
 * it. So a fixture that seeds a document row must record the genesis too.
 *
 * The proposal is fixed (nonce, timestamp, properties), so its id — the document id — is a pure
 * function of the two parties and can be a module-level constant.
 */
import {
  encodeDocumentProposal,
  documentIdFromProposal,
  DOCUMENT_FEATURE_VERSION,
  ASSURANCE_TIER_V1,
  TOPOLOGY_DEFAULT,
  type DocumentProposalEnvelope,
} from "@cello-protocol/protocol-types";

/** The genesis proposal `proposer` made to `peer`. Unsigned: derivation reads it, never re-verifies it. */
export function genesisProposal(proposer: string, peer: string, documentType = "markdown"): DocumentProposalEnvelope {
  return {
    type: "document_proposal",
    feature_version: DOCUMENT_FEATURE_VERSION,
    proposer_agent_id: proposer,
    peer_agent_id: peer,
    document_type: documentType,
    properties: { assurance_tier: ASSURANCE_TIER_V1, schema_enforcement: false, topology: TOPOLOGY_DEFAULT, append_only: false },
    starting_content: null,
    nonce: new Uint8Array([9, 9, 9, 9]),
    proposed_at_ms: 1,
    signature: new Uint8Array(64),
  };
}

/** The document id of that genesis. */
export function genesisDocumentId(proposer: string, peer: string, documentType = "markdown"): string {
  return documentIdFromProposal(genesisProposal(proposer, peer, documentType));
}

/** Record the genesis on `owner`'s side, as a received genesis is recorded. Returns the document id. */
export function recordGenesis(
  handshake: { recordJoined(owner: string, genesis: Uint8Array, nowMs: number): string },
  owner: string,
  proposer: string,
  peer: string,
  documentType = "markdown",
): string {
  return handshake.recordJoined(owner, encodeDocumentProposal(genesisProposal(proposer, peer, documentType)), 1);
}
