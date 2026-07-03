/**
 * FINDING-4 — the bundled consortium roster (sovereign-node REDUNDANCY invariant).
 *
 * This is the signed list of the sovereign directory nodes that make up the CELLO consortium,
 * COMPILED INTO the client. It is loaded by default (when the operator does not override it via
 * CELLO_CONSORTIUM_MANIFEST) so that a cold-boot daemon already knows every directory — and can
 * fail over to a reachable one — even when its configured/primary directory is unreachable. Without
 * a bundled roster the failover resolver has nothing to route to (the exact FINDING-4 gap: the
 * roster-aware dialer was correct but the roster was empty), so a single directory being down
 * stranded the client at startup, violating the redundancy invariant.
 *
 * Trust model:
 *   - The manifest is threshold-signed by the consortium officer key(s). At load the client
 *     RE-VERIFIES it against BUNDLED_CONSORTIUM_ROOT_KEYS (a self-consistency / anti-corruption
 *     gate — the manifest and root keys ship together, so this catches a bad regeneration, not a
 *     network adversary).
 *   - The node `pubkey`s are the directories' Ed25519 node keys. They are the trust anchor for
 *     step-6 directory identity auth (M7-MANIFEST-002): when the client connects to (or fails over
 *     to) a directory, the directory must sign the client's challenge with the matching node key,
 *     proving it is the real consortium node for that nodeId — defeating a MITM on the plaintext
 *     /bootstrap that would otherwise redirect the client to a rogue directory. THIS is the
 *     adversarial defense; it is enabled by default alongside the roster.
 *
 * nodeId MUST equal the directory's reported NODE_ID (its AWS region string); the step-6 verifier
 * looks the node up by nodeId. pubkey MUST equal /cello/<env>/directory/manifest-signer-pubkey for
 * that region (derived from the directory's node-private-key). endpoint is the HTTP /bootstrap base.
 *
 * Regeneration: on directory node-key or officer-key rotation, re-sign with
 * infra/scripts/sign-consortium-manifest and update this constant + BUNDLED_CONSORTIUM_ROOT_KEYS.
 * The officer signing key lives in Secrets Manager (cello/<env>/consortium/officer-key-0); only its
 * PUBLIC key is embedded here.
 *
 * Crypto reference: RFC 8032 (Ed25519 threshold signatures, verified by verifyManifest).
 */

import type { ConsortiumManifestInput } from "@cello-protocol/crypto";

/** The signed consortium manifest (roster of sovereign directory nodes). */
export const BUNDLED_CONSORTIUM_MANIFEST: ConsortiumManifestInput = {
  version: 1,
  not_before: "2026-01-01T00:00:00Z",
  expires: "2030-01-01T00:00:00Z",
  nodes: [
    {
      nodeId: "us-east-1",
      pubkey: "167ca6b145bfdd3696af8f4befd883c3dc610f4a9c8d52a30f6a22f669dc27b5",
      region: "us-east-1",
      provider: "aws",
      endpoint: "http://directory-us1.cello.mygentic.ai",
    },
    {
      nodeId: "eu-central-1",
      pubkey: "8105b180b753d97b50039a7e94433fd2b419f43d61f9ad7caf2ac15ad5cd1b45",
      region: "eu-central-1",
      provider: "aws",
      endpoint: "http://directory-eu1.cello.mygentic.ai",
    },
    {
      nodeId: "ap-northeast-1",
      pubkey: "9b4b673a16487ba47363e3eaff844bf68f19736d82967918fb896b813e39b984",
      region: "ap-northeast-1",
      provider: "aws",
      endpoint: "http://directory-ap1.cello.mygentic.ai",
    },
  ],
  signatures: [
    {
      officerIndex: 0,
      signature:
        "1a372676e83ae323be8dbc6f8b786b3424706999efcccd70027798cbca91fe0b60cb35ac1e1af21078f24618d1f740b61bdcf06da03c5f90acc48d954039a104",
    },
  ],
};

/**
 * Pinned consortium officer root public key(s). Officer 0's Ed25519 public key (hex). The client
 * verifies BUNDLED_CONSORTIUM_MANIFEST's threshold signatures against this set. Public data.
 */
export const BUNDLED_CONSORTIUM_ROOT_KEYS: readonly string[] = [
  "8e9b99e5aa5505f2f50ec9f933f497a64956614575edce3427ec8a096c864199",
];

/** Minimum number of distinct valid officer signatures required (dev: single officer, threshold 1). */
export const BUNDLED_CONSORTIUM_THRESHOLD = 1;
