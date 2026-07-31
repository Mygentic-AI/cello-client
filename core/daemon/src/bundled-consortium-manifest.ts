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
 * nodeId MUST equal the directory's reported NODE_ID (`<cloud>-<region>`, e.g. `gcp-use1`); the step-6 verifier
 * looks the node up by nodeId. pubkey MUST equal /cello/<env>/directory/manifest-signer-pubkey for
 * that region (derived from the directory's node-private-key). endpoint is the HTTP /bootstrap base.
 *
 * Regeneration: on directory node-key or officer-key rotation, re-sign with
 * infra/scripts/sign-gcp-consortium-manifest and update this constant + BUNDLED_CONSORTIUM_ROOT_KEYS.
 * The officer signing key lives in Secrets Manager (GCP Secret Manager `cello-consortium-officer-key-0`); only its
 * PUBLIC key is embedded here.
 *
 * Crypto reference: RFC 8032 (Ed25519 threshold signatures, verified by verifyManifest).
 */

import type { ConsortiumManifestInput } from "@cello-protocol/crypto";

/** The signed consortium manifest (roster of sovereign directory nodes). */
export const BUNDLED_CONSORTIUM_MANIFEST: ConsortiumManifestInput = {
  version: 2,
  not_before: "2026-01-01T00:00:00Z",
  expires: "2030-01-01T00:00:00Z",
  nodes: [
    {
      nodeId: "gcp-use1",
      pubkey: "7969e22a7d95293ae343cb2667c2a4d7127aa8748478582fa637674c30e0113c",
      region: "use1",
      provider: "gcp",
      endpoint: "http://34.75.172.108:9090",
      peerId: "12D3KooWMH58hm8xpuwgwaNSvnvXBuc126jfuUMVbrGNcU2MeEAX",
      multiaddr: "/ip4/34.75.172.108/tcp/8080/ws",
      role: "validator",
    },
    {
      nodeId: "gcp-usc1",
      pubkey: "ef961384100bb087f36b68e3a270acb8f22fdf62c4cd5e517e423afb7f399002",
      region: "usc1",
      provider: "gcp",
      endpoint: "http://34.136.176.190:9090",
      peerId: "12D3KooWExQLMbvaioVqQCPkc1ZZgJ5kdoePymtMrg46ugMBs5zi",
      multiaddr: "/ip4/34.136.176.190/tcp/8080/ws",
      role: "validator",
    },
    {
      nodeId: "gcp-euw1",
      pubkey: "9cb77b68a98f49056fef232f4d56eeb9b66b1a6646fe06b966ff570a82ca6c14",
      region: "euw1",
      provider: "gcp",
      endpoint: "http://34.34.166.245:9090",
      peerId: "12D3KooWP52VSVrakyRdPyt23kAuhgp3FV6tiVRByfdyVvHAaEeJ",
      multiaddr: "/ip4/34.34.166.245/tcp/8080/ws",
      role: "validator",
    },
  ],
  // M10B / DOD-END-INGRESS-1 — the PORTAL INTAKE KEY. A submitting daemon seals its trust-signal
  // submission to this key so the DIRECTORY cannot read it; without it `cello_attestations_issue`
  // refuses with `intake_key_absent` rather than sending in the clear. It has to be in the BUNDLED
  // manifest and not only in the served one, because a cold-boot daemon that cannot yet reach a
  // directory falls back to this constant — and "your first submission fails until you have polled"
  // is indistinguishable from the feature being broken.
  intake_key: { key_id: "intake-dev-1", pubkey: "87da56bf2ca5ef75d62d88dfed1f667f9fa565ee0a5306aeeef50f5d7053b3d1" },
  signatures: [
    {
      officerIndex: 0,
      signature:
        "d85802b8c9ea876ff3b2774e7c5feab8413b953d5a4f41291309a9bd38ea90ab53203c50fa41f8b74b2fc4370880098ad1f0c317081a898990afafffd5c49508",
    },
  ],
};

/**
 * Pinned consortium officer root public key(s). Officer 0's Ed25519 public key (hex). The client
 * verifies BUNDLED_CONSORTIUM_MANIFEST's threshold signatures against this set. Public data.
 */
export const BUNDLED_CONSORTIUM_ROOT_KEYS: readonly string[] = [
  "e8300a2b9de7be6f6d629f778dc319715ad0010c0639f3a1564181d56d3eb104",
];

/** Minimum number of distinct valid officer signatures required (dev: single officer, threshold 1). */
export const BUNDLED_CONSORTIUM_THRESHOLD = 1;
