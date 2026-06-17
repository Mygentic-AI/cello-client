/**
 * CELLO Transport — protocols.ts
 *
 * Protocol ID constants for the CELLO transport layer.
 */

/**
 * CELLO M0 stream protocol identifier.
 * Used for all CELLO envelope exchanges in the walking skeleton (M0) milestone.
 * Stream framing: it-length-prefixed varint-prefixed frames
 * (unsigned varint per https://github.com/multiformats/unsigned-varint).
 */
export const CELLO_PROTOCOL_ID = "/cello/m0/1.0.0";

/**
 * Circuit Relay v2 HOP protocol identifier.
 * Read from @libp2p/circuit-relay-v2 package (RELAY_V2_HOP_CODEC constant).
 * Value: '/libp2p/circuit/relay/0.2.0/hop'
 * Source: @libp2p/circuit-relay-v2 v4.2.3, src/constants.ts
 */
export const CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/hop";

/**
 * CELLO content protocol identifier.
 * Used for direct peer-to-peer content exchange after session establishment (SESSION-002).
 * Stream framing: it-length-prefixed varint-prefixed frames.
 */
export const CELLO_CONTENT_PROTOCOL_ID = "/cello/content/1.0.0";

/**
 * AutoNAT protocol identifier (CELLO-M7-TRANSPORT-001).
 * Read from @libp2p/autonat constants: `/${prefix}/${name}/${version}` =>
 * `/libp2p/autonat/1.0.0`. Registered on every CELLO node — client role
 * (session / standing receiver nodes probing directory nodes for dial-back) and
 * server/responder role (directory nodes answering dial-back requests, AC-011).
 *
 * NOTE: AC-011 references `/libp2p/autonat/2.0.0` (AutoNAT v2). CELLO uses
 * AutoNAT v1 (@libp2p/autonat) to stay version-aligned with the rest of the
 * libp2p v3.0.x service stack (dcutr, identify, circuit-relay-v2). The responder
 * semantics required by AC-011 are identical; only the wire protocol version
 * string differs.
 */
export const AUTONAT_PROTOCOL_ID = "/libp2p/autonat/1.0.0";
