/**
 * @cello-protocol/transport — public API
 *
 * Exports the CelloNode factory, interface, protocol constants, and error types.
 */

export { createNode, isValidMultiaddr, buildConfiguredHosts } from "./node.js";
// DOD-RELAY-KEEPALIVE-1: the connection-monitor policy. WAN_PING_TIMEOUT_FLOOR_MS doubles as the
// capability marker a consumer can test for — the relay refuses to start on a transport that
// predates the policy, because there the connectionMonitor option is silently ignored.
export { resolveConnectionMonitorConfig, WAN_PING_TIMEOUT_FLOOR_MS } from "./node.js";
// DOD-M15-IDLE-CONNS-1 — the declared connection posture and the idle-connection judgement.
export {
  resolveConnectionLimits,
  selectIdleConnections,
  IDLE_CONNECTION_GRACE_MS,
  IDLE_CONNECTION_SWEEP_MS,
  DECLARED_MAX_CONNECTIONS,
  DECLARED_INBOUND_CONNECTION_THRESHOLD,
  DECLARED_MAX_INCOMING_PENDING,
  DECLARED_INBOUND_UPGRADE_TIMEOUT_MS,
} from "./node.js";
export type { ResolvedConnectionLimits, IdleConnectionCandidate } from "./node.js";
export type { ResolvedConnectionMonitorConfig } from "./node.js";
export type { CelloNode, CreateNodeOptions, CelloStreamHandler } from "./types.js";
export type {
  CelloTransportError,
  ProtocolNotSupportedError,
  ConnectionLostError,
  NodeStoppedError,
  ListenFailedError,
} from "./types.js";
export { CELLO_PROTOCOL_ID, CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID, CELLO_CONTENT_PROTOCOL_ID, AUTONAT_PROTOCOL_ID } from "./protocols.js";

// CELLO-M7-TRANSPORT-001: AutoNAT dialability adapter + stub
export type { IAutoNatService, Dialability, Unsubscribe } from "./autonat.js";
export { LocalAutoNatStub, DEFAULT_DIALABILITY } from "./autonat.js";
// CELLO-M7-TRANSPORT-001: real IAutoNatService over a live CelloNode (emits the
// transport.autonat.result / transport.autonat.unavailable observability events).
export { NodeAutoNatService } from "./autonat-service.js";
export type {
  AutoNatLogger,
  AutoNatNodeType,
  NodeAutoNatServiceOptions,
} from "./autonat-service.js";

// M7-MSG-001: content-size cap on inbound content decode
export { readCappedContentFrame } from "./content-cap.js";
export type { CappedFrameResult } from "./content-cap.js";

// M7-MANIFEST-002: manifest interfaces
export type {
  IManifestVersionStore,
  IManifestProvider,
  IDirectoryChallengeVerifier,
  ChallengeVerifyResult,
  ChallengeVerifyOk,
  ChallengeVerifyFail,
  IManifestPollScheduler,
  DirectoryKeyProvider,
  DirectoryManifestStore,
} from "./manifest-interfaces.js";

// M7-MANIFEST-002: manifest stubs (for test use)
export {
  InMemoryManifestVersionStore,
  TestManifestProvider,
  TestDirectoryChallengeVerifier,
  ManifestDirectoryChallengeVerifier,
  ImmediatePollScheduler,
  TestDirectoryKeyProvider,
  TestDirectoryManifestStore,
} from "./manifest-stubs.js";

// M7-SIGNAL-001 + M7-MANIFEST-002: SignalingManager, frame types, and helpers
export {
  SignalingManager,
  InMemorySignalingOutboundQueue,
  buildStep5Tbs,
} from "./signaling-manager.js";
export type {
  SignalingAuthOkFrame,
  ManifestPollResponseFrame,
  ISignalingOutboundQueue,
  SignalingManagerConfig,
  SignalingManagerOptions,
  SignalingLogger,
  Logger as SignalingConnectionLogger,
  ProcessStep5Result,
  SignalingStream,
  ConnectResult,
  OperationResult,
  OperationSuccess,
  OperationFailure,
  SignalingFailureReason,
} from "./signaling-manager.js";
