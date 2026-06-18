/**
 * @cello-protocol/transport — public API
 *
 * Exports the CelloNode factory, interface, protocol constants, and error types.
 */

export { createNode } from "./node.js";
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
