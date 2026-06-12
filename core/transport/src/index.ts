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
export { CELLO_PROTOCOL_ID, CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID, CELLO_CONTENT_PROTOCOL_ID } from "./protocols.js";

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

// M7-MANIFEST-002: SignalingManager and outbound queue
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
  SignalingLogger,
  ProcessStep5Result,
} from "./signaling-manager.js";
