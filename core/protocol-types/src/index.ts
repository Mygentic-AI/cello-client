export { encodeCbor, decodeCbor } from "./cbor.js";

// M10 / DOD-CBOR-1 — the canonical trust-signal envelope. ONE implementation, consumed by the
// portal (mint), the directory (submission + presentation), and both daemons (receipt +
// verification) — M10-D16.
export {
  TRUST_SIGNAL_DOMAIN,
  encodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  verifyTrustSignalHash,
} from "./trust-signal.js";
export type {
  TrustSignalEnvelope,
  SignalSubjectKind,
  SignalIssuerKind,
} from "./trust-signal.js";

export type {
  MessageEnvelope,
  MessageEnvelopeV1,
  EnvelopeError,
  BuildResult,
  BuildResultV1,
  ValidateResult,
  ValidateResultV1,
  DeserializeResult,
  DeserializeResultV1,
} from "./types.js";

export { MAX_CONTENT_BYTES } from "./limits.js";
export { encodeStructure1, STRUCTURE1_VERSION } from "./structure1.js";

export type { ScanResultSentinel, Structure2, BuildStructure2Result } from "./structure2.js";
export {
  SCAN_RESULT_SENTINEL,
  buildStructure2,
  encodeStructure2,
  encodeScanResultSentinel,
  verifyStructure2Signature,
} from "./structure2.js";

export { computeGenesisPrevRoot, encodeSealPayload, decodeSealPayload, buildSessionEstablishmentTbs, buildSealTbs, SEAL_RECEIPT_DISCLAIMER } from "./session.js";
export type {
  SessionAssignment, SessionAssignmentFrost, SessionAssignmentSingle, ParticipantInfo, RelayEndpointInfo, SealPayload,
  SessionAbandoned, SessionSealedSingle, SessionSealedFrost, SessionSealed, SealRejectionReason, SessionSealRejected, SealVerified,
  AttestationMode, SealLegibility, SealLegibilityParticipant, SealLegibilityFinalMessage,
} from "./session.js";

export type {
  MlDsaKeyProvider,
  MlDsaVerifier,
  PseudonymBinding,
  Endorsement,
  Attestation,
  ConnectionPackage,
  EndorsementValidationStatus,
  AttestationValidationStatus,
  ValidatedEndorsement,
  ValidatedAttestation,
  PackageValidationResult,
  BuildPseudonymBindingResult,
  SignalCondition,
  SignalRequirement,
  ConnectionPolicy,
  DirectoryContext,
} from "./connection-package.js";

export {
  MAX_PSEUDONYM_LABEL_BYTES,
  ML_DSA_PUBKEY_BYTES,
  ML_DSA_SIGNATURE_BYTES,
  buildPseudonymBinding,
  verifyPseudonymBinding,
  verifyEndorsement,
  verifyAttestation,
  validateConnectionPackage,
  encodeConnectionPackage,
  decodeConnectionPackage,
} from "./connection-package.js";


export type {
  RegisterRequest,
  DkgComplete,
  DkgReady,
  RegisterSuccess,
  RegisterError,
  RegisterErrorReason,
  AgentProfile,
  RegistrationState,
} from "./registration.js";

export type {
  PrimaryTransferRequest,
  PrimaryTransferAck,
  PrimaryTransferError,
} from "./primary-transfer.js";
export { buildPrimaryTransferTbs, PRIMARY_TRANSFER_DOMAIN } from "./primary-transfer.js";

export { buildAgentRevocationTbs, AGENT_REVOCATION_DOMAIN } from "./revocation.js";
export type {
  RevokeAgentRequest,
  AgentRevocationAck,
  AgentRevocationError,
  AgentRevocationErrorReason,
} from "./revocation.js";

export type {
  ConnectionRequest,
  ConnectionRequestInbound,
  ConnectionResponse,
  ConnectionResponseVerdict,
  ConnectionEstablished,
  ConnectionRejected,
  ConnectionInsufficient,
  ConnectionRequestError,
  ConnectionRequestErrorReason,
  DisclosureRequest,
  DisclosureRequestItem,
  DisclosureRequestInbound,
  DisclosureResponse,
  DisclosureResponseInbound,
  ConnectionRecord,
  PendingConnectionRequest,
  ClientConnectionRecord,
  SessionRequestM3,
  SessionRequestM3ErrorReason,
} from "./connection-request.js";

export type {
  DkgRound1Broadcast,
  DkgRound2Share,
  FrostDkgRound1Request,
  FrostDkgRound1Response,
  FrostDkgRound2Request,
  FrostDkgRound2Response,
  FrostDkgRound3Request,
  FrostDkgRound3Response,
  FrostDkgRequest,
  FrostDkgResponse,
} from "./frost-dkg.js";

export type {
  FrostRefreshContribution,
  FrostRefreshRound1Request,
  FrostRefreshRound1Response,
  FrostRefreshRound2Request,
  FrostRefreshRound2Response,
  FrostRefreshRequest,
  FrostRefreshResponse,
} from "./frost-refresh.js";

// M7-MANIFEST-001: Consortium manifest types
export type {
  ConsortiumManifest,
  ConsortiumNode,
  OfficerSignature,
  ManifestError,
} from "./manifest.js";

export {
  MANIFEST_SIGNATURE_INVALID,
  MANIFEST_VERSION_ROLLBACK,
  MANIFEST_EXPIRED,
} from "./manifest.js";

// M7-SESSION-001: Seal-interrupted protocol types
export type {
  SealInterruptedLeaf,
  SealInterruptedRequest,
  SealInterruptedAck,
  SealInterruptedRejection,
  SessionInterruptedFrame,
  SealInterruptedSignalingMessage,
} from "./seal-interrupted.js";

// M7-MSG-001: content-delivery (delivery ACK, recovery, park) wire types
export type {
  ContentAckLevel,
  ContentDeliveryAck,
  ContentResendRequest,
  ContentParkDeposit,
  ContentParkDepositAck,
  ContentParkNotify,
  ContentParkPullRequest,
  ContentParkPullResponse,
} from "./content-delivery.js";
export {
  IT_LENGTH_PREFIX_DEFAULT_MAX,
  CONTENT_PARK_PROTOCOL_ID,
  CONTENT_PARK_AUTH_DOMAIN,
  buildContentParkAuthMsg,
  PARK_CONTENT_DOMAIN,
  buildParkContentTbs,
  isContentDeliveryAck,
  isContentResendRequest,
  isContentParkDeposit,
} from "./content-delivery.js";
// M7-SESSION-003: Session-path liveness wire types + codec
export type {
  SessionLiveness,
  SessionLivenessQuery,
  SessionLivenessResponse,
} from "./session-liveness.js";
export {
  encodeSessionLivenessQuery,
  decodeSessionLivenessQuery,
  encodeSessionLivenessResponse,
  decodeSessionLivenessResponse,
} from "./session-liveness.js";

// MONIKER-0 — the single home of the agent-name / moniker charset rule (wire contract).
export { MONIKER_RE, validateMoniker } from "./moniker.js";
