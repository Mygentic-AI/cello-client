export { encodeCbor, decodeCbor } from "./cbor.js";

// M10 / DOD-CBOR-1 — the canonical trust-signal envelope. ONE implementation, consumed by the
// portal (mint), the directory (submission + presentation), and both daemons (receipt +
// verification) — M10-D16.
export {
  TRUST_SIGNAL_DOMAIN,
  // The one sentence a co-owned endorsement shows a reader. Exported so the portal that mints it
  // and the client that displays it cannot drift into two wordings for one fact.
  CO_OWNERSHIP_NOTE,
  encodeTrustSignalEnvelope,
  decodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  verifyTrustSignalHash,
} from "./trust-signal.js";
export type {
  TrustSignalEnvelope,
  SignalSubjectKind,
  SignalIssuerKind,
} from "./trust-signal.js";

// M10B / DOD-END-SUBMIT-1 — the sealed submission wire contract (M10B-D2). ONE implementation,
// because the daemon signs these bytes and the portal verifies and re-derives them; a byte-identical
// local copy on each side is how two implementations drift into disagreeing (M10B-D28).
export {
  SUBMISSION_DOMAIN,
  buildSubmissionTbs,
  encodeSubmission,
  decodeSubmission,
  submissionId,
} from "./submission.js";
export type { SubmissionBody, SubmissionOp, SignedSubmission } from "./submission.js";

// M16 / DOD-M16-ARTIFACT-1 — the doubly-signed broadcast post wire format.
export {
  BROADCAST_ARTIFACT_DOMAIN,
  MAX_BROADCAST_TITLE_CHARS,
  MAX_BROADCAST_BODY_BYTES,
  validateBroadcastTitle,
  buildBroadcastArtifactTbs,
  signBroadcastArtifact,
  encodeBroadcastArtifact,
  decodeBroadcastArtifact,
  verifyBroadcastArtifact,
} from "./broadcast-artifact.js";
export type {
  BroadcastArtifact,
  BroadcastDecodeReason,
  BroadcastVerifyReason,
  BroadcastVerifyResult,
} from "./broadcast-artifact.js";

// M16 / DOD-M16-ARTIFACT-1 — the relay's signed receipt: the post's hash and the relay's own time.
export {
  RELAY_POST_RECEIPT_DOMAIN,
  broadcastPostHash,
  buildRelayPostReceiptTbs,
  signRelayPostReceipt,
  encodeRelayPostReceipt,
  decodeRelayPostReceipt,
  verifyRelayPostReceipt,
} from "./relay-post-receipt.js";
export type { RelayPostReceipt, RelayPostReceiptDecodeReason } from "./relay-post-receipt.js";

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
export {
  encodeStructure1,
  decodeStructure1,
  STRUCTURE1_VERSION,
  STRUCTURE1_FIELD_COUNT,
  LAST_SEEN_HASH_BYTES,
  PREV_OWN_HASH_BYTES,
  STRUCTURE1_DECODE_REASONS,
} from "./structure1.js";
export type {
  Structure1Fields,
  Structure1DecodeResult,
  Structure1DecodeReason,
} from "./structure1.js";

export type { ScanResultSentinel, Structure2, BuildStructure2Result } from "./structure2.js";
export {
  SCAN_RESULT_SENTINEL,
  buildStructure2,
  encodeStructure2,
  encodeScanResultSentinel,
} from "./structure2.js";

export { computeGenesisPrevRoot, computeChainAnchor,encodeSealPayload, decodeSealPayload, buildSessionEstablishmentTbs, buildSealTbs, SEAL_RECEIPT_DISCLAIMER } from "./session.js";
export type {
  SessionAssignment, ParticipantInfo, RelayEndpointInfo, SealPayload,
  SessionAbandoned, SessionAbandonedNotice, SessionSealed, SealRejectionReason, SessionSealRejected, SealVerified,
  AttestationMode, SealLegibility, SealLegibilityParticipant, SealLegibilityFinalMessage,
} from "./session.js";

export type {
  MlDsaKeyProvider,
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
  ML_DSA_PUBLIC_KEY_BYTES,
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
  NodeRole,
} from "./manifest.js";

export {
  MANIFEST_SIGNATURE_INVALID,
  MANIFEST_VERSION_ROLLBACK,
  MANIFEST_EXPIRED,
  nodeRole,
  isValidator,
  validatorNodes,
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
  RelayParkRefusal,
} from "./content-delivery.js";
export {
  RELAY_PARK_REFUSALS,
  IT_LENGTH_PREFIX_DEFAULT_MAX,
  CONTENT_PARK_PROTOCOL_ID,
  CONTENT_PARK_AUTH_DOMAIN,
  buildContentParkAuthMsg,
  PARK_CONTENT_DOMAIN,
  buildParkContentTbs,
  isContentDeliveryAck,
  isContentResendRequest,
} from "./content-delivery.js";
// M7-SESSION-003: Session-path liveness wire types + codec
export type {
  SessionLiveness,
  SessionLivenessQuery,
  SessionLivenessResponse,
  SessionAttendance,
  SessionAttendanceNotice,
} from "./session-liveness.js";
export {
  encodeSessionLivenessQuery,
  decodeSessionLivenessQuery,
  encodeSessionLivenessResponse,
  decodeSessionLivenessResponse,
  encodeSessionAttendanceNotice,
  decodeSessionAttendanceNotice,
} from "./session-liveness.js";

// MONIKER-0 — the single home of the agent-name / moniker charset rule (wire contract).
export { MONIKER_RE, validateMoniker } from "./moniker.js";
export {
  DOCUMENT_UPDATE_DOMAIN,
  DOCUMENT_UPDATE_ENCODING_V1,
  buildDocumentUpdateTbs,
  encodeDocumentUpdateEnvelope,
  decodeDocumentUpdateEnvelope,
  documentEnvelopeHash,
  verifyDocumentChainLink,
} from "./document-envelope.js";
export type { DocumentUpdateEnvelope } from "./document-envelope.js";
export {
  DOCUMENT_PROPOSAL_DOMAIN,
  DOCUMENT_FEATURE_VERSION,
  ASSURANCE_TIER_V1,
  TOPOLOGY_DEFAULT,
  SUPPORTED_TOPOLOGIES,
  buildDocumentProposalTbs,
  documentIdFromProposal,
  encodeDocumentProposal,
  decodeDocumentProposal,
  seamViolation,
  documentFeatureIncompatibility,
} from "./document-proposal.js";
export type {
  DocumentProposalEnvelope,
  DocumentProperties,
  DocumentConsentState,
} from "./document-proposal.js";
export { arrangementGenesisFromProposal } from "./document-proposal.js";
export { documentGovernancePolicy } from "./document-governance.js";
export type { GovernanceVerdict } from "./document-governance.js";
export {
  DOCUMENT_AMENDMENT_DOMAIN,
  AMENDMENT_SUBJECT_KIND,
  AMENDMENT_KINDS,
  AMENDABLE_PROPERTIES,
  MAX_DOCUMENT_HOLDERS,
  buildDocumentAmendmentTbs,
  documentAmendmentHash,
  encodeDocumentAmendment,
  decodeDocumentAmendment,
} from "./document-amendment.js";
export type {
  AmendmentKind,
  DocumentAmendmentBody,
  DocumentAmendmentEnvelope,
  ArrangementGenesis,
  Arrangement,
  SignerPolicy,
} from "./document-amendment.js";
export { MAX_ENTRY_PARENTS } from "./document-amendment.js";
export {
  deriveDocumentState,
  deriveDocumentStateAt,
  checkEntryAdmissible,
} from "./document-derive.js";
export {
  DOCUMENT_RECONCILE_EXCHANGE_VERSION,
  MAX_RECONCILE_DOCUMENTS,
  encodeDocumentReconcile,
  decodeDocumentReconcile,
} from "./document-reconcile.js";
export type {
  DocumentReconcileFrame,
  DocumentReconcileBlock,
  GovernancePosition,
  ContentPosition,
} from "./document-reconcile.js";
export type { DocumentStateView, DeriveDocumentStateResult } from "./document-derive.js";
export {
  DOCUMENT_MULTISIG_DOMAIN,
  buildDocumentMultisigTbs,
  collectionStatus,
  encodeMultisigCollection,
  decodeMultisigCollection,
} from "./document-multisig.js";
export type {
  MultisigSubject,
  MultisigSignature,
  MultisigCollection,
  MultisigStatus,
} from "./document-multisig.js";
export {
  encodeDocumentProposalAck,
  decodeDocumentProposalAck,
  buildDocumentProposalAckTbs,
  assertDocumentProposalAckConsistent,
  DOCUMENT_PROPOSAL_ACK_DOMAIN,
  DOCUMENT_PROPOSAL_ACK_VERSION,
  MAX_PROPOSAL_REFUSAL_REASON_LENGTH,
} from "./document-proposal-ack.js";
export type { DocumentProposalAck } from "./document-proposal-ack.js";
export {
  DOCUMENT_REJECTION_DOMAIN,
  DOCUMENT_REJECTION_VERSION,
  MAX_REJECTION_DETAIL_LENGTH,
  buildDocumentRejectionTbs,
  documentRejectionHash,
  assertDocumentRejectionConsistent,
  encodeDocumentRejection,
  decodeDocumentRejection,
} from "./document-rejection-envelope.js";
export type { DocumentRejectionEnvelope } from "./document-rejection-envelope.js";

// M16 / 018-PUBCOLLECT — the channel info record: how a subscriber finds a channel without a
// directory lookup, and the only thing a PUBLIC channel has to learn from. Signed by the CHANNEL
// key alone; an admin-signed record would let a replaced admin redirect a channel's subscribers.
export {
  CHANNEL_INFO_DOMAIN,
  MAX_CHANNEL_GUIDANCE_CHARS,
  MAX_CHANNEL_RELAYS,
  buildChannelInfoTbs,
  signChannelInfo,
  encodeChannelInfo,
  decodeChannelInfo,
  verifyChannelInfo,
} from "./channel-info.js";
export type { ChannelInfo, ChannelAccess, ChannelInfoDecodeReason } from "./channel-info.js";
// M16 019-MEMBERSHIP: the join exchange. These travel inside an ordinary sealed session with the
// channel's ADMIN — a channel never converses itself.
export {
  encodeChannelJoinRequest, decodeChannelJoinRequest,
  encodeChannelJoinAccepted, decodeChannelJoinAccepted,
  encodeChannelJoinRefused, decodeChannelJoinRefused,
  encodeChannelRekey, decodeChannelRekey,
  isChannelJoinFrame,
  channelJoinFrameType,
  MAX_JOIN_NOTE_CHARS, MAX_JOIN_GUIDANCE_CHARS, MAX_JOIN_RELAYS,
  JOIN_REQUEST_TYPE, JOIN_ACCEPTED_TYPE, JOIN_REFUSED_TYPE, REKEY_TYPE,
} from "./channel-join.js";
export type {
  ChannelJoinRequest, ChannelJoinAccepted, ChannelJoinRefused, ChannelRekey,
  ChannelJoinAccess, ChannelJoinRefusedReason, JoinDecodeReason, JoinDecodeResult,
} from "./channel-join.js";

// The channel frames that carry a signature of their own. ONE definition, imported by the client
// that signs and the relay that verifies — see the header of channel-auth.ts.
export {
  buildChannelFetchAuthTbs,
  buildChannelPruneTbs,
  buildChannelReaderCountsTbs,
  buildChannelFetchKeyTbs,
  CHANNEL_FETCH_AUTH_DOMAIN,
  CHANNEL_PRUNE_DOMAIN,
  CHANNEL_READER_COUNTS_DOMAIN,
  CHANNEL_FETCH_KEY_DOMAIN,
} from "./channel-auth.js";
