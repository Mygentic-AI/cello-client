export type { KeyProvider, PublicKey, Signature, KeyFileCorruptError } from "./types.js";
export { InMemoryKeyProvider, FileKeyProvider, generateKeypair, generateKLocalSeed, decodeKeyFileSeed, verify } from "./ed25519.js";
export type { MlDsaPublicKey, MlDsaSignature, MlDsaKeyPair, MlDsaKeyProvider } from "./ml-dsa.js";
export {
  InMemoryMlDsaKeyProvider,
  FileMlDsaKeyProvider,
  mlDsaKeygen,
  mlDsaKeygenWithBytes,
  mlDsaSign,
  mlDsaVerify,
  mlDsaEnsureLoaded,
} from "./ml-dsa.js";
export { hash, msgLeafHash, nodeHash, ctrlLeafHash, docLeafHash, rejectLeafHash, opaqueLeafHash, buildRelayAckTbs } from "./hashing.js";
export type { MerkleTree, LeafInput } from "./merkle.js";
export { buildMerkleTree, merkleRoot, inclusionProof, verifyInclusion } from "./merkle.js";
export type {
  IThresholdSigner,
  ThresholdSignature,
  ThresholdSignatureOk,
  ThresholdSignatureError,
  FrostThresholdSignerConfig,
  FrostContext,
  BootstrapResult,
} from "./frost/index.js";
export {
  CONTEXT_SESSION_ESTABLISHMENT,
  CONTEXT_SEAL,
  CONTEXT_PRIMARY_RELEASE,
  FrostThresholdSigner,
  MockThresholdSigner,
} from "./frost/index.js";

// SESSION-004: standalone FROST verify (no signer instance needed — used by counterparty client)
export { verifyFrostSignature } from "./frost/frost-threshold-signer.js";

// M8B DOD-REFRESH-1: FROST proactive share resharing (PSS) — used by the directory (its own share) and
// the daemon coordinator (the client's share). Group key unchanged; old-epoch shares die.
export {
  generateRefreshContribution,
  verifyRefreshContribution,
  applyRefresh,
} from "./frost/frost-resharing.js";
export type { RefreshContribution } from "./frost/frost-resharing.js";
// Client-side refresh helpers (daemon coordinator): rotate the client's own share in-package.
export {
  getClientFrostIdentifier,
  getClientRefreshRoster,
  generateClientRefreshContribution,
  applyRefreshToLocalShare,
} from "./frost/frost-threshold-signer.js";

// LIVE, load-bearing: core/daemon's network-directory-node imports ed25519_FROST FROM THIS RE-EXPORT
// to run the client-side DKG (DKG.round1/round2/round3). It has no in-package caller, so a grep of
// core/crypto alone makes it look dead. It is not. Do not remove it.
export { ed25519_FROST } from "@noble/curves/ed25519.js";

// FEDERATION-002: canonical checkpoint TBS serialization and hash computation
export { buildCheckpointTbs, computeCheckpointHash } from "./checkpoint.js";

// FEDERATION-003: relay registration TBS and signature verification
export { buildRelayRegistrationTbs, verifyRelayRegistrationSignature } from "./relay-registration.js";

// M7-MSG-001: recipient content sealed box (E2E encryption for parked content)
export { sealToRecipient, openSealed, CONTENT_SEAL_OVERHEAD_BYTES } from "./content-seal.js";

// M7-MANIFEST-001: consortium manifest verification and root key constants
export type { ManifestVerifyResult, ManifestVerifyDiagnostics, ManifestVerifySkipReason, ManifestVerifySkippedEntry, ConsortiumManifestInput } from "./manifest.js";
export { canonicalManifestBody, verifyManifest } from "./manifest.js";
// M8B-PREAUTH-CAP: signed pre-authorization capability (replaces the opaque single-use token).
export type { PreAuthCapability, PreAuthCapabilityBody, CapabilityVerifyResult, CapabilityVerifyReason } from "./preauth-capability.js";
export { canonicalCapabilityBody, signCapability, verifyCapability, encodeCapability, decodeCapability } from "./preauth-capability.js";
export {
  CONSORTIUM_ROOT_KEYS,
  CONSORTIUM_THRESHOLD,
  TEST_CONSORTIUM_ROOT_KEYS,
  TEST_CONSORTIUM_THRESHOLD,
} from "./consortium-keys.js";
export type { TestConsortiumNode, MakeTestManifestOpts } from "./manifest-test-fixture.js";
export { makeTestManifest, TEST_DIRECTORY_NODE_KEYPAIR } from "./manifest-test-fixture.js";

// M12 DOD-AE-APPEND-1: directory<->directory anti-entropy peer-auth TBS
export { buildAePeerAuthTbs, verifyAePeerAuth, AE_PEER_AUTH_DOMAIN } from "./ae-peer-auth.js";
export type { AePeerAuthParams } from "./ae-peer-auth.js";
