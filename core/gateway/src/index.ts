/**
 * @cello-protocol/gateway — the CELLO security gateway.
 *
 * A separate program from the daemon. The daemon imports only the contract
 * (`SecurityGatewayClient` + verdict types) and a client implementation; all detection lives
 * here. M9-CORE-001 ships the seam with a pass-through; later stories add the pipeline.
 */
export type { GatewayMode } from "./types.js";
export type {
  ScreenDirection,
  ScreenDisposition,
  GovernanceDisposition,
  GovernanceEvent,
  ScreenContext,
  ScreenVerdict,
  SecurityGatewayClient,
} from "./types.js";

// The composed inbound/outbound screens (the gateway runs these; M9-FEED-001 renders the verdict).
export { OutboundScreener } from "./screen/outbound.js";
export type { OutboundVerdict, OutboundScreenerOptions, OutboundScreenContext } from "./screen/outbound.js";
export { InboundScreener, INBOUND_INJECTION_BLOCKED } from "./screen/inbound.js";
export type { InboundVerdict, InboundScreenerOptions } from "./screen/inbound.js";

// The RE2 linear-time regex engine (native re2 preferred, re2-wasm fallback) + the injection
// pattern scanner (M9-IN-001 Step-9). initLinearRegex() must be awaited once before use.
export { initLinearRegex, linearRegexEngine, LinearRegex } from "./detect/linear-regex.js";
export { compileInjectionPatterns, scanInjectionPatterns, injectionPatternsReady } from "./detect/injection-patterns.js";
export { compileSecretRules, redactSecrets, secretRulesReady } from "./detect/secrets.js";
export type { SecretFinding, SecretScanResult } from "./detect/secrets.js";
// Shared with the document content rule — the message path strips these, the document path refuses
// them, and neither may own a private copy of the list (DOD-DOC-SCREEN-CONTENT-1).
export { PRIVILEGED_TURN_MARKERS, PIPE_TURN_MARKER_SOURCE, pipeTurnMarkerRegex, sanitizeInbound } from "./detect/sanitize.js";
export { screenInboundLanguage } from "./detect/language.js";
export type { LanguageVerdict, LanguageOptions, Script } from "./detect/language.js";
export { InjectionScanner, scoreToVerdict, BLOCK_THRESHOLD, FLAG_THRESHOLD } from "./detect/injection-scanner.js";
export type { InjectionClassifier, InjectionVerdict, ScanResult } from "./detect/injection-scanner.js";
export { isModelInstalled, installModel, verifyModel, sha256File } from "./detect/model-installer.js";
export type { InstallResult, InstallOptions } from "./detect/model-installer.js";
export { DEBERTA_MODEL } from "./detect/deberta-model-manifest.js";
export { loadInjectionClassifier } from "./detect/injection-classifier-onnx.js";
export type { ClassifierLoad } from "./detect/injection-classifier-onnx.js";
export { GatewayConfigStore } from "./config/config-store.js";
export type { ConfigDirection, SetResult, ConfigVersionRow } from "./config/config-store.js";
export { GatewayStoreError, stderrStoreEventSink, openEncryptedStoreDb } from "./store/encrypted-db.js";
export type { GatewayStoreErrorCode, StoreEventSink } from "./store/encrypted-db.js";
export { GatewayRecordStore } from "./records/record-store.js";
export type { RecordDisposition, RecordDirection, RecordInput, SecurityRecord } from "./records/record-store.js";
export { GATEWAY_UNAVAILABLE, GOVERNANCE_TIMEOUT, failClosedVerdict } from "./types.js";
// The provenance marker is EXPORTED because it has consumers outside this package: the MCP tool
// descriptions and SKILL.md teach it to the agent, and the daemon's own guidance is marked with it.
// Review H2: F10 shipped it unexported and unspoken, so the agent that was supposed to "have
// something to check" was never told the marker existed. A marker no consumer knows is decoration.
export { AFFORDANCE_PREFIX, withProvenance } from "./screen/affordance.js";
// PassthroughGatewayClient is NOT exported here — it lives at `@cello-protocol/gateway/testing`
// (DOD-M9B-WIRE-1). An always-allow client on the production barrel is how the security layer
// shipped inert; reaching for it should be a deliberate act, visible in a diff.

// Wire protocol (shared by the local sidecar; Phase 2's mTLS gateway reuses these shapes).
export {
  SCREEN_OUTBOUND,
  SCREEN_INBOUND,
  encodeFrame,
  FrameDecoder,
} from "./protocol.js";
export type { ScreenMethod, WireScreenRequest, WireScreenResponse } from "./protocol.js";

// The gateway server (the separate program) + the screen-function and logger seams.
export { createGatewayServer } from "./server.js";
export type {
  GatewayScreenFn,
  GatewayServerOptions,
  GatewayServerHandle,
  GatewayLogger,
} from "./server.js";

// The daemon's local-sidecar adapter.
export { LocalSidecarGatewayClient } from "./client.js";
export type { LocalSidecarGatewayClientOptions } from "./client.js";

// Spawn the gateway as a child process (composition root + tests).
export { spawnGatewaySidecar, GATEWAY_READY_TOKEN } from "./spawn.js";
export type { SpawnGatewayOptions, SpawnedGateway } from "./spawn.js";
