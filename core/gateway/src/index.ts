/**
 * @cello-protocol/gateway — the CELLO security gateway.
 *
 * A separate program from the daemon. The daemon imports only the contract
 * (`SecurityGatewayClient` + verdict types) and a client implementation; all detection lives
 * here. M9-CORE-001 ships the seam with a pass-through; later stories add the pipeline.
 */
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
export { InboundScreener } from "./screen/inbound.js";
export type { InboundVerdict, InboundScreenerOptions } from "./screen/inbound.js";

// The RE2 linear-time regex engine (native re2 preferred, re2-wasm fallback) + the injection
// pattern scanner (M9-IN-001 Step-9). initLinearRegex() must be awaited once before use.
export { initLinearRegex, linearRegexEngine, LinearRegex } from "./detect/linear-regex.js";
export { compileInjectionPatterns, scanInjectionPatterns, injectionPatternsReady } from "./detect/injection-patterns.js";
export { compileSecretRules, redactSecrets, secretRulesReady } from "./detect/secrets.js";
export type { SecretFinding, SecretScanResult } from "./detect/secrets.js";
export { screenInboundLanguage } from "./detect/language.js";
export type { LanguageVerdict, LanguageOptions, Script } from "./detect/language.js";
export { InjectionScanner, scoreToVerdict, BLOCK_THRESHOLD, FLAG_THRESHOLD } from "./detect/injection-scanner.js";
export type { InjectionClassifier, InjectionVerdict, ScanResult } from "./detect/injection-scanner.js";
export { isModelInstalled, installModel, verifyModel, sha256File } from "./detect/model-installer.js";
export type { InstallResult, InstallOptions } from "./detect/model-installer.js";
export { DEBERTA_MODEL } from "./detect/deberta-model-manifest.js";
export { GatewayConfigStore } from "./config/config-store.js";
export type { ConfigDirection, SetResult, ConfigVersionRow } from "./config/config-store.js";
export { GatewayRecordStore } from "./records/record-store.js";
export type { RecordDisposition, RecordDirection, RecordInput, SecurityRecord } from "./records/record-store.js";
export { GATEWAY_UNAVAILABLE, GOVERNANCE_TIMEOUT, failClosedVerdict } from "./types.js";
export { PassthroughGatewayClient } from "./passthrough.js";

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
