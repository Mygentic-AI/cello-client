/**
 * M10B / DOD-END-SCAN-1 (`M10B-D17`) — the deterministic Layer-1 detectors, as a NARROW subpath.
 *
 * Spec §7 constraint 2 wants the intake scanner to be "a versioned shared component", and these are
 * it: pure, deterministic, RE2-backed rule corpora with no I/O and no model. The portal's intake
 * consumes THIS entry point and never the package barrel.
 *
 * WHY A SEPARATE ENTRY POINT AT ALL. `src/index.ts` re-exports `GatewayConfigStore` and
 * `GatewayRecordStore`, and both statically `import { DatabaseSync } from "node:sqlite"` — VERBOTEN
 * in this project — alongside the gateway HTTP server and the sidecar spawner. A barrel import from
 * the portal would evaluate all of that inside a Next.js Fargate app. The package `exports` map
 * previously offered only `"."`, so there was no deep-import escape; this is that escape, made
 * deliberate and narrow.
 *
 * WHAT IS DELIBERATELY ABSENT, and it is the more important half:
 *
 *   - `injection-scanner.ts` — the DeBERTa Layer-2 ONNX classifier. Excluded by `M10B-D16` on three
 *     independent grounds: spec §7 says "No LLM"; it **degrades OPEN** by design ("when it is absent,
 *     Layer-2 is OFF"), and intake must fail CLOSED — a scanner that can be silently off cannot back
 *     a signed `scanner_version` assertion, because the record would then claim a scan that did not
 *     happen; and its verdicts are score-thresholded over per-operator downloaded weights, which
 *     "byte-identical across nodes" does not survive.
 *   - `model-installer.ts`, the server, the stores, the sidecar — none of it is a rule corpus.
 *
 * WHAT THIS DOES NOT EXPORT EITHER: a verdict. The gateway's own disposition is deliberately the
 * OPPOSITE of intake's — "it is not, by itself, an auto-block. CELLO is not a moderation tool; this
 * surfaces evidence, it does not police content" — while intake is reject-always, fail-closed (§7
 * constraint 3). Reusing `InboundScreener`'s disposition would produce a scanner that passes its
 * tests and never refuses anything (`M10B-D16`). The corpus is shared; the policy is the portal's.
 */

export { compileInjectionPatterns, injectionPatternsReady, scanInjectionPatterns, injectionPatternIds } from "./injection-patterns.js";
export { compileSecretRules, secretRulesReady, redactSecrets, secretRuleIds } from "./secrets.js";
export { detectorCorpusDigest } from "./corpus-digest.js";
export type { SecretFinding, SecretScanResult } from "./secrets.js";
