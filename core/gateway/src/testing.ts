/**
 * TEST-ONLY exports. Reachable as `@cello-protocol/gateway/testing`, deliberately NOT from the
 * package barrel (DOD-M9B-WIRE-1: "the stub moves to test-only visibility").
 *
 * `PassthroughGatewayClient` screens nothing and allows everything. It was the daemon's DEFAULT
 * once, and because no production caller ever overrode it, the entire security layer shipped inert
 * while the daemon logged that its gateway was connected. It still has to EXIST — tests are
 * out-of-tree consumers and need a way to satisfy the now-required `securityGateway` field — but
 * putting it on the main barrel leaves an always-allow client one ordinary import away from any
 * production file. A separate entry point makes reaching for it a deliberate act that shows up in
 * a diff.
 */
export { PassthroughGatewayClient } from "./passthrough.js";
