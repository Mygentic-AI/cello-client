/**
 * TEST-ONLY exports. Reachable as `@cello-protocol/daemon/testing`, deliberately NOT from the
 * package barrel (DOD-M9C-WIRE-1).
 *
 * `DaemonConfig.securityGateway` is REQUIRED (INV-9), so every caller needs a way to satisfy it —
 * including a test that deliberately does not screen. That test says so by importing from here.
 * The daemon's own barrel stays free of an always-allow client.
 */
export { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
