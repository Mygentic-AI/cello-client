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
  ScreenContext,
  ScreenVerdict,
  SecurityGatewayClient,
} from "./types.js";
export { GATEWAY_UNAVAILABLE, failClosedVerdict } from "./types.js";
export { PassthroughGatewayClient } from "./passthrough.js";

// Wire protocol, the local-sidecar client, the gateway server, and the spawn helper are
// added next in M9-CORE-001 (see ./protocol.ts, ./client.ts, ./server.ts, ./spawn.ts).
