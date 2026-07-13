import type { ScreenContext, ScreenVerdict, SecurityGatewayClient } from "./types.js";

/**
 * The null-object gateway client: screens nothing, always allows.
 *
 * This is the daemon's default when no gateway is configured — the case for a deployment that
 * has not enabled the security layer, and for the daemon/SNM tests that construct no gateway.
 * It still RETURNS a verdict (`allow`) — so SI-001 ("never act on content without a verdict")
 * holds even on the default path; "no gateway configured" means "always-allow verdict", not
 * "no verdict".
 *
 * It contains no detection logic. Real screening lives in the gateway PROGRAM (the server +
 * the local sidecar / remote client), never in the daemon.
 */
export class PassthroughGatewayClient implements SecurityGatewayClient {
  async screenOutbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> {
    return { disposition: "allow", content };
  }

  async screenInbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> {
    return { disposition: "allow", content };
  }
}
