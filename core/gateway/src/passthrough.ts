import type { GatewayMode, ScreenContext, ScreenVerdict, SecurityGatewayClient } from "./types.js";

/**
 * The null-object gateway client: screens nothing, always allows.
 *
 * ⚠️ TEST-ONLY (INV-9). No shipped code path may construct this. It was once the daemon's DEFAULT
 * when no gateway was configured, and because nothing in the product ever configured one, the
 * entire security layer was inert in every released build for weeks while the daemon cheerfully
 * announced it was connected. `DaemonConfig.securityGateway` is now REQUIRED, so a test that
 * wants no screening must say so by passing this explicitly — an honest declaration instead of a
 * silent inheritance.
 *
 * It still RETURNS a verdict (`allow`), so SI-001 ("never act on content without a verdict") holds
 * on this path too: "not screening" means "always-allow verdict", never "no verdict".
 *
 * It contains no detection logic. Real screening lives in the gateway PROGRAM (the server +
 * the local sidecar / remote client), never in the daemon.
 */
export class PassthroughGatewayClient implements SecurityGatewayClient {
  readonly mode: GatewayMode = "passthrough";

  async screenOutbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> {
    return { disposition: "allow", content };
  }

  async screenInbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> {
    return { disposition: "allow", content };
  }
}
