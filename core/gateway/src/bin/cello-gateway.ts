#!/usr/bin/env node
/**
 * cello-gateway — the gateway program entry point.
 *
 * Reads its socket path (and optional request-log path) from the environment, starts the
 * gateway server, and prints a READY line so a parent (spawnGatewaySidecar) knows it is
 * listening. M9-CORE-001 runs the pass-through screen; later stories wire the detection
 * pipeline into createGatewayServer's `screen` option here.
 *
 * This is the gateway's composition root — the one place a startup banner goes to stdout. The
 * server itself stays logger-injected (no console.* in library code, INV-7).
 */
import { createGatewayServer } from "../server.js";
import { GATEWAY_READY_TOKEN } from "../spawn.js";
import { OutboundScreener } from "../screen/outbound.js";
import { InboundScreener } from "../screen/inbound.js";
import { initLinearRegex } from "../detect/linear-regex.js";
import { compileInjectionPatterns } from "../detect/injection-patterns.js";
import type { ScreenVerdict } from "../types.js";

async function main(): Promise<void> {
  const socketPath = process.env["CELLO_GATEWAY_SOCKET"];
  if (!socketPath) {
    process.stderr.write("cello-gateway: CELLO_GATEWAY_SOCKET is required\n");
    process.exit(2);
    return;
  }
  const requestLogPath = process.env["CELLO_GATEWAY_REQUEST_LOG"];

  // The real screen compositions. Config (PII whitelist, rate limit) is M9-CFG-001; defaults here
  // (no whitelist, no rate cap) until that lands. Secret detection (M9-OUT-001) slots into the
  // outbound screener once its RE2/gitleaks binding is chosen.
  // Resolve the RE2 engine (native preferred, WASM fallback) and compile the injection-pattern set
  // BEFORE accepting traffic — so the ReDoS-safe Step-9 scan is live from the first message.
  const engine = await initLinearRegex();
  compileInjectionPatterns();

  const piiWhitelist = (process.env["CELLO_GATEWAY_PII_WHITELIST"] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const outbound = new OutboundScreener({ piiWhitelist });
  const inbound = new InboundScreener();

  const handle = await createGatewayServer({
    socketPath,
    ...(requestLogPath ? { requestLogPath } : {}),
    screen: (req): ScreenVerdict => {
      if (req.direction === "outbound") {
        const v = outbound.screen(req.content, { agentName: req.agentName, sessionId: req.sessionId });
        return {
          disposition: v.disposition,
          content: v.content,
          events: v.events,
          ...(v.reason !== undefined ? { reason: v.reason } : {}),
          ...(v.guidance !== undefined ? { guidance: v.guidance } : {}),
        };
      }
      const v = inbound.screen(req.content);
      return { disposition: v.disposition, content: v.content, events: v.events };
    },
  });

  // Signal readiness to the parent (spawnGatewaySidecar waits for this).
  process.stdout.write(`${GATEWAY_READY_TOKEN} ${socketPath} regex-engine=${engine}\n`);

  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    void handle.stop().then(() => {
      process.stderr.write(`cello-gateway: stopped (${signal})\n`);
      process.exit(0);
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err: unknown) => {
  process.stderr.write(`cello-gateway: fatal ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
