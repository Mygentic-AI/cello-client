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

async function main(): Promise<void> {
  const socketPath = process.env["CELLO_GATEWAY_SOCKET"];
  if (!socketPath) {
    process.stderr.write("cello-gateway: CELLO_GATEWAY_SOCKET is required\n");
    process.exit(2);
    return;
  }
  const requestLogPath = process.env["CELLO_GATEWAY_REQUEST_LOG"];

  const handle = await createGatewayServer({
    socketPath,
    ...(requestLogPath ? { requestLogPath } : {}),
    // M9-CORE-001: pass-through. Detection pipeline (M9-IN-* / M9-OUT-*) is injected here later.
  });

  // Signal readiness to the parent (spawnGatewaySidecar waits for this).
  process.stdout.write(`${GATEWAY_READY_TOKEN} ${socketPath}\n`);

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
