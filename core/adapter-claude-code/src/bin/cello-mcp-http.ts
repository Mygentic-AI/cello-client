#!/usr/bin/env node
/**
 * cello-mcp-http — the CELLO MCP tools over Streamable HTTP, in front of the operator's own daemon.
 *
 * For MCP clients that speak only remote HTTPS. Holds no key material: it proxies to the daemon over
 * ~/.cello/daemon.sock exactly as cello-mcp does. TLS and public exposure are the operator's.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { HTTP_USAGE, McpHttpConfigError, parseHttpArgs, readTokenFile } from "../http-config.js";
import { startMcpHttpServer } from "../http-server.js";
import { logEvent } from "../shim-log.js";

const pkg = createRequire(import.meta.url)("../../package.json") as { version: string };

if (process.argv.includes("--version") || process.argv.includes("-v")) {
  process.stdout.write(`${pkg.version}\n`);
  process.exit(0);
}

try {
  const args = parseHttpArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HTTP_USAGE);
    process.exit(0);
  }
  const envToken = process.env["CELLO_MCP_HTTP_TOKEN"]?.trim() ?? "";
  const token = args.tokenFile !== undefined ? readTokenFile(args.tokenFile) : envToken;
  const celloDir = process.env["CELLO_DIR"] || join(homedir(), ".cello");

  const handle = await startMcpHttpServer({
    socketPath: join(celloDir, "daemon.sock"),
    host: args.host,
    port: args.port,
    token,
    version: pkg.version,
    agents: args.agents,
    toolsFileText: args.toolsFile !== undefined ? readFileSync(args.toolsFile, "utf8") : undefined,
    tls: args.tlsCert !== undefined && args.tlsKey !== undefined
      ? { cert: readFileSync(args.tlsCert, "utf8"), key: readFileSync(args.tlsKey, "utf8") }
      : undefined,
    maxSessions: args.maxSessions,
    idleTimeoutMs: args.idleTimeoutS * 1000,
  });

  const stop = (): void => {
    void handle.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
} catch (err: unknown) {
  const reason = err instanceof McpHttpConfigError ? err.reason : "startup_failed";
  const message = err instanceof Error ? err.message : String(err);
  logEvent("mcp.http.config.invalid", { reason, message });
  process.stderr.write(`cello-mcp-http: ${message}\n`);
  process.exit(1);
}
