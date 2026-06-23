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
import { compileSecretRules } from "../detect/secrets.js";
import { GatewayConfigStore } from "../config/config-store.js";
import { GatewayRecordStore, type RecordDisposition } from "../records/record-store.js";
import { createHash } from "node:crypto";
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
  compileSecretRules();

  // M9-CFG-001 (INV-4): the gateway owns its config. When CELLO_GATEWAY_CONFIG_DB is set, the versioned
  // config store is the SOURCE OF TRUTH (with its tighten-free / loosen-confirmed governance); env vars
  // are the bootstrap fallback for any key the store has not set. Each setting defaults to its TIGHTEST
  // value (empty whitelist, override off, no rate cap) so an absent/empty config never silently loosens.
  const configDbPath = process.env["CELLO_GATEWAY_CONFIG_DB"];
  const config = configDbPath ? new GatewayConfigStore(configDbPath) : undefined;
  const cfg = <T>(key: string, envFallback: T): T => {
    const v = config?.get(key);
    return v !== undefined ? (v as T) : envFallback;
  };

  const piiWhitelist = cfg<string[]>(
    "pii_whitelist",
    (process.env["CELLO_GATEWAY_PII_WHITELIST"] ?? "").split(",").map((s) => s.trim()).filter(Boolean),
  );
  // autonomous_override defaults OFF — the agent's only autonomous lever over a PII warn is `redact`;
  // allowing a value out is a human action (loosening the store requires confirmation).
  const autonomousOverride = cfg<boolean>("autonomous_override", process.env["CELLO_GATEWAY_AUTONOMOUS_OVERRIDE"] === "1");
  // OUT-004 per-agent outbound rate cap. A positive cap enables it. NOTE: "no cap" is the LOOSEST state,
  // not the tightest — so rate-limiting is OFF by default (the operator opts in to a cap). If a cap IS
  // set but the window is missing/invalid, do NOT silently disable the cap (code-review M1) — fall back
  // to a sane default window so a configured limit is never lost.
  const DEFAULT_RATE_WINDOW_MS = 60_000;
  const rateMax = Number(cfg<number>("rate_max_per_window", Number(process.env["CELLO_GATEWAY_RATE_MAX_PER_WINDOW"])));
  const rawWindow = Number(cfg<number>("rate_window_ms", Number(process.env["CELLO_GATEWAY_RATE_WINDOW_MS"])));
  const rateWindowMs = Number.isFinite(rawWindow) && rawWindow > 0 ? rawWindow : DEFAULT_RATE_WINDOW_MS;
  const rateLimit = Number.isFinite(rateMax) && rateMax > 0
    ? { maxPerWindow: rateMax, windowMs: rateWindowMs }
    : undefined;
  const outbound = new OutboundScreener({ piiWhitelist, autonomousOverride, ...(rateLimit ? { rateLimit } : {}) });
  const inbound = new InboundScreener();

  // M9-REC-001 (INV-4): the gateway records what it did to EVERY message in its own local store,
  // hash-chained for tamper-evidence. Enabled when CELLO_GATEWAY_RECORD_DB is set. The verdict's
  // disposition maps to the record: allow → clean (a clean pass IS recorded — an absent record is
  // itself evidence of suppression), redact/block/warn verbatim.
  const recordDbPath = process.env["CELLO_GATEWAY_RECORD_DB"];
  const records = recordDbPath ? new GatewayRecordStore(recordDbPath) : undefined;
  const recordOutcome = (direction: "inbound" | "outbound", v: ScreenVerdict, content: Uint8Array, correlationId?: string): void => {
    if (!records) return;
    const disposition: RecordDisposition = v.disposition === "allow" ? "clean" : v.disposition;
    // A clean pass has no driving reason. For block/redact/warn the top-level reason wins, else the
    // category of the event that drove the disposition — the two disposition enums (ScreenDisposition /
    // GovernanceDisposition) share spelling for block/redact/warn, so this match is exact for those.
    const reason = disposition === "clean"
      ? undefined
      : v.reason ?? v.events?.find((e) => e.disposition === v.disposition)?.category ?? v.events?.[0]?.category;
    records.record({
      direction,
      disposition,
      contentHash: createHash("sha256").update(content).digest("hex"),
      ...(reason !== undefined ? { reason } : {}),
      ...(correlationId !== undefined ? { correlationId } : {}), // INV-7: bind the flow id into the record (code-review HIGH)
    });
  };
  /** Best-effort record on the error path — a record-write failure must not mask the screen_error block. */
  const recordOutcomeBestEffort = (direction: "inbound" | "outbound", v: ScreenVerdict, content: Uint8Array, correlationId?: string): void => {
    try { recordOutcome(direction, v, content, correlationId); }
    catch (err) { process.stderr.write(`cello-gateway: record write failed on screen_error: ${err instanceof Error ? err.message : String(err)}\n`); }
  };

  const handle = await createGatewayServer({
    socketPath,
    ...(requestLogPath ? { requestLogPath } : {}),
    screen: async (req): Promise<ScreenVerdict> => {
      // Catch a screener fault HERE (not in the server's outer catch) so the screen_error block is
      // RECORDED — otherwise a screened-and-blocked message would leave no audit row (code-review MED).
      try {
        if (req.direction === "outbound") {
          const v = outbound.screen(req.content, {
            agentName: req.agentName,
            sessionId: req.sessionId,
            ...(req.governanceDecisions !== undefined ? { governanceDecisions: req.governanceDecisions } : {}),
          });
          const verdict: ScreenVerdict = {
            disposition: v.disposition,
            content: v.content,
            events: v.events,
            ...(v.reason !== undefined ? { reason: v.reason } : {}),
            ...(v.guidance !== undefined ? { guidance: v.guidance } : {}),
          };
          recordOutcome("outbound", verdict, req.content, req.correlationId);
          return verdict;
        }
        const v = await inbound.screen(req.content);
        // On a block, nothing is delivered — omit the (original) content so a block doesn't ship the
        // whole payload back over the socket (the daemon uses its own content hash). Only allow/redact
        // carry content (redact's sanitized bytes; allow is reconstructed from the original by the client).
        const verdict: ScreenVerdict = {
          disposition: v.disposition,
          ...(v.disposition !== "block" ? { content: v.content } : {}),
          events: v.events,
          ...(v.terminal !== undefined ? { terminal: v.terminal } : {}),
          ...(v.reason !== undefined ? { reason: v.reason } : {}),
          ...(v.guidance !== undefined ? { guidance: v.guidance } : {}),
        };
        recordOutcome("inbound", verdict, req.content, req.correlationId);
        return verdict;
      } catch (err) {
        // A screener fault (or a record-write throw above) → fail-closed screen_error, recorded so the
        // blocked message still leaves an audit row. The record is best-effort: a persistent DB failure
        // still returns the block (fail-closed), logged, never silently swallowed.
        process.stderr.write(`cello-gateway: screen error (${req.direction}): ${err instanceof Error ? err.message : String(err)}\n`);
        const verdict: ScreenVerdict = {
          disposition: "block",
          reason: "screen_error",
          guidance: "The security gateway hit an internal error while screening this message. " +
            "Nothing was delivered or sent. Check the gateway logs.",
        };
        recordOutcomeBestEffort(req.direction, verdict, req.content, req.correlationId);
        return verdict;
      }
    },
  });

  // Signal readiness to the parent (spawnGatewaySidecar waits for this).
  process.stdout.write(`${GATEWAY_READY_TOKEN} ${socketPath} regex-engine=${engine}\n`);

  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    void handle.stop().then(() => {
      config?.close();
      records?.close();
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
