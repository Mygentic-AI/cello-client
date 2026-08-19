#!/usr/bin/env node
/**
 * cello-gateway — the gateway program entry point.
 *
 * Reads its socket path and store paths from the environment, starts the
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
import { stderrStoreEventSink } from "../store/encrypted-db.js";
import { GatewayRecordStore, type RecordDisposition } from "../records/record-store.js";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { InjectionScanner } from "../detect/injection-scanner.js";
import { loadInjectionClassifier } from "../detect/injection-classifier-onnx.js";
import type { ScreenVerdict } from "../types.js";

/**
 * Fold the WAL into the main database without CLOSING the connection.
 *
 * `PRAGMA wal_checkpoint(TRUNCATE)` writes committed frames back into `gateway.db` and empties the
 * log. Unlike `close()`, it does not unlink `-wal`/`-shm` out from under the daemon's long-lived
 * handles — which is the whole point (review F1/F2). Best-effort by design: a failed checkpoint
 * loses nothing, because the records are already committed and the next reader recovers the WAL.
 */
function checkpointStore(...stores: Array<{ checkpoint?: () => void } | undefined>): void {
  for (const s of stores) {
    try { s?.checkpoint?.(); }
    catch (err) { process.stderr.write(`cello-gateway: checkpoint failed: ${err instanceof Error ? err.message : String(err)}\n`); }
  }
}

async function main(): Promise<void> {
  const socketPath = process.env["CELLO_GATEWAY_SOCKET"];
  if (!socketPath) {
    process.stderr.write("cello-gateway: CELLO_GATEWAY_SOCKET is required\n");
    process.exit(2);
    return;
  }

  // The real screen compositions. Config (PII whitelist, rate limit) is M9-CFG-001; defaults here
  // (no whitelist, no rate cap) until that lands. Secret detection (M9-OUT-001) slots into the
  // outbound screener once its RE2/gitleaks binding is chosen.
  // Resolve the RE2 engine (native preferred, WASM fallback) and compile the injection-pattern set
  // BEFORE accepting traffic — so the ReDoS-safe Step-9 scan is live from the first message.
  const engine = await initLinearRegex();
  compileInjectionPatterns();
  compileSecretRules();

  // DOD-M9B-STORE-1 (M9B-D9): ONE encrypted store file holds both the config versions and the
  // security records, keyed by the daemon's key file — the daemon's spawn plumbing passes the two
  // paths (M9B-D8: a key FILE path, never key bytes). Both stores fail closed: a missing or wrong
  // key throws GatewayStoreError, which exits the process rather than screening unconfigured.
  // `|| undefined` so the guard below and the two call sites read the SAME value. Testing
  // `=== undefined` here while the call sites test truthiness let CELLO_GATEWAY_STORE_DB="" pass
  // the guard and then silently produce NO stores — screening every message with no audit trail
  // and no config governance, while printing READY as if healthy. An empty string is exactly what
  // a path computation that returned nothing interpolates to.
  const storeDbPath = process.env["CELLO_GATEWAY_STORE_DB"] || undefined;
  const storeKeyFile = process.env["CELLO_GATEWAY_STORE_KEY_FILE"] || undefined;
  if ((storeDbPath === undefined) !== (storeKeyFile === undefined)) {
    // Half-configured storage is a plumbing bug, not a degraded mode to run through: it would
    // silently drop either the operator's config or the whole audit trail.
    process.stderr.write("cello-gateway: CELLO_GATEWAY_STORE_DB and CELLO_GATEWAY_STORE_KEY_FILE must be set together\n");
    process.exit(2);
    return;
  }

  // M9-CFG-001 (INV-4) + DOD-M9B-ENV-1 (policy D-5): the gateway owns its config, and the STORE IS
  // THE ONLY SOURCE. There is deliberately no environment fallback for any policy value.
  //
  // There used to be four: CELLO_GATEWAY_AUTONOMOUS_OVERRIDE, _PII_WHITELIST,
  // _RATE_MAX_PER_WINDOW and _RATE_WINDOW_MS sat UNDER the store as defaults. Each one could loosen
  // a guard with no confirmation, no versioned row, and no hash-chained fingerprint — the entire
  // tighten-free / loosen-confirmed mechanism bypassed by anyone who could set a variable. A gate
  // with a published bypass is not a gate. They are gone; `cello config set` is the way in, and it
  // asks a human before it weakens anything.
  //
  // Each key still falls back to its TIGHTEST value when the store has not set it (empty whitelist,
  // override off, no rate cap), so an absent or empty config never silently loosens.
  const config = storeDbPath && storeKeyFile ? new GatewayConfigStore(storeDbPath, storeKeyFile, stderrStoreEventSink) : undefined;
  const cfg = <T>(key: string, tightestDefault: T): T => {
    const v = config?.get(key);
    return v !== undefined ? (v as T) : tightestDefault;
  };

  const piiWhitelist = cfg<string[]>("pii_whitelist", []);
  // autonomous_override defaults OFF — the agent's only autonomous lever over a PII warn is `redact`;
  // allowing a value out is a human action (loosening the store requires confirmation).
  const autonomousOverride = cfg<boolean>("autonomous_override", false);
  // OUT-004 per-agent outbound rate cap. A positive cap enables it. NOTE: "no cap" is the LOOSEST state,
  // not the tightest — so rate-limiting is OFF by default (the operator opts in to a cap). If a cap IS
  // set but the window is missing/invalid, do NOT silently disable the cap (code-review M1) — fall back
  // to a sane default window so a configured limit is never lost.
  const DEFAULT_RATE_WINDOW_MS = 60_000;
  const rateMax = Number(cfg<number>("rate_max_per_window", 0));
  const rawWindow = Number(cfg<number>("rate_window_ms", DEFAULT_RATE_WINDOW_MS));
  const rateWindowMs = Number.isFinite(rawWindow) && rawWindow > 0 ? rawWindow : DEFAULT_RATE_WINDOW_MS;
  const rateLimit = Number.isFinite(rateMax) && rateMax > 0
    ? { maxPerWindow: rateMax, windowMs: rateWindowMs }
    : undefined;
  const outbound = new OutboundScreener({ piiWhitelist, autonomousOverride, ...(rateLimit ? { rateLimit } : {}) });
  // DOD-DOC-SCREEN-CLASSIFIER-1 — Layer 2, wired at last.
  //
  // This line was `new InboundScreener()` with no arguments, so the scanner fell back to its null
  // classifier, reported itself unavailable, and the semantic check short-circuited on every
  // inbound frame in every shipped build — while the gateway announced mode `enforcing`. Layer 1
  // (the deterministic sanitizer) and Layer 3 (the pattern matcher) were live throughout; the layer
  // that judges MEANING was not, and nothing said so.
  //
  // The state is ANNOUNCED either way, on stderr, at startup. "Is semantic screening on?" must be
  // answerable by reading a log line rather than by reading this file — that is the whole reason
  // the gap survived as long as it did.
  const modelDir = process.env["CELLO_GATEWAY_MODEL_DIR"] || join(homedir(), ".cello", "gateway-model");
  const load = await loadInjectionClassifier(modelDir);
  // ON STDOUT, and specifically on the line the PARENT reads. Written to stderr this was drained
  // into an in-memory tail that the spawner only ever surfaces when the spawn FAILS — so on a
  // successful boot the answer to "is semantic screening on?" was captured and thrown away. That is
  // the exact shape of the defect this whole unit exists to fix: a state nothing can report.
  const layer2 = load.classifier ? "active" : `off:${load.reason ?? "unknown"}`;
  const inbound = new InboundScreener(
    load.classifier ? { injectionScanner: new InjectionScanner(load.classifier) } : {},
  );

  // M9-REC-001 (INV-4): the gateway records what it did to EVERY message, hash-chained for
  // tamper-evidence, in the same encrypted store as the config (M9B-D9). The verdict's disposition
  // maps to the record: allow → clean (a clean pass IS recorded — an absent record is itself
  // evidence of suppression), redact/block/warn verbatim.
  const records = storeDbPath && storeKeyFile ? new GatewayRecordStore(storeDbPath, storeKeyFile, stderrStoreEventSink) : undefined;
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
  const bootCorrelationId = process.env.CELLO_GATEWAY_CORRELATION_ID;
  if (bootCorrelationId) {
    // The restarted sidecar names the flow that restarted it (review M2). The commit that claimed
    // "plus the restarted sidecar's own boot lines" shipped without this, which is why the claim
    // was false — the id reached `applied` and stopped there.
    process.stderr.write(`${JSON.stringify({ level: "info", event: "gateway.boot", correlationId: bootCorrelationId, socketPath })}\n`);
  }
  process.stdout.write(`${GATEWAY_READY_TOKEN} ${socketPath} regex-engine=${engine} layer2=${layer2.replace(/\s+/g, " ")}\n`);

  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    void handle.stop().then(() => {
      // DO NOT close() these.
      //
      // CORRECTED 2026-07-30 (review M1). This comment used to assert, as reproduced fact, that
      // "ANY connection's close unlinks `-wal`/`-shm` — not just the last one." That is WRONG, and
      // measuring it takes one script: with a second connection open, a close leaves `-wal`/`-shm`
      // in place, the holder's later writes succeed, and a fresh reader sees them. It is the LAST
      // closer that checkpoints and unlinks — ordinary SQLite behaviour.
      //
      // The conclusion does not change, and the real reason is sharper than the wrong one:
      // `restartSecurityGateway` SIGTERMs this process on every successful `cello config set`, so
      // during that window this sidecar is DEAD and a per-call daemon handle is the last one open.
      // That is how the live defect happened — `cello policy log` under-reporting for the rest of
      // that daemon's life while still reporting chainValid:true, and the next write through the
      // stale handle returning ok on a SQLITE_CORRUPT store.
      //
      // Checkpoint instead, and never be in the business of guessing who is last.
      //
      // Checkpoint instead: fold the WAL into the main file so nothing is lost, and let process
      // exit release the descriptors. Exit unlinks nothing that another process is still using.
      checkpointStore(config, records);
      process.stderr.write(`cello-gateway: stopped (${signal})\n`);
      process.exit(0);
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  // PARENT DEATH SWITCH (review F5). The daemon spawns this process with a piped stdin and never
  // writes to it; when the daemon dies — including the ways that skip its shutdown path entirely,
  // SIGKILL and crashes — the kernel closes the pipe and this fires. Without it the gateway
  // outlives its daemon holding the store's write lock, and the next daemon comes up permanently
  // fail-closed against a lock nobody can explain.
  process.stdin.on("end", () => shutdown("parent_exited"));
  process.stdin.on("close", () => shutdown("parent_exited"));
  process.stdin.resume();
}

main().catch((err: unknown) => {
  // Print the CODE and the GUIDANCE, not just the message. The guidance is the only part that
  // tells the operator what to do, and dropping it was how "your key file is missing" reached
  // them as "sidecar exited before ready (code 1)".
  const code = (err as { code?: string } | null)?.code;
  const guidance = (err as { guidance?: string } | null)?.guidance;
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`cello-gateway: fatal${code ? ` [${code}]` : ""} ${message}\n`);
  if (guidance) process.stderr.write(`cello-gateway: ${guidance}\n`);
  process.exit(1);
});
