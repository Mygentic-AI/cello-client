#!/usr/bin/env node
/**
 * cello-daemon — the long-running CELLO daemon process.
 *
 * This binary is spawned by `cello login` as a detached background process.
 * It manages agent identities, IPC connections, and (future) directory signaling.
 *
 * Environment variables:
 *   CELLO_DIR       Override ~/.cello directory (default: ~/.cello)
 *   CELLO_VERSION   Version string for lock file (default: from package.json)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";
import { LocalSidecarGatewayClient, spawnGatewaySidecar, type SpawnedGateway } from "@cello-protocol/gateway";
import { startDaemon } from "../daemon.js";
import { resolveDbKey, dbKeyPathFor } from "../sqlcipher-db.js";
import { createDirectoryEndpointResolver } from "../directory-bootstrap.js";
import { buildManifestDeps } from "../manifest-deps.js";
import { RandomizedPollScheduler } from "../manifest-poll-scheduler.js";
// EXIT_ALREADY_RUNNING is distinct from 1 (generic startup failure) so a caller can tell "lost the
// race" from "broken" — connectOrStart relies on exactly that distinction, so the constant is shared
// rather than written down twice.
import { DaemonAlreadyRunningError, EXIT_ALREADY_RUNNING } from "../singleton-lock.js";
import type { Logger } from "../types.js";

const MAX_CONNECTIONS = 16;

// DOD-REGISTRY-1: build-time-pinned registry signer pubkey. The daemon polls GET /registry
// on the directory and verifies the inner Ed25519 signature against this key. A registry
// update requires NO release (INV-ZERO-BUMP) — but the daemon must trust THIS key to accept it.
const REGISTRY_SIGNER_PUBKEY = "d4f9a531205a3aca23dede0ad5f4fb6cd42260c8bbae5f33d2866c39e870d586";
const REGISTRY_POLL_MIN_MS = 5 * 60_000;  // 5 minutes
const REGISTRY_POLL_MAX_MS = 15 * 60_000; // 15 minutes

// Composition root: stdout JSON logger
const logger: Logger = {
  debug(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "debug", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
  info(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "info", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
  warn(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "warn", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
  error(event: string, context: Record<string, unknown>): void {
    const line = JSON.stringify({ level: "error", event, ...context, ts: new Date().toISOString() });
    process.stdout.write(line + "\n");
  },
};

const celloDir = process.env.CELLO_DIR || join(homedir(), ".cello");
const socketPath = join(celloDir, "daemon.sock");
const lockFilePath = join(celloDir, "daemon.lock");
const version = process.env.CELLO_VERSION || "0.0.1";

/**
 * Bring up the security and governance layer (DOD-M9B-WIRE-1, policy D-2).
 *
 * THE DEFECT THIS EXISTS TO CLOSE: this function did not exist. `startDaemon` was called without a
 * gateway, fell back to an always-allow stub, and every shipped daemon screened nothing while
 * logging `security.gateway.connected`. The layer was fully built, unit-green and gate-green the
 * whole time — the gate injected the client the product never did.
 *
 * Fail-closed, never passthrough (M9B-D12): if the sidecar cannot be spawned, the client is STILL
 * the enforcing one. It fails closed on every call (`gateway_unavailable`, INV-6), the failure is
 * announced, and the daemon stays up so the operator can run `cello config` / `cello policy log`
 * against it and find out why. A dead agent with a cryptic startup error diagnoses nothing, and a
 * silent downgrade to passthrough is the original bug wearing a hat.
 */
async function startSecurityLayer(correlationId?: string): Promise<{ client: LocalSidecarGatewayClient; sidecar: SpawnedGateway | undefined }> {
  const socketPath = join(celloDir, "gateway.sock");
  const client = new LocalSidecarGatewayClient({ socketPath, logger });

  // The sidecar opens the encrypted store at startup, but the key file is only created when the
  // daemon first opens its own database — which happens AFTER this. So resolve it here (M9B-D13):
  // the same idempotent call the daemon makes, which on a fresh install is the one that generates
  // the key. The bytes are deliberately unused; only the side effect matters, and the key never
  // travels to the child — the child gets the PATH (M9B-D8).
  const keyFilePath = dbKeyPathFor(join(celloDir, "sessions.db"));
  let sidecar: SpawnedGateway | undefined;
  try {
    mkdirSync(celloDir, { recursive: true, mode: 0o700 });
    resolveDbKey(join(celloDir, "sessions.db"), keyFilePath);
    sidecar = await spawnGatewaySidecar({
      socketPath,
      env: {
        CELLO_GATEWAY_STORE_DB: join(celloDir, "gateway.db"),
        CELLO_GATEWAY_STORE_KEY_FILE: keyFilePath,
        // Review M2: the child's own boot lines join the flow that RESTARTED it. Without this the
        // operator sees `gateway.config.applied{correlationId}` and, on the next line, a sidecar
        // that failed to open its store with no way to tie the two together — which is the exact
        // correlation the config surface exists to provide.
        ...(correlationId !== undefined ? { CELLO_GATEWAY_CORRELATION_ID: correlationId } : {}),
      },
    });
    logger.info("security.gateway.spawned", { pid: sidecar.pid ?? -1, socketPath, ...(correlationId !== undefined ? { correlationId } : {}) });
    // WHETHER THE SEMANTIC LAYER IS RUNNING, in the daemon log, at every boot.
    //
    // `mode: "enforcing"` on the next line says the gateway is REACHABLE, not that it judges
    // meaning — and for every shipped build before daemon 0.0.181 it judged none, while reporting
    // exactly that. This is the line that makes the difference legible, and `off:` carries the
    // reason so the answer to "why" is in the same place as the answer to "whether".
    logger.info("security.gateway.layer2", {
      state: sidecar.layer2,
      ...(correlationId !== undefined ? { correlationId } : {}),
    });
    sidecar.process.once("exit", (code, signal) => {
      // No auto-restart (M9B-D14). Every subsequent screen fails closed with a real cause; this
      // line is how the operator learns the screening process died rather than inferring it from
      // a wall of blocked sends.
      logger.error("security.gateway.exited", { code: code ?? -1, signal: signal ?? "none", ...(correlationId !== undefined ? { correlationId } : {}) });
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // The gateway's own errors carry a code and actionable guidance; the spawner appends the
    // child's stderr tail. Keep BOTH, and hand them to the client so every later refusal names
    // this cause instead of the generic "could not be reached, retry" (review F2) — which points
    // at the transport when the fault was a key file, a lock, or a stale plaintext store, and
    // suggests a retry that can never succeed.
    const code = (err as { code?: string } | null)?.code ?? "sidecar_spawn_failed";
    const guidance = (err as { guidance?: string } | null)?.guidance
      ?? "The security layer could not start, so nothing can be sent or received: every message " +
         "fails closed. Fix the cause below and restart the daemon.";
    logger.error("security.gateway.spawn_failed", { reason: code, error: message, guidance, ...(correlationId !== undefined ? { correlationId } : {}) });
    client.setUnavailableCause(code, `${guidance} (cause: ${message})`);
  }
  return { client, sidecar };
}

/**
 * Stop the screening sidecar. Idempotent, and safe to call when the spawn failed.
 *
 * An orphaned gateway holds the encrypted store's write lock against the NEXT daemon, and its
 * stdio pipes keep this process's event loop alive — so a daemon stopped over IPC would never
 * actually exit. Both are why this is wired into the daemon's own stop() rather than only into
 * the signal handler.
 */
let securityLayer: { client: LocalSidecarGatewayClient; sidecar: SpawnedGateway | undefined } | undefined;
async function stopSecurityLayer(): Promise<void> {
  if (!securityLayer) return;
  await securityLayer.client.close();
  if (securityLayer.sidecar) {
    await securityLayer.sidecar.stop();
    logger.info("security.gateway.stopped", {});
  }
}

async function main(): Promise<void> {
  // M7 Keystone (Part 1): give the daemon its door to the directory. The resolver
  // discovers the directory endpoint via GET ${CELLO_DIRECTORY_URL}/bootstrap (the
  // proven M6 path); startDaemon builds the real signalingConnect from it + the
  // primary agent identity.
  // FINDING-4: this resolver is wrapped by the daemon's roster-aware failover resolver, which owns
  // ALL fallback semantics (roster + sticky). staleFallback:false makes it report a dead primary as
  // null on a fresh /bootstrap failure — WITHOUT it, the wrapper would keep receiving the stale dead
  // endpoint and never fail over (the exact live kill-primary bug). The roster is the real fallback.
  const directoryEndpointResolver = createDirectoryEndpointResolver({ logger, staleFallback: false });

  // M7 J-AUTH (DOD-AUTH-1/2) + FINDING-4: consortium-manifest deps. buildManifestDeps chooses:
  //   - DEFAULT (no CELLO_CONSORTIUM_MANIFEST) — load the COMPILED-IN production roster + step-6
  //     directory identity auth, so a cold-boot daemon knows every directory and can fail over to a
  //     reachable one (redundancy invariant). Gated on CELLO_DIRECTORY_URL actually being a bundled
  //     node — a daemon pointed at a local/non-bundled directory (local dev, e2e spine harness) gets
  //     the M6 backward-compat path (no roster, no step-6) instead of wrongly failing step-6.
  //   - OVERRIDE (CELLO_CONSORTIUM_MANIFEST set) — operator-supplied manifest FILE + env root keys /
  //     threshold + optional /manifest poll (the pre-FINDING-4 opt-in path).
  // When a manifest is active, the daemon verifies the directory's step-6 identity proof against the
  // node pubkeys in it. Both dialers (keystone + per-agent) receive the verifier via startDaemon.
  const manifest = buildManifestDeps(logger);

  // D-2: the security and governance layer runs ENFORCING in the shipped daemon. This is the line
  // whose absence made every guard M9 built inert.
  const security: { client: LocalSidecarGatewayClient; sidecar: SpawnedGateway | undefined } =
    await startSecurityLayer();
  securityLayer = security;

  /**
   * Restart the sidecar so a stored config change takes effect (M9B-D17). The gateway reads its
   * config only at boot, so without this a confirmed loosening is recorded and does nothing.
   * The socket path is unchanged and `LocalSidecarGatewayClient` reconnects lazily, so the client
   * needs no involvement. A failure PROPAGATES — the caller reports stored-but-not-applied rather
   * than telling the operator a guard changed when it did not.
   */
  const restartSecurityGateway = async (correlationId?: string): Promise<void> => {
    if (security.sidecar) await security.sidecar.stop();
    const restarted = await startSecurityLayer(correlationId);
    security.sidecar = restarted.sidecar;
    if (!restarted.sidecar) throw new Error("the screening process did not come back up");
  };

  /**
   * ⚠️ THE SIGNAL HANDLERS ARE REGISTERED BEFORE `startDaemon` IS AWAITED, AND THE ORDER IS THE BUG.
   *
   * `daemon.started` is logged INSIDE `startDaemon` (`daemon.ts`), and the handlers used to be
   * registered ~50 lines BELOW the `await` that resolves it. So between the daemon announcing it had
   * started and it being able to handle a shutdown, there was a window in which **SIGTERM's default
   * action kills the process** — no handler, no `handle.stop()`, no `UPDATE sessions SET status =
   * 'interrupted'`. The daemon dies claiming nothing and every active session stays `active`.
   *
   * ⚠️ THIS IS A PRODUCTION DEFECT, NOT A TEST ARTIFACT, and it is worth being explicit because it
   * was found through a test. Anything that starts the daemon and stops it promptly — `systemctl
   * stop` on a slow boot, a supervisor restarting a flapping unit, an operator hitting Ctrl-C
   * because startup looked stuck — lands in that window. The sessions are then indistinguishable
   * from ones abandoned mid-conversation, which is the state `interrupted` exists to prevent.
   *
   * HOW IT WAS FOUND, because the route matters: `AC-009` failed twice in CI, passed locally twice,
   * and its message could not say why. Instrumenting both sides — `rowsMarkedInterrupted` on the
   * daemon, and refusing to treat `code === null` as a clean exit in the test — produced, on the
   * very next run: *"Daemon was KILLED by SIGTERM rather than exiting — the SIGTERM handler never
   * ran."* Not a WAL snapshot race, which is what it had been attributed to and "fixed" as once.
   *
   * A signal arriving during startup now WAITS for startup to finish and then shuts down properly,
   * rather than being dropped. The alternative — exiting immediately — would be the same data loss
   * with a tidier exit code.
   */
  let handle: Awaited<ReturnType<typeof startDaemon>> | null = null;
  let startupFailed = false;

  const shutdown = async (signal: string): Promise<void> => {
    if (!handle) {
      // The signal beat startup. Wait for it rather than dying with sessions still marked active —
      // this is the window that produced the defect above.
      logger.info("daemon.shutdown.awaiting_startup", {
        signal,
        impact: "the signal arrived before startup finished. Waiting for it so sessions are marked interrupted rather than left active by a daemon that died before it could handle a shutdown.",
      });
      const deadline = Date.now() + 30_000;
      while (!handle && !startupFailed && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      if (!handle) {
        logger.error("daemon.shutdown.startup_never_completed", {
          signal,
          startupFailed,
          impact: "the daemon is exiting without marking any session interrupted, because startup never produced a handle to stop. Sessions left 'active' in the database were not touched by this process.",
          guidance: "Check the lines above for why startup did not complete — a singleton-lock loss, a security-gateway failure, or a manifest refusal all land here.",
        });
        process.exit(1);
      }
    }
    // handle.stop() runs onShutdown (stopSecurityLayer) for us — the teardown lives there so that
    // `cello logout`, which stops the daemon over IPC and never reaches this handler, tears the
    // sidecar down too.
    //
    // DOD-LOGOUT-EXIT-1: stop()'s onStopped hook exits, so this await does not return while the
    // hook is wired below — the line after is unreachable in the shipped binary. It is kept so that
    // removing the hook cannot silently produce a signal path that never exits, which is the state
    // the IPC path was in before this unit.
    await handle.stop(signal);
    process.exit(0);
  };

  const onSignal = (signal: "SIGTERM" | "SIGINT") => () => {
    try {
      shutdown(signal).catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          signal,
          error: err instanceof Error ? err.message : String(err),
        });
        process.exit(1);
      });
    } catch (err: unknown) {
      logger.error("daemon.shutdown.failed", {
        signal,
        error: err instanceof Error ? err.message : String(err),
      });
      process.exit(1);
    }
  };
  process.on("SIGTERM", onSignal("SIGTERM"));
  process.on("SIGINT", onSignal("SIGINT"));

  handle = await startDaemon({
    celloDir,
    socketPath,
    lockFilePath,
    maxConnections: MAX_CONNECTIONS,
    version,
    logger,
    directoryEndpointResolver,
    ...manifest,
    securityGateway: security.client,
    restartSecurityGateway,
    onShutdown: stopSecurityLayer,
    // DOD-LOGOUT-EXIT-1: THIS is what makes `cello logout` honest. The IPC `shutdown` verb never
    // reaches the signal handlers below, so before this line the logout path had nothing that
    // ended the process — it released the socket, the lock file and the singleton lock (the exact
    // two facts logout consults to decide the daemon is gone) and then kept running, still
    // connected to a directory node. This is the only place that may exit: the daemon module is
    // also used in-process by tests and embedders, where exiting would kill the host.
    //
    // The log line is not decoration — it is the evidence that the exit was DELIBERATE. Without it
    // a daemon whose event loop merely happened to drain is indistinguishable from one that was
    // told to stop, and this wiring could be deleted without any test noticing.
    onStopped: ({ ok, error }) => {
      // A dirty stop still ENDS — a half-stopped daemon may not keep talking to a directory — but
      // it exits non-zero and says why. Exiting 0 for both would let `cello logout` print
      // "Daemon stopped." over a shutdown that never marked its sessions interrupted.
      logger.info("daemon.exit", { pid: process.pid, ok, ...(error ? { error: error.message } : {}) });
      // stdout is a PIPE here (the daemon is spawned detached with piped stdio) and pipe writes are
      // asynchronous, so `process.exit` can truncate the line above — including the one case where
      // it matters most, the `ok:false` cause. Yield one turn so the write drains first.
      setImmediate(() => process.exit(ok ? 0 : 1));
    },
    registryPubkey: REGISTRY_SIGNER_PUBKEY,
    registryPollScheduler: new RandomizedPollScheduler({ minMs: REGISTRY_POLL_MIN_MS, maxMs: REGISTRY_POLL_MAX_MS }),
  });

}

main().catch((err: unknown) => {
  // DOD-SINGLE-DAEMON-1 (AC2): losing the singleton race is not a crash — it is the system working.
  // Say so in one plain line an operator can act on, name the pid that holds the lock, and exit
  // non-zero without a stack trace. Two daemons is the silent, wrong outcome; this is the loud, right
  // one.
  if (err instanceof DaemonAlreadyRunningError) {
    logger.info("daemon.start.refused", { reason: "already_running", holderPid: err.holderPid });
    process.stderr.write(`${err.message}\n`);
    process.exit(EXIT_ALREADY_RUNNING);
  }
  logger.error("daemon.startup.failed", {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
