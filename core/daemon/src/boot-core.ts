/**
 * Phase 1 of boot: everything the daemon needs before it knows which agents exist.
 *
 * The transport selector, the security gateway, the session manager and its encrypted database, the
 * consortium manifest gate, the roster sweep and the type registry. Three inputs — the config, the
 * resolved directory URL, a logger — and everything below comes out. That asymmetry is what a boot
 * phase looks like: it takes almost nothing and produces almost everything, which is exactly why
 * leaving it inline made the composition root look like it had a hundred dependencies.
 *
 * ⚠️ `lastRosterSweepError` IS RETURNED AS A READER, NOT A VALUE, AND THAT IS NOT STYLE. The sweep's
 * own callbacks write it long after this phase returns, and `cello status` reads it later still. By
 * value the caller would hold the snapshot taken at boot — permanently `undefined` — and the status
 * block would report a healthy roster through every sweep failure. Same defect unit 4 shipped for
 * the document reconcile scheduler: silent, type-legal, invisible to a green suite.
 */
import { mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { acquireLock, removeLockIfOwned } from "./lock-file.js";
import { directoryAuthRequired } from "./directory-auth-posture.js";
import { ProductionSessionNodeFactory } from "./session-node-factory.js";
import { RandomizedPollScheduler } from "./manifest-poll-scheduler.js";
import { startRosterSweep, ROSTER_SWEEP_INTERVAL_MS } from "./roster-freshness.js";
import type { SecurityGatewayClient } from "@cello-protocol/gateway";
import { resolveCelloEnv, createTransportSelector, isProductionVariant } from "./transport-composition.js";
import { SessionNodeManager } from "./session-node-manager.js";
import { DbManifestVersionStore } from "./manifest-version-store-db.js";
import { verifyStartupManifest, createConsortiumRouting } from "./consortium-bootstrap.js";
import { startManifestValidityWatch, type ManifestOrigin } from "./manifest-validity.js";
import { resolveDirectoryUrl } from "./directory-bootstrap.js";
import type { RosterFreshness } from "./roster-freshness.js";
import type { IManifestVersionStore } from "@cello-protocol/transport";
import type { DaemonConfig, Logger } from "./types.js";

export interface BootCoreDeps {
  config: DaemonConfig;
  logger: Logger;
  /** The configured directory URL, or undefined when nothing was configured. */
  directoryHttpUrl: string | undefined;
}

export async function startBootCore(deps: BootCoreDeps) {
  const { config, logger, directoryHttpUrl } = deps;
  // The same fields the composition root destructures, named here rather than threaded one by one:
  // this phase reads config, and a nine-argument dependency list would be the root with an extra hop.
  const {
    celloDir, socketPath, lockFilePath,
    manifestProvider, manifestRootKeys, manifestThreshold,
    manifestVersionStore: injectedManifestVersionStore, manifestPollScheduler,
    challengeVerifier, sessionNodeFactory, directoryEndpointResolver, version,
  } = config;

  // CELLO-M7-TRANSPORT-001: composition-root selection of the transport selector.
  // Driven by CELLO_ENV; fails fast at startup (here, not at first session) when a
  // production environment is missing the required transport dialer (AC-010).
  const celloEnv = resolveCelloEnv(process.env["CELLO_ENV"]);
  const transportSelector = createTransportSelector({
    env: celloEnv,
    logger,
    transportDialer: config.transportDialer,
  });
  logger.info("transport.adapters.wired", {
    env: celloEnv,
    selector: isProductionVariant(celloEnv) ? "real" : "stub",
  });

  // ADV-006 + ADV-008 (hoisted — code-review MED): pure config validation runs BEFORE any disk side
  // effect (lock, the irreversible one-time migration, DB open). A misconfigured daemon must fail
  // before mutating state. If manifestProvider is set, manifestRootKeys + a positive threshold are
  // required.
  if (manifestProvider && (!manifestRootKeys || !manifestThreshold || manifestThreshold <= 0)) {
    throw new Error(
      "DaemonConfig: manifestProvider requires manifestRootKeys (non-empty) and manifestThreshold (positive integer >= 1)",
    );
  }

  /**
   * DOD-M15-DIRAUTH-1 — an operator can DEMAND directory identity authentication.
   *
   * HERE, under the ADV-006/008 rule above, because this IS pure config validation: both operands
   * are already in hand and it touches nothing.
   *
   * Review F1 caught me putting it ninety lines lower, next to ADV-002, on the reasoning that it
   * "mirrors" it. It does not. ADV-002 sits down there because it MUST — it depends on
   * `verifyStartupManifest`, which depends on the anti-rollback floor in the DB. This depends on
   * nothing, and down there it ran AFTER: the irreversible flat-file → SQLCipher identity migration
   * (which renames and unlinks files), the creation of `sessions.db` and its key, and the sweep that
   * marks every `active` session `interrupted` with `interrupted_by='local'`.
   *
   * So a misconfigured daemon "failed to start" and changed the operator's record on the way out —
   * two live sessions permanently interrupted, attributed to a local cause, by a config check that
   * could have run before anything was touched.
   */
  if (directoryAuthRequired(process.env) && challengeVerifier === undefined) {
    const url = config.directoryHttpUrl ?? resolveDirectoryUrl(process.env);
    logger.error("directory.auth.required.unavailable", {
      directoryUrl: url,
      impact: "the daemon refused to start rather than connect without directory identity authentication.",
      guidance:
        "CELLO_REQUIRE_DIRECTORY_AUTH is set, but no challenge verifier could be built for this " +
        "directory URL. Point CELLO_DIRECTORY_URL at a bundled endpoint, or supply a manifest with " +
        "CELLO_CONSORTIUM_MANIFEST plus CELLO_CONSORTIUM_ROOT_KEYS and CELLO_CONSORTIUM_THRESHOLD " +
        "(all three are required together), or set CELLO_REQUIRE_DIRECTORY_AUTH to 0/false/no/off " +
        "to accept the risk.",
    });
    throw new Error(
      `CELLO_REQUIRE_DIRECTORY_AUTH is set, but directory identity authentication (step 6) cannot ` +
      `be enforced: no challenge verifier was supplied for this daemon. The directory URL is ` +
      `compared against the bundled consortium roster after NORMALISATION (trimmed, trailing slash ` +
      `dropped, lowercased) — so case and a trailing slash are forgiven, but a DNS hostname ` +
      `pointing at exactly the right machine is NOT, which is the usual cause. Either use a bundled ` +
      `endpoint address, or supply a manifest with CELLO_CONSORTIUM_MANIFEST plus ` +
      `CELLO_CONSORTIUM_ROOT_KEYS and CELLO_CONSORTIUM_THRESHOLD (all three are required together), ` +
      `or set CELLO_REQUIRE_DIRECTORY_AUTH to 0/false/no/off to start without step 6.`,
    );
  }

  // ── PERSIST-002: open the encrypted store FIRST (runs the one-time flat-file → SQLCipher migration
  // (AC-006) + creates the agents/manifest_state schema), under the single-instance lock. This must
  // precede the manifest verification below because the manifest version is now stored in the
  // encrypted DB (AC-008), not a manifest-version.json file. ──
  await mkdir(celloDir, { recursive: true });
  await mkdir(dirname(socketPath), { recursive: true });

  // DOD-SINGLE-DAEMON-1: the caller already took the kernel's exclusive lock (see startDaemon) —
  // BEFORE this function touches anything that assumes a single writer. A daemon that loses that race
  // never reaches here at all: it never opens the database, never registers an agent, never connects
  // to the directory. Two daemons sharing an identity is how a hash chain gets two leaves at the same
  // index, and the seal then attests to the damage.
  //
  // AC4: the advisory JSON keeps its metadata role (it is how the NEXT process learns our pid), but
  // the OS lock is what decides whether a daemon may run. This file never gates startup.
  await acquireLock(lockFilePath, { pid: process.pid, socketPath, version });

  // M9-CORE-001: one security-gateway client, shared by both seams — the outbound screen in
  // cello_send and the inbound screen inside SessionNodeManager. REQUIRED (INV-9): there is no
  // fallback, because the fallback WAS the bug — an always-allow default that nothing in the
  // product ever overrode.
  // The type says required, but tests are excluded from typecheck and JS callers exist, so the
  // absence has to be LOUD here rather than a TypeError three lines later that names the wrong
  // subsystem. A test that genuinely does not screen says so by passing the passthrough client.
  if (!config.securityGateway) {
    throw new Error(
      "startDaemon: securityGateway is required (INV-9). The daemon no longer defaults to " +
        "always-allow screening, because that default shipped a security layer that never ran. " +
        "Pass a LocalSidecarGatewayClient in production, or new PassthroughGatewayClient() if " +
        "this caller deliberately does not screen.",
    );
  }
  const securityGateway: SecurityGatewayClient = config.securityGateway;
  // Observability: announce the mode the CLIENT declares (M9B-D11), never a ternary over the
  // config. The sidecar socket connects lazily on the first screen, so this reports which adapter
  // is wired, not a live socket handshake — but it reports it from the object that will do the
  // screening, so a wiring mistake shows up here instead of hiding behind a correct-looking line.
  logger.info("security.gateway.connected", { mode: securityGateway.mode });

  const sessionNodeManager = new SessionNodeManager({
    factory: sessionNodeFactory ?? new ProductionSessionNodeFactory(logger),
    logger,
    dbPath: join(celloDir, "sessions.db"),
    contentTtfMs: config.contentTtfMs,
    autoNatProbers: () => [],
    securityGateway,
  });
  await sessionNodeManager.initialize();

  // AC-008: the manifest version store is DB-backed by default (encrypted manifest_state table). A
  // test may inject an override (e.g. InMemoryManifestVersionStore) via config.
  const manifestVersionStore: IManifestVersionStore =
    injectedManifestVersionStore ?? new DbManifestVersionStore(sessionNodeManager.getDb(), logger);

  // M7-MANIFEST-002: load and verify the consortium manifest BEFORE any directory connection.
  // The gate REPORTS; it does not decide (consortium-bootstrap.ts). The refuse below is ours
  // because only we hold the DB handle and the singleton lock a refusal has to release.
  const { manifestVerified, verifiedManifestVersion, verifiedManifest, unresolvedNodes: startupUnresolvedNodes, unresolvedSweptAt: startupSweptAt } = await verifyStartupManifest({
    manifestProvider,
    manifestRootKeys,
    manifestThreshold,
    manifestVersionStore,
    logger,
    // DOD-M15-STALEROSTER-1: the same injected fetch the sweep uses, so the startup probe and the
    // background probe are exercised through one seam rather than one being untestable.
    ...(config.fetchFn ? { fetchFn: config.fetchFn } : {}),
  });

  // ADV-002: an operator who configures manifestProvider has opted INTO manifest enforcement, so a
  // failed verification is fatal — never a warning we start anyway on.
  if (manifestProvider && !manifestVerified) {
    // This refuse runs AFTER the DB is open and the lock is held (the DB had to open for the
    // anti-rollback check), so release both before rethrowing — an in-process caller must not be
    // left holding the DB handle. (In production the process exits, but be tidy.)
    try { sessionNodeManager.getDb().close(); } catch { /* ignore */ }
    await removeLockIfOwned(lockFilePath, process.pid, logger).catch(() => { /* best-effort */ });
    // The singleton lock is released by startDaemon's catch — every throw out of this function goes
    // through it, so no failure path can leak the lock by forgetting.
    throw new Error(
      "Manifest verification failed. The daemon cannot start with an unverified manifest when manifestProvider is configured. " +
      "Check the logs for the specific failure reason (manifest_signature_invalid, manifest_expired, or manifest_version_rollback).",
    );
  }

  // The manifest poll starts only AFTER the refuse above — a refused startup must not leak a timer.
  const { resolveConsortiumRoster, failoverEndpointResolver, getFailoverEndpoint, getUnresolvedNodes, getUnresolvedSweptAt, getDeclaredNodeCount, stopHttpManifestPoll } =
    createConsortiumRouting({
      manifestProvider,
      manifestRootKeys,
      manifestThreshold,
      manifestVersionStore,
      manifestPollScheduler,
      directoryHttpUrl,
      directoryEndpointResolver,
      // Carry the boot sweep's findings into the operator surface. Without this the status block is
      // empty until a ceremony resolves a roster — i.e. empty exactly when someone whose sessions
      // are all failing goes looking for why.
      initialUnresolvedNodes: startupUnresolvedNodes,
      initialUnresolvedSweptAt: startupSweptAt,
      logger,
      ...(config.fetchFn ? { fetchFn: config.fetchFn } : {}),
    });

  /**
   * DOD-M15-STALEROSTER-1 — keep measuring directory reachability even when nothing is wrong.
   *
   * Every existing caller of the sweep is ACTIVITY-driven — ceremonies, session setup,
   * `cello_refresh`, the seal broker. So an IDLE daemon never re-measures, and sitting idle is what
   * a daemon does between conversations: the reading it was seeded with at boot is the reading it
   * still has an hour later. Measured twice, on two machines — node failures from minutes past
   * displayed while `curl` reached all three nodes in 37–184 ms.
   *
   * (An earlier version of this comment said the sweep had ONE caller, the failover path, and that
   * recovering was what stopped the measurement. That was wrong — there are ten — and it is
   * corrected here rather than deleted because believing it is why the concurrent-sweep race in
   * `consortium-bootstrap.ts` went unnoticed until review.)
   *
   * Skipped when there is no manifest provider: there is no node roster to enumerate, so a timer
   * that can only ever re-measure nothing is noise. That case is NOT silent — `cello_status`
   * reports `measurement: "not_configured"` and says why.
   */
  /**
   * WHERE the held manifest came from, because it decides what the operator can actually DO about
   * an expired one — `DOD-M15-MANIFEST-EXPIRY-LIVE-1` review F5.
   *
   * `EmbeddedManifestProvider` is the compiled-in bundled roster: there is no file to replace and no
   * poll to adopt a replacement, so "rotate the manifest" is not an available action and telling
   * that operator to do it routes them toward the one workaround that silently disables directory
   * identity authentication. Detected by the provider's own constructor rather than by re-reading
   * the env var, so a caller that injects a provider directly is classified by what it IS.
   */
  const manifestOrigin: ManifestOrigin =
    manifestProvider?.constructor?.name === "EmbeddedManifestProvider" ? "bundled" : "file";

  /** REVIEW F4: the last sweep failure, surfaced in `cello_status` alongside the log line. */
  let lastRosterSweepError: RosterFreshness["last_sweep_error"] | undefined;

  /**
   * DOD-M15-MANIFEST-EXPIRY-LIVE-1 — re-check the trust anchor's validity while the daemon runs.
   *
   * The window is enforced at STARTUP and nowhere else. The manifest poll's expiry check looks at
   * the manifest being FETCHED, never the one held, so a daemon past its expiry keeps polling, keeps
   * correctly refusing expired replacements, and keeps using the lapsed anchor it already has.
   *
   * Rides the roster sweep rather than owning a timer: that tick already fires every 90–180 s on
   * exactly the path where a manifest provider exists.
   */
  const checkManifestValidity = startManifestValidityWatch({
    getManifest: () => manifestProvider?.getCurrentManifest() ?? null,
    logger,
  });
  const rosterSweepScheduler = manifestProvider
    ? config.rosterSweepScheduler ??
      new RandomizedPollScheduler({ minMs: ROSTER_SWEEP_INTERVAL_MS, maxMs: ROSTER_SWEEP_INTERVAL_MS * 2 })
    : undefined;
  const stopRosterSweep = rosterSweepScheduler
    ? startRosterSweep({
        scheduler: rosterSweepScheduler,
        // FAST_PROBE is deliberately NOT used here. It exists because the failover resolver runs
        // inside the 10 s signaling wait; nothing waits on this sweep, so it can afford the
        // patient probe and give the more trustworthy answer.
        sweep: async () => {
          /**
           * DOD-M15-MANIFEST-EXPIRY-LIVE-1: the anchor's validity is re-checked on the same tick.
           * BEFORE the probe, so an expired manifest is reported even on a cycle where every node is
           * unreachable and the roster resolve throws.
           *
           * Its OWN try/catch — review F11. Sharing the sweep's error path meant a throw in here
           * would surface as `directory.roster.sweep.failed` AND skip `resolveConsortiumRoster()`
           * entirely: the roster reading would freeze while the operator was pointed at the
           * directory. A manifest-check failure must never be reported as a directory failure, and
           * must never cost the measurement it rides along with.
           */
          try {
            checkManifestValidity();
          } catch (err: unknown) {
            logger.error("directory.auth.manifest.check.failed", {
              error: err instanceof Error ? err.message : String(err),
              impact:
                "the manifest validity re-check did not run this cycle. cello_status still computes " +
                "it independently on every read, so the FIELD is unaffected; what is lost is the " +
                "unprompted log line on a transition.",
            });
          }
          return resolveConsortiumRoster();
        },
        logger,
        // REVIEW F4: the failure reaches the agent's response, not just the log. Without this a
        // sweep failing every cycle is invisible for the first two or three failures, because the
        // reading is still inside its 5-minute freshness bound and reports stale:false.
        onSweepError: (e) => { lastRosterSweepError = e; },
        onSweepSuccess: () => { lastRosterSweepError = undefined; },
      })
    : undefined;

  return {
    failoverEndpointResolver,
    getDeclaredNodeCount,
    getFailoverEndpoint,
    getUnresolvedNodes,
    getUnresolvedSweptAt,
    manifestOrigin,
    manifestVerified,
    resolveConsortiumRoster,
    rosterSweepScheduler,
    securityGateway,
    sessionNodeManager,
    stopHttpManifestPoll,
    stopRosterSweep,
    transportSelector,
    verifiedManifest,
    verifiedManifestVersion,
    /** A READER. See the header — a snapshot here reports a healthy roster forever. */
    lastRosterSweepError: () => lastRosterSweepError,
  };
}
