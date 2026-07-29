/**
 * DOD-M9C-SURFACE-1 — the security layer's control surface (policy D-4).
 *
 * The gateway's config store has enforced tighten-free / loosen-confirmed since June 2026, and
 * NOTHING in the product could ever satisfy the confirmation — there was no CLI, no MCP tool, no
 * portal page. A `confirmed` flag that only tests set is a gate nobody can pass and nobody can
 * open. These three verbs are the surface, and the confirmation is a human at a terminal.
 *
 * INV-10 — WHAT THIS GATE ACTUALLY GUARANTEES, stated honestly (audit finding, 2026-07-29).
 *
 * Every loosening flows through the versioned store, and `confirmed` is honored only from a
 * connection whose declared `clientType` is exactly `cli` — an MCP caller, or one that never
 * handshook at all, is refused with the command a human must run.
 *
 * **That is not an authentication boundary, and it must not be described as one.** `clientType` is
 * SELF-DECLARED: the daemon records whatever string arrives in `ipc.connect`. Any process running
 * as the operator can open `~/.cello/daemon.sock` (mode 0600), announce `clientType: "cli"`, and
 * pass `confirmed: true`. That includes an agent with a shell tool. The TTY check that represents
 * the human lives in the CLI process (`confirmAtTty`), and the daemon has no way to verify it —
 * a same-uid process is indistinguishable from the operator by any local mechanism, so no amount
 * of daemon-side checking closes this.
 *
 * What it therefore DOES do, which is worth having: it removes every path an agent reaches by
 * ORDINARY means — the MCP tools it is given, and the CLI it can invoke (which refuses on a
 * non-TTY stdin). An agent must go out of its way, speaking raw IPC and misrepresenting itself,
 * and that is a different and much louder act than calling a tool it was handed.
 *
 * The real boundary is the one D-4 already names as the destination: the portal passkey. A
 * confirmation the operator performs on a surface the local machine cannot forge is the only thing
 * that makes "and nothing else produces this flag" true. Until then, this is a friction gate with
 * a versioned, hash-chained audit trail — not a lock.
 *
 * STORE HANDLES ARE HELD OPEN FOR THE PROCESS LIFETIME. They were originally opened per call, on
 * the reasoning that config commands are rare and a second long-lived handle buys only lock
 * contention. That was wrong, and it cost the entire audit trail — proven against the shipped
 * daemon on 2026-07-29:
 *
 *   1. sidecar screens a message  -> record written, visible, `-wal` present
 *   2. a reader opens and CLOSES  -> SQLite unlinks `-wal`/`-shm` out from under the live sidecar
 *   3. sidecar screens again      -> the write lands in the now-orphaned WAL
 *   4. a fresh reader sees        -> only the FIRST record. Everything after step 2 is lost.
 *
 * So `cello policy log` and `cello config list` — the surfaces that exist to show what the layer
 * did — were silently destroying the record of what it did next. Holding the handle open means no
 * connection ever performs the last-connection close while the sidecar is alive, which is the
 * event that removes the WAL. The handles are deliberately not closed per call; process exit
 * releases them, and the sidecar is torn down before the daemon exits (INV-9 shutdown ordering).
 */
import { join } from "node:path";
import { GatewayConfigStore, GatewayRecordStore, type ConfigDirection } from "@cello-protocol/gateway";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";
import { dbKeyPathFor } from "./sqlcipher-db.js";

/** The five keys the gateway reads. Kept here so the surface can list them without a store open. */
export const GATEWAY_CONFIG_KEYS = [
  "autonomous_override",
  "pii_whitelist",
  "language_allow",
  "rate_max_per_window",
  "rate_window_ms",
] as const;

/** What each key controls, in the words an operator needs to decide whether to change it. */
const KEY_HELP: Record<string, string> = {
  autonomous_override: "whether the agent may send a flagged value with no human present",
  pii_whitelist: "values (e.g. your own email) that pass outbound without a warning",
  language_allow: "which languages are accepted inbound",
  rate_max_per_window: "how many outbound messages are allowed per window (0 = no cap)",
  rate_window_ms: "the window the outbound cap applies to, in milliseconds",
};

export interface GatewayConfigHandlerDeps {
  handlers: Map<string, IpcHandler>;
  celloDir: string;
  logger: Logger;
  /** Read this connection's declared client type — `"mcp"` or `"cli"` (M9C-D15). */
  getClientType: (connectionId: string) => string | undefined;
  /**
   * Restart the screening sidecar so a stored change actually applies (M9C-D17). Supplied by the
   * composition root, which owns the sidecar's lifecycle. Absent in tests that assert storage only.
   */
  restartSecurityGateway?: () => Promise<void>;
}

/** Parse a wire value into the type the store's validator expects for that key. */
function coerce(key: string, raw: unknown): { ok: true; value: unknown } | { ok: false; reason: string } {
  if (key === "autonomous_override") {
    if (typeof raw === "boolean") return { ok: true, value: raw };
    if (raw === "true" || raw === "false") return { ok: true, value: raw === "true" };
    return { ok: false, reason: "autonomous_override is a boolean — pass true or false." };
  }
  if (key === "pii_whitelist" || key === "language_allow") {
    if (Array.isArray(raw) && raw.every((v) => typeof v === "string")) return { ok: true, value: raw };
    // A comma-separated string is what a CLI argument looks like. An EMPTY string means the empty
    // list (the tightest value), not [""] — a stray empty member would whitelist nothing but would
    // read as a loosening in the version history.
    if (typeof raw === "string") {
      return { ok: true, value: raw.split(",").map((s) => s.trim()).filter(Boolean) };
    }
    return { ok: false, reason: `${key} is a list — pass comma-separated values, or an empty string to clear it.` };
  }
  const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : NaN;
  if (!Number.isFinite(n)) return { ok: false, reason: `${key} is a number.` };
  // Mirror the store's own range rules HERE (review F6). Without this, `rate_window_ms 0` reached
  // the store's validator, which THROWS — and an uncaught throw becomes `internal_error: an
  // unexpected error occurred, check daemon logs`. The operator asked for something out of range
  // and was told the daemon broke.
  if (key === "rate_max_per_window" && n < 0) {
    return { ok: false, reason: "rate_max_per_window cannot be negative (0 means no cap)." };
  }
  if (key === "rate_window_ms" && n <= 0) {
    return { ok: false, reason: "rate_window_ms must be greater than 0 milliseconds." };
  }
  return { ok: true, value: n };
}

/**
 * Map a store-layer throw onto a named cause. An exit-point label on a corrupt security store is
 * the error-substitution defect this project keeps finding (review F7).
 */
function storeFault(message: string): { ok: false; reason: string; guidance: string } {
  if (/SQLITE_CORRUPT|malformed|SQLITE_IOERR/i.test(message)) {
    return {
      ok: false,
      reason: "store_corrupt",
      guidance:
        "The security layer's store could not be read — the file is damaged. Screening still runs " +
        "and still fails closed, but the config history and the audit trail are unreadable. Stop " +
        `the daemon, move ~/.cello/gateway.db aside, and restart to begin a fresh store. (${message})`,
    };
  }
  if (/SQLITE_BUSY|locked/i.test(message)) {
    return {
      ok: false,
      reason: "store_locked",
      guidance:
        "The security layer's store is locked by another process — usually an orphaned gateway " +
        `from a previous daemon. Stop it and retry. (${message})`,
    };
  }
  return {
    ok: false,
    reason: "store_read_failed",
    guidance: `The security layer's store could not be read. (${message})`,
  };
}

export function registerGatewayConfigHandlers(deps: GatewayConfigHandlerDeps): void {
  const { handlers, celloDir, logger, getClientType, restartSecurityGateway } = deps;

  // ONE handle, opened lazily, never closed per call — see the header. Closing is what unlinks the
  // WAL and orphans every subsequent sidecar write.
  let configStore: GatewayConfigStore | undefined;
  const openStore = (): GatewayConfigStore => {
    if (!configStore) {
      configStore = new GatewayConfigStore(
        join(celloDir, "gateway.db"),
        dbKeyPathFor(join(celloDir, "sessions.db")),
        // INV-7: the daemon logs through its injected logger and nowhere else. Without this sink the
        // store would write raw lines to the daemon's stderr.
        (event, context) => logger.info(event, context),
      );
    }
    return configStore;
  };

  let recordStore: GatewayRecordStore | undefined;
  const openRecordStore = (): GatewayRecordStore => {
    if (!recordStore) {
      recordStore = new GatewayRecordStore(
        join(celloDir, "gateway.db"),
        dbKeyPathFor(join(celloDir, "sessions.db")),
        (event, context) => logger.info(event, context),
      );
    }
    return recordStore;
  };

  /** Every store open can fail closed (missing key, locked file). Report the CAUSE, not a label. */
  const withStore = <T>(fn: (store: GatewayConfigStore) => T): T | { ok: false; reason: string; guidance: string } => {
    let store: GatewayConfigStore;
    try {
      store = openStore();
    } catch (err: unknown) {
      const code = (err as { code?: string } | null)?.code ?? "config_store_unavailable";
      const guidance = (err as { guidance?: string } | null)?.guidance
        ?? "The security layer's config store could not be opened. Check the daemon log.";
      return { ok: false, reason: code, guidance };
    }
    try {
      return fn(store);
    } catch (err: unknown) {
      // The store validates too, and it THROWS. A validation fault is the caller's input being
      // wrong, not the daemon being broken — surfacing it as `internal_error` sends the operator
      // to the logs for a problem they can fix in the command they just typed.
      const message = err instanceof Error ? err.message : String(err);
      if (/invalid value for config key|unknown config key/i.test(message)) {
        return { ok: false, reason: "invalid_value", guidance: message };
      }
      // Review F7: a READ that throws used to escape as `internal_error: an unexpected error
      // occurred, check daemon logs` — sending the operator to the logs for a corrupted security
      // store, with no remedy named, while the OPEN path carefully produces store_plaintext_file /
      // store_locked / store_key_mismatch. The read path deserves the same.
      return storeFault(message);
    }
    // NO `finally { store.close() }`. The close is the defect: it unlinks the WAL from under the
    // sidecar and every record it writes afterwards is lost.
  };

  // Read the whole surface. Shows the GOVERNANCE, not just the value (M9C-D18): after an incident
  // the question is not "what is this set to" but "who weakened it, and did a human agree".
  handlers.set("cello_config_list", async () =>
    withStore((store) => ({
      ok: true,
      config: GATEWAY_CONFIG_KEYS.map((key) => {
        const history = store.history(key);
        const latest = history[history.length - 1];
        return {
          key,
          describes: KEY_HELP[key],
          // `null`, never a fabricated default: the gateway applies its own tightest default for an
          // unset key, and echoing that value here would make "never configured" indistinguishable
          // from "deliberately set to the same value".
          value: latest ? latest.value : null,
          version: latest?.version ?? 0,
          lastChange: latest?.direction ?? null,
          confirmed: latest?.confirmed ?? false,
        };
      }),
    })),
  );

  handlers.set("cello_config_get", async (params) => {
    const key = typeof params?.key === "string" ? params.key : undefined;
    if (!key || !(GATEWAY_CONFIG_KEYS as readonly string[]).includes(key)) {
      return {
        ok: false,
        reason: "unknown_key",
        guidance: `Provide one of: ${GATEWAY_CONFIG_KEYS.join(", ")}.`,
      };
    }
    return withStore((store) => {
      const history = store.history(key);
      const latest = history[history.length - 1];
      return {
        ok: true,
        key,
        describes: KEY_HELP[key],
        value: latest ? latest.value : null,
        version: latest?.version ?? 0,
        lastChange: latest?.direction ?? null,
        confirmed: latest?.confirmed ?? false,
        chainValid: store.verifyChain(key),
      };
    });
  });

  // DOD-M9C-AUDIT-1 (policy D-11) — "what did my policy do?"
  //
  // This ships WITH the enforcement flip, by decision, and not later: it is the concrete answer to
  // the question D-2 raised — *"I have ongoing development everywhere, and if a new error appears
  // I won't know whether it came from the flip or from my own work."* Attribution should be a
  // lookup, not a guess, so every screened message is already recorded with its disposition and
  // the rule that fired. This reads that record. Deliberately a list, not a dashboard.
  //
  // Newest first, because the question is almost always "what just happened".
  handlers.set("cello_policy_log", async (params) => {
    const rawLimit = params?.limit;
    const limit = typeof rawLimit === "number" && Number.isFinite(rawLimit) && rawLimit > 0
      ? Math.min(Math.floor(rawLimit), 500)
      : 50;
    const since = typeof params?.since_ms === "number" && Number.isFinite(params.since_ms)
      ? params.since_ms
      : undefined;

    let store: GatewayRecordStore;
    try {
      store = openRecordStore();
    } catch (err: unknown) {
      const code = (err as { code?: string } | null)?.code ?? "record_store_unavailable";
      const guidance = (err as { guidance?: string } | null)?.guidance
        ?? "The security layer's record store could not be opened. Check the daemon log.";
      return { ok: false, reason: code, guidance };
    }
    try {
      const all = store.all();
      const filtered = since === undefined ? all : all.filter((r) => r.recordedAt >= since);
      const page = filtered.slice(-limit).reverse();
      return {
        ok: true,
        // `source` is here from day one so the reachability half (refusals, tier gates, away
        // responses — policy audit §15 items 5-8) can join this list later without changing its
        // shape. A consumer that learns to read one source reads both.
        entries: page.map((r) => ({
          source: "security" as const,
          at: r.recordedAt,
          direction: r.direction,
          disposition: r.disposition,
          reason: r.reason ?? null,
          correlationId: r.correlationId ?? null,
          contentHash: r.contentHash,
        })),
        total: filtered.length,
        returned: page.length,
        // A broken chain means the log itself was tampered with, which the operator must be told
        // BEFORE they reason from its contents.
        chainValid: store.verifyChain(),
      };
    } catch (err: unknown) {
      return storeFault(err instanceof Error ? err.message : String(err));
    }
  });

  handlers.set("cello_config_set", async (params, connectionId) => {
    const key = typeof params?.key === "string" ? params.key : undefined;
    if (!key || !(GATEWAY_CONFIG_KEYS as readonly string[]).includes(key)) {
      return { ok: false, reason: "unknown_key", guidance: `Provide one of: ${GATEWAY_CONFIG_KEYS.join(", ")}.` };
    }
    if (!params || !("value" in params)) {
      return { ok: false, reason: "missing_params", guidance: `Provide 'value' — ${KEY_HELP[key]}.` };
    }
    const parsed = coerce(key, params.value);
    if (!parsed.ok) return { ok: false, reason: "invalid_value", guidance: parsed.reason };

    // F1 (review, BLOCKING): the permissive side must not be the DEFAULT. `getClientType` returns
    // undefined for a connection that never sent `ipc.connect`, and the daemon itself defaults a
    // handshake with no clientType to "cli" — so `!== "mcp"` meant a raw socket write could carry
    // `confirmed: true` and land a human-confirmed loosening with no human anywhere near it. Ten
    // lines of node against ~/.cello/daemon.sock was the whole attack.
    //
    // And the justification for the original shape was FALSE in the direction that mattered: an
    // agent running `cello config set …` from a Bash tool gets a NON-TTY stdin and is refused, so
    // the raw socket was not "the same as just running the CLI" — it was the only route that worked
    // for a non-human. Now only an EXPLICIT `cli` handshake may confirm; everything else is an
    // untrusted surface.
    const clientType = getClientType(connectionId);
    const surface = clientType === "cli" ? "cli" : clientType === "mcp" ? "mcp" : "unknown";
    const confirmed = params.confirmed === true;

    return withStore((store) => {
      // Ask the store to classify WITHOUT confirmation first. Its classifier is the authority on
      // what counts as a loosening — re-deriving that here would be a second opinion that drifts.
      const attempt = store.set(key, parsed.value);
      if (attempt.ok) {
        logger.info("gateway.config.changed", {
          key, direction: attempt.direction, version: attempt.version, confirmed: false, surface,
        });
        return applied(key, attempt.direction, attempt.version, false);
      }

      // It is a loosening. Three ways to be refused, and they are different failures.
      if (surface !== "cli") {
        logger.warn("gateway.config.loosen_refused", { key, surface, reason: "loosen_requires_cli" });
        return {
          ok: false,
          reason: "loosen_requires_cli",
          guidance:
            `Changing '${key}' this way makes the security layer LESS protective, so it needs a ` +
            `human at a terminal — an agent cannot weaken its own guards. Ask the operator to run: ` +
            `cello config set ${key} ${String(params.value)}`,
        };
      }
      if (!confirmed) {
        logger.warn("gateway.config.loosen_refused", { key, surface, reason: "needs_confirmation" });
        const history = store.history(key);
        const latest = history[history.length - 1];
        return {
          ok: false,
          reason: "needs_confirmation",
          direction: "loosen" as ConfigDirection,
          // The CURRENT value travels with the refusal (review F7). `set` REPLACES a list, so
          // `cello config set pii_whitelist new@x.example` against a five-entry whitelist drops
          // four of them — and a prompt that shows only the new value hides that entirely.
          // `null` means never configured, i.e. the built-in tightest default applies.
          from: latest ? latest.value : null,
          guidance: `This makes ${KEY_HELP[key]} LESS restrictive.`,
        };
      }

      const result = store.set(key, parsed.value, { confirmed: true });
      if (!result.ok) {
        // The store refused a confirmed loosening — it should not, so do not paper over it.
        return { ok: false, reason: result.reason, guidance: "The config store rejected a confirmed change. Check the daemon log." };
      }
      logger.info("gateway.config.changed", {
        key, direction: result.direction, version: result.version, confirmed: true, surface,
      });
      return applied(key, result.direction, result.version, true);
    });

    /** Store the change, then make it REAL — the gateway reads config only at boot (M9C-D17). */
    function applied(k: string, direction: ConfigDirection, version: number, wasConfirmed: boolean) {
      const base = { ok: true as const, key: k, direction, version, confirmed: wasConfirmed };
      if (!restartSecurityGateway) return { ...base, applied: false as const };
      return restartSecurityGateway().then(
        () => {
          logger.info("gateway.config.applied", { key: k, restarted: true });
          return { ...base, applied: true as const };
        },
        (err: unknown) => {
          // STORED BUT NOT APPLIED. Never a bare ok: the operator would believe a guard changed
          // when the running gateway still holds the old value.
          const error = err instanceof Error ? err.message : String(err);
          logger.error("gateway.config.restart_failed", { key: k, error });
          return {
            ...base,
            applied: false as const,
            warning: "stored_but_not_applied",
            guidance:
              "The change is recorded but the screening process did not restart, so it is NOT yet " +
              `in effect. Restart the daemon to apply it. Cause: ${error}`,
          };
        },
      );
    }
  });
}
