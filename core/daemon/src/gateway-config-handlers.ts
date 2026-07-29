/**
 * DOD-M9C-SURFACE-1 — the security layer's control surface (policy D-4).
 *
 * The gateway's config store has enforced tighten-free / loosen-confirmed since June 2026, and
 * NOTHING in the product could ever satisfy the confirmation — there was no CLI, no MCP tool, no
 * portal page. A `confirmed` flag that only tests set is a gate nobody can pass and nobody can
 * open. These three verbs are the surface, and the confirmation is a human at a terminal.
 *
 * INV-10 — the loosen gate has no side door. Every loosening flows through the versioned store,
 * and `confirmed` is honored ONLY from a `cli` connection (M9C-D15). An MCP caller — which is what
 * an LLM agent is — gets a refusal naming the command a human must run. Stated plainly: this is
 * not a cryptographic boundary, because it does not need to be. The threat is an agent talking
 * itself into weakening its own guards; the agent reaches the daemon through the MCP server, which
 * declares `mcp`. Anyone who can spawn a process claiming to be the CLI can simply run the CLI.
 *
 * The store is opened per call rather than held open: config commands are rare, the file is shared
 * with the gateway process, and a long-lived second write handle buys nothing but lock contention.
 */
import { join } from "node:path";
import { GatewayConfigStore, type ConfigDirection } from "@cello-protocol/gateway";
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
  return { ok: true, value: n };
}

export function registerGatewayConfigHandlers(deps: GatewayConfigHandlerDeps): void {
  const { handlers, celloDir, logger, getClientType, restartSecurityGateway } = deps;

  const openStore = (): GatewayConfigStore =>
    new GatewayConfigStore(
      join(celloDir, "gateway.db"),
      dbKeyPathFor(join(celloDir, "sessions.db")),
      // INV-7: the daemon logs through its injected logger and nowhere else. Without this sink the
      // store would write raw lines to the daemon's stderr.
      (event, context) => logger.info(event, context),
    );

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
    } finally {
      store.close();
    }
  };

  // Read the whole surface. Shows the GOVERNANCE, not just the value (M9C-D18): after an incident
  // the question is not "what is this set to" but "who weakened it, and did a human agree".
  handlers.set("cello_gateway_config_list", async () =>
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

  handlers.set("cello_gateway_config_get", async (params) => {
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

  handlers.set("cello_gateway_config_set", async (params, connectionId) => {
    const key = typeof params?.key === "string" ? params.key : undefined;
    if (!key || !(GATEWAY_CONFIG_KEYS as readonly string[]).includes(key)) {
      return { ok: false, reason: "unknown_key", guidance: `Provide one of: ${GATEWAY_CONFIG_KEYS.join(", ")}.` };
    }
    if (!params || !("value" in params)) {
      return { ok: false, reason: "missing_params", guidance: `Provide 'value' — ${KEY_HELP[key]}.` };
    }
    const parsed = coerce(key, params.value);
    if (!parsed.ok) return { ok: false, reason: "invalid_value", guidance: parsed.reason };

    const surface = getClientType(connectionId) === "mcp" ? "mcp" : "cli";
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

      // It is a loosening. Two ways to be refused, and they are different failures.
      if (surface === "mcp") {
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
        return {
          ok: false,
          reason: "needs_confirmation",
          direction: "loosen" as ConfigDirection,
          guidance: `This weakens ${KEY_HELP[key]}. Re-run and confirm at the prompt to apply it.`,
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
