/**
 * The daemon-down gate, shared by the stdio and HTTP MCP entrypoints.
 *
 * `installDaemonGate` dials the daemon, registers this connection as an MCP client, and replaces
 * `proxy.call` so every tool answers `daemon_not_running` (with the recovery) instead of the process
 * exiting. See the block comment inside for why exiting is the wrong behaviour.
 */

import type { IpcProxy } from "./ipc-proxy.js";
import { logEvent } from "./shim-log.js";

export async function installDaemonGate(proxy: IpcProxy, label = "cello-mcp"): Promise<void> {

/**
 * ─── THE SHIM MUST STAY UP WITHOUT A DAEMON ────────────────────────────────────────────────────
 *
 * It used to write a genuinely good recovery message here and then `process.exit(1)`. Claude Code
 * reports a server that exits as:
 *
 *     plugin:cello:cello (CONNECTION_CLOSED): "Connection closed"
 *
 * — which names neither CELLO, nor the daemon, nor a next step. So on a fresh machine the ONE
 * message written for that exact moment was invisible, every time, and the only thing a new
 * operator saw was a generic transport error. The text was never the problem; exiting was.
 *
 * The `setup` skill already documents the behaviour we want — "Without the daemon every tool
 * returns `daemon_not_running`" — so the documentation and the binary simply disagreed, and the
 * documentation was right.
 *
 * Now: the shim starts regardless, every tool answers `daemon_not_running` carrying the recovery,
 * and the guidance reaches the model's context where it can be acted on rather than a log nobody
 * opens.
 *
 * AND IT RE-DIALS ON THE NEXT TOOL CALL. That is the second half, and it removes a separate
 * papercut: the sequence a new operator hits is plugin installs → shim cannot connect → install
 * cli → `cello login` succeeds → and the tools were STILL dead until they somehow knew to run
 * `/mcp` → Reconnect. Nothing announced that, so the first failure was opaque and its recovery was
 * unadvertised. Retrying here means starting the daemon is sufficient on its own: the next tool
 * call connects. `connect()` builds a fresh socket per call, so re-dialling after a failure is
 * safe.
 */
const DAEMON_RECOVERY =
  "No CELLO daemon is running on this machine.\n" +
  "\n" +
  "The plugin ships this MCP shim only — the daemon and the `cello` command install separately.\n" +
  "Ask the operator to run these at their own terminal:\n" +
  "\n" +
  "  npm i -g --prefer-online @cello-protocol/cli@latest\n" +
  "  cello login\n" +
  "\n" +
  "Then just call a CELLO tool again — this shim re-dials on its own, so no reconnect or restart\n" +
  "is needed. (If it still fails, `/mcp` → cello → Reconnect forces a fresh attempt.)\n" +
  "\n" +
  "If CELLO has never been set up on this machine, run the `setup` skill instead — it covers\n" +
  "creating and registering an agent as well, which starting the daemon does not.";

/** Null while connected; otherwise the guidance every tool call answers with. */
let daemonDown: string | null = null;

/** The un-gated call, captured before the gate below replaces `proxy.call`. */
const rawCall = proxy.call.bind(proxy);

/** Register this connection as an MCP client. Returns guidance on refusal, null on success. */
async function handshake(): Promise<string | null> {
  const result = await rawCall("ipc.connect", { clientType: "mcp" });
  if (result && typeof result === "object" && "reason" in (result as Record<string, unknown>)) {
    const r = result as { reason: string };
    if (r.reason === "version_mismatch") {
      // Also no longer an exit. A version mismatch that kills the shim is reported as
      // CONNECTION_CLOSED too, so the one message that names the actual fix never arrives.
      return (
        "The CELLO daemon is running, but its version does not match this shim.\n" +
        "\n" +
        "Ask the operator to restart it onto a matching build:\n" +
        "\n" +
        "  npm i -g --prefer-online @cello-protocol/cli@latest\n" +
        "  cello logout && cello login"
      );
    }
  }
  return null;
}

try {
  await proxy.connect();
  daemonDown = await handshake();
} catch (err: unknown) {
  const code = (err as NodeJS.ErrnoException).code;
  daemonDown =
    code === "ENOENT" || code === "ECONNREFUSED"
      ? DAEMON_RECOVERY
      : `Could not reach the CELLO daemon — ${err instanceof Error ? err.message : String(err)}`;
}
if (daemonDown) {
  // Still teed to ~/.cello/cello-mcp-stderr.log for an operator debugging at the terminal. The
  // tool-call answer is what actually reaches the agent; this is the durable copy.
  process.stderr.write(`${label}: ${daemonDown}\n`);
}

/**
 * Single-flight re-dial. Two tool calls arriving while the daemon is down must not open two
 * sockets — the second would overwrite `#socket` under the first and orphan it.
 */
let redialInFlight: Promise<void> | null = null;

async function ensureDaemon(): Promise<string | null> {
  if (!daemonDown) return null;
  const attempt =
    redialInFlight ??
    (redialInFlight = (async () => {
      try {
        await proxy.connect();
        daemonDown = await handshake();
        if (!daemonDown) logEvent("mcp.daemon.redialed");
      } catch {
        // Still down. Keep the existing guidance — a fresh ENOENT says nothing new, and
        // overwriting a version-mismatch message with a connection error would lose the
        // more specific of the two.
      } finally {
        redialInFlight = null;
      }
    })());
  await attempt;
  return daemonDown;
}

/**
 * THE GATE. Every tool in this file goes through `proxy.call`, so wrapping it here is what makes
 * "the shim stays up" true for all ~80 of them at once — rather than 80 call sites each remembering
 * to check, which is the version of this that would rot.
 */
(proxy as unknown as { call: typeof rawCall }).call = async (
  method: string,
  params?: Record<string, unknown>,
): Promise<unknown> => {
  const guidance = await ensureDaemon();
  if (guidance !== null) {
    return { ok: false, reason: "daemon_not_running", guidance };
  }
  return rawCall(method, params);
};
}
