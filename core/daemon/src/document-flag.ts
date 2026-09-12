/**
 * 074-DOCSFLAG — whether the collaborative-document layer exists in this process.
 *
 * ONE value, default OFF, gating all five document surfaces: the 14 IPC handler registrations, the
 * 15 MCP tools, the 14 CLI commands and their help, the 14 vocabulary entries, and the reconcile
 * sweep timer. Not five toggles — five toggles is five states nobody can reason about.
 *
 * ⚠️ THIS IS A GATE, NOT A REMOVAL. Nothing is deleted. Every line of the document layer stays
 * where it is and its tests keep running; with the flag ON behaviour is byte-identical to before
 * this flag existed. The flag flips when the base protocol is solid.
 *
 * ── WHY AN ENVIRONMENT VARIABLE AND NOT THE GATEWAY CONFIG STORE ──────────────────────────────
 *
 * Three separate OS processes have to agree on this answer, and two of them cannot reach a database:
 *
 *   - the DAEMON reads it once at startup, and could read any store;
 *   - the CLI renders `cello --help` in a fresh short-lived process, before it has spoken to a
 *     daemon at all — help must be right when no daemon is running;
 *   - the MCP SHIM (`@cello-protocol/connect`) declares its tool list at module load and has
 *     `@cello-protocol/daemon` as a DEV dependency only, on purpose: it is a thin standalone
 *     package. It cannot import this module, let alone open the daemon's SQLCipher database.
 *
 * So the value is an environment variable, and the shim reads the same variable by name with its
 * own three-line parser. `documents-flag-parity` asserts the shim's literal equals
 * `DOCUMENTS_FLAG_ENV`, so the two cannot drift.
 *
 * What IS taken from the config store's posture: **the tightest value is the default.** Absent
 * reads as off, an unparseable value reads as off, and only an explicit affirmative turns the layer
 * on. There is no value that means "on" by accident.
 *
 * ── WHAT THIS IS NOT ──────────────────────────────────────────────────────────────────────────
 *
 * Not a security control, and it must not be described as one. An operator who can set an
 * environment variable can also edit the source — the document code is on their disk. What the
 * flag removes is the ADVERTISEMENT: with it off, an agent reading its tool list finds no document
 * verb to call, and an operator who turns it on has opted in deliberately.
 */

/** The one variable name. Read by the daemon, the CLI and (by literal) the MCP shim. */
export const DOCUMENTS_FLAG_ENV = "CELLO_DOCUMENTS";

/**
 * The values that turn the layer ON. Everything else — absent, empty, `"0"`, `"off"`, a typo — is
 * off, because the default is the tightest value and a misread must never loosen.
 */
const AFFIRMATIVE = new Set(["1", "true", "on", "yes"]);

/**
 * Is the collaborative-document layer enabled in this process?
 *
 * Takes the environment as an argument so a test can answer the question for a given environment
 * without mutating the real one. Callers in production pass nothing.
 */
export function documentsEnabled(env: Record<string, string | undefined> = process.env): boolean {
  const raw = env[DOCUMENTS_FLAG_ENV];
  if (typeof raw !== "string") return false;
  return AFFIRMATIVE.has(raw.trim().toLowerCase());
}

/**
 * The word the daemon logs at startup, so "are documents on?" is one grep rather than an inference
 * from the absence of something (074-DOCSFLAG clause 9).
 */
export function documentLayerState(env?: Record<string, string | undefined>): "on" | "off" {
  return documentsEnabled(env) ? "on" : "off";
}
