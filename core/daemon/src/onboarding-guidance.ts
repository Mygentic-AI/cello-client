/**
 * What a machine with NO agents is told, and why it is one string in one place.
 *
 * ─── The failure this exists to prevent ──────────────────────────────────────────────────────
 * A new operator installs the plugin, runs `cello login`, and gets `No registered agents to
 * start.` — nine words that name no next command, no token, and no gate. So they go looking,
 * find the CELLO operations agent on Telegram, ask it for a registration token, and are refused,
 * because tokens only exist for someone a cohort has already admitted.
 *
 * Nothing in the client said so. Measured 2026-09-07: the words "waitlist", "cohort" and "wave"
 * appeared NOWHERE in the CLI, the daemon, or any of the five plugin skills. The setup skill
 * explains the token's format and that it is single-use, and never mentions that one has to be
 * issued to you first. The wasted trip to Telegram was not a risk — it was the only path the
 * product described.
 *
 * ─── Why the gate comes FIRST in the text ────────────────────────────────────────────────────
 * Ordering the steps by what the operator types (create → register → "you need a token") puts the
 * gate at the end, which is where they discover it AFTER the trip. Leading with it costs one line
 * and turns a disappointment into an expectation.
 *
 * ─── Why step 4 is called out as free ────────────────────────────────────────────────────────
 * `create-agent` needs no token and no permission — the identity is local until registration
 * publishes it. Someone waiting on a cohort can still get that far and see something succeed,
 * which is the difference between "gated" and "broken".
 *
 * ─── Why it lives in the daemon ──────────────────────────────────────────────────────────────
 * Two surfaces show it: the CLI (`cello login`, `cello status`) and the MCP shim, for the operator
 * who never opens a terminal. The CLI can import this constant because `cli` depends on `daemon`.
 * **`connect` depends on NO @cello-protocol package** — it is a 233 KB socket shim by design, and
 * making it depend on the 7.8 MB daemon would put a native SQLCipher build on every session start.
 * So the shim cannot import this, and the text has to reach it over the wire: `cello_list_agents`
 * returns it as `onboarding` when the roster is empty. One definition, two renderers, no drift.
 */

/** Where someone who has not signed up starts. Live as of 2026-09-07. */
export const WAITLIST_URL = "https://cello.mygentic.ai/waitlist";

/**
 * Shown when a machine has zero agents. Plain text, terminal-width, no ANSI — it is rendered
 * verbatim by the CLI and passed through to an agent by the shim, and neither can assume a TTY.
 */
export const NO_AGENTS_GUIDANCE =
  "No agents on this machine yet.\n" +
  "\n" +
  "CELLO is in cohort launch, so registration is gated. The order is:\n" +
  "\n" +
  `  1. Join the waitlist          ${WAITLIST_URL}\n` +
  "  2. Wait to be admitted to a cohort — you'll be notified\n" +
  "  3. Collect your token from the CELLO operations agent on Telegram\n" +
  "  4. cello create-agent <name>            <- works right now, no token needed\n" +
  "  5. cello register-agent <name> <token>\n" +
  "\n" +
  "Step 4 costs nothing and needs no permission — your identity is local until you\n" +
  "register it.";
