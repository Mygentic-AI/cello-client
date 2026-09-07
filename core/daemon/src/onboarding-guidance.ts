/**
 * What a machine with NO agents is told, and why it is one string in one place.
 *
 * ─── The failure this exists to prevent ──────────────────────────────────────────────────────
 * A new operator installs the plugin, runs `cello login`, and gets `No registered agents to
 * start.` — nine words that name no next command, no token, and no bot. Measured 2026-09-07: the
 * words "waitlist", "cohort" and "wave" appeared NOWHERE in the CLI, the daemon, or any of the
 * five plugin skills, and the bot was referred to only as "the CELLO Operations Agent on
 * Telegram" — a description, never a handle you could search for.
 *
 * ─── THERE ARE TWO TOKENS, AND CONFLATING THEM IS THE DEFECT ─────────────────────────────────
 * The first draft of this text treated them as one thing and got the shape wrong.
 *
 *   **Waitlist token** — minted by a wave when you are admitted from the waitlist. The gate
 *   handler calls it a grant of NETWORK ACCESS. You present it to the bot ONCE and it is
 *   BURNED; the burn links your Telegram account. It is not per-agent and you never see it again.
 *
 *   **Agent token** — the `CELLO-` pre-authorization capability the bot issues so a specific
 *   agent may register. One per agent, single-use, 24-hour expiry.
 *
 * The system's own name for the first is `waitlist_tokens`, and that is what it is called here.
 * It is deliberately NOT "telegram token": `cello-ops-agent-telegram-bot-token` already exists in
 * the infrastructure as the bot's API credential, and giving two unrelated secrets one name is a
 * support conversation nobody can untangle.
 *
 * ─── WHY THE GATE IS AT THE BOTTOM, NOT THE TOP ──────────────────────────────────────────────
 * An earlier version led with the cohort gate on the theory that it prevents a wasted trip to
 * Telegram. Andre's correction, and the gate handler agrees with him: the gate's first step is
 * "is this Telegram ID already linked? → proceed". Once the waitlist token is burned, the
 * condition is permanently satisfied. Leading with it means everyone past that point reads a
 * standing warning about a door they already walked through, every time they have no agent on a
 * machine — which is also true on a second laptop, after a reset, and after an ecosystem wipe.
 *
 * So the happy path leads and the gate is a CONDITION underneath it, phrased as a question so a
 * reader who is past it skips it instead of re-reading it.
 *
 * ─── Why the gate is bullets and not a paragraph ─────────────────────────────────────────────
 * It was a prose block, and it dropped out of scanning mode exactly where the reader is still
 * scanning. Both halves are now lists — numbered steps, then bulleted steps — so the whole
 * message reads as one shape rather than switching from instructions to explanation halfway
 * down. The bullets are ACTIONS for the same reason: at that point the reader's question is
 * "what do I do", not "what is this thing".
 *
 * ─── Why the handle is DERIVED and not a constant ────────────────────────────────────────────
 * There are two bots — production and staging — and a hardcoded handle sends a staging operator
 * to the production bot, which will refuse their staging waitlist token with a message about a
 * grant they do hold, on a bot they should not be talking to. `CELLO_ENV` already exists in this
 * daemon and already carries `staging`, so the handle derives from it.
 *
 * **The mapping is a whitelist of ONE, deliberately.** `resolveCelloEnv` defaults an unset
 * `CELLO_ENV` to `"local"`, and the overwhelmingly common case — an operator who installed from
 * npm and set nothing — must never be pointed at staging. So only a literal `staging` gets the
 * staging bot and everything else gets production: a misconfiguration sends someone to the real
 * bot, which is the recoverable direction of that error.
 *
 * ─── Why it lives in the daemon ──────────────────────────────────────────────────────────────
 * Two surfaces show it: the CLI (`cello login`) and the MCP shim, for the operator who never
 * opens a terminal. The CLI imports this because `cli` depends on `daemon`. **`connect` depends
 * on NO @cello-protocol package** — it is a 233 KB socket shim by design, and making it depend on
 * the 7.8 MB daemon would put a native SQLCipher build on every session start. So the shim cannot
 * import this, and the text reaches it over the wire: `cello_list_agents` returns it as
 * `onboarding` when the roster is empty. One definition, two renderers, no drift.
 */

/** Where someone who has not signed up starts. Live as of 2026-09-07. */
export const WAITLIST_URL = "https://cello.mygentic.ai/waitlist";

/** The operations agent on Telegram, by environment. */
export const BOT_HANDLE_PRODUCTION = "@CelloConnectBot";
export const BOT_HANDLE_STAGING = "@CelloConnectStagingBot";

/**
 * Which bot to send this operator to. Only an explicit `staging` diverges — see the whitelist
 * note above for why an unrecognised or unset value must resolve to production.
 */
export function botHandle(celloEnv: string | undefined = process.env["CELLO_ENV"]): string {
  return celloEnv === "staging" ? BOT_HANDLE_STAGING : BOT_HANDLE_PRODUCTION;
}

/**
 * Shown when a machine has zero agents. Plain text, terminal-width, no ANSI — it is rendered
 * verbatim by the CLI and passed through to an agent by the shim, and neither can assume a TTY.
 */
export function noAgentsGuidance(celloEnv?: string): string {
  return (
    "No agents on this machine yet. To make one:\n" +
    "\n" +
    `  1. Get an agent token from ${botHandle(celloEnv)} on Telegram\n` +
    "  2. cello create-agent <name>\n" +
    "  3. cello register-agent <name> <token>\n" +
    "\n" +
    "That's it — your agent is live and reachable.\n" +
    "\n" +
    "First time with the bot? It asks for a waitlist token first. To get one:\n" +
    "\n" +
    `  - Join the waitlist: ${WAITLIST_URL}\n` +
    "  - Wait to be admitted to a launch cohort — you'll be notified\n" +
    "  - Give the bot that token once. It is burned on use and never asked for again"
  );
}
