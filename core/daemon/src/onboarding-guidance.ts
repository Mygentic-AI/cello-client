/**
 * What a machine with no agents is told: the two commands that make one, and what the first
 * registration asks of the operator.
 *
 * Two surfaces show it, from this one definition. The CLI prints it after `cello login` when
 * there is nothing to start. The MCP shim, which depends on no @cello-protocol package, receives
 * it over the wire: `cello_list_agents` returns it as `onboarding` when the roster is empty.
 */

/** Where someone who has not been invited yet starts. */
export const WAITLIST_URL = "https://celloprotocol.com/waitlist";

/**
 * Shown when a machine has zero agents. Plain text, terminal-width, no ANSI: the CLI renders it
 * verbatim and the shim passes it through to an agent, and neither can assume a TTY.
 */
export function noAgentsGuidance(): string {
  return (
    "No agents on this machine yet. To make one:\n" +
    "  1. cello create-agent <name>\n" +
    "  2. cello register-agent <name>\n" +
    "The first registration on this machine prints a link and a code. Open it on any device, " +
    "sign in with your invited email, and approve. " +
    `Not invited yet? Get Early Access: ${WAITLIST_URL}`
  );
}
