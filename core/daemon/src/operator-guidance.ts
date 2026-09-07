/**
 * The two things the daemon says when a call cannot proceed.
 *
 * Both are text an operator reads, and both exist because the wire code alone is not an answer.
 * `no_current_agent` names the command that fixes it. The registration guidance goes further: the
 * wire code stays `dkg_failed` because it is a closed protocol union, but this string is a local
 * daemon-to-IPC message, so it can say what actually happened instead of asserting a guess.
 *
 * ⚠️ The `dkg_failed` case is why this file exists rather than a switch inline somewhere; what that
 * case used to claim, and why it was wrong, is recorded at the case itself — once, not twice.
 */

/**
 * FROZEN. This used to be a per-daemon `const`; it is now one module object handed BY IDENTITY to
 * twelve handlers across six modules. Nothing mutates it today (the CLI renderer is copy-on-write and
 * the fallback notice merges via spread), but an in-place annotation by any one of those callers
 * would silently rewrite every other caller's guidance, in every future response. The freeze makes
 * that fail at the write instead.
 */
export const NO_CURRENT_AGENT_RESPONSE = Object.freeze({
  ok: false,
  reason: "no_current_agent",
  guidance: "No current agent is set for this connection. Call cello_start_agent to bring an agent online, then call cello_use_agent to set it as the current agent for this connection.",
});

// `detail` carries the ACTUAL cause when one is known. The wire code stays `dkg_failed` — it is a
// closed protocol union — but this string is a local daemon→IPC message, so it can say what really
// happened instead of asserting a guess.
export const registrationGuidance = (reason: string, detail?: string): string => {
  switch (reason) {
    case "already_registered":
      return "This agent is already registered with the directory. No action needed.";
    case "directory_unreachable":
      return "The directory signaling stream is not connected (or its bootstrap endpoint could not be resolved). Wait for directory_signaling to show connected in cello status, then retry.";
    case "dkg_failed":
      // NOT "this usually means the pre-auth token". That diagnosis is confidently wrong for the
      // causes that actually occur — a colliding NODE_ID across two directory boxes, a commitment
      // that does not match the client's primary_pubkey, a node dropping mid-ceremony — and it sends
      // the operator to the wrong subsystem. The cause is now captured one call frame away
      // (registration.dkg.failed), so it is reported rather than guessed at.
      return detail
        ? `The FROST DKG ceremony with the directory failed: ${detail}`
        : "The FROST DKG ceremony with the directory failed, and no underlying cause was captured. Check the daemon log for registration.dkg.failed, which carries the reason.";
    case "timeout":
      return "The directory did not respond within the registration timeout. Retry once directory_signaling is connected.";
    default:
      return detail
        ? `Registration failed: ${reason} — ${detail}`
        : `Registration failed: ${reason}. Check the daemon logs (registration.* events).`;
  }
};
