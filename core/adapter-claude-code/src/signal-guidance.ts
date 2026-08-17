/**
 * The `signal` vocabulary for `cello_send`, and the refusal an agent gets when it omits it.
 *
 * This lives in its own module for one reason: the accepted values and the guidance that names
 * them must be the SAME list. `DOD-M12B-SIGNAL-GUIDANCE-1` was exactly that drift — the schema
 * wanted a parameter and the refusal described a token you type into the message, so an agent
 * doing precisely what it was told got the same refusal forever.
 */

/** The values `cello_send` accepts. The zod enum and the guidance are both built from this. */
export const SIGNAL_VALUES = ["over", "standby", "wrap"] as const;

export type SignalValue = (typeof SIGNAL_VALUES)[number];

/**
 * Returned as `guidance` alongside `reason: "missing_signal"`.
 *
 * Every line here is written to be executed by a machine that will not read the docs: it names the
 * parameter, shows the call, and deliberately shows NO `[[…]]` token — a token displayed in a
 * refusal is a token that ends up pasted into `content`, which is the failure this replaced.
 */
export const SIGNAL_ERROR =
  "Missing the required `signal` parameter.\n\n" +
  "`signal` is a PARAMETER of cello_send, alongside `content`. It is not something you write\n" +
  "into the message text — cello_send composes the wire token itself from this parameter, and\n" +
  "anything you type into `content` is treated as message text and will not satisfy this check.\n" +
  "Re-send the same call with `signal` set to one of:\n\n" +
  "  signal: \"over\"\n" +
  "    Your turn is complete. You are now entering read mode and waiting for\n" +
  "    a reply. Use this for most messages.\n\n" +
  "  signal: \"standby\", est_minutes: <number>\n" +
  "    Your turn is not yet complete, but your full response will take time.\n" +
  "    Use this when you want to acknowledge immediately — letting the other\n" +
  "    party know you received their message and are working on it — before\n" +
  "    going off to do the work. `est_minutes` is your estimate in minutes and\n" +
  "    is required with this signal. The other party does not need to reply; a\n" +
  "    follow-up message is coming from you in approximately that many minutes.\n\n" +
  "  signal: \"wrap\"\n" +
  "    This is your final message. You intend to close the session after\n" +
  "    sending. No reply is expected or needed.\n\n" +
  "Example: cello_send({ cello_session_id: \"…\", content: \"…\", signal: \"over\" })\n" +
  "     or: cello_send({ cello_session_id: \"…\", content: \"…\", signal: \"standby\", est_minutes: 10 })";

/**
 * Returned as `guidance` alongside `reason: "missing_est_minutes"`.
 *
 * Lives here rather than inline at the call site because it is the refusal you land on by TAKING
 * the `standby` remedy above — the two are one path, and a caller who follows the first message into
 * the second must not find the second written to a different standard. `10` is a real number rather
 * than a `<placeholder>` for the same reason the marker prose shows a real call: whatever a refusal
 * displays is what gets pasted back.
 */
export const EST_MINUTES_ERROR =
  "Missing the required `est_minutes` parameter, which `signal: \"standby\"` needs.\n\n" +
  "`est_minutes` is a PARAMETER of cello_send, a positive number of minutes until the follow-up\n" +
  "message you are promising. Re-send the same call with both parameters set, for example:\n\n" +
  "  cello_send({ cello_session_id: \"…\", content: \"…\", signal: \"standby\", est_minutes: 10 })\n\n" +
  "If you are not going away to do work, you do not want standby — use signal: \"over\" instead and\n" +
  "go straight to cello_receive.";
