/**
 * DOD-AWAY-MUTUAL-SEAL-1 — two away agents must not seal a conversation nobody had.
 *
 * ── THE SEQUENCE, measured from the relay's log 2026-08-09 ───────────────────────────────────────
 *
 * Two agents contact each other while BOTH are unattended:
 *
 *   1. A's away responder answers B.
 *   2. That answer arrives at B as an inbound message, so B's away responder answers A.
 *   3. That answer arrives at A as a SECOND inbound message — and the one-shot rule
 *      (`DOD-INBOX-ONESHOT-1`) exists for exactly that: "the caller ignored the leave-a-message
 *      instruction". A sends a `[[WRAP]]` rejection and initiates the seal.
 *   4. B does the same, for the same reason, within a second.
 *   5. Two distinct-sender SEAL ctrl leaves is precisely what triggers notarization. The relay
 *      sealed the session **three seconds after it opened**.
 *
 * The one-shot is not wrong about a human who keeps typing. It is wrong about another away
 * responder, which is not a caller ignoring anything — it is a machine answering a machine.
 *
 * ── WHAT IT COSTS ────────────────────────────────────────────────────────────────────────────────
 *
 * The session is now sealed and dead, and neither operator knows: the seal completion is pushed with
 * no pull twin, so both daemons still show `active`. They come back, find what looks like a live
 * conversation, and talk into a closed room. Every message delivers. Nothing is recorded. It
 * announces itself only at close, after the work is done — measured at 12 messages held against 6
 * witnessed, frozen 68 minutes.
 *
 * A notarized receipt was also minted for a "conversation" whose entire content is two machines
 * telling each other nobody is home. That is a receipt attesting to nothing anyone said.
 *
 * ── THE RULE ─────────────────────────────────────────────────────────────────────────────────────
 *
 * An away responder does not answer an away responder, and does not treat one as a caller who
 * ignored the one-shot instruction. Machine-to-machine away traffic ends the exchange quietly
 * instead of minting a seal.
 *
 * Recognised by the `[[AUTO-REPLY]]` marker at the FRONT of the text (DOD-M12B-AWAY-MARK-1), applied
 * at the single send choke point — so a configured away message carries it too. Anchored, never a
 * substring: a human who merely mentions the marker or the word "away" is answered normally.
 */

import { describe, it, expect } from "vitest";
import { isAutoReplyMarked, markAsAutoReply, AWAY_AUTO_REPLY_TEXTS, AWAY_AUTO_REPLY_MARKER } from "../away-detection.js";

describe("an away responder recognises another away responder", () => {
  it("recognises every away text this daemon sends — the offer for any agent, and the stranger reply", () => {
    expect(isAutoReplyMarked(AWAY_AUTO_REPLY_TEXTS.offerFor("Alice"))).toBe(true);
    expect(isAutoReplyMarked(AWAY_AUTO_REPLY_TEXTS.offerFor("Miss_Chelly"))).toBe(true);
    expect(isAutoReplyMarked(AWAY_AUTO_REPLY_TEXTS.stranger)).toBe(true);
  });

  it("recognises an operator's CONFIGURED away message once it is marked at the send choke point", () => {
    expect(isAutoReplyMarked(markAsAutoReply("Back Monday — leave a note."))).toBe(true);
  });

  it("does NOT match a human message that merely mentions being away, or the marker mid-text", () => {
    // Silencing a real message is a worse failure than the one being fixed: the operator would
    // never learn it arrived.
    for (const human of [
      "I am currently away from my desk, can we talk tomorrow?",
      "away",
      "Are you away? Leave a message and I will read it when I return.",
      `Did you mean to send ${AWAY_AUTO_REPLY_MARKER}?`,
      "",
    ]) {
      expect(isAutoReplyMarked(human), `'${human.slice(0, 40)}' must be treated as a real message`).toBe(false);
    }
  });

  it("marking is idempotent — a default text is not double-marked", () => {
    const once = AWAY_AUTO_REPLY_TEXTS.stranger;
    expect(markAsAutoReply(once)).toBe(once);
  });
});
