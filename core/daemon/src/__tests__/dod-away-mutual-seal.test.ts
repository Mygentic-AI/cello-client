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
 * Matched on the EXACT text, never a substring: a human who happens to quote the away message should
 * be answered normally, and a loose match would silence real messages. The texts are this daemon's
 * own constants, so a foreign implementation's away text will not match — and it also will not be
 * ping-ponging with ours, because the loop needs both sides running this logic.
 */

import { describe, it, expect } from "vitest";
import { isOwnAwayAutoReply, AWAY_AUTO_REPLY_TEXTS, AWAY_AUTO_REPLY_MARKER } from "../away-detection.js";

const ONE_SHOT = "Agent is currently away. Your message has been received and will be read when the operator returns. This inbox accepts one message per visit — please close the session now (send with signal: wrap) instead of sending more.";
const OFFER = "Alice is currently away. Leave a message (send with signal: wrap to close) and it will be read when they return.";

describe("an away responder recognises another away responder", () => {
  it("recognises the one-shot away acknowledgement", () => {
    expect(isOwnAwayAutoReply(ONE_SHOT)).toBe(true);
  });

  it("recognises the per-agent away offer, whatever the agent is called", () => {
    // The offer text is built per agent, so the check cannot be a fixed-string equality on one name.
    expect(isOwnAwayAutoReply(OFFER)).toBe(true);
    expect(isOwnAwayAutoReply("Miss_Chelly is currently away. Leave a message (send with signal: wrap to close) and it will be read when they return.")).toBe(true);
  });

  it("does NOT match a human message that merely mentions being away", () => {
    // The guard against over-matching. Silencing a real message is a worse failure than the one
    // being fixed: the operator would never learn it arrived.
    for (const human of [
      "I am currently away from my desk, can we talk tomorrow?",
      "away",
      "Are you away? Leave a message and I will read it when I return.",
      "",
    ]) {
      expect(isOwnAwayAutoReply(human), `'${human.slice(0, 40)}' must be treated as a real message`).toBe(false);
    }
  });

  it("exposes the texts it matches, so the check cannot drift from what is actually sent", () => {
    // Both the detector and the sender read this list. A second hardcoded copy is how a reworded
    // away message would silently stop being recognised, and the loop would come back.
    //
    // DOD-M12B-AWAY-MARK-1: what this daemon SENDS now carries the marker; ONE_SHOT and OFFER above
    // are the pre-marker bodies, kept verbatim because the two tests at the top of this file assert
    // an un-upgraded peer's away reply is still recognised. Both facts are pinned here at once —
    // the sent text is the marker plus the unchanged body, so neither the wording nor the marker
    // can drift away from the detector without failing.
    expect(AWAY_AUTO_REPLY_TEXTS.oneShot).toBe(`${AWAY_AUTO_REPLY_MARKER} ${ONE_SHOT}`);
    expect(AWAY_AUTO_REPLY_TEXTS.offerFor("Alice")).toBe(`${AWAY_AUTO_REPLY_MARKER} ${OFFER}`);
  });
});
