/**
 * DOD-M15-DOORBELL-1 — a daemon shutdown does not ring like an incoming message.
 *
 * ─── What happens to an operator today ─────────────────────────────────────────────────────────
 *
 * The agent's standing contract is: **the doorbell rings, you call the inbox.** That is the whole
 * point of the channel — an agent should not have to reason about which notification means what
 * before acting, and every skill in the repo tells it to read when woken.
 *
 * `shutdown` rides the same channel with the same shape. So the daemon dies, the doorbell rings, the
 * agent does exactly what it was told, and `cello_inbox` answers `daemon_not_running` — an error
 * that reads like a protocol fault. The agent reports CELLO is broken.
 *
 * Meanwhile the thing that actually happened — *your daemon stopped, run `cello login`* — goes
 * unreported, because the agent is busy explaining a failure it was led into.
 *
 * ─── Why fixing only the words was not enough ──────────────────────────────────────────────────
 *
 * The body already says "Tools will fail until you run `cello login`", and that is worth having.
 * But an agent following a standing instruction acts on the SHAPE before it weighs the prose, and
 * an instruction that competes with a sentence in a body is the weaker of the two. `DOD-M15-
 * GUARD-HEARD-1` is the same lesson: a signal whose only consumer has to notice it is not a
 * control.
 *
 * So the frame carries a machine-readable disposition. The DoD line offers two options — *"either
 * do not forward shutdown through the channel, or give it distinguishable metadata"* — and
 * suppressing it is the wrong one: the daemon dying is precisely the event an operator must know
 * about, and the previous version of this file records that it was already made LOUDER on purpose.
 */

import { describe, it, expect } from "vitest";
import { buildChannelParams } from "../channel-params.js";

/** Every doorbell type the shim can forward, from the switch that renders them. */
const INBOX_DOORBELLS = ["cello_message", "cello_session_request", "daemon_reconnected"] as const;
const HOUSEKEEPING = ["shutdown", "agent_state_changed", "agent_current_changed"] as const;

describe("DOD-M15-DOORBELL-1: a shutdown is distinguishable from an invitation to read", () => {
  it("shutdown carries a disposition an agent can BRANCH on, not just prose", () => {
    const { meta, content } = buildChannelParams({}, "shutdown");
    expect(
      meta["wake_action"],
      `The shutdown doorbell carries no machine-readable disposition. An agent following its ` +
        `standing "doorbell → read the inbox" contract will call cello_inbox, get ` +
        `daemon_not_running, and report a protocol failure — while the real event (the daemon ` +
        `stopped) goes unreported.`,
    ).toBe("none");
    // The prose stays: it is what a human reads, and it names the recovery.
    expect(content).toMatch(/cello login/);
  });

  it("a real doorbell still says READ — the distinction has to cut both ways", () => {
    /**
     * The counterexample. A disposition that said "none" everywhere would stop the false alarm and
     * also stop every real message being read, which is a far worse defect and would look like the
     * protocol silently dropping conversations.
     */
    for (const type of INBOX_DOORBELLS) {
      const { meta } = buildChannelParams({ agent: "alice" }, type);
      expect(meta["wake_action"], `${type} must still tell the agent to read`).toBe("read_inbox");
    }
  });

  it("EVERY housekeeping event is marked as not-an-inbox-event, not just shutdown", () => {
    /**
     * `shutdown` is the one that was measured, but it is not the only frame that wakes an agent
     * with nothing to read. An agent-state change and a reconnect ring the same bell and have the
     * same effect: a wasted inbox call, and on a dead daemon an error that reads like a fault.
     *
     * Enumerated rather than fixed one-by-one, for the reason GUARD-HEARD-1 landed on: fixing the
     * measured instance leaves the next one to be discovered in the field.
     */
    for (const type of HOUSEKEEPING) {
      const { meta } = buildChannelParams({ agent: "alice" }, type);
      expect(meta["wake_action"], `${type} wakes an agent with nothing to read`).toBe("none");
    }
  });

  it("an UNKNOWN future type defaults to read — absence must not silence a real doorbell", () => {
    /**
     * The fail-safe direction, and it is the opposite of the one instinct suggests.
     *
     * A new message-bearing doorbell added to the daemon before this file learns about it must still
     * be read. Defaulting to "none" would make the new type silently ignored — a conversation that
     * never gets answered, with nothing anywhere reporting a problem. Defaulting to "read" costs at
     * worst one empty inbox call.
     */
    const { meta } = buildChannelParams({ agent: "alice" }, "cello_some_future_doorbell");
    expect(meta["wake_action"]).toBe("read_inbox");
  });

  it("the disposition cannot be spoofed by the daemon frame's own data", () => {
    /**
     * `meta` is built by copying scalar fields out of the daemon's `data` blob, so a frame carrying
     * `wake_action` must not be able to overwrite the shim's decision.
     *
     * WHAT THIS TEST DOES AND DOES NOT PIN, because I got it wrong once: there are TWO mechanisms —
     * an explicit skip in the copy loop, and the fact that the shim's assignment runs after the
     * loop and overwrites it. Revert-testing showed the second is what carries the property today:
     * deleting the skip leaves this green. The skip is kept because the protection it duplicates is
     * positional, and reordering is a plausible tidy-up.
     *
     * So this asserts the PROPERTY (a frame cannot spoof it), not either mechanism. That is the
     * right level — but it means the skip has no test of its own, and pretending otherwise would be
     * the hollow-test shape this milestone keeps finding.
     */
    const { meta } = buildChannelParams({ agent: "alice", wake_action: "none" }, "cello_message");
    expect(meta["wake_action"], "a frame must not be able to talk the agent out of reading").toBe("read_inbox");
  });
});
