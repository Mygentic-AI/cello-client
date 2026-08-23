/**
 * DOD-M15-SEAL-FAILED-TERMINAL-1 — a seal that FAILED is discoverable, not just a slow one.
 *
 * ─── What an agent lives through ───────────────────────────────────────────────────────────────
 *
 * `DOD-M15-CLOSEWAIT-1` made the close answer at commitment. So:
 *
 *   1. the agent closes and is told `ok: true, seal_status: "committed"` — and told to fetch the
 *      receipt later;
 *   2. the background ceremony THROWS (directory unreachable, agent not started, carry unusable);
 *   3. the session stays `active`, holding a durable commitment, with **nothing retrying**;
 *   4. the agent asks for the receipt and is told… what?
 *
 * Before this unit: `not_sealed_yet`, byte-identical to a session that was never closed. The only
 * account of the failure was a `session.seal.background.failed` line in `daemon.log`, which is not a
 * surface an agent can read. It holds an `ok: true` and has no reason to suspect anything is wrong.
 *
 * `seal_in_progress` distinguishes RUNNING from NO-CEREMONY. Neither of those is DEAD.
 *
 * ─── The ordering property, which is the one worth getting right ───────────────────────────────
 *
 * A re-close is the documented remedy for a failed seal. If the failure marker survived that retry,
 * the agent would be told the seal is dead **while it is running** — a stale reading presented as
 * current, which is `DOD-M15-STALEROSTER-1`'s defect in a different subsystem. So a running ceremony
 * outranks a recorded failure, and starting one clears the marker.
 */

import { describe, it, expect } from "vitest";
import { SealFailureStore, describeSealFailed } from "../seal-failure-store.js";

const AGENT = "agent-a";
const SESSION = "ab".repeat(16);
const AT = "2026-08-23T04:00:00.000Z";

describe("DOD-M15-SEAL-FAILED-TERMINAL-1: remembering a dead ceremony", () => {
  it("a session with no failure has none recorded", () => {
    expect(new SealFailureStore().get(AGENT, SESSION)).toBeUndefined();
  });

  it("★ a recorded failure survives the read — that is the whole point", () => {
    const s = new SealFailureStore();
    s.record(AGENT, SESSION, "directory_unreachable", AT);
    expect(s.get(AGENT, SESSION)?.reason).toBe("directory_unreachable");
    expect(s.get(AGENT, SESSION)?.reason, "reading must not consume it").toBe("directory_unreachable");
  });

  it("★ clearing forgets it, because a new ceremony makes the old verdict false", () => {
    const s = new SealFailureStore();
    s.record(AGENT, SESSION, "directory_unreachable", AT);
    s.clear(AGENT, SESSION);
    expect(
      s.get(AGENT, SESSION),
      "a re-close is the documented remedy; if the marker outlived the retry the agent would be " +
        "told the seal is dead while it is running",
    ).toBeUndefined();
  });

  it("★ two agents holding the SAME session id do not share a failure", () => {
    /**
     * The loopback case is real and supported — `DOD-LOOP-1` exists because both of an operator's
     * own agents can hold the two ends of one session on one daemon. Keying on session id alone
     * would let one end's failed ceremony report the other end's seal as dead.
     */
    const s = new SealFailureStore();
    s.record("agent-a", SESSION, "directory_unreachable", AT);
    expect(s.get("agent-b", SESSION), "the other end's seal is a different ceremony").toBeUndefined();
  });

  it("the key cannot be forged by a name containing the separator", () => {
    // `${agent}\x1f${session}` — a delimiter no agent name can contain, so "a\x1fb" + "c" cannot
    // collide with "a" + "\x1fbc". Concatenation without one is how two sessions become one entry.
    const s = new SealFailureStore();
    s.record("a", "bc", "first", AT);
    s.record("ab", "c", "second", AT);
    expect(s.get("a", "bc")?.reason).toBe("first");
    expect(s.get("ab", "c")?.reason).toBe("second");
  });
});

describe("DOD-M15-SEAL-FAILED-TERMINAL-1: what the agent is told", () => {
  const failed = () => describeSealFailed({ sessionId: SESSION, failure: { reason: "ceremony_exhausted", at: AT } });

  it("★ it is NOT ok, and says failed rather than pending", () => {
    const d = failed();
    expect(d["ok"]).toBe(false);
    expect(d["reason"]).toBe("seal_failed");
    expect(d["seal_status"]).toBe("failed");
  });

  it("★ it carries the UPSTREAM cause, not a label invented here", () => {
    /**
     * "The seal failed" tells an operator nothing about whether their directory is unreachable,
     * their agent is not started, or the carry was unusable — three different fixes. Replacing the
     * cause with an exit-point label is the substitution this milestone keeps finding.
     */
    expect(failed()["seal_failure_reason"]).toBe("ceremony_exhausted");
    expect(String(failed()["guidance"])).toContain("ceremony_exhausted");
  });

  it("★ it says nothing is retrying — the difference from seal_in_progress", () => {
    expect(
      String(failed()["guidance"]),
      "an agent that reads this as 'still running' will wait forever, because nothing is",
    ).toMatch(/not "still running"|nothing is retrying/i);
  });

  it("★ it names the remedy that WORKS, and the one that destroys the receipt", () => {
    const g = String(failed()["guidance"]);
    expect(g, "re-closing starts a fresh ceremony — that is the fix").toContain("cello_close_session");
    expect(g, "and force must be named as the irreversible one").toMatch(/force/);
    expect(g).toMatch(/PERMANENTLY forfeits/);
  });

  it("★ it says the conversation is intact, so nobody panics", () => {
    /**
     * The failure is that a receipt was not produced, NOT that anything was lost. An agent that
     * reads a seal failure as data loss will do something drastic — and the drastic option here
     * (force) is the only one that actually destroys anything.
     */
    expect(String(failed()["guidance"])).toMatch(/intact|not lost|only unproduced/i);
  });
});
