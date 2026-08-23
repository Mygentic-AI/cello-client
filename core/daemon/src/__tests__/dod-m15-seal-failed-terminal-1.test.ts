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
    s.record(AGENT, SESSION, "directory_unreachable", AT, "unresolved");
    expect(s.get(AGENT, SESSION)?.reason).toBe("directory_unreachable");
    expect(s.get(AGENT, SESSION)?.reason, "reading must not consume it").toBe("directory_unreachable");
  });

  it("★ clearing forgets it, because a new ceremony makes the old verdict false", () => {
    const s = new SealFailureStore();
    s.record(AGENT, SESSION, "directory_unreachable", AT, "unresolved");
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
    s.record("agent-a", SESSION, "directory_unreachable", AT, "unresolved");
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
  const failed = () => describeSealFailed({ sessionId: SESSION, failure: { reason: "ceremony_exhausted", at: AT, kind: "threw" } });

  it("★ it is NOT ok, and says failed rather than pending", () => {
    const d = failed();
    expect(d["ok"]).toBe(false);
    expect(d["reason"]).toBe("seal_failed");
    expect(d["seal_status"]).toBe("failed");
  });

  it("★ a RESOLVED failure reads as 'unresolved', not as an error — review HIGH-1", () => {
    /**
     * The distinction the first cut could not make, and the reason it closed almost none of the gap:
     * `escalateToUnilateralSeal` has ZERO throws, so all nine real failure paths RESOLVE. Recording
     * only in the `.catch` meant every ordinary dead ceremony went unrecorded.
     *
     * They also need different words. An exception is usually a local fault; a resolved failure is
     * most often "the counterparty has not closed yet", which is not an error at all.
     */
    const d = describeSealFailed({ sessionId: SESSION, failure: { reason: "seal_unilateral_timeout", at: AT, kind: "unresolved" } });
    expect(d["seal_status"]).toBe("unresolved");
    expect(
      String(d["guidance"]),
      "it must tell the agent to READ the reason before acting — waiting is right for a " +
        "counterparty who has not closed, and wrong for a local fault",
    ).toMatch(/seal_counterparty_pending|other side has not closed/i);
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

describe("DOD-M15-SEAL-FAILED-TERMINAL-1: the daemon actually wires the store", () => {
  /**
   * Asserted at the wiring, because a module test proving the helper works has failed to notice a
   * missing daemon call THREE times in this milestone — the roster sweep, its probe budget, and the
   * manifest validity tick. Each time the module tests were green and the daemon never called it.
   *
   * The writer is the close handler's detached tail; the reader is `cello_get_sealed_receipt`. The
   * property is that they share ONE store, so a failure recorded by the tail is the one the receipt
   * surface reports.
   */
  const AGENT2 = "agent-a";
  const SESSION2 = "cd".repeat(16);

  async function readHandlerWith(failure: { reason: string; at: string; kind: "unresolved" | "threw" } | undefined, sealing: boolean) {
    const { registerSessionReadHandlers } = await import("../session-read-handlers.js");
    const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
    registerSessionReadHandlers({
      handlers,
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      sessionNodeManager: {
        getSealCertificate: () => null,
        getSessionRecord: () => ({ agent_name: AGENT2, agent_id: "aid", session_id: SESSION2, status: "active" }),
        getSessionTree: () => ({ leaves: () => [] }),
        listSessions: () => [],
        resolveAgentId: () => "aid",
      },
      loadedAgents: [{ name: AGENT2 }],
      getConnState: () => ({ currentAgent: AGENT2 }),
      resolveCurrentAgent: () => AGENT2,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
      resolveWho: () => ({ who: "someone", whoKnown: false }),
      isSealing: () => sealing,
      getSealFailure: () => failure,
      safeCursorAdvance: () => {},
      safeWatermarkAdvance: () => {},
      attendanceCount: () => 0,
      reapDeadHalfOpenSessions: () => {},
      frontierMismatches: { get: () => undefined },
    } as never);
    return handlers.get("cello_get_sealed_receipt")!;
  }

  it("★ a recorded failure reaches cello_sealed_receipt as seal_failed", async () => {
    const h = await readHandlerWith({ reason: "directory_below_threshold", at: AT, kind: "unresolved" }, false);
    const res = (await h({ session_id: SESSION2 }, "c1")) as Record<string, unknown>;
    expect(
      res["reason"],
      "the ceremony died and the receipt surface still reported not_sealed_yet — indistinguishable " +
        "from a session that was never closed, while the agent holds an ok:true from the close",
    ).toBe("seal_failed");
    expect(res["seal_failure_reason"]).toBe("directory_below_threshold");
  });

  it("★ a RUNNING ceremony outranks an old failure — the re-close remedy must not read as dead", async () => {
    /**
     * The ordering property. The marker is cleared when a ceremony starts, but the read must ALSO
     * prefer "running" — belt and braces, because getting this backwards tells an operator their
     * retry is dead while it is working, and the retry is the remedy this unit's own guidance names.
     */
    const h = await readHandlerWith({ reason: "stale_verdict", at: AT, kind: "unresolved" }, true);
    const res = (await h({ session_id: SESSION2 }, "c1")) as Record<string, unknown>;
    expect(res["reason"], "a running ceremony must win over a remembered failure").toBe("seal_in_progress");
  });

  it("no failure and no ceremony still reads as not_sealed_yet", async () => {
    const h = await readHandlerWith(undefined, false);
    const res = (await h({ session_id: SESSION2 }, "c1")) as Record<string, unknown>;
    expect(res["reason"]).toBe("not_sealed_yet");
  });
});

describe("DOD-M15-SEAL-FAILED-TERMINAL-1: the WRITE side is wired too", () => {
  /**
   * The revert test caught this: my wiring test injected `getSealFailure` directly, so it proved the
   * READER consults the store and said nothing about the WRITER filling it. Deleting the `record`
   * call in the detached tail — and deleting the `clear` on ceremony start — both stayed green.
   *
   * One layer up from the gap I had just written a comment about avoiding.
   */
  const AGENT3 = "agent-a";
  const SESSION3 = "ef".repeat(16);

  async function closeWith(opts: { throwInTail: boolean }) {
    const { registerCloseSessionHandler } = await import("../close-session-handler.js");
    const { SealFailureStore: Store } = await import("../seal-failure-store.js");
    const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
    const store = new Store();
    const backgroundSeals: Array<Promise<unknown>> = [];

    registerCloseSessionHandler({
      handlers,
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      sealFailures: store,
      registerBackgroundSeal: (p: Promise<unknown>) => { backgroundSeals.push(p); },
      sessionNodeManager: {
        getSessionRecord: () => ({ agent_name: AGENT3, agent_id: "aid", session_id: SESSION3, status: "active" }),
        submitSealLeaf: async () => ({ ok: true as const, sequenceNumber: 1, reportedRootHex: "aa".repeat(32) }),
        getSealCarry: () => [],
        getSealCertificate: () => null,
        resolveAgentId: () => "aid",
        setSessionName: () => {},
        sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0, heldOwn: 0, heldReceived: 0, diverged: false }),
      },
      getConnState: () => ({ currentAgent: AGENT3 }),
      resolveCurrentAgent: () => AGENT3,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
      // The seam that makes the TAIL throw: the escalation asks for the signing key.
      getKeyProvider: opts.throwInTail
        ? () => { throw new Error("key vault locked"); }
        : () => ({ getPublicKey: async () => new Uint8Array(32) }),
      signalingFor: () => ({ status: "connected" }),
      sendOver: async () => ({ ok: true }),
      waitForSignalingConnected: async () => true,
      openVisitingConnection: () => null,
      crossNodeBrokerBySession: new Map<string, string>(),
      sealKey: (a: string, s: string) => `${a}\x1f${s}`,
      sealInterruptedInProgress: new Set<string>(),
      pendingSealWaiters: new Map(),
      pendingUnilateralWaiters: new Map(),
      resolveConsortiumRoster: async () => [],
      unilateralTimeoutMs: 10,
      handleSealInterruptedFlow: async () => ({ ok: false, reason: "unused" }),
      handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
    } as never);

    return { close: handlers.get("cello_close_session")!, store, backgroundSeals };
  }

  it("★ a tail that THROWS records the failure in the store", async () => {
    const { close, store, backgroundSeals } = await closeWith({ throwInTail: true });
    const prev = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "20";
    try {
      const res = (await close({ session_id: SESSION3 }, "c1")) as Record<string, unknown>;
      expect(res["seal_status"], "PRECONDITION: the handed-off path").toBe("committed");
      await Promise.allSettled(backgroundSeals);
      const rec = store.get(AGENT3, SESSION3);
      expect(
        rec,
        "the background ceremony threw and nothing was recorded, so cello_sealed_receipt still " +
          "cannot tell a dead seal from a slow one — the whole point of this unit",
      ).toBeDefined();
      expect(rec?.reason, "and the upstream cause must survive, not a label").toContain("key vault locked");
    } finally {
      if (prev === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
      else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = prev;
    }
  }, 30_000);

  it("★ starting a NEW ceremony clears a previous failure — the retry must not read as dead", async () => {
    const { close, store, backgroundSeals } = await closeWith({ throwInTail: false });
    store.record(AGENT3, SESSION3, "a_previous_failure", "2026-01-01T00:00:00.000Z", "unresolved");
    const prev = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "20";
    try {
      await close({ session_id: SESSION3 }, "c1");
      expect(
        store.get(AGENT3, SESSION3),
        "the stale verdict survived the retry, so the agent is told the seal is dead while its " +
          "replacement ceremony is running — a stale reading presented as current. " +
          "(Asserting ABSENCE, not merely 'not the old reason': `.not.toBe(...)` would have passed " +
          "if clear() had been replaced by a record() of something else — review §4.)",
      ).toBeUndefined();
      await Promise.allSettled(backgroundSeals);
    } finally {
      if (prev === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
      else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = prev;
    }
  }, 30_000);
});
