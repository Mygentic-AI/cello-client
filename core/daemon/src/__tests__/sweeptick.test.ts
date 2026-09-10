/**
 * 048-SWEEPTICK / DOD-M15-SWEEPTICK-1 — collection cannot wait for a reconnect.
 *
 * 043-SIGNALDELIVERY C2 built the sweep and wired it to `onConnected` and to nothing else. So
 * collection happened once per CONNECTION: a daemon that connects in the morning and stays up never
 * swept again, whatever arrived at the other nodes meanwhile.
 *
 * Measured, not argued — a signal sat 23 minutes at a node this daemon was not attached to, on a
 * fleet with nothing wrong with it, and arrived the instant the daemon was restarted. The sweep
 * inherited the shape of the very defect it was built to fix: the mechanism exists, it is correct,
 * and nothing runs it often enough to matter.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { createTrustSignalSweepTicker, SWEEP_TICK_INTERVAL_MS } from "../trust-signal-sweep-tick.js";
import { createTrustSignalSweep, type SweepResult } from "../trust-signal-sweep.js";

const noop = () => {};
const silent = { debug: noop, info: noop, warn: noop, error: noop } as never;
const KP = {} as never;

const EMPTY: SweepResult = { visited: [], unreachable: [], incomplete: [], rosterUnavailable: false };

afterEach(() => { vi.useRealTimers(); });

/** A sweep that records every call and resolves immediately. */
function recordingSweep() {
  const calls: string[] = [];
  const sweep = vi.fn(async (agentName: string) => { calls.push(agentName); return EMPTY; });
  return { calls, sweep: sweep as never };
}

describe("048-SWEEPTICK — the tick", () => {
  it("SWEEPS AGAIN WHILE THE CONNECTION STAYS UP — the whole point of the unit", async () => {
    // THE REVERT TEST. Remove the interval and this must show exactly ONE sweep for the life of the
    // connection, which is the behaviour that let a signal sit for 23 minutes.
    vi.useFakeTimers();
    const { calls, sweep } = recordingSweep();
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa");
    expect(calls, "the onConnected sweep still happens immediately").toEqual(["alice"]);

    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    expect(calls, "and twice more without the connection ever dropping").toEqual(["alice", "alice", "alice"]);

    ticker.stopAll();
  });

  it("sweeps IMMEDIATELY on the connect trigger, not one interval later", async () => {
    // `onConnected` keeps its trigger — a daemon back from a closed laptop must not wait out an
    // interval before collecting. This adds a second trigger; it does not move the first.
    vi.useFakeTimers();
    const { calls, sweep } = recordingSweep();
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa");
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS - 1);
    expect(calls, "nothing extra before the interval elapses").toHaveLength(1);

    ticker.stopAll();
  });

  it("does NOT sweep for an agent that is OFFLINE — round trips for nobody", async () => {
    vi.useFakeTimers();
    const { calls, sweep } = recordingSweep();
    let online = true;
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => online });

    await ticker.sweepAndTick("alice", KP, "aa");
    expect(calls).toHaveLength(1);

    online = false;                                    // the kill switch, or cello_set_agent_offline
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 3);
    expect(calls, "three intervals pass and nothing is swept").toHaveLength(1);

    online = true;                                     // back online WITHOUT a signaling reconnect
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    expect(calls, "the tick resumes on its own — see the module docblock on why it does not self-stop")
      .toHaveLength(2);

    ticker.stopAll();
  });

  it("arms ONE tick per agent however many times the connect trigger fires", async () => {
    // A flapping stream fires `onConnected` repeatedly. Arming a second interval each time would
    // multiply the fleet load by the flap count — silently, because each sweep on its own is
    // correct.
    vi.useFakeTimers();
    const { calls, sweep } = recordingSweep();
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa");
    await ticker.sweepAndTick("alice", KP, "aa");
    await ticker.sweepAndTick("alice", KP, "aa");
    expect(calls, "three connects, three immediate sweeps").toHaveLength(3);

    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    expect(calls, "but only ONE tick fired").toHaveLength(4);

    ticker.stopAll();
  });

  it("ticks each agent independently", async () => {
    vi.useFakeTimers();
    const { calls, sweep } = recordingSweep();
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: (n) => n === "alice" });

    await ticker.sweepAndTick("alice", KP, "aa");
    await ticker.sweepAndTick("bob", KP, "bb");
    calls.length = 0;

    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    expect(calls, "bob is offline, alice is not").toEqual(["alice"]);

    ticker.stopAll();
  });

  it("stop() ends one agent's tick and leaves the others running", async () => {
    vi.useFakeTimers();
    const { calls, sweep } = recordingSweep();
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa");
    await ticker.sweepAndTick("bob", KP, "bb");
    calls.length = 0;

    ticker.stop("alice");
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    expect(calls).toEqual(["bob"]);

    ticker.stopAll();
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 2);
    expect(calls, "stopAll ends the rest").toEqual(["bob"]);
  });

  it("a sweep that THROWS on a tick is REPORTED by name, and the tick survives", async () => {
    /**
     * ⚠️ THE FIRST VERSION OF THIS TEST WAS HOLLOW, and it is worth saying how. It asserted only
     * that a third tick still ran — which is true of `setInterval` whether or not anything catches.
     * Deleting the `.catch` left it green, with nothing but an "Unhandled Rejection" line in the
     * reporter that the suite still counted as passing. It was testing the timer, not the handling.
     *
     * The property is that the failure is NAMED somewhere an operator can find it. A background
     * sweep failing in silence is exactly how the original defect survived for weeks, so the
     * assertion is on the log event and its reason, not on the tick count alone.
     */
    vi.useFakeTimers();
    const warnings: { event: string; fields: Record<string, unknown> }[] = [];
    const logger = {
      debug: noop, info: noop, error: noop,
      warn: (event: string, fields: Record<string, unknown>) => { warnings.push({ event, fields }); },
    } as never;
    const calls: string[] = [];
    const sweep = vi.fn(async (agentName: string) => {
      calls.push(agentName);
      if (calls.length === 2) throw new Error("node exploded");
      return EMPTY;
    }) as never;
    const ticker = createTrustSignalSweepTicker({ logger, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa");
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);   // this one throws
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);

    const failure = warnings.find((w) => w.event === "trust_signal.sweep.tick_failed");
    expect(failure, "the failure is reported, not swallowed").toBeDefined();
    expect(failure?.fields).toMatchObject({ agentName: "alice", reason: "node exploded" });
    expect(calls, "and the third tick still ran").toHaveLength(3);

    ticker.stopAll();
  });

  it("does not hold the process open", async () => {
    // A 5-minute interval that keeps the event loop alive would stop the daemon exiting for up to
    // five minutes after everything else had shut down.
    vi.useFakeTimers();
    const unref = vi.fn();
    const spy = vi.spyOn(globalThis, "setInterval").mockImplementation(((fn: () => void, ms: number) => {
      void fn; void ms;
      return { unref } as unknown as NodeJS.Timeout;
    }) as never);
    try {
      const { sweep } = recordingSweep();
      const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });
      await ticker.sweepAndTick("alice", KP, "aa");
      expect(unref).toHaveBeenCalled();
      ticker.stopAll();
    } finally {
      spy.mockRestore();
    }
  });
});

describe("048-SWEEPTICK — the tick must not become a second source of log noise", () => {
  it("says it is skipping ONCE per offline stretch, not once per tick", async () => {
    // The tick is armed for EVERY loaded agent at boot, online or not. At one info line per tick
    // that is 288 a day per idle agent, all of them saying the system works as designed — and this
    // milestone already has an order open because daemon.log reached 176 MB of one condition
    // talking to itself. The line has to mark the TRANSITION.
    vi.useFakeTimers();
    const events: string[] = [];
    const logger = {
      debug: noop, warn: noop, error: noop,
      info: (event: string) => { events.push(event); },
    } as never;
    const { sweep } = recordingSweep();
    let online = false;
    const ticker = createTrustSignalSweepTicker({ logger, sweep, isAgentOnline: () => online });

    await ticker.sweepAndTick("alice", KP, "aa");
    events.length = 0;

    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 5);
    expect(events.filter((e) => e === "trust_signal.sweep.tick_skipped"), "five ticks, one line").toHaveLength(1);

    online = true;
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS);
    expect(events, "and coming back is stated, so the gap in the log has two ends")
      .toContain("trust_signal.sweep.tick_resumed");

    online = false;
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 3);
    expect(events.filter((e) => e === "trust_signal.sweep.tick_skipped"), "a NEW stretch says so again").toHaveLength(2);

    ticker.stopAll();
  });

  it("forwards homeNodeId on every tick, not only on the connect sweep", async () => {
    // Inert today — nothing supplies it. It is asserted because the two paths diverging silently is
    // what would happen the moment someone wires it: connect would skip home, every tick would
    // visit it.
    vi.useFakeTimers();
    const seen: (string | undefined)[] = [];
    const sweep = vi.fn(async (_n: string, _k: unknown, _p: string, homeNodeId?: string) => {
      seen.push(homeNodeId); return EMPTY;
    }) as never;
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa", "gcp-use1");
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 2);
    expect(seen).toEqual(["gcp-use1", "gcp-use1", "gcp-use1"]);

    ticker.stopAll();
  });
});

describe("048-SWEEPTICK — a sweep says WHICH trigger fired it", () => {
  it("the connect sweep says `connect` and the tick says `tick`", async () => {
    /**
     * ⚠️ ADDED BECAUSE THE UNIT COULD NOT BE VERIFIED ON A LIVE DAEMON. The two triggers produced
     * byte-identical log lines, and signaling turns its stream over often enough that a tick's sweep
     * lands inside a burst of reconnect-driven ones — measured 2026-09-10, sweeps at 19:05:20 and
     * 19:05:21 sitting inside reconnects at 19:05:16/18/19/20/21. Every candidate observation was
     * equally explained by the trigger this unit was meant to supplement, so nothing could be shown.
     *
     * That is this unit's own defect one level up: 043-C2's sweep was correct and unobservable, so
     * nobody noticed it ran once per connection.
     */
    vi.useFakeTimers();
    const triggers: (string | undefined)[] = [];
    const sweep = vi.fn(async (_n: string, _k: unknown, _p: string, _h?: string, trigger?: string) => {
      triggers.push(trigger); return EMPTY;
    }) as never;
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    await ticker.sweepAndTick("alice", KP, "aa");
    expect(triggers, "the onConnected path names itself").toEqual(["connect"]);

    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 2);
    expect(triggers, "and the two ticks are distinguishable from it").toEqual(["connect", "tick", "tick"]);

    ticker.stopAll();
  });
});

describe("048-SWEEPTICK — overlap is the EXISTING guard's job, not a second mechanism", () => {
  it("a tick that lands while a sweep is still running does not start a second one", async () => {
    // Composed over the REAL createTrustSignalSweep, because the property belongs to its in-flight
    // set (043-SIGNALDELIVERY C2 review, finding 4). A ticker that carried its own guard would pass
    // this test while leaving the real one unexercised — and two guards for one property is how
    // they drift.
    vi.useFakeTimers();
    // A node that connects and NEVER sends the terminal frame, so the sweep sits on its ceiling and
    // is still in flight when the tick lands.
    const openVisitingConnection = vi.fn(() => ({
      mgr: { status: "connected", registerInboundHandler: noop },
      stop: async () => {},
    })) as never;
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => [{ nodeId: "n1", pubkey: "p", peerId: "pid", multiaddr: "/m" }] as never,
      openVisitingConnection,
      ceilingMs: SWEEP_TICK_INTERVAL_MS * 4,          // outlives several ticks
    });
    const ticker = createTrustSignalSweepTicker({ logger: silent, sweep, isAgentOnline: () => true });

    void ticker.sweepAndTick("alice", KP, "aa");      // starts, and stays in flight
    await vi.advanceTimersByTimeAsync(SWEEP_TICK_INTERVAL_MS * 2);

    expect(
      (openVisitingConnection as unknown as { mock: { calls: unknown[] } }).mock.calls.length,
      "two ticks landed during one sweep and neither opened a second connection",
    ).toBe(1);

    ticker.stopAll();
  });
});

describe("048-SWEEPTICK — the interval", () => {
  it("is five minutes, and the number is stated where it is chosen", () => {
    // Each tick opens a visiting connection to every other node and triggers that node's drain, so
    // this is fleet load. Pinned so moving it is a decision someone makes on purpose.
    expect(SWEEP_TICK_INTERVAL_MS).toBe(5 * 60_000);
  });
});

describe("048-SWEEPTICK — the wiring, because a unit test cannot see the composition root", () => {
  it("the signaling wiring is handed the TICKING sweep, not the bare one", async () => {
    /**
     * Every test above passes against a daemon that still hands `sweepTrustSignals` to
     * `getSweepTrustSignals`, because they exercise the ticker directly. That one-line revert would
     * restore the exact defect — collection on connect and never again — with a fully green suite,
     * which is how the original went unnoticed.
     *
     * `daemon.ts` sits on a `max-lines` ratchet and cannot grow a seam to inject, so this reads the
     * composition root. A source assertion is weak on its own; it is paired with the deliberate
     * failure below, which is what proves it can see.
     */
    const { readFile } = await import("node:fs/promises");
    const src = await readFile(new URL("../daemon.ts", import.meta.url), "utf8");

    // Positive control FIRST: prove the read reached the file we mean, before trusting a negative.
    expect(src, "positive control — the getter exists at all").toContain("getSweepTrustSignals:");
    expect(src).toContain("getSweepTrustSignals: () => sweepTrustSignalsAndTick");
    expect(src, "the bare sweep must not be the thing wired in").not.toContain("getSweepTrustSignals: () => sweepTrustSignals,");
    // And the ticks must be stopped on shutdown, or the daemon keeps sweeping while tearing down.
    expect(src).toContain("trustSignalSweepTicker.stopAll()");
    // The per-agent stop must actually reach the handlers, or `stop` is a method nothing calls.
    expect(src).toContain("stopSweepTick: (n: string) => trustSignalSweepTicker.stop(n)");
  });

  it("a REMOVED agent's tick is stopped — and an OFFLINE agent's deliberately is not", async () => {
    /**
     * The asymmetry is the finding, not an oversight, and it is asserted so nobody "fixes" it.
     *
     * Offline: the tick is already inert (it checks `isAgentOnline` before every sweep), and
     * cancelling it there would be a one-way door — `cello_set_agent_offline` leaves the signaling
     * manager connected, so a later `cello_start_agent` hits `getAgentSignaling`'s cached-entry
     * early return and fires no `onConnected`. Nothing would re-arm it.
     *
     * Removed: the agent is never coming back, so the timer should genuinely end rather than skip
     * every five minutes for a name that no longer exists.
     */
    const { readFile } = await import("node:fs/promises");
    const src = await readFile(new URL("../agent-handlers.ts", import.meta.url), "utf8");

    // Positive control: prove the read reached the file and found both handlers.
    expect(src, "positive control — removal handler").toContain("cello_remove_agent");
    expect(src, "positive control — offline handler").toContain("cello_set_agent_offline");

    // ⚠️ SLICED FROM THE HANDLER REGISTRATIONS, not from the first mention of each name — and the
    // first version of this got it wrong in the way that matters. It sliced between the two NAMES,
    // but `cello_remove_agent` is registered ABOVE `cello_set_agent_offline`, so the slice came out
    // EMPTY and `.not.toContain(...)` passed against nothing. Adding the call to the offline handler
    // on purpose left the test green. An empty search result is evidence only once the search has
    // been shown capable of finding something, which is what the two controls below do.
    const removeAt = src.indexOf('handlers.set("cello_remove_agent"');
    const offlineAt = src.indexOf('handlers.set("cello_set_agent_offline"');
    expect(removeAt, "positive control — removal handler is registered").toBeGreaterThan(-1);
    expect(offlineAt, "positive control — offline handler is registered").toBeGreaterThan(-1);

    const removal = src.slice(removeAt, offlineAt);
    const offline = src.slice(offlineAt);
    // Controls ON THE SLICES: each must contain something only that handler has, or the slice is
    // not the region it is named for and neither assertion below means anything.
    expect(removal, "control — the removal slice really is the removal handler").toContain("agent.removal.signaling_teardown_failed");
    expect(offline, "control — the offline slice really is the offline handler").toContain("agent.stop.receiver_teardown_failed");

    expect(removal, "removal stops the tick").toContain("stopSweepTick(name)");
    expect(offline, "offline does NOT — see the dep's docblock in agent-handlers.ts").not.toContain("stopSweepTick(");
  });
});
