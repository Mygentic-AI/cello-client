/**
 * DOD-M15-RELAYLEAK-1 — relay clients are closed.
 *
 * ─── Two leaks, both verified in the code before being fixed ───────────────────────────────────
 *
 * A cached `AgentRelayClient` is not a cheap object: it holds an authenticated libp2p stream to a
 * relay and a reader loop. Leaking one is not untidiness — **the relay counts a reservation per
 * client and its slots are finite**, so a daemon that restarts repeatedly consumes them faster than
 * they are released. That is the "agents cannot get a reservation" failure the relay's own limits
 * note describes, seen from the other side.
 *
 * **1. Shutdown never closed them.** `gracefulShutdown` stops every session NODE and referenced
 * `relayClient` **zero times** across its whole body. `cello logout` left every cached client open
 * until the process itself exited.
 *
 * **2. A seal-only transport registered a session and never released it.** The seal transport
 * resolver has two branches: a LIVE one that reuses an existing session's client, and a DETACHED one
 * that builds and caches a client and calls `registerSession`. Nothing ever unregistered it — and
 * `#detachSessionRelay` closes a client only when `!client.hasSessions()`, so that predicate stayed
 * false **forever** and the client was immortal.
 *
 * ─── ⚠️ THE FIRST VERSION OF THIS FILE NEVER REACHED THE CODE IT TESTED ────────────────────────
 *
 * Review ran it and captured the actual return: `{"ok":false,"reason":"no_persisted_relay_endpoint"}`
 * with `builderCalled: 0`. `#resolveSealTransport` needs **three** conditions to take the detached
 * branch, and the first draft supplied none of them:
 *
 *   1. **No live `#activeNodes` entry** for the session — an entry short-circuits to the LIVE branch
 *      (or to `relay_unavailable`) and never falls through.
 *   2. **A persisted relay endpoint** on the `sessions` row (`relay_peer_id` + `relay_addrs`).
 *   3. **A standing receiver** for the agent.
 *
 * So `submitSealLeaf` returned *before the `try`*, the builder was never called, nothing was cached
 * and nothing was registered. One test was red; the other was green **for the wrong reason** and
 * stayed green with the fix reverted — it asserted `hasSessions() === false`, which was true because
 * `registerSession` had never run.
 *
 * `#setUpDetachedSeal` below builds all three through PRODUCTION entry points, and it builds the
 * real scenario rather than a convenient one: a session whose node is gone (`destroySessionNode(…,
 * "interrupted")`) while its relay endpoint survives on the row. **That is precisely the case the
 * detached path exists for** — a daemon that restarted, marked the session interrupted, and now has
 * to seal it.
 *
 * ⚠️ **Every test here asserts the branch was ENTERED before asserting anything about it.** That is
 * the guard against this exact regression: if a future change sends the resolver back out through
 * `no_persisted_relay_endpoint`, these go red on the precondition instead of passing vacuously.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { AgentRelayClient } from "../session-relay-client.js";

const SID = "1d".repeat(32);
const RELAY_PEER = "12D3KooWRelayForSealLeak000000000000000000000";
const RELAY_ADDRS = ["/ip4/127.0.0.1/tcp/4001"];

/** A relay client that records what was asked of it and nothing else. */
function makeFakeRelayClient(): AgentRelayClient & {
  closed: number;
  sessions: Set<string>;
  /** Every id ever registered — survives release, so a test can prove registration HAPPENED. */
  registered: string[];
  /** Completed submits — a 0 here means the tests are exercising the throw path, not the real one. */
  submitCount: () => number;
} {
  const sessions = new Set<string>();
  const registered: string[] = [];
  let submits = 0;
  const fake = {
    closed: 0,
    sessions,
    registered,
    registerSession(sessionId: string) { sessions.add(sessionId); registered.push(sessionId); },
    unregisterSession(sessionId: string) { sessions.delete(sessionId); },
    hasSessions() { return sessions.size > 0; },
    // Required by the release-claim check. Omitting it made `#resolveSealTransport` throw a
    // TypeError that the old `.catch(() => undefined)` swallowed whole — see `submitSeal` below.
    hasSession(sessionId: string) { return sessions.has(sessionId); },
    /**
     * ⚠️ **THE TESTS USED TO PASS WITHOUT THIS, AND THAT WAS THE PROBLEM.** With no `submitLeaf` on
     * the fake, the submit threw a TypeError and the release was only ever exercised on the THROW
     * path — the `finally` runs there too, so the leak assertions still held and nothing said the
     * normal path had never been tried. Returning a successful submit makes these tests cover the
     * case that actually happens: a submit that COMPLETES, and a client that must be released after.
     */
    submitLeaf() { submits += 1; return Promise.resolve({ ok: true as const, sequence_number: 1 }); },
    close() { (fake as { closed: number }).closed += 1; },
    getLastReaderError() { return undefined; },
    /** How many submits actually COMPLETED — proves the throw path is not what is being tested. */
    submitCount() { return submits; },
  };
  return fake as unknown as AgentRelayClient & {
    closed: number; sessions: Set<string>; registered: string[]; submitCount: () => number;
  };
}

/**
 * Build the one state in which the DETACHED seal branch is reachable, through production calls.
 *
 * Returns the fake client and a `builderCalled` probe. The probe is not decoration: it is what
 * distinguishes "the fix works" from "the resolver bailed out early and the assertion happened to
 * hold anyway", which is exactly how the first draft of this file passed.
 */
async function setUpDetachedSeal(fx: TwoConnectionFixture): Promise<{
  client: ReturnType<typeof makeFakeRelayClient>;
  builderCalled: () => number;
}> {
  const client = makeFakeRelayClient();
  let calls = 0;

  // A session exists on disk...
  await fx.createSession(SID, "alice");
  // ...with a relay endpoint recorded on its row, which is what a relay assignment writes and what
  // the detached path reads back. Seeded the same way msg-022-session-rebuild does it.
  fx.snm.getDb()
    .prepare("UPDATE sessions SET relay_peer_id = ?, relay_addrs = ? WHERE session_id = ?")
    .run(RELAY_PEER, JSON.stringify(RELAY_ADDRS), SID);
  // ...and its live node is GONE — the interrupted-by-restart state that makes a seal need a
  // detached transport in the first place. Without this the LIVE branch wins and nothing below runs.
  await fx.snm.destroySessionNode("alice", SID, "interrupted");
  // The detached path dials FROM the agent's standing receiver.
  await fx.snm.ensureStandingReceiverForAgent("alice");

  fx.snm.setDetachedRelayClientBuilder(() => { calls += 1; return client; });
  return { client, builderCalled: () => calls };
}

/**
 * Call `submitSealLeaf` and assert it did not THROW.
 *
 * ⚠️ It is expected to RETURN `{ok:false, …}` here — there is no live relay to accept the leaf, and
 * that is fine; the leak is on the way out either way. What must not happen is an exception, and a
 * bare `.catch(() => undefined)` cannot tell the two apart. It hid a real one: the fake client was
 * missing `hasSession`, so the resolver threw a TypeError, nothing was ever registered, and the only
 * thing that noticed was the precondition assertion.
 */
async function submitSeal(fx: TwoConnectionFixture, correlationId: string): Promise<void> {
  let thrown: unknown;
  try {
    await fx.snm.submitSealLeaf("alice", SID, correlationId);
  } catch (err: unknown) {
    thrown = err;
  }
  expect(
    thrown,
    "submitSealLeaf must not THROW here — a failed submit is a returned {ok:false}. An exception " +
      "means the detached path broke before doing its work, and every assertion after it is vacuous.",
  ).toBeUndefined();
}

describe("DOD-M15-RELAYLEAK-1 — a cached relay client does not outlive the daemon", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★★★ gracefulShutdown CLOSES cached relay clients — it used to leave every one open", async () => {
    /**
     * ⚠️ THE ASSERTION THE FIX EXISTS FOR. Before it, `gracefulShutdown` stopped session nodes and
     * left the relay-client cache untouched, so `cello logout` released the daemon's own resources
     * and none of the relay's.
     *
     * ⚠️ The client here reports `hasSessions() === true` — a STAND-IN FOR A LIVE SESSION, and the
     * reason is worth stating: the detached-release fix removes a client from the cache once it has
     * no sessions left, so a released one is gone before shutdown ever runs. The case shutdown has
     * to cover is the one that is still legitimately in use, and that is what this builds.
     *
     * **Revert test:** delete the close loop from `gracefulShutdown` and this goes red while
     * everything else stays green — nothing else in the suite looks at that cache at teardown, which
     * is exactly why the leak survived.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-relayleak-shutdown-" });
    const { client, builderCalled } = await setUpDetachedSeal(fx);
    // Stays "in use" so the release leaves it cached — see the note above.
    (client as unknown as { hasSessions: () => boolean }).hasSessions = () => true;

    await submitSeal(fx, "corr-cache");

    expect(
      builderCalled(),
      "PRECONDITION — the detached branch must have been entered and a client cached. If this is 0 " +
        "the resolver bailed out early (it returned `no_persisted_relay_endpoint` in the first " +
        "draft) and everything below would pass without the fix existing.",
    ).toBeGreaterThan(0);

    await fx.snm.gracefulShutdown();

    expect(
      client.closed,
      "shutdown must close every cached relay client. Each holds an authenticated stream and a " +
        "reader loop, and the relay counts a reservation per client — leaking them is how a daemon " +
        "that restarts repeatedly exhausts a finite pool.",
    ).toBeGreaterThan(0);
  }, 60_000);

  it("★★★ a DETACHED seal transport releases its registration, so the client can ever be closed", async () => {
    /**
     * ⚠️ THE SUBTLER LEAK, and the one that made a client immortal rather than merely long-lived.
     *
     * `#detachSessionRelay` closes a client only when it has no sessions left. The detached seal path
     * registered one and never removed it, so that condition could never become true — no shutdown,
     * no teardown, no idle sweep would ever close it.
     *
     * ⚠️ **`registered` is asserted BEFORE `hasSessions()`, and that ordering is the whole lesson of
     * this file.** "No session is registered" is trivially true of a path that never registered one,
     * which is how the first draft stayed green with the fix removed. Proving the registration
     * happened first is what makes the emptiness afterwards mean the RELEASE ran.
     *
     * **Revert test:** remove the `finally { releaseDetached(); }` and this goes red — `registered`
     * still holds the id, `hasSessions()` is still true. The release is in a `finally` rather than at
     * each of the three returns precisely so a fourth exit added later cannot reintroduce the leak.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-relayleak-release-" });
    const { client, builderCalled } = await setUpDetachedSeal(fx);

    await submitSeal(fx, "corr-leak");

    expect(
      builderCalled(),
      "PRECONDITION — the detached branch must have been entered; a 0 here means the assertions " +
        "below are about a path that never ran",
    ).toBeGreaterThan(0);
    expect(
      client.submitCount(),
      "PRECONDITION — the submit must have COMPLETED. Before the fake implemented submitLeaf this " +
        "threw, and the release was exercised only on the exception path while the normal one was " +
        "never tried at all.",
    ).toBeGreaterThan(0);
    expect(
      client.registered,
      "PRECONDITION — the detached path must actually have REGISTERED the session. Without this, " +
        "the emptiness asserted next is satisfied by a path that never registered anything at all.",
    ).toContain(SID);

    expect(
      client.hasSessions(),
      "the detached seal transport must not leave a session registered. While one remains, " +
        "hasSessions() is true forever and the client can never be closed by any path.",
    ).toBe(false);
  }, 60_000);
});
