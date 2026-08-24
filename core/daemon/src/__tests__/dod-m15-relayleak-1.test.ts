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
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { AgentRelayClient } from "../session-relay-client.js";

const SID = "1d".repeat(32);

/** A relay client that records what was asked of it and nothing else. */
function makeFakeRelayClient(): AgentRelayClient & { closed: number; sessions: Set<string> } {
  const sessions = new Set<string>();
  const fake = {
    closed: 0,
    sessions,
    registerSession(sessionId: string) { sessions.add(sessionId); },
    unregisterSession(sessionId: string) { sessions.delete(sessionId); },
    hasSessions() { return sessions.size > 0; },
    close() { (fake as { closed: number }).closed += 1; },
    getLastReaderError() { return undefined; },
  };
  return fake as unknown as AgentRelayClient & { closed: number; sessions: Set<string> };
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
    const client = makeFakeRelayClient();
    // Stays "in use" so the detached release leaves it cached — see the note above.
    (client as unknown as { hasSessions: () => boolean }).hasSessions = () => true;
    fx.snm.setDetachedRelayClientBuilder(() => client);

    // The production way an entry lands in the cache: a detached seal transport.
    await fx.snm.submitSealLeaf("alice", SID, new Uint8Array(32).fill(0xab), "corr-cache").catch(() => undefined);

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
     * **Revert test:** remove the `finally { releaseDetached(); }` and this goes red. The release is
     * in a `finally` rather than at each of the three returns precisely so a fourth exit added later
     * cannot reintroduce the leak.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-relayleak-release-" });
    const client = makeFakeRelayClient();
    fx.snm.setDetachedRelayClientBuilder(() => client);

    // No session node exists for this id, so the resolver must take the DETACHED branch.
    await fx.snm.submitSealLeaf("alice", SID, new Uint8Array(32).fill(0xab), "corr-leak").catch(() => undefined);

    expect(
      client.hasSessions(),
      "the detached seal transport must not leave a session registered. While one remains, " +
        "hasSessions() is true forever and the client can never be closed by any path.",
    ).toBe(false);
  }, 60_000);
});
