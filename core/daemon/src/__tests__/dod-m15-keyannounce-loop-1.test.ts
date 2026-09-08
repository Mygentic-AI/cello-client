/**
 * DOD-M15-KEYANNOUNCE-LOOP-1 — the session-key announce retry never gave up.
 *
 * `sendEphemeralFrame`'s catch called `retryEphemeralAnnounce(…, 1)` with a LITERAL, so every
 * failure re-entered the chain at attempt 1. `attempt > SESSION_KEY_ANNOUNCE_RETRIES` was
 * therefore never true and `session.key.announce.gave_up` was dead code — never logged once in
 * production. Measured on session `0646b474` (2026-09-08): 49,137 failures at ~17/second, still
 * running eleven hours after the session went quiet.
 *
 * The revert test: put the literal `1` back at either call site and "stops after a bounded number
 * of attempts" fails by never terminating.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SessionEphemerals, type SessionEphemeralContext } from "../session-ephemerals.js";
import { SESSION_KEY_ANNOUNCE_RETRIES, SESSION_KEY_ANNOUNCE_RETRY_MS } from "../session-node-types.js";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { randomBytes } from "node:crypto";

const AGENT = "Agent_A";
const SESSION = "0646b474d919e8b9a866b0c85c11ea6a";

/**
 * The production throw, reproduced in shape — review F2.
 *
 * libp2p's errors are NOT `instanceof Error` across this realm boundary, which is the whole reason
 * the old ternary printed `[object Object]`. A test that throws a real `Error` passes under BOTH
 * implementations and proves nothing, which is exactly what the first version of test 3 did.
 */
const LIBP2P_SHAPED_THROW = {
  name: "CodeError",
  code: "ERR_UNSUPPORTED_PROTOCOL",
  message: "protocol selection failed",
};

function makeCtx(
  events: Array<{ event: string; ctx: Record<string, unknown> }>,
  thrown: unknown = new Error("stream_open_refused"),
) {
  const record = (event: string) => (ctx: Record<string, unknown>) => { events.push({ event, ctx }); };
  const logger = {
    info: (e: string, c: Record<string, unknown> = {}) => record(e)(c),
    warn: (e: string, c: Record<string, unknown> = {}) => record(e)(c),
    error: (e: string, c: Record<string, unknown> = {}) => record(e)(c),
    debug: (e: string, c: Record<string, unknown> = {}) => record(e)(c),
  };
  const keyProvider = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
  const entry = {
    // The whole point: opening the stream ALWAYS throws, exactly as it did in production.
    node: { newStream: () => { throw thrown; } },
    counterpartySessionPeerId: "12D3KooWtestpeer",
  };
  const ctx: SessionEphemeralContext = {
    logger: logger as unknown as SessionEphemeralContext["logger"],
    sessionKey: (a, s) => `${a}:${s}`,
    activeEntry: () => entry as unknown as ReturnType<SessionEphemeralContext["activeEntry"]>,
    keyProvider: () => keyProvider,
    freezeSessionForKeyRefusal: async () => {},
  };
  return ctx;
}

describe("DOD-M15-KEYANNOUNCE-LOOP-1: a failing key announce gives up", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("★★ stops after a bounded number of attempts and says so — it does not retry forever", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const eph = new SessionEphemerals(makeCtx(events));
    eph.mintSessionEphemeral(AGENT, SESSION);

    await eph.sendEphemeralFrame(AGENT, SESSION, "test");

    // Drain generously: far more time than the whole backoff needs, so a chain that never
    // terminates keeps producing failures and blows the assertion below.
    for (let i = 0; i < SESSION_KEY_ANNOUNCE_RETRIES + 5; i++) {
      await vi.advanceTimersByTimeAsync(SESSION_KEY_ANNOUNCE_RETRY_MS * (SESSION_KEY_ANNOUNCE_RETRIES + 2));
    }

    const failures = events.filter((e) => e.event === "session.key.announce.failed");
    const gaveUp = events.filter((e) => e.event === "session.key.announce.gave_up");

    // One initial attempt plus RETRIES retries, and not one more.
    expect(failures.length).toBe(SESSION_KEY_ANNOUNCE_RETRIES + 1);
    expect(gaveUp.length).toBe(1);
  });

  it("★★ each attempt is NUMBERED, so the log shows the chain advancing rather than restarting", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const eph = new SessionEphemerals(makeCtx(events));
    eph.mintSessionEphemeral(AGENT, SESSION);

    await eph.sendEphemeralFrame(AGENT, SESSION, "test");
    for (let i = 0; i < SESSION_KEY_ANNOUNCE_RETRIES + 5; i++) {
      await vi.advanceTimersByTimeAsync(SESSION_KEY_ANNOUNCE_RETRY_MS * (SESSION_KEY_ANNOUNCE_RETRIES + 2));
    }

    const attempts = events
      .filter((e) => e.event === "session.key.announce.failed")
      .map((e) => e.ctx["attempt"]);
    // 0,1,2,…,RETRIES — a pinned chain would read 0,0,0,… forever.
    expect(attempts).toEqual(Array.from({ length: SESSION_KEY_ANNOUNCE_RETRIES + 1 }, (_, i) => i));
  });

  it("★★ a NON-Error libp2p throw reaches the log with its code — not \"[object Object]\"", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const eph = new SessionEphemerals(makeCtx(events, LIBP2P_SHAPED_THROW));
    eph.mintSessionEphemeral(AGENT, SESSION);

    await eph.sendEphemeralFrame(AGENT, SESSION, "test");

    const first = events.find((e) => e.event === "session.key.announce.failed");
    // The old ternary hit its `String(err)` branch on this value and printed "[object Object]",
    // so this assertion is the one that actually separates the two implementations.
    expect(first?.ctx["error"]).not.toBe("[object Object]");
    expect(first?.ctx["error"]).toBe("protocol selection failed");
    // Review F3: the code is the diagnosis. `reason: "stream_failed"` alone cannot tell an
    // old-build counterparty from a transport fault from the stream cap.
    expect(first?.ctx["errorCode"]).toBe("ERR_UNSUPPORTED_PROTOCOL");
    expect(first?.ctx["errorName"]).toBe("CodeError");
  });

  it("★ the give-up line reports how many attempts were ACTUALLY made", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const eph = new SessionEphemerals(makeCtx(events));
    eph.mintSessionEphemeral(AGENT, SESSION);

    await eph.sendEphemeralFrame(AGENT, SESSION, "test");
    for (let i = 0; i < SESSION_KEY_ANNOUNCE_RETRIES + 5; i++) {
      await vi.advanceTimersByTimeAsync(SESSION_KEY_ANNOUNCE_RETRY_MS * (SESSION_KEY_ANNOUNCE_RETRIES + 2));
    }

    const gaveUp = events.find((e) => e.event === "session.key.announce.gave_up");
    const failures = events.filter((e) => e.event === "session.key.announce.failed");
    // The count it prints must equal the count it actually made — it printed the constant (4)
    // while making five. Asserted against the observed failures, not against a second literal.
    expect(gaveUp?.ctx["attempts"]).toBe(failures.length);
  });
});
