/**
 * 081-RELAYFREE — **A FORCE-CLOSE TELLS THE RELAY TO LET GO (client half, C1-C2).**
 *
 * `cello_close_session { force: true }` marked a session terminal locally and told the relay nothing,
 * so the relay kept counting it against `SESSION_CAP_PER_PAIR` for up to 24h. Repeated force-closes
 * between the same pair filled the cap and refused new sessions. The fix is a best-effort
 * `session_abandon` frame the force branch sends to the session's assigned relay.
 *
 * C1 proves the wiring: a real force-close reaches the relay client and sends the abandon for the
 * session. C2 proves the escape hatch is not conditional on the relay: an unreachable relay does not
 * stop the local abandon, the failure is logged, and the guidance says the slot stays held.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { AgentRelayClient } from "../session-relay-client.js";

const SID = "ab".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";

/**
 * A relay client that records the one call this unit is about — `relayAbandon`. Every other method
 * (attendance announcements, session registration, teardown) is a tolerant no-op, because a patched
 * client sits behind the whole per-agent relay surface and a force-close is not the only thing that
 * touches it (connecting an agent announces attendance across its active nodes). Only `relayAbandon`
 * is observed; nothing else this unit does depends on what the other methods return.
 */
function makeRecordingRelayClient(
  result: { released: boolean } | { failed: string },
): { client: AgentRelayClient; recorder: { abandonedSessionHex?: string; calls: number } } {
  const recorder: { abandonedSessionHex?: string; calls: number } = { calls: 0 };
  const target = {
    relayAbandon(_node: unknown, sessionIdBytes: Uint8Array) {
      recorder.calls += 1;
      recorder.abandonedSessionHex = Buffer.from(sessionIdBytes).toString("hex");
      return Promise.resolve(result);
    },
  } as Record<string, unknown>;
  const client = new Proxy(target, {
    get(t, prop: string) {
      if (prop in t) return t[prop];
      // Any incidental method call is a no-op returning undefined.
      return () => undefined;
    },
  }) as unknown as AgentRelayClient;
  return { client, recorder };
}

describe("081-RELAYFREE: a force-close tells the relay to let go", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★★★ C1: force-close sends session_abandon to the session's relay for that session id", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-081a-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER, { relay: true });

    const { client: recording, recorder } = makeRecordingRelayClient({ released: true });
    snm.patchRelayClientForTest("alice", SID, recording, Buffer.from(SID, "hex"));

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_close_session", { session_id: SID, force: true })) as Record<string, unknown>;

    expect(res.ok, "the local abandon must succeed").toBe(true);
    expect(res.status).toBe("abandoned");

    expect(
      recorder.calls,
      "the force branch must tell the relay to let go — without the wiring the frame is never sent " +
        "and the slot stays held for 24h",
    ).toBe(1);
    expect(
      recorder.abandonedSessionHex,
      "the abandon must name the RELAY session id the relay knows this session by",
    ).toBe(SID);

    expect(fx.eventsNamed("session.relay.abandon.released").length).toBe(1);
  }, 60_000);

  it("★★★ C2: relay unreachable → still abandoned locally, failure logged, guidance says the slot is held", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-081b-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER, { relay: true });

    const { client: recording, recorder } = makeRecordingRelayClient({ failed: "not_connected" });
    snm.patchRelayClientForTest("alice", SID, recording, Buffer.from(SID, "hex"));

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_close_session", { session_id: SID, force: true })) as Record<string, unknown>;

    // The escape hatch must not become conditional on the relay being reachable.
    expect(res.ok, "force-abandon must succeed locally even when the relay cannot be told").toBe(true);
    expect(res.status).toBe("abandoned");
    expect(snm.getSessionRecord("alice", SID)!.status).toBe("abandoned");
    expect(recorder.calls, "the abandon was attempted").toBe(1);

    const failed = fx.eventsNamed("session.relay.abandon.failed");
    expect(failed.length, "an unreachable relay is a warn, not silence").toBe(1);
    expect(
      String(failed[0]!.ctx["impact"] ?? ""),
      "the operator must be told the slot is still counted until the 24h sweep",
    ).toContain("24 hours");

    expect(
      String(res.guidance ?? ""),
      "the close answer must echo that the relay still holds the slot",
    ).toMatch(/relay|slot|cap/i);
  }, 60_000);

  it("★★★ a relay-less session does NOT warn about a held slot — there was never a slot", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-081c-" });
    const { snm } = fx;
    // No `{ relay: true }` — this session has no relay client, so relayAbandon returns no_relay.
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_close_session", { session_id: SID, force: true })) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.status).toBe("abandoned");
    expect(snm.getSessionRecord("alice", SID)!.status).toBe("abandoned");

    expect(
      fx.eventsNamed("session.relay.abandon.failed").length,
      "no relay means no slot was ever held — warning that one is held for 24h is a false alarm",
    ).toBe(0);
    expect(
      fx.eventsNamed("session.relay.abandon.no_slot").length,
      "the no-relay case is its own quiet info line",
    ).toBe(1);
    expect(
      String(res.guidance ?? ""),
      "the guidance must not claim the slot is held for 24h",
    ).not.toContain("24 hours");
    expect(String(res.guidance ?? "")).toMatch(/no relay/i);
  }, 60_000);

  it("★★★ a relay that never answers cannot hold up the local abandon past the cap", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-081d-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER, { relay: true });

    // A relay client whose relayAbandon NEVER answers within the test — a genuinely hung relay, not a
    // synchronous short-circuit. The force branch caps the whole relay step, so the local abandon must
    // complete regardless.
    const recorder: { calls: number } = { calls: 0 };
    const target = {
      relayAbandon() {
        recorder.calls += 1;
        return new Promise(() => { /* never resolves — the relay is down */ });
      },
    } as Record<string, unknown>;
    const hung = new Proxy(target, {
      get(t, prop: string) { return prop in t ? t[prop] : () => undefined; },
    }) as unknown as AgentRelayClient;
    snm.patchRelayClientForTest("alice", SID, hung, Buffer.from(SID, "hex"));

    const client = await fx.connectAs("alice");
    const started = Date.now();
    const res = (await client.send("cello_close_session", { session_id: SID, force: true })) as Record<string, unknown>;
    const elapsed = Date.now() - started;

    expect(res.ok, "the escape hatch must not depend on a reachable relay").toBe(true);
    expect(res.status).toBe("abandoned");
    expect(snm.getSessionRecord("alice", SID)!.status).toBe("abandoned");
    expect(recorder.calls, "the abandon was attempted").toBe(1);
    expect(
      elapsed,
      "a down relay must never hold the local abandon past the ~2s cap (plus IPC overhead)",
    ).toBeLessThan(6_000);

    const failed = fx.eventsNamed("session.relay.abandon.failed");
    expect(failed.length, "a capped-out relay step is a logged failure").toBe(1);
    expect(failed[0]!.ctx["reason"]).toBe("relay_timeout");
  }, 60_000);
});
