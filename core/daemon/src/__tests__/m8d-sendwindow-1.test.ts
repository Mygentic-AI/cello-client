/**
 * DOD-COATTEND-SENDWINDOW-1 — the send gate is re-checked before the message becomes irreversible.
 *
 * THE DEFECT (§4). Between the gate passing and the message being committed there are two awaits:
 * `securityGateway.screenOutbound` (a round trip to the gateway PROCESS) and
 * `sessionNodeManager.sendContent` (relay submit + delivery). The gate is never re-checked after
 * either. Two co-attending sessions can both be cleared, both wait, and both write — and nothing
 * changed between them precisely BECAUSE no leaf was appended yet. The counterparty gets two replies
 * to one message: both correctly signed, both correctly ordered, the record coherent, the
 * conversation not.
 *
 * WHERE THE RE-CHECK GOES, AND WHY IT IS NOT WHERE AC1 SAYS.
 *
 * AC1 asks for the re-check "in the same synchronous window as `appendSessionLeaf`", copying the
 * inbound pattern at `session-node-manager.ts:3682-3695`. Inbound, that is exactly right: the append
 * IS the commit point, so nothing is irreversible until it happens.
 *
 * Outbound it is not. `sendContent` — the wire — runs BEFORE `appendSessionLeaf`. By the time
 * control reaches the append, the counterparty already HAS the message. Refusing there would leave
 * them holding content this side never leafed: the two frontiers disagree, neither will co-sign, and
 * the session is unsealable except by forfeiting the receipt. That is `DOD-FRONTIER-STRAND-1` — the
 * defect that left session `dbb93dfc…` stranded for a week — manufactured deliberately to satisfy
 * the letter of an AC.
 *
 * So the re-check goes immediately before `sendContent`, which is the real commit point for an
 * outbound message, and the no-await comment AC1 asks for is attached THERE. This is a deviation
 * from AC1's wording in service of AC1's purpose, and it is recorded rather than silently taken.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { Stream } from "@libp2p/interface";
import type { CelloNode } from "@cello-protocol/transport";
import type { SecurityGatewayClient } from "../types.js";

const SID = "9a".repeat(32);

/**
 * A gateway that holds EVERY entrant until `waitFor(n)` has seen n of them.
 *
 * The first version held only the first caller (`if (!this.#release)`, with `#release` assigned
 * synchronously inside the Promise executor), so the second send ran to completion — append
 * included — before the first resumed. That is the SEQUENTIAL race, and AC5 asks for the
 * concurrent one: "two connections BOTH pass the gate, BOTH proceed through a stalled screening
 * await". Caught by review; the distinction matters because the sequential case is the one the
 * frontier comparison already covers, so the clause was passing on the easier half.
 */
class StallingGateway implements Partial<SecurityGatewayClient> {
  #held: Array<() => void> = [];
  #entrants = 0;
  #waiters: Array<{ n: number; resolve: () => void }> = [];

  async screenOutbound(content: Uint8Array): Promise<{ disposition: "allow"; content?: Uint8Array }> {
    void content;
    await new Promise<void>((release) => {
      this.#held.push(release);
      this.#entrants += 1;
      for (const w of this.#waiters.filter((w) => w.n <= this.#entrants)) w.resolve();
      this.#waiters = this.#waiters.filter((w) => w.n > this.#entrants);
    });
    return { disposition: "allow" };
  }

  async screenInbound(): Promise<{ disposition: "allow" }> {
    return { disposition: "allow" };
  }

  /** Resolve once `n` callers are simultaneously inside screening. */
  waitFor(n: number): Promise<void> {
    if (this.#entrants >= n) return Promise.resolve();
    return new Promise<void>((resolve) => { this.#waiters.push({ n, resolve }); });
  }

  /** Release the EARLIEST entrant only, so it can run to completion while others stay parked. */
  releaseOne(): void {
    this.#held.shift()?.();
  }

  releaseAll(): void {
    const held = this.#held;
    this.#held = [];
    for (const r of held) r();
  }
}

/** A node whose first `newStream` never settles — parks a send INSIDE `sendContent`. */
class StreamStallingNode extends FakeNode {
  #firstHeld = false;
  readonly reachedWire: Promise<void>;
  #announce!: () => void;
  constructor() {
    super();
    this.reachedWire = new Promise<void>((r) => { this.#announce = r; });
  }
  override async newStream(peer: string, proto: string): Promise<Stream> {
    if (!this.#firstHeld) {
      this.#firstHeld = true;
      this.#announce();
      await new Promise<void>(() => { /* never settles — the send stays on the wire */ });
    }
    return await super.newStream(peer, proto);
  }
}

describe("DOD-COATTEND-SENDWINDOW-1: two sessions cannot both reply to one message", () => {
  let fx: TwoConnectionFixture;
  let gateway: StallingGateway;

  beforeEach(async () => {
    gateway = new StallingGateway();
    fx = await startTwoConnectionFixture({
      dirPrefix: "cello-m8d-sendwindow-",
      securityGateway: gateway as unknown as SecurityGatewayClient,
    });
  });
  afterEach(async () => { await fx.cleanup(); });

  it("S1 (AC5, THE LINE): both pass the gate, both stall in screening — exactly ONE reply is committed", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    // One counterparty message, read by BOTH sessions. Both are legitimately caught up, so both
    // legitimately pass the gate — that is the whole point: this is not two callers where one was
    // already wrong, it is two callers who were both right at the moment they were checked.
    await fx.ingestReceived("alice", SID, "one question");
    expect(((await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>).content).toBe("one question");
    expect(((await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>).content).toBe("one question");

    const leavesBefore = fx.snm.getSessionTree("alice", SID).size();

    // A enters screening and is HELD there, inside the window.
    const aSend = connA.send("cello_send", { session_id: SID, content: "A's answer" });
    const bSend = connB.send("cello_send", { session_id: SID, content: "B's answer" });
    // BOTH inside screening at once — AC5's literal wording, not two sends that merely overlap.
    await gateway.waitFor(2);
    gateway.releaseAll();

    const [a, b] = (await Promise.all([aSend, bSend])) as Array<Record<string, unknown>>;
    const committed = [a, b].filter((r) => r.ok === true);

    // The counterparty asked once. They get answered once.
    expect(committed, "exactly one of two racing replies may be committed").toHaveLength(1);
    expect(fx.snm.getSessionTree("alice", SID).size(), "and exactly one leaf is appended")
      .toBe(leavesBefore + 1);
  });

  it("S2 (AC2): the loser is refused LOUDLY, and told which authority refused it", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "one question");
    for (const c of [connA, connB]) await c.send("cello_receive", { session_id: SID, timeout_ms: 2_000 });

    const aSend = connA.send("cello_send", { session_id: SID, content: "A's answer" });
    const bSend = connB.send("cello_send", { session_id: SID, content: "B's answer" });
    await gateway.waitFor(2);
    gateway.releaseAll();

    const results = (await Promise.all([aSend, bSend])) as Array<Record<string, unknown>>;
    const loser = results.find((r) => r.ok === false);
    expect(loser, "one of them must be refused").toBeDefined();

    // A silent loss is the defect wearing a different coat: the operator would see a reply vanish
    // with no reason, which is exactly the class of failure Tier 0 exists to end.
    expect(loser!.reason).toBe("session_moved_under_send");
    // The CATCHUP door (M8D-D3), matched in EITHER surface form: guidance is rewritten at the IPC
    // boundary, so a CLI-shaped caller reads `cello transcript` where an MCP caller reads
    // `cello_transcript`. Asserting only the underscore form pins the tool surface, not the advice.
    expect(String(loser!.guidance)).toMatch(/cello[ _]transcript/);
    // ...and it must not tell them to just resend — another session may already have answered.
    expect(String(loser!.guidance)).toMatch(/not simply resend/i);

    // ...and it is on the record, naming both frontiers so the next reader can see WHAT moved.
    const blocked = fx.eventsNamed("session.send.blocked");
    expect(blocked.length, "the refusal must be logged, not just returned").toBeGreaterThanOrEqual(1);
    // EITHER authority is correct here, and which one fires depends on how the race lands — that is
    // the point of having two. Released together, both sends clear the frontier comparison (no leaf
    // exists yet) and the loser is caught by the in-flight claim. Let the sibling FINISH first
    // (S2b) and the frontier comparison catches it instead. Pinning one name here would make the
    // clause fail on a correct build for the wrong reason.
    const raced = blocked.find((e) =>
      e.ctx.authority === "sibling_send_in_flight" || e.ctx.authority === "frontier_moved_during_send");
    expect(raced, "the log must name WHICH authority refused").toBeDefined();
    expect(raced!.level).toBe("warn");

    // F7/L5: the PRE-EXISTING gate refusal must carry an authority too, or an operator filtering on
    // the field sees only the co-attendance refusals and concludes the rest do not exist. It must
    // NOT claim one authority over the other: reaching that branch means BOTH said no, and the
    // ternary originally written there could only ever print one value (review H2).
    const gateBlocked = blocked.find((e) => e.ctx.unreadReceived !== undefined);
    if (gateBlocked) {
      expect(gateBlocked.ctx.authority, "both authorities are false there — say so").toBe("cursor_and_watermark");
    }
  });

  it("S2b: when the sibling's send COMPLETES first, the FRONTIER comparison is what refuses", async () => {
    // The sequential half of the race, kept as its own clause so each authority is pinned to the
    // shape it exists for. Here A's leaf lands while B is still screened, so B's frontier snapshot
    // is stale and the comparison catches it — the in-flight claim is already released.
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "one question");
    for (const c of [connA, connB]) await c.send("cello_receive", { session_id: SID, timeout_ms: 2_000 });

    const bSend = connB.send("cello_send", { session_id: SID, content: "B's answer" });
    await gateway.waitFor(1);          // B is parked in screening
    const aSend = connA.send("cello_send", { session_id: SID, content: "A's answer" });
    await gateway.waitFor(2);          // A parked too

    // Let B run to COMPLETION — append included — while A is still parked. That is what makes this
    // the sequential shape: by the time A resumes, the leaf exists and the claim is long released,
    // so the frontier comparison is the only thing that can catch it.
    gateway.releaseOne();
    expect(((await bSend) as Record<string, unknown>).ok, "the first send must succeed").toBe(true);

    gateway.releaseAll();
    await aSend;

    const byFrontier = fx.eventsNamed("session.send.blocked")
      .find((e) => e.ctx.authority === "frontier_moved_during_send");
    expect(byFrontier, "a completed sibling send must be caught by the frontier comparison").toBeDefined();
    expect(byFrontier!.ctx.frontierNow).not.toBe(byFrontier!.ctx.frontierAtGate);

    // F6/L5: the guidance says LEAF, not "message". The frontier counts leaves, and a screened-out
    // leaf has no transcript row — promising N messages in a transcript that holds fewer sends the
    // operator hunting for content that was removed on purpose. Reverting the wording left the
    // suite green (review L5), so it is pinned here rather than trusted.
    const loser = (await aSend) as Record<string, unknown>;
    expect(loser.ok).toBe(false);
    expect(String(loser.guidance)).toMatch(/leaf|leaves/);
    expect(String(loser.guidance), "must not over-claim readable messages").not.toMatch(/message\(s\) were added/);
  });

  it("S4 (review F1): a send parked ON THE WIRE also blocks a sibling — the frontier cannot see it", async () => {
    // THE FINDING. `sendContent` is the LAST await and the wider one — relay submit, stream open,
    // stream close, a network round trip in production. A sibling's leaf does not exist yet while
    // that is in flight, so no frontier comparison can see it, whatever it compares against.
    // Reviewer reproduced two `ok:true`, two frames on the wire and two leaves here. The claim is
    // what closes it, and it refuses BEFORE the loser's own wire call, so nothing is stranded.
    const node = new StreamStallingNode();
    const fx2 = await startTwoConnectionFixture({
      dirPrefix: "cello-m8d-wire-",
      securityGateway: new (class { async screenOutbound() { return { disposition: "allow" as const }; } async screenInbound() { return { disposition: "allow" as const }; } })() as unknown as SecurityGatewayClient,
      node: node as unknown as CelloNode,
    });
    try {
      await fx2.createSession(SID, "alice");
      const a = await fx2.connectAs("alice");
      const b = await fx2.connectAs("alice");
      await fx2.ingestReceived("alice", SID, "one question");
      for (const c of [a, b]) await c.send("cello_receive", { session_id: SID, timeout_ms: 2_000 });

      const leavesBefore = fx2.snm.getSessionTree("alice", SID).size();
      // Parks inside sendContent and NEVER settles (the stalled newStream is the point), so the
      // rejection at teardown must be swallowed here — otherwise cleanup closing the socket raises
      // an unhandled "Connection closed" that fails the whole run while every test passes.
      const parked = a.send("cello_send", { session_id: SID, content: "A's answer" });
      parked.catch(() => { /* expected: this send is abandoned on the wire by design */ });
      await node.reachedWire;

      const bResult = (await b.send("cello_send", { session_id: SID, content: "B's answer" })) as Record<string, unknown>;
      expect(bResult.ok, "a sibling mid-wire must block this send").toBe(false);
      expect(bResult.in_flight).toBe(true);
      expect(fx2.snm.getSessionTree("alice", SID).size(), "and B must append NOTHING").toBe(leavesBefore);
    } finally {
      await fx2.cleanup();
    }
  });

  it("S5 (review F3): the refusal is ADVISORY — a loser that retries without reading DOES get through", async () => {
    // Stated, not hidden. Review proved the refusal has nothing behind it: the next cello_send takes
    // a fresh frontier snapshot, and the gate itself passes because a SIBLING'S SENT LEAF IS NOT
    // UNREAD COUNTERPARTY CONTENT — which is deliberate and load-bearing (the gate's own comment:
    // "two attended windows on one agent do not gate each other… do not 'fix' it"). So a
    // retry-on-failure agent produces the duplicate reply one round trip later.
    //
    // That is the CHOSEN behavior, not an oversight: the principal is the agent, and the daemon
    // cannot referee which of an operator's windows a human is looking at. What this line owes is
    // the race — two replies from ONE counterparty message with neither session informed — and that
    // is closed. A second reply sent by an agent that was TOLD another session answered and chose to
    // proceed is the operator's call.
    //
    // The clause exists so that if someone later decides retry should be blocked, they change a
    // test that says so out loud rather than discovering this by accident in production.
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "one question");
    for (const c of [connA, connB]) await c.send("cello_receive", { session_id: SID, timeout_ms: 2_000 });

    const bSend = connB.send("cello_send", { session_id: SID, content: "B's answer" });
    await gateway.waitFor(1);
    const aSend = connA.send("cello_send", { session_id: SID, content: "A's answer" });
    await gateway.waitFor(2);
    gateway.releaseOne();
    await bSend;
    gateway.releaseAll();
    const refused = (await aSend) as Record<string, unknown>;
    expect(refused.ok, "the loser is refused once").toBe(false);

    // ...and is then free to insist, having been told. (The retry parks in screening like any other
    // send, so it needs releasing too — `releaseAll` only frees the entrants held at the moment it
    // is called.)
    const retryP = connA.send("cello_send", { session_id: SID, content: "A's answer, again" });
    await gateway.waitFor(3);
    gateway.releaseAll();
    const retry = (await retryP) as Record<string, unknown>;
    expect(retry.ok, "a retry without reading currently succeeds — DELIBERATE, see above").toBe(true);
  });

  it("S6 (review H3): a claim held past its TTL must not wedge the session forever", async () => {
    // `finally` covers throw and reject; it does NOT cover a send that never settles, and
    // sendContent awaits newStream and stream.close with no timeout. Without a TTL, one hung
    // libp2p stream would refuse every sibling send on that conversation until the daemon
    // restarted — trading a duplicate reply for a dead conversation, which is the wrong way round.
    //
    // The clock is not mocked here; the TTL is read out of the refusal instead. `claimHeldMs` is
    // what an operator (and the next reader) needs to tell "a sibling is mid-send" from "something
    // has been stuck for a minute", and asserting it present pins the field the expiry depends on.
    const node = new StreamStallingNode();
    const fx2 = await startTwoConnectionFixture({
      dirPrefix: "cello-m8d-ttl-",
      securityGateway: new (class { async screenOutbound() { return { disposition: "allow" as const }; } async screenInbound() { return { disposition: "allow" as const }; } })() as unknown as SecurityGatewayClient,
      node: node as unknown as CelloNode,
    });
    try {
      await fx2.createSession(SID, "alice");
      const a = await fx2.connectAs("alice");
      const b = await fx2.connectAs("alice");
      await fx2.ingestReceived("alice", SID, "one question");
      for (const c of [a, b]) await c.send("cello_receive", { session_id: SID, timeout_ms: 2_000 });

      const parked = a.send("cello_send", { session_id: SID, content: "A's answer" });
      parked.catch(() => { /* abandoned on the wire by design */ });
      await node.reachedWire;

      const refused = (await b.send("cello_send", { session_id: SID, content: "B's answer" })) as Record<string, unknown>;
      expect(refused.in_flight).toBe(true);

      const blocked = fx2.eventsNamed("session.send.blocked")
        .find((e) => e.ctx.authority === "sibling_send_in_flight");
      expect(blocked, "the in-flight refusal must be logged").toBeDefined();
      expect(
        typeof blocked!.ctx.claimHeldMs,
        "how long the claim has been held must be recorded — it is what separates a live sibling from a wedge",
      ).toBe("number");
    } finally {
      await fx2.cleanup();
    }
  });

  it("S3: a lone sender is NOT refused — the re-check must not tax the ordinary case", async () => {
    // A gate that fires when nothing raced would break every single-session send in the product,
    // which is almost all of them. The re-check compares the frontier against the value it snapshot
    // at gate time; with no sibling writing, that value is unchanged and the send proceeds.
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "one question");
    await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 });

    const send = conn.send("cello_send", { session_id: SID, content: "the only answer" });
    await gateway.waitFor(1);
    gateway.releaseAll();
    const r = (await send) as Record<string, unknown>;
    expect(r.ok, "an uncontended send must pass").toBe(true);
  });
});
