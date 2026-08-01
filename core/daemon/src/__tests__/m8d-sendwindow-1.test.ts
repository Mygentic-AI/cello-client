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
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { SecurityGatewayClient } from "../types.js";

const SID = "9a".repeat(32);

/**
 * A gateway that HOLDS the first screening until released. The passthrough resolves in the same
 * microtask, which closes the window faster than any test can aim at — so the race would be
 * unobservable and a test built on it would pass against the broken build.
 */
class StallingGateway implements Partial<SecurityGatewayClient> {
  #release: (() => void) | null = null;
  readonly entered: Promise<void>;
  #announceEntered!: () => void;

  constructor() {
    this.entered = new Promise<void>((r) => { this.#announceEntered = r; });
  }

  async screenOutbound(content: Uint8Array): Promise<{ disposition: "allow"; content?: Uint8Array }> {
    if (!this.#release) {
      const held = new Promise<void>((r) => { this.#release = r; });
      this.#announceEntered();
      await held;
    }
    void content;
    return { disposition: "allow" };
  }

  async screenInbound(): Promise<{ disposition: "allow" }> {
    return { disposition: "allow" };
  }

  release(): void { this.#release?.(); }
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
    await gateway.entered;

    // B now sends. Under the passthrough this is a coin flip; held open, it is deterministic.
    const bSend = connB.send("cello_send", { session_id: SID, content: "B's answer" });
    await new Promise((r) => setTimeout(r, 100));
    gateway.release();

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
    await gateway.entered;
    const bSend = connB.send("cello_send", { session_id: SID, content: "B's answer" });
    await new Promise((r) => setTimeout(r, 100));
    gateway.release();

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
    const raced = blocked.find((e) => e.ctx.authority === "frontier_moved_during_send");
    expect(raced, "the log must name WHICH authority refused").toBeDefined();
    expect(raced!.level).toBe("warn");
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
    await gateway.entered;
    gateway.release();
    const r = (await send) as Record<string, unknown>;
    expect(r.ok, "an uncontended send must pass").toBe(true);
  });
});
