/**
 * DOD-M12B-ABANDON-NOTIFY-1 — tell the far side you have hung up.
 *
 * `cello_close_session { force: true }` marked the session terminal on THIS side and did nothing
 * else. The counterparty kept its half live, kept retrying delivery into it, and kept trying to
 * re-establish — forever, because nothing would ever answer. That is what produced the 2026-08-17
 * "notification storm": the operator saw connection requests from agents nobody was driving.
 *
 * THE NOTICE RETIRES THE TRANSPORT, NOT THE SESSION. The first build flipped the receiver's status
 * to `abandoned`, which handed the abandoning party a button that denies its counterparty a
 * receipt: the unilateral seal exists for exactly "they never co-closed" and produces a notarized
 * certificate after a grace period, but a close refuses an `abandoned` session outright. Going
 * silent is what the unilateral seal was built to survive, so hanging up must not be worse than
 * going silent. The notice stops us calling them and leaves the session sealable.
 *
 * Best-effort by construction, and the answer says WHICH of the three things happened — most
 * often that this side had already torn its own session down, which is not a network fault and
 * must not be reported as one.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";

const SID = "ab".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const OTHER_PEER = "12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("DOD-M12B-ABANDON-NOTIFY-1: a force-abandon reaches the counterparty", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("the surviving half stops calling — and STAYS that way", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "a conversation that happened");

    expect(await snm.retireOnCounterpartyAbandon("alice", SID, "corr")).toBe(true);
    expect(snm.counterpartyAbandonedAt("alice", SID), "the marker must be durable").not.toBeNull();

    // SETTLE FIRST. The first build flipped the status and then fired a fire-and-forget teardown
    // that wrote it BACK to `interrupted` a few hundred milliseconds later — and every assertion
    // ran inside that window, so the suite was green on a state that no longer existed by the time
    // anyone read it.
    await wait(400);
    expect(snm.counterpartyAbandonedAt("alice", SID), "the marker must survive the teardown").not.toBeNull();

    // NOT terminal: the unilateral seal is still available. Losing that is a bigger harm than the
    // storm this fixes, and it would be a harm the counterparty could inflict for free.
    const status = snm.getSessionRecord("alice", SID)!.status;
    expect(status, `a hung-up session must stay sealable (got ${status})`).not.toBe("abandoned");

    expect(fx.eventsNamed("session.counterparty.abandoned").length).toBe(1);
  }, 60_000);

  it("an inbound notice from the real counterparty is acted on, and from anyone else is refused", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009b-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const frame = (sessionId: string): Uint8Array =>
      lp.encode.single(encodeCbor({ type: "session_abandoned_notice", session_id: sessionId }) as Uint8Array).subarray();

    // WRONG PEER. A session node is a promoted standing receiver and a standing receiver accepts
    // everyone; libp2p's gater runs at connection establishment and does not close connections that
    // already exist. So a peer that dialled this node earlier still holds one after the gater
    // narrows — and without pinning, it could hang up a session it is not party to.
    await snm.handleContentFrameForTest("alice", SID, frame(SID), OTHER_PEER);
    expect(snm.counterpartyAbandonedAt("alice", SID), "a stranger must not be able to end this session").toBeNull();
    expect(fx.eventsNamed("session.content.peer_mismatch").length).toBe(1);

    // RIGHT PEER, WRONG SESSION. The frame names its session and the handler is bound to one.
    await snm.handleContentFrameForTest("alice", SID, frame("cd".repeat(32)), PEER);
    expect(snm.counterpartyAbandonedAt("alice", SID)).toBeNull();
    expect(fx.eventsNamed("session.content.session_mismatch").length).toBe(1);

    // RIGHT PEER, RIGHT SESSION.
    await snm.handleContentFrameForTest("alice", SID, frame(SID), PEER);
    await wait(200);
    expect(snm.counterpartyAbandonedAt("alice", SID), "the counterparty's own notice must be acted on").not.toBeNull();
  }, 60_000);

  it("force-abandon actually SENDS the notice, and says which of the three things happened", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009c-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_close_session", { session_id: SID, force: true })) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.status).toBe("abandoned");
    // The wiring is what makes this unit real: without it the two halves exist and neither is
    // reached. The reason is asserted, not just the boolean — "could not be reached" standing in
    // for "this side had already torn the session down" is what sends an operator to debug a
    // network fault that does not exist.
    expect(res).toHaveProperty("counterparty_notified");
    expect(["sent", "no_local_node", "send_failed", "notice_timeout"]).toContain(res.counterparty_notice_reason);
    expect(
      fx.eventsNamed("session.abandon.notice.sent").length +
      fx.eventsNamed("session.abandon.notice.skipped").length +
      fx.eventsNamed("session.abandon.notice.failed").length,
      "the close must have attempted the notice exactly once",
    ).toBe(1);
  }, 60_000);

  it("the transcript and the held content survive — retiring is not deleting", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009d-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "worth keeping");

    await snm.retireOnCounterpartyAbandon("alice", SID, "corr");
    await wait(200);

    // The counterparty walking away must not cost the operator the record of what was said — that
    // is theirs, and it is the whole product. And because the session is NOT flipped terminal, held
    // content is not swept to the annex either: it stays where a later delivery can still release it.
    const rows = snm.getDb().prepare("SELECT COUNT(*) AS n FROM transcript WHERE session_id = ?").get(SID) as { n: number };
    expect(rows.n).toBe(1);
    expect(snm.getSessionTree("alice", SID).size()).toBe(1);
  }, 60_000);

  it("a session that already ended is not disturbed, and a duplicate notice says nothing twice", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009e-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    snm.getDb().prepare("UPDATE sessions SET status = 'sealed' WHERE session_id = ?").run(SID);

    // A SEALED session has a notarized receipt. A late or duplicated notice must never touch it.
    expect(await snm.retireOnCounterpartyAbandon("alice", SID, "corr")).toBe(false);
    expect(snm.getSessionRecord("alice", SID)!.status).toBe("sealed");
    expect(fx.eventsNamed("session.counterparty.abandoned")).toEqual([]);

    // And a repeat on a live session announces once, not once per frame.
    const LIVE = "ef".repeat(32);
    await fx.createSession(LIVE, "alice", "bobpubkeyhex", PEER);
    expect(await snm.retireOnCounterpartyAbandon("alice", LIVE, "corr")).toBe(true);
    expect(await snm.retireOnCounterpartyAbandon("alice", LIVE, "corr")).toBe(false);
    expect(fx.eventsNamed("session.counterparty.abandoned").length).toBe(1);
  }, 60_000);

  it("an unknown session is refused, not created", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009f-" });
    const { snm } = fx;
    expect(await snm.retireOnCounterpartyAbandon("alice", "cc".repeat(32), "corr")).toBe(false);
    expect(snm.getSessionRecord("alice", "cc".repeat(32))).toBeNull();
  }, 60_000);
});
