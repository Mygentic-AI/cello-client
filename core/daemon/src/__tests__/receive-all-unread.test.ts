/**
 * `cello_receive` returns EVERY unread message in one answer, tracked by ONE bookmark per agent.
 *
 * Andre's ruling, live test 2026-09-13. What the operator lived through before it:
 *
 *   1. Away. Message A arrives. They come back and catch up (`since_seq`), and get A.
 *   2. The other side sends B. The notification rings.
 *   3. They read — and get A again. Only a second read gives B.
 *
 * The cause was three bookmarks: catch-up moved two, the plain read used a third that belonged to
 * the CONNECTION and started empty on every new one. So every `/mcp` reconnect and every `cello`
 * CLI command also started the read from the oldest message in the conversation.
 *
 * Now: one bookmark per (agent, session), persisted. A read hands over everything after it and moves
 * it. Catch-up mode is gone because the ordinary read already is catch-up.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "5e".repeat(32);

type Msg = { sequence: number; content: string };
type Answer = { ok: boolean; messages?: Msg[]; reason?: string; content?: unknown };

describe("cello_receive — every unread message, one bookmark per agent", () => {
  let fx: TwoConnectionFixture;
  beforeEach(async () => { fx = await startTwoConnectionFixture({ dirPrefix: "cello-receive-all-" }); });
  afterEach(async () => { await fx.cleanup(); });

  const texts = (a: Answer) => (a.messages ?? []).map((m) => m.content);

  it("★ two unread messages come back in ONE read, in order, and are not served again", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "first");
    await fx.ingestReceived("alice", SID, "second");

    const got = (await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer;
    expect(got.ok).toBe(true);
    expect(texts(got)).toEqual(["first", "second"]);

    const again = (await conn.send("cello_receive", { session_id: SID, timeout_ms: 200 })) as Answer;
    expect(texts(again), "a read message must never be handed over twice").toEqual([]);
  });

  it("★★★ the live-test journey: after reading A, the next read gives B — not A again", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "A");
    expect(texts((await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer)).toEqual(["A"]);

    await fx.ingestReceived("alice", SID, "B");
    expect(texts((await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer)).toEqual(["B"]);
  });

  it("★★★ a RECONNECT does not start the read over from the oldest message", async () => {
    await fx.createSession(SID, "alice");
    const first = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "old");
    expect(texts((await first.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer)).toEqual(["old"]);

    // A fresh connection — what `/mcp`, a restarted Claude Code, and every CLI command are.
    const second = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "new");
    expect(texts((await second.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer)).toEqual(["new"]);
  });

  it("★★ a message this agent SENT in between does not stop the read, and the send gate clears", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "one");
    fx.seedSent("alice", SID, "my reply from another window");
    await fx.ingestReceived("alice", SID, "two");

    expect(texts((await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer)).toEqual(["one", "two"]);
    await conn.send("cello_send", { session_id: SID, content: "answer", signal: "over" });
    // The gate logs every refusal; a send that fails later for a fixture reason must not pass this.
    expect(fx.eventsNamed("session.send.blocked"), "everything was read, so the read-before-send gate must not refuse").toEqual([]);
  });

  it("★★ a permanent hole (a blocked message) does not strand every later message", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    fx.seedLeafWithoutTranscriptRow("alice", SID);
    await fx.ingestReceived("alice", SID, "after the hole");
    expect(texts((await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Answer)).toEqual(["after the hole"]);
    expect(texts((await conn.send("cello_receive", { session_id: SID, timeout_ms: 200 })) as Answer)).toEqual([]);
  });

  it("★ it WAITS when nothing is unread, and answers the moment something arrives", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    const pending = conn.send("cello_receive", { session_id: SID, timeout_ms: 5_000 });
    await new Promise((r) => setTimeout(r, 150));
    await fx.ingestReceived("alice", SID, "late");
    expect(texts((await pending) as Answer)).toEqual(["late"]);
  });

  it("catch-up mode is gone: since_seq is refused by name, not silently ignored", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    const got = (await conn.send("cello_receive", { session_id: SID, since_seq: -1 })) as Answer;
    expect(got.ok).toBe(false);
    expect(got.reason).toBe("since_seq_removed");
  });
});
