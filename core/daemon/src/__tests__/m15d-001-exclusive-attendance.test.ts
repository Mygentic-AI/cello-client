/**
 * M15D 001-DAEMON — the order's WHAT MUST NOT CHANGE clauses, through a real daemon socket.
 *
 * 1. A plugin socket and a Hermes socket attend: a message arrives, BOTH get the doorbell, and the
 *    holder is the plugin.
 * 2. A caller id cannot be chosen by the client: `caller` on a cli or mcp socket → caller_not_permitted;
 *    an endpoint socket without one → caller_missing. Both in the response AND the log.
 * 3. No guarded call as a held agent without force: per method, caller B → agent_held naming A; the
 *    message is not sent, the watermark does not move.
 * 4. No watermark without delivery: an endpoint receive with no commit leaves the messages unread; a
 *    receive waiting when its socket closes stops at once and marks nothing read.
 * Plus: an endpoint caller's hold outlives the socket it was taken on; an offline agent is refused.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { connectToDaemon } from "../ipc-client.js";
import { ReceiveCommits } from "../receive-commit.js";

type R = Record<string, unknown>;
const SID = "e1".repeat(32);
const CHATGPT = { id: "oauth:chatgpt-client", label: "ChatGPT" };
const CLAUDE = { id: "oauth:claude-client", label: "Claude" };
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const texts = (r: R) => ((r["messages"] as Array<{ text?: string; content?: string }> | undefined) ?? []).map((m) => m.text ?? m.content);

describe("M15D 001-DAEMON: exclusive attendance and a delivery-safe receive", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m15d-001-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  it("MUST NOT CHANGE 1: plugin and Hermes both get the doorbell; the holder is the plugin", async () => {
    await fx.createSession(SID, "alice");
    const plugin = await fx.connect("mcp");
    await plugin.send("cello_start_agent", { name: "alice" });
    expect(await plugin.send("cello_use_agent", { name: "alice" })).toMatchObject({ ok: true, role: "holder" });
    const hermes = await fx.connect("hermes");
    expect(await hermes.send("cello_use_agent", { name: "alice" })).toMatchObject({ ok: true, role: "listener" });

    const rang: string[] = [];
    plugin.onNotification((n) => { if (n.notification === "cello_message") rang.push("plugin"); });
    hermes.onNotification((n) => { if (n.notification === "cello_message") rang.push("hermes"); });
    await fx.ingestReceived("alice", SID, "hello");
    await wait(100);

    expect(rang.sort()).toEqual(["hermes", "plugin"]);
    const agents = ((await plugin.send("cello_list_agents", {})) as R)["agents"] as R[];
    expect(agents.find((a) => a["name"] === "alice")?.["holder"]).toMatchObject({ label: "an MCP session" });
    // The listener is never refused: it may receive as the agent the plugin holds.
    expect(await hermes.send("cello_receive", { session_id: SID, timeout_ms: 50 })).toMatchObject({ ok: true });
  });

  it("MUST NOT CHANGE 2: a caller on a cli or mcp socket is refused caller_not_permitted; an endpoint without one, caller_missing", async () => {
    for (const clientType of ["cli", "mcp"]) {
      const raw = await connectToDaemon(fx.socketPath, { caller: CHATGPT });
      await raw.send("ipc.connect", { clientType });
      expect(await raw.send("cello_list_agents", {})).toMatchObject({ ok: false, reason: "caller_not_permitted" });
      raw.close();
    }
    const bare = await connectToDaemon(fx.socketPath);
    await bare.send("ipc.connect", { clientType: "endpoint" });
    expect(await bare.send("cello_list_agents", {})).toMatchObject({ ok: false, reason: "caller_missing" });
    const malformed = await connectToDaemon(fx.socketPath, { caller: { id: "", label: "x" } });
    await malformed.send("ipc.connect", { clientType: "endpoint" });
    expect(await malformed.send("cello_list_agents", {})).toMatchObject({ ok: false, reason: "caller_missing" });
    bare.close();
    malformed.close();

    const logged = fx.eventsNamed("daemon.ipc.caller.refused").map((e) => e.ctx["reason"]);
    expect(logged).toEqual(["caller_not_permitted", "caller_not_permitted", "caller_missing", "caller_missing"]);
  });

  it("MUST NOT CHANGE 3: each guarded call by a second caller is refused agent_held naming the holder, and changes nothing", async () => {
    await fx.createSession(SID, "alice");
    const holder = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "unread");
    const watermark = fx.snm.getLastDeliveredSeq("alice", SID);
    const leaves = fx.snm.getSessionTree("alice", SID).size();
    const other = await fx.connectEndpoint(CHATGPT);

    const calls: Array<[string, R]> = [
      ["cello_send", { session_id: SID, content: "as alice [[OVER]]", agent: "alice" }],
      ["cello_receive", { session_id: SID, timeout_ms: 50, agent: "alice" }],
      ["cello_close_session", { session_id: SID, agent: "alice" }],
      ["cello_initiate_session", { target_pubkey: "bb".repeat(32), agent: "alice" }],
      ["cello_await_session", { timeout_ms: 50, agent: "alice" }],
    ];
    for (const [method, params] of calls) {
      const res = (await other.send(method, params)) as R;
      expect(res, method).toMatchObject({ ok: false, reason: "agent_held", agent: "alice", holder: { label: "test" } });
      expect(String(res["guidance"]), method).toMatch(/force: true/);
    }
    expect(fx.snm.getSessionTree("alice", SID).size(), "nothing was sent").toBe(leaves);
    expect(fx.snm.getLastDeliveredSeq("alice", SID), "nothing was marked read").toBe(watermark);
    expect(fx.snm.getSessionRecord("alice", SID)?.status, "nothing was closed").toBe("active");
    // Reads are never guarded.
    expect(await other.send("cello_transcript", { session_id: SID, agent: "alice" })).toMatchObject({ ok: true });
    // The holder is untouched.
    expect(texts((await holder.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as R)).toEqual(["unread"]);
  });

  it("an endpoint caller's hold outlives the socket it was taken on; another caller is still refused", async () => {
    await fx.createSession(SID, "alice");
    const first = await fx.connectEndpoint(CHATGPT);
    await first.send("cello_start_agent", { name: "alice" });
    expect(await first.send("cello_use_agent", { name: "alice" })).toMatchObject({ ok: true, role: "holder" });
    first.close();
    await wait(50);

    // ChatGPT's next tool call arrives on a new socket and names no agent: its hold is its selection.
    await fx.ingestReceived("alice", SID, "for chatgpt");
    const next = await fx.connectEndpoint(CHATGPT);
    expect(texts((await next.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as R)).toEqual(["for chatgpt"]);

    const claude = await fx.connectEndpoint(CLAUDE);
    expect(await claude.send("cello_receive", { session_id: SID, timeout_ms: 50, agent: "alice" }))
      .toMatchObject({ ok: false, reason: "agent_held", holder: { label: "ChatGPT" } });
  });

  it("a guarded call naming an offline agent is refused agent_offline and starts nothing", async () => {
    const c = await fx.connectEndpoint(CHATGPT);
    const res = (await c.send("cello_receive", { session_id: SID, timeout_ms: 50, agent: "alice" })) as R;
    expect(res).toMatchObject({ ok: false, reason: "agent_offline", agent: "alice" });
    expect(String(res["guidance"])).toMatch(/cello_start_agent/);
  });

  it("MUST NOT CHANGE 4a: an endpoint receive returns a commit token and marks nothing read until it is committed", async () => {
    await fx.createSession(SID, "alice");
    const c = await fx.connectEndpoint(CHATGPT, false);
    await c.send("cello_start_agent", { name: "alice" });
    await c.send("cello_use_agent", { name: "alice" });
    await fx.ingestReceived("alice", SID, "one");

    const first = (await c.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as R;
    expect(texts(first)).toEqual(["one"]);
    expect(typeof first["commit"]).toBe("string");
    // Not committed: the same message comes back.
    const again = (await c.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as R;
    expect(texts(again)).toEqual(["one"]);
    // Committed: it is read.
    expect(await c.send("session.receive.commit", { token: again["commit"] })).toEqual({ ok: true });
    const after = (await c.send("cello_receive", { session_id: SID, timeout_ms: 50 })) as R;
    expect(texts(after)).toEqual([]);
    // A token is single use.
    expect(await c.send("session.receive.commit", { token: again["commit"] })).toMatchObject({ ok: false, reason: "commit_unknown" });
  });

  it("MUST NOT CHANGE 4b: an uncommitted token expires and the messages stay unread", async () => {
    const committed: string[] = [];
    const expired: unknown[] = [];
    const logger = { debug() {}, info() {}, error() {}, warn(e: string, ctx?: R) { if (e === "session.receive.commit.expired") expired.push(ctx); } };
    const commits = new ReceiveCommits(logger, 30);
    const token = commits.issue(() => committed.push("x"), { sessionId: SID });
    await wait(80);
    expect(commits.redeem(token)).toBe(false);
    expect(committed).toEqual([]);
    expect(expired).toHaveLength(1);
  });

  it("MUST NOT CHANGE 4c: a receive waiting when its socket closes stops within 100 ms and marks nothing read", async () => {
    await fx.createSession(SID, "alice");
    const c = await fx.connectAs("alice");
    void c.send("cello_receive", { session_id: SID, timeout_ms: 20_000 }).catch(() => {});
    await wait(100);
    const closedAt = Date.now();
    c.close();
    await wait(100);
    // Present 100 ms after the close: the wait stopped instead of running to its 20 s timeout.
    expect(fx.eventsNamed("session.receive.cancelled"), `checked ${Date.now() - closedAt} ms after close`).toHaveLength(1);
    // And the hold went with the socket, so the agent is no longer reachable.
    const probe = await fx.connect("cli");
    const agents = ((await probe.send("cello_list_agents", {})) as R)["agents"] as R[];
    expect(agents.find((a) => a["name"] === "alice")?.["holder"]).toBeNull();
  });
});
