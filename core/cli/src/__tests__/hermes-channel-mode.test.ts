/**
 * DOD-HERMES-4 — the Hermes adapter owns inbound content and outbound delivery.
 *
 * Three behaviours, all previously absent (M8C DoD, Tier 1½ addendum 2026-08-06):
 *
 *   1. `chat_id` is no longer the constant "default". It is the bound agent name, or
 *      `<agent>/<counterparty-pubkey>` under `session_scope: peer` — so a support desk gets one
 *      Hermes context per customer instead of every caller sharing one.
 *   2. In `delivery_mode: channel` the adapter FETCHES the screened message itself (cello_receive)
 *      and hands the agent the peer's actual words, rather than a content-free wake the agent must
 *      act on. The screening happened in the daemon either way — see the discussion log; this only
 *      changes which door the same screened bytes come through.
 *   3. `send()` delivers. It resolves the CELLO session from the reply anchor the Hermes gateway
 *      threads back (`metadata["reply_to_message_id"]`) and calls cello_send on the adapter's own
 *      socket — so delivery no longer depends on the model remembering a tool call.
 *
 * These tests EXECUTE the real Python out of HERMES_PLUGIN_INIT_PY against a stubbed `gateway`
 * package and a fake IPC `_call`, exactly as hermes-wake-prompt.test.ts does. Asserting on the TS
 * template's substrings would pass for code that never runs.
 *
 * Written RED-first per SPARC Phase R.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { HERMES_PLUGIN_INIT_PY } from "../hermes/assets.js";

/**
 * Stand-ins for the gateway symbols the plugin imports at module scope.
 *
 * `MessageEvent` and `SendResult` record their kwargs here (the real ones are dataclasses) because
 * what the adapter PUTS IN THEM is the whole assertion — the text the agent is handed, the chat_id
 * it is filed under, the message_id that later becomes the reply anchor.
 */
const GATEWAY_STUB = `
class Platform:
    def __init__(self, *a, **k): pass
class PlatformConfig:
    def __init__(self, extra=None): self.extra = extra or {}
class MessageType:
    TEXT = "text"
class MessageEvent:
    def __init__(self, **kw): self.__dict__.update(kw)
class SendResult:
    def __init__(self, success=False, message_id=None, error=None, retryable=False):
        self.success = success; self.message_id = message_id
        self.error = error; self.retryable = retryable
class BasePlatformAdapter:
    def __init__(self, config, platform):
        self.config = config; self._message_handler = None
        self._active_sessions = set(); self._pending_messages = {}
    def build_source(self, **kw):
        class S: pass
        s = S(); s.__dict__.update(kw); return s
    async def handle_message(self, event): self.delivered.append(event)
    def _mark_connected(self): pass
    def _mark_disconnected(self): pass
def merge_pending_message_event(pending, key, event, *, merge_text=False):
    # Mirrors gateway/platforms/base.py:2438 for the TEXT/TEXT case: WITHOUT merge_text the
    # pending slot is REPLACED (the earlier event is discarded outright); with it, the texts are
    # appended. Faithful on purpose — a stub that always appended would make the merge_text=True
    # fix untestable, and one that always replaced would hide it.
    existing = pending.get(key)
    if existing is not None and merge_text:
        existing.text = (existing.text + "\\n" + event.text) if existing.text else event.text
        return
    pending[key] = event
def build_session_key(source, **kw):
    # The REAL shape from gateway/session.py:1058 — namespaced, NOT the bare chat_id. A stub that
    # returned chat_id made a busy-check comparing against chat_id look correct while it could
    # never match anything in production. The stub must not assert the identity the code under
    # test is being checked for.
    return "agent:main:cello:dm:" + str(getattr(source, "chat_id", "?"))
`;

/**
 * Drives one adapter operation and prints a JSON verdict.
 *
 * The adapter is built with __new__ + explicit field assignment rather than __init__ so a test
 * never depends on gateway config plumbing; `_call` is replaced with a recorder so every IPC the
 * adapter attempts is visible, including ones it should NOT make.
 */
const DRIVER = `
import asyncio, json, sys
import cello_plugin as m

spec = json.loads(sys.argv[1])

adapter = m.CelloAdapter.__new__(m.CelloAdapter)
adapter._agent_name = spec.get("agent", "Ms_Chelly_Hermes")
adapter._delivery_mode = spec.get("delivery_mode", "channel")
adapter._session_scope = spec.get("session_scope", "agent")
adapter._runtime_session = "default"
adapter._writer = object()          # send()/receive must believe the socket is up
adapter._message_handler = lambda *a, **k: None
adapter._active_sessions = set()
adapter._pending_messages = {}
adapter.delivered = []
adapter.config = m.PlatformConfig(extra={})
# __new__ skips __init__, so this driver stands in for it. These two must match __init__'s
# starting state or _start_wake_worker cannot tell "no worker yet" from "worker running".
adapter._wake_queue = None
adapter._wake_task = None
adapter._retry_tasks = set()
# Stub the busy-retry timer: the test asserts THAT a retry was scheduled, not that asyncio can
# sleep. Leaving the real one in would make every busy case cost BUSY_RETRY_DELAY_SECONDS.
retry_scheduled = {"v": False}
adapter._requeue_wake_later = lambda frame, delay: retry_scheduled.__setitem__("v", True)

calls = []
receive_result = spec.get("receive_result", {"ok": True, "content": "hello from the peer"})
# A QUEUE of pending messages, mirroring the daemon: cello_receive serves this connection's
# oldest unread and returns an empty 'ok' once drained. Default is a single message so the
# existing cases are unchanged.
receive_queue = list(spec.get("receive_queue") or [])

async def fake_call(method, params=None, timeout=None):
    calls.append({"method": method, "params": params or {}})
    if method == "cello_receive":
        if receive_result == "raise":
            raise ConnectionError("socket died")
        if spec.get("receive_queue") is not None:
            if not receive_queue:
                return {"ok": True, "content": None}
            nxt = receive_queue.pop(0)
            if nxt == "raise":
                raise ConnectionError("socket died mid-drain")
            return {"ok": True, "content": nxt}
        return receive_result
    if method == "cello_send":
        return spec.get("send_result") or {"ok": True}
    return {"ok": True}

adapter._call = fake_call

async def main():
    out = {}
    op = spec["op"]
    if op == "readloop":
        # NO stubbed _call. The real _read_loop, the real _call, a real StreamReader, and a writer
        # that answers on that same reader - i.e. the actual topology, in which the response to
        # the adapter's own cello_receive can only be delivered BY the read loop.
        del adapter._call
        adapter._pending = {}
        adapter._next_id = 1
        adapter._closing = False
        adapter._reconnect_task = None
        reader = asyncio.StreamReader()

        class FakeWriter:
            def write(self, blob):
                req = json.loads(blob.decode("utf-8"))
                calls.append({"method": req.get("method"), "params": req.get("params") or {}})
                if req.get("method") == "cello_receive":
                    body = {"id": req["id"], "result": {"ok": True, "content": "hello from the peer"}}
                    reader.feed_data((json.dumps(body) + "\\n").encode("utf-8"))
            async def drain(self): pass
            def close(self): pass
            async def wait_closed(self): pass

        adapter._writer = FakeWriter()
        adapter._start_wake_worker()
        loop_task = asyncio.create_task(adapter._read_loop(reader))
        reader.feed_data(
            (json.dumps({"notification": "cello_message", "data": spec["data"]}) + "\\n").encode("utf-8")
        )

        started = asyncio.get_running_loop().time()
        while not adapter.delivered and asyncio.get_running_loop().time() - started < 4.0:
            await asyncio.sleep(0.02)
        out["elapsed"] = round(asyncio.get_running_loop().time() - started, 2)
        out["delivered"] = [{"text": e.text, "message_id": e.message_id} for e in adapter.delivered]
        adapter._closing = True
        loop_task.cancel()
        adapter._wake_task.cancel()
    elif op == "notify":
        if spec.get("busy"):
            # Mark the chat busy the way the GATEWAY does — by session key, derived through the
            # adapter's own helper. Adding the bare chat_id here would re-create the bug: the
            # production guard would look correct while never matching anything.
            _src = adapter.build_source(chat_id=spec["busy"], chat_type="dm")
            adapter._active_sessions.add(adapter._session_key_for(_src))
        for frame in spec.get("frames") or [{"kind": spec.get("kind"), "data": spec.get("data")}]:
            _f = {"notification": frame["kind"], "data": frame["data"]}
            if spec.get("busy_retries") is not None:
                _f["_cello_busy_retries"] = spec["busy_retries"]
            await adapter._on_notification(_f)
        out["delivered"] = [
            {"text": e.text, "chat_id": getattr(e.source, "chat_id", None), "message_id": e.message_id}
            for e in adapter.delivered
        ]
        out["pending"] = {k: v.text for k, v in adapter._pending_messages.items()}
        out["retry_scheduled"] = retry_scheduled["v"]
        out["pending_anchors"] = {
            k: getattr(v, "message_id", None) for k, v in adapter._pending_messages.items()
        }
    elif op == "connect":
        # The REAL connect() mode-agreement check. hint_mode is what register() baked into the
        # standing instructions (env, read once); _delivery_mode is what this adapter runs.
        import os as _os
        _os.environ["CELLO_DELIVERY_MODE"] = spec["hint_mode"]
        adapter._closing = False
        adapter._read_task = None
        reached = {"v": False}
        async def _fake_establish():
            reached["v"] = True
        adapter._establish = _fake_establish
        # A mode disagreement returns False BEFORE any socket work. Agreement falls through to
        # _establish, which succeeds here - so connect() returning True means the check passed.
        out["connected"] = bool(await adapter.connect())
        out["reached_establish"] = reached["v"]
    elif op == "send":
        res = await adapter.send(
            chat_id=spec.get("chat_id", "Ms_Chelly_Hermes"),
            content=spec.get("content", "the reply"),
            reply_to=spec.get("reply_to"),
            metadata=spec.get("metadata"),
        )
        out["success"] = res.success
        out["error"] = res.error
        out["delivered"] = [
            {"text": e.text, "chat_id": getattr(e.source, "chat_id", None), "message_id": e.message_id}
            for e in adapter.delivered
        ]
    out["calls"] = calls
    sys.stdout.write(json.dumps(out))

asyncio.run(main())
`;

interface Delivered { text: string; chat_id: string | null; message_id: string }
interface Verdict {
  delivered?: Delivered[];
  pending?: Record<string, string>;
  pending_anchors?: Record<string, string>;
  retry_scheduled?: boolean;
  success?: boolean;
  error?: string | null;
  /** AC13's connect() verdict. Declared because the assertions read it — and they pass, so the
   *  Python side does return it; the type was simply behind the tests that use it. */
  connected?: boolean;
  calls: Array<{ method: string; params: Record<string, unknown> }>;
}

describe("DOD-HERMES-4 — the adapter owns inbound content and outbound delivery", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-channel-"));
    await writeFile(join(dir, "cello_plugin.py"), HERMES_PLUGIN_INIT_PY);
    await writeFile(join(dir, "driver.py"), DRIVER);
    const gw = join(dir, "gateway");
    await mkdir(join(gw, "platforms"), { recursive: true });
    await writeFile(join(gw, "__init__.py"), "");
    await writeFile(join(gw, "config.py"), GATEWAY_STUB);
    await writeFile(join(gw, "session.py"), GATEWAY_STUB);
    await writeFile(join(gw, "platforms", "__init__.py"), "");
    await writeFile(join(gw, "platforms", "base.py"), GATEWAY_STUB);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  function run(spec: Record<string, unknown>): Verdict {
    const out = execFileSync("python3", [join(dir, "driver.py"), JSON.stringify(spec)], {
      cwd: dir,
      encoding: "utf8",
      env: { ...process.env, PYTHONPATH: dir, PYTHONDONTWRITEBYTECODE: "1" },
    });
    return JSON.parse(out) as Verdict;
  }

  /** The mode-specific half of the platform hint, as the plugin would build it under `mode`. */
  function hintFor(mode: string | null): string {
    // Typed as the process environment it actually is: spreading `process.env` into an object
    // literal loses its index signature, so TS refuses a key it carries perfectly well at runtime.
    const env: NodeJS.ProcessEnv = { ...process.env, PYTHONPATH: dir, PYTHONDONTWRITEBYTECODE: "1" };
    if (mode === null) delete env.CELLO_DELIVERY_MODE;
    else env.CELLO_DELIVERY_MODE = mode;
    return execFileSync(
      "python3",
      ["-c", "import cello_plugin as m; print(m._delivery_hint())"],
      { cwd: dir, encoding: "utf8", env },
    );
  }

  const AGENT = "Ms_Chelly_Hermes";
  const SID = "aabbccdd11223344";
  const PUB = "77d0c806".repeat(8);
  const MSG = { session_id: SID, from: PUB, who: "Ms_Chelly", whoKnown: true };

  // ─────────────────────────────────────────────── AC1: session_scope keying

  it("AC1: default scope files the session under the AGENT, never the constant 'default'", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG });
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].chat_id).toBe(AGENT);
    // The old constant collapsed every CELLO session into one Hermes chat — the defect this line fixes.
    expect(v.delivered![0].chat_id).not.toBe("default");
  });

  it("AC1: session_scope 'peer' gives each counterparty its own chat", () => {
    const a = run({ op: "notify", kind: "cello_message", data: MSG, session_scope: "peer" });
    const other = "11aa22bb".repeat(8);
    const b = run({
      op: "notify", kind: "cello_message", session_scope: "peer",
      data: { session_id: "cafe1234", from: other },
    });
    expect(a.delivered![0].chat_id).toBe(`${AGENT}/${PUB}`);
    expect(b.delivered![0].chat_id).toBe(`${AGENT}/${other}`);
    // Two customers, two contexts. Under 'agent' scope both of these are the same key — which is
    // exactly the support-desk failure (two problems in one session).
    expect(a.delivered![0].chat_id).not.toBe(b.delivered![0].chat_id);
  });

  it("AC1: peer scope with no counterparty on the frame DROPS the wake — it does not bucket it", () => {
    // Routing an unattributable wake to `<agent>/unknown` would merge unrelated peers into one
    // context under the very setting chosen to keep them apart. Dropping is the loud answer.
    const v = run({
      op: "notify", kind: "cello_message", session_scope: "peer",
      data: { session_id: SID },
    });
    expect(v.delivered).toHaveLength(0);
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
  });

  // ─────────────────────────────────────────────── AC2: inbound content

  it("AC2: channel mode hands the agent the PEER'S WORDS, fetched by the adapter", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG });
    const recv = v.calls.find((c) => c.method === "cello_receive");
    expect(recv).toBeDefined();
    expect(recv!.params.session_id).toBe(SID);
    expect(v.delivered![0].text).toContain("hello from the peer");
    // The agent is handed a MESSAGE, not a set of orders. Instructions in the same string as
    // counterparty content would build a bigger injection surface than Telegram's, not an equal one.
    expect(v.delivered![0].text).not.toContain("cello_receive");
    expect(v.delivered![0].text).not.toContain("cello_send");
  });

  it("AC2: wake mode is unchanged — content-free prose, and the adapter fetches nothing", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG, delivery_mode: "wake" });
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
    expect(v.delivered![0].text).toContain("CELLO wake");
    expect(v.delivered![0].text).toContain("cello_receive"); // the agent is told to fetch
    expect(v.delivered![0].text).not.toContain("hello from the peer");
  });

  it("AC2: a state-change notice stays prose even in channel mode — there is no content to fetch", () => {
    // Uses a TERMINAL state: 'created' is suppressed entirely in channel mode now (AC11), so
    // asserting on it here would be asserting the old behaviour. The point of this case is that a
    // state notice is never fetched, which holds for the states that ARE still delivered.
    const v = run({
      op: "notify", kind: "session_state_changed",
      data: { session_id: SID, counterpartyPubkey: PUB, state: "sealed" },
    });
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
    expect(v.delivered![0].text).toContain("CELLO wake");
    expect(v.delivered![0].text).toContain("sealed");
  });

  it("AC2: a failed fetch degrades to the wake prose LOUDLY, so the peer is not left waiting", () => {
    // The peer is blocked on a reply. Dropping the event would strand them silently; the prose wake
    // still routes the agent to cello_receive through the MCP surface, which remains registered.
    const v = run({ op: "notify", kind: "cello_message", data: MSG, receive_result: "raise" });
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].text).toContain("CELLO wake");
    expect(v.delivered![0].text).toContain("cello_receive");
  });

  it("AC2: a receive that returns no content degrades the same way — never an empty user turn", () => {
    const v = run({
      op: "notify", kind: "cello_message", data: MSG,
      receive_result: { ok: false, reason: "session_not_found" },
    });
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].text).toContain("CELLO wake");
  });

  // ─────────────────────────────────────────────── AC3: the anchor round-trip

  it("AC3: the inbound message_id carries the session id, so the reply can be routed back", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG });
    expect(v.delivered![0].message_id).toContain(SID);
  });

  it("AC3: an anchor minted on inbound routes an outbound send to the same session", () => {
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG });
    const anchor = inbound.delivered![0].message_id;

    const v = run({ op: "send", metadata: { reply_to_message_id: anchor }, content: "my reply" });
    const sent = v.calls.find((c) => c.method === "cello_send");
    expect(v.success).toBe(true);
    expect(sent).toBeDefined();
    expect(sent!.params.session_id).toBe(SID);
    expect(sent!.params.content).toBe("my reply");
  });

  // ─────────────────────────────────────────────── AC4: send() routing rules

  it("AC4: metadata is the carrier — 5 of 7 gateway send sites pass ONLY metadata", () => {
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG });
    const v = run({ op: "send", metadata: { reply_to_message_id: inbound.delivered![0].message_id } });
    expect(v.calls.find((c) => c.method === "cello_send")).toBeDefined();
  });

  it("AC4: the reply_to positional also works, for the two sites that pass it", () => {
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG });
    const v = run({ op: "send", reply_to: inbound.delivered![0].message_id });
    expect(v.calls.find((c) => c.method === "cello_send")).toBeDefined();
  });

  it("AC4: NO anchor means the turn did not come from CELLO — deliver nothing, report success", () => {
    // A turn typed into the Hermes desktop app on a shared session, a cron delivery, a progress
    // bubble. Telegram behaves identically: delivery follows the ORIGIN of the turn, not the
    // session. Failing here would error on every legitimate local turn.
    const v = run({ op: "send", metadata: {} });
    expect(v.success).toBe(true);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });

  it("AC4: an anchor that is PRESENT but unresolvable FAILS LOUDLY — never a nearest-session guess", () => {
    // The silent-fallback class: routing this to 'the most recent session' would deliver one
    // counterparty's words to another under session_scope: agent.
    const v = run({ op: "send", metadata: { reply_to_message_id: "cello-wake-" } });
    expect(v.success).toBe(false);
    expect(v.error).toBeTruthy();
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });

  it("AC4: a foreign anchor (another platform's message id) is not a CELLO turn", () => {
    const v = run({ op: "send", metadata: { reply_to_message_id: "12345" } });
    expect(v.success).toBe(true);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });

  it("AC4: an anchor carrying an unsafe session id is REJECTED, not passed to the daemon", () => {
    const v = run({ op: "send", metadata: { reply_to_message_id: "cello-wake-a b\nc-deadbeef" } });
    expect(v.success).toBe(false);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });

  // ─── AC13: the residue from the review, fixed rather than carried

  it("AC13: a reply held by the security gateway is surfaced TO THE AGENT, not just logged", () => {
    // The one case the agent cannot resolve on its own: only it knows whether each flagged item
    // should be redacted or allowed, but in channel mode it never called cello_send, so without
    // this it has no idea the reply was swallowed and the peer is still waiting.
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG });
    const v = run({
      op: "send", metadata: { reply_to_message_id: inbound.delivered![0].message_id },
      send_result: { ok: false, reason: "governance_warn", guidance: "flag-7 held" },
    });
    expect(v.success).toBe(false);
    expect(v.delivered).toHaveLength(1);
    const notice = v.delivered![0].text;
    expect(notice).toContain("was NOT sent");
    expect(notice).toContain("governance_decisions");
    expect(notice).toContain("flag-7 held");        // the daemon's own reason reaches the agent
  });

  it("AC13: the governance notice carries NO anchor — its answer must not auto-deliver", () => {
    // If it had one, the agent's response to "your message was held" would itself be sent to the
    // peer, which is neither what the agent meant nor a resolution of the hold.
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG });
    const v = run({
      op: "send", metadata: { reply_to_message_id: inbound.delivered![0].message_id },
      send_result: { ok: false, reason: "governance_warn", guidance: "held" },
    });
    expect(v.delivered![0].message_id.startsWith("cello-wake-")).toBe(false);
  });

  it("AC13: an ordinary send refusal is NOT surfaced — only the one the agent can act on", () => {
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG });
    const v = run({
      op: "send", metadata: { reply_to_message_id: inbound.delivered![0].message_id },
      send_result: { ok: false, reason: "session_not_active", guidance: "sealed" },
    });
    expect(v.success).toBe(false);
    expect(v.delivered ?? []).toHaveLength(0);
  });

  it("AC13: connect() REFUSES when the adapter's mode and the standing hint disagree", () => {
    // One direction is silent: adapter 'wake' + hint 'channel' tells the agent not to send while
    // send() is a no-op returning success — every reply lost, success reported at every layer.
    const v = run({ op: "connect", delivery_mode: "wake", hint_mode: "channel" });
    expect(v.connected).toBe(false);
  });

  it("AC13: connect() proceeds when they agree", () => {
    expect(run({ op: "connect", delivery_mode: "wake", hint_mode: "wake" }).connected).toBe(true);
    expect(run({ op: "connect", delivery_mode: "channel", hint_mode: "channel" }).connected).toBe(true);
  });

  // ─── AC11: the phantom doorbell — a 'created' notice must not occupy the agent

  it("AC11: channel mode does NOT wake the agent for a 'created' state notice", () => {
    // Live 2026-08-07: this notice started a turn, the message arrived ~1s later and found the
    // chat busy, and the whole feature fell back to the manual path. The one time it worked, the
    // agent had answered the notice [SILENT] fast enough to free itself — so the difference
    // between "it works" and "it does nothing" was a race.
    const v = run({
      op: "notify", kind: "session_state_changed",
      data: { session_id: SID, counterpartyPubkey: PUB, state: "created" },
    });
    expect(v.delivered).toHaveLength(0);
  });

  it("AC11: TERMINAL state notices still reach the agent — nothing follows those", () => {
    for (const state of ["sealed", "closed", "interrupted"]) {
      const v = run({
        op: "notify", kind: "session_state_changed",
        data: { session_id: SID, counterpartyPubkey: PUB, state },
      });
      expect(v.delivered, `state=${state}`).toHaveLength(1);
      expect(v.delivered![0].text).toContain(state);
    }
  });

  it("AC11: an UNKNOWN state is delivered, not dropped — the list is a denylist", () => {
    // Dropping an unrecognised state would be the silent kind of wrong: a future state that
    // carries its own information would vanish with no trace.
    const v = run({
      op: "notify", kind: "session_state_changed",
      data: { session_id: SID, counterpartyPubkey: PUB, state: "some_future_state" },
    });
    expect(v.delivered).toHaveLength(1);
  });

  it("AC11: wake mode still delivers 'created' — that mode has no message-delivery to protect", () => {
    const v = run({
      op: "notify", kind: "session_state_changed", delivery_mode: "wake",
      data: { session_id: SID, counterpartyPubkey: PUB, state: "created" },
    });
    expect(v.delivered).toHaveLength(1);
  });

  // ───────── AC10: the fetch must DRAIN, or the agent answers a stale message and is then muted

  it("AC10: everything queued is delivered, in order, as one turn", () => {
    // Live failure 2026-08-07: cello_receive serves this CONNECTION's oldest unread, not the
    // message the notification announced. With history behind it the adapter handed the agent a
    // five-minute-old message; the agent answered THAT, and the send was then refused because the
    // real message was still unread. The reply was lost and the agent believed it had answered.
    const v = run({
      op: "notify", kind: "cello_message", data: MSG,
      receive_queue: ["older message", "the one that just arrived"],
    });
    const text = v.delivered![0].text;
    expect(text).toContain("older message");
    expect(text).toContain("the one that just arrived");
    expect(text.indexOf("older message")).toBeLessThan(text.indexOf("the one that just arrived"));
    expect(v.delivered).toHaveLength(1); // one turn, so one reply — not a reply per message
  });

  it("AC10: it keeps reading until the queue is EMPTY, so nothing is left to block the reply", () => {
    const v = run({
      op: "notify", kind: "cello_message", data: MSG,
      receive_queue: ["a", "b", "c"],
    });
    const receives = v.calls.filter((c) => c.method === "cello_receive");
    // 3 messages + 1 read that comes back empty = the drain proved it reached the end.
    expect(receives.length).toBe(4);
  });

  it("AC10: only the FIRST read waits — the rest are non-blocking, or a drain costs 5s per message", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG, receive_queue: ["a", "b"] });
    const receives = v.calls.filter((c) => c.method === "cello_receive");
    expect(Number(receives[0].params.timeout_ms)).toBeGreaterThan(0);
    for (const r of receives.slice(1)) expect(Number(r.params.timeout_ms)).toBe(0);
  });

  it("AC10: a single queued message behaves exactly as before — no drain-shaped regression", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG, receive_queue: ["just one"] });
    expect(v.delivered![0].text).toBe("just one");
  });

  it("AC10: an empty queue still falls back to the notice, never an empty turn", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG, receive_queue: [] });
    expect(v.delivered![0].text).toContain("CELLO wake");
  });

  it("AC10: a mid-drain failure delivers what was already read rather than losing it", () => {
    // Dropping the successfully-read messages on a later error would put them nowhere: the daemon
    // has already marked them read, so they are not recoverable from the wake notice either.
    const v = run({
      op: "notify", kind: "cello_message", data: MSG,
      receive_queue: ["first one arrived", "raise"],
    });
    expect(v.delivered![0].text).toContain("first one arrived");
    expect(v.delivered![0].text).not.toContain("CELLO wake");
  });

  // ─────────────── AC9: the fallback notice must not tell a channel-mode agent to send

  it("AC9: channel mode's fallback notice FORBIDS cello_send — the bridge already sends", () => {
    // Found live 2026-08-07. The notice used to say "reply with cello_send" in BOTH modes, while
    // the adapter also delivered the turn's final text. An agent following it correctly produced
    // two messages to the peer: its reply, then the turn's tail — which was the agent's own
    // internal note-to-self. Delivering a counterparty the agent's private status is worse than
    // the duplicate that carried it.
    const v = run({ op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99 });
    const notice = Object.values(v.pending!)[0];
    expect(notice).toContain("CELLO wake");
    expect(notice).toContain("cello_receive");          // reading is still manual on this path
    expect(notice).toContain("Do NOT call cello_send");
    expect(notice).not.toContain("reply with the cello_send tool");
  });

  it("AC9: wake mode's notice still instructs cello_send — that mode has no bridge delivery", () => {
    const v = run({ op: "notify", kind: "cello_message", data: MSG, delivery_mode: "wake" });
    const notice = v.delivered![0].text;
    expect(notice).toContain("reply with the cello_send tool");
    expect(notice).not.toContain("Do NOT call cello_send");
  });

  it("AC9: neither mode's notice contradicts what that mode's send() actually does", () => {
    // The defect was a contradiction between two strings, so assert they cannot both appear.
    for (const mode of ["channel", "wake"]) {
      const v = run({ op: "notify", kind: "cello_message", data: MSG, delivery_mode: mode, busy: AGENT, busy_retries: 99 });
      const notice = Object.values(v.pending!)[0] ?? v.delivered?.[0]?.text ?? "";
      const forbids = notice.includes("Do NOT call cello_send");
      const instructs = notice.includes("reply with the cello_send tool");
      expect(forbids && instructs).toBe(false);
      expect(forbids || instructs).toBe(true);
    }
  });

  // ────────────────────────────── AC7: a busy chat must not lose a message it already consumed

  it("AC12: a busy chat gets RETRIED, not immediately downgraded to a notice", () => {
    // Before: busy meant instantly handing the agent the manual-path notice. The agent is busy
    // more often than not, so that was most messages. Now it waits for the turn — fetching DURING
    // one is the only thing that can lose a message outright, so waiting is the only safe option.
    const v = run({ op: "notify", kind: "cello_message", data: MSG, busy: AGENT });
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
    expect(v.delivered).toHaveLength(0);        // nothing handed over yet…
    expect(Object.keys(v.pending ?? {})).toHaveLength(0); // …and not queued as a notice either
    expect(v.retry_scheduled).toBe(true);       // it is coming back
  });

  it("AC12: after the retry budget is spent, it DOES fall back to a notice — no infinite wait", () => {
    // A peer blocked forever on an agent that never frees is worse than the manual path.
    const v = run({ op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99 });
    expect(Object.values(v.pending!)[0]).toContain("CELLO wake");
    expect(v.retry_scheduled).toBe(false);
  });

  it("AC7: a wake for a BUSY chat is not fetched — consuming it could destroy it", () => {
    // cello_receive CONSUMES (it advances the delivery bookmark and read watermark). A busy chat's
    // event goes to the pending slot, where it can be merged or replaced — so fetching first can
    // leave a message that is neither in Hermes nor unread in the daemon. Left unfetched it stays
    // recoverable, and the prose wake tells the agent how.
    const v = run({ op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99 });
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
    expect(Object.values(v.pending!)[0]).toContain("CELLO wake");
  });

  it("AC7: two wakes on one busy chat BOTH survive — the second does not evict the first", () => {
    const second = "99ff88ee".repeat(8);
    const v = run({
      op: "notify", busy: AGENT, busy_retries: 99,
      frames: [
        { kind: "cello_message", data: MSG },
        { kind: "cello_message", data: { session_id: "beef9999", from: second } },
      ],
    });
    const pending = Object.values(v.pending!)[0];
    // Without merge_text=True the pending slot REPLACES, so the first peer's notice would be gone
    // with nothing anywhere recording that it existed.
    expect(pending).toContain(SID);
    expect(pending).toContain("beef9999");
  });

  it("AC7: merging TWO sessions into one turn disables automatic delivery — it never picks one", () => {
    // merge_pending_message_event keeps the EXISTING event and mutates only .text, so the second
    // anchor is dropped. Left alone, one reply written in view of both peers' words would be
    // delivered entirely to whichever arrived first: B's content quoted to A, and B never
    // answered. Cross-conversation leak plus silent non-delivery, in the DEFAULT config.
    const second = "99ff88ee".repeat(8);
    const v = run({
      op: "notify", busy: AGENT, busy_retries: 99,
      frames: [
        { kind: "cello_message", data: MSG },
        { kind: "cello_message", data: { session_id: "beef9999", from: second } },
      ],
    });
    const anchor = Object.values(v.pending_anchors!)[0]!;
    expect(anchor).not.toContain(SID); // the surviving anchor must NOT still route to peer A
    expect(anchor.startsWith("cello-ambiguous-")).toBe(true);

    // …and that poisoned anchor must make send() refuse rather than deliver to a guess.
    const sent = run({ op: "send", metadata: { reply_to_message_id: anchor } });
    expect(sent.success).toBe(false);
    expect(sent.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });

  it("AC7: two wakes on the SAME session keep their anchor — only cross-session merges poison it", () => {
    // The common case (a peer sending twice while the agent thinks) must still deliver normally.
    const v = run({
      op: "notify", busy: AGENT, busy_retries: 99,
      frames: [
        { kind: "cello_message", data: MSG },
        { kind: "cello_message", data: { session_id: SID, from: PUB } },
      ],
    });
    expect(Object.values(v.pending_anchors!)[0]).toContain(SID);
  });

  // ───────────────────────────────────── AC8: a routing key is never fabricated

  it("AC8: a wake with no session id is DROPPED — 'unknown' must never become a destination", () => {
    // _safe_scalar's "unknown" default is right for prose and catastrophic as an id: it parses
    // cleanly out of an anchor and would be handed to the daemon as a real session to send to.
    const v = run({ op: "notify", kind: "cello_message", data: { from: PUB } });
    expect(v.delivered).toHaveLength(0);
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
  });

  it("AC8: an unsafe session id is rejected, not smuggled into the anchor", () => {
    const v = run({ op: "notify", kind: "cello_message", data: { session_id: "aa bb\ncc", from: PUB } });
    expect(v.delivered).toHaveLength(0);
  });

  it("AC8: a state notice with no counterparty under peer scope is FILED, not dropped", () => {
    // counterpartyPubkey is nullable on the daemon's frame, so this is ordinary. Dropping it would
    // hide seals from a support desk — the configuration that most needs to see them. Content-free,
    // so the agent-level chat leaks nothing.
    const v = run({
      op: "notify", kind: "session_state_changed", session_scope: "peer",
      data: { session_id: SID, state: "sealed" },
    });
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].chat_id).toBe(AGENT);
    expect(v.delivered![0].text).toContain("sealed");
  });

  // ────────────────────────────────── AC6: the fetch must not deadlock the loop that feeds it

  it("AC6: the REAL read loop delivers content promptly — the fetch cannot await its own reader", () => {
    // The defect this exists to catch: handling the wake inline in _read_loop makes the adapter's
    // own cello_receive wait for a reply that only _read_loop can deliver. Nothing hangs visibly
    // — it times out and degrades to the wake prose, so every stubbed-_call test stays green
    // while the feature is 100% dead. Only a test that drives the real loop can see it.
    const v = run({ op: "readloop", data: MSG }) as Verdict & { elapsed: number };
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].text).toContain("hello from the peer");
    expect(v.delivered![0].text).not.toContain("CELLO wake"); // i.e. NOT the degraded fallback
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeDefined();
    expect(v.elapsed).toBeLessThan(2);
  });

  it("AC6: the adapter asks the daemon for a SHORT wait, not one that races its own timeout", () => {
    // A server-side wait equal to CALL_TIMEOUT_SECONDS lets the client give up on a call the
    // daemon is about to answer.
    const v = run({ op: "readloop", data: MSG });
    const recv = v.calls.find((c) => c.method === "cello_receive")!;
    expect(recv.params.timeout_ms).toBeDefined();
    expect(Number(recv.params.timeout_ms)).toBeLessThan(30000);
  });

  // ─────────────────────────────────────────────── AC5: the agent's standing instructions

  it("AC5: channel mode tells the agent NOT to call cello_receive/cello_send for the back-and-forth", () => {
    // Handing a channel-mode agent the wake-mode instructions makes it fetch a message the
    // adapter already delivered and send a reply the adapter will also send — a duplicate
    // delivered to the peer. The two instruction sets are mutually exclusive.
    const hint = hintFor("channel");
    expect(hint).toContain("Do NOT call cello_receive or cello_send");
    expect(hint).not.toContain("Fetch the actual message with cello_receive");
  });

  it("AC5: wake mode still tells the agent to fetch and reply itself", () => {
    const hint = hintFor("wake");
    expect(hint).toContain("cello_receive");
    expect(hint).toContain("session_not_current");
    expect(hint).not.toContain("Do NOT call cello_receive or cello_send");
  });

  it("AC5: an unset mode gets the channel hint, matching the adapter's own default", () => {
    // A default that disagrees between the hint and the code is how an agent ends up told to do
    // one thing while the adapter does another.
    expect(hintFor(null)).toContain("Do NOT call cello_receive or cello_send");
  });

  it("AC4: wake mode never delivers from the adapter, even holding a valid anchor", () => {
    const inbound = run({ op: "notify", kind: "cello_message", data: MSG, delivery_mode: "wake" });
    const v = run({
      op: "send", delivery_mode: "wake",
      metadata: { reply_to_message_id: inbound.delivered![0].message_id },
    });
    expect(v.success).toBe(true);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });
});
