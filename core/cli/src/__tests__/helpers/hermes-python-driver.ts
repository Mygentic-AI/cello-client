/**
 * Shared test harness for the Hermes CELLO adapter (HERMES_PLUGIN_INIT_PY).
 *
 * The adapter is Python held in a TS string. These helpers EXECUTE that real Python against a
 * stubbed `gateway` package and a fake IPC `_call`, so a test asserts on the adapter's actual
 * behaviour — the text it hands the agent, the chat_id it files under, the reply anchor it mints —
 * not on substrings of the TS template (which would pass for code that never runs).
 *
 * Extracted from hermes-channel-mode.test.ts so hermes-explicit-mode.test.ts reuses the exact same
 * stub and driver rather than copying them (work order 049-BRIDGEREPLY: "Do not copy them.").
 */

import { mkdir, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { HERMES_PLUGIN_INIT_PY } from "../../hermes/assets.js";

/**
 * Stand-ins for the gateway symbols the plugin imports at module scope.
 *
 * `MessageEvent` and `SendResult` record their kwargs here (the real ones are dataclasses) because
 * what the adapter PUTS IN THEM is the whole assertion — the text the agent is handed, the chat_id
 * it is filed under, the message_id that later becomes the reply anchor.
 */
export const GATEWAY_STUB = `
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
def get_session_env(name, default=""):
    # Real signature from gateway/session_context.py:363. The real one reads a ContextVar carried
    # into the tool worker thread; here the driver sets HERMES_SESSION_CHAT_ID / _PLATFORM in the
    # process env, so reading os.environ mirrors what the hook sees inside a Hermes turn.
    import os as _os
    return _os.environ.get(name, default)
`;

/**
 * Drives one adapter operation and prints a JSON verdict.
 *
 * The adapter is built with __new__ + explicit field assignment rather than __init__ so a test
 * never depends on gateway config plumbing; `_call` is replaced with a recorder so every IPC the
 * adapter attempts is visible, including ones it should NOT make.
 */
export const DRIVER = `
import asyncio, json, sys
import cello_plugin as m

spec = json.loads(sys.argv[1])

adapter = m.CelloAdapter.__new__(m.CelloAdapter)
adapter._agent_name = spec.get("agent", "Ms_Chelly_Hermes")
adapter._delivery_mode = spec.get("delivery_mode", "explicit")
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
# Part B/C state (049-BRIDGEREPLY). __new__ skips __init__, so the driver seeds these too.
adapter._bindings = dict(spec.get("bindings") or {})
adapter._bindings_path = spec.get("bindings_path", "/tmp/cello-test-bindings.json")
adapter._awaiting = {}
adapter._loop = None
# The recording/reminder hooks reach the adapter through this module global (set in __init__).
m._ADAPTER_INSTANCE = None if spec.get("no_adapter") else adapter
# Stub the busy-retry timer: the test asserts THAT a retry was scheduled, not that asyncio can
# sleep. Leaving the real one in would make every busy case cost BUSY_RETRY_DELAY_SECONDS.
retry_scheduled = {"v": False}
adapter._requeue_wake_later = lambda frame, delay: retry_scheduled.__setitem__("v", True)

calls = []
receive_result = spec.get("receive_result", {"ok": True, "count": 1, "messages": [{"sequence": 0, "content": "hello from the peer"}]})
# The pending messages, mirroring the daemon since 2026-09-13: ONE cello_receive returns every
# unread message as 'messages' and marks them read, so a second read returns nothing.
receive_queue = list(spec.get("receive_queue") or [])

async def fake_call(method, params=None, timeout=None):
    calls.append({"method": method, "params": params or {}})
    if method == "cello_receive":
        if receive_result == "raise":
            raise ConnectionError("socket died")
        if spec.get("receive_queue") is not None:
            batch = [{"sequence": i, "content": c} for i, c in enumerate(receive_queue)]
            receive_queue.clear()
            if not batch:
                return {"ok": True, "content": None}
            return {"ok": True, "count": len(batch), "messages": batch}
        return receive_result
    if method == "cello_send":
        return spec.get("send_result") or {"ok": True}
    if method == "cello_list_sessions":
        if spec.get("sessions_result") == "raise":
            raise ConnectionError("socket died")
        return spec.get("sessions_result", {"ok": True, "sessions": []})
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
                    body = {"id": req["id"], "result": {"ok": True, "count": 1, "messages": [{"sequence": 0, "content": "hello from the peer"}]}}
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
        out["bindings"] = adapter._bindings
        out["awaiting"] = {k: list(v.keys()) for k, v in adapter._awaiting.items()}
    elif op == "record":
        # Part B/C recording via the module-level post_tool_call hook.
        import os as _os
        if "chat_env" in spec:
            _os.environ["HERMES_SESSION_CHAT_ID"] = spec["chat_env"]
        else:
            _os.environ.pop("HERMES_SESSION_CHAT_ID", None)
        _os.environ["HERMES_SESSION_PLATFORM"] = spec.get("platform_env", "cello")
        m._on_post_tool_call(
            tool_name=spec["tool_name"], args=spec.get("args") or {}, result=spec.get("hook_result")
        )
        out["bindings"] = adapter._bindings
        out["awaiting"] = {k: list(v.keys()) for k, v in adapter._awaiting.items()}
    elif op == "prune":
        # Finding 1(b): the connect/reconnect prune drops links the daemon no longer lists as open.
        await adapter._prune_bindings()
        out["bindings"] = adapter._bindings
    elif op == "loadbindings":
        # Part B4: a brand-new adapter instance must recover bindings from disk (restart).
        fresh = m.CelloAdapter.__new__(m.CelloAdapter)
        fresh._bindings_path = spec["bindings_path"]
        out["bindings"] = fresh._load_bindings()
    elif op == "cflow":
        # Part C: arm an awaiting reply by delivering peer messages, then drive the post_* hooks.
        import os as _os
        adapter._loop = asyncio.get_running_loop()
        _os.environ["HERMES_SESSION_PLATFORM"] = "cello"
        for frame in spec.get("frames") or []:
            await adapter._on_notification({"notification": frame["kind"], "data": frame["data"]})
        for hook in spec.get("hooks") or []:
            if hook["type"] == "send":
                m._on_post_tool_call(
                    tool_name="mcp__cello__cello_send",
                    args={"session_id": hook["session_id"]},
                    result=hook.get("result") or {"ok": True},
                )
            elif hook["type"] == "llm":
                _os.environ["HERMES_SESSION_CHAT_ID"] = hook["chat_id"]
                m._on_post_llm_call(platform=hook.get("platform", "cello"), session_id=hook.get("session_id", ""))
        await asyncio.sleep(0.15)
        out["delivered"] = [
            {"text": e.text, "chat_id": getattr(e.source, "chat_id", None), "message_id": e.message_id}
            for e in adapter.delivered
        ]
        out["awaiting"] = {k: list(v.keys()) for k, v in adapter._awaiting.items()}
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

export interface Delivered {
  text: string;
  chat_id: string | null;
  message_id: string;
}
export interface Verdict {
  delivered?: Delivered[];
  pending?: Record<string, string>;
  pending_anchors?: Record<string, string>;
  retry_scheduled?: boolean;
  success?: boolean;
  error?: string | null;
  connected?: boolean;
  reached_establish?: boolean;
  elapsed?: number;
  bindings?: Record<string, string>;
  awaiting?: Record<string, string[]>;
  calls: Array<{ method: string; params: Record<string, unknown> }>;
}

/** Write the plugin, driver and stubbed `gateway` package into `dir`. */
export async function installHermesDriver(dir: string): Promise<void> {
  await writeFile(join(dir, "cello_plugin.py"), HERMES_PLUGIN_INIT_PY);
  await writeFile(join(dir, "driver.py"), DRIVER);
  const gw = join(dir, "gateway");
  await mkdir(join(gw, "platforms"), { recursive: true });
  await writeFile(join(gw, "__init__.py"), "");
  await writeFile(join(gw, "config.py"), GATEWAY_STUB);
  await writeFile(join(gw, "session.py"), GATEWAY_STUB);
  await writeFile(join(gw, "session_context.py"), GATEWAY_STUB);
  await writeFile(join(gw, "platforms", "__init__.py"), "");
  await writeFile(join(gw, "platforms", "base.py"), GATEWAY_STUB);
}

/** Run one driver operation and parse its JSON verdict. */
export function runDriver(dir: string, spec: Record<string, unknown>): Verdict {
  const out = execFileSync("python3", [join(dir, "driver.py"), JSON.stringify(spec)], {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, PYTHONPATH: dir, PYTHONDONTWRITEBYTECODE: "1" },
  });
  return JSON.parse(out) as Verdict;
}

/** The mode-specific half of the platform hint, as the plugin builds it under `mode`. */
export function hintFor(dir: string, mode: string | null): string {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONPATH: dir, PYTHONDONTWRITEBYTECODE: "1" };
  if (mode === null) delete env.CELLO_DELIVERY_MODE;
  else env.CELLO_DELIVERY_MODE = mode;
  return execFileSync(
    "python3",
    ["-c", "import cello_plugin as m; print(m._delivery_hint())"],
    { cwd: dir, encoding: "utf8", env },
  );
}
