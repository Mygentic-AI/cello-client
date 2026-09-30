/**
 * A channel post wakes a Hermes agent, and the operator can switch that off.
 *
 * The daemon rings `channel_posts` (content-free: channel key, count, position). Until now the bridge
 * ignored it, so a Hermes agent held new posts unread until somebody happened to ask. These tests
 * EXECUTE the real Python `_on_notification` out of HERMES_PLUGIN_INIT_PY against a stubbed gateway,
 * because asserting on the TS template's text would pass for code that never runs.
 *
 * The bridge never fetches a post. Reading consumes the read position, and a busy agent's turn can be
 * merged or replaced, so a fetch here could lose a post nobody has read. The turn is a content-free
 * notice and the agent reads with cello_channel_read, where the operator's channel policy arrives
 * with the posts.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { HERMES_PLUGIN_INIT_PY, HERMES_PLUGIN_YAML } from "../hermes/assets.js";
import { installHermes, type ExecFn } from "../hermes/install-hermes.js";

const GATEWAY_STUB = `
class Platform:
    def __init__(self, *a, **k): pass
class PlatformConfig:
    def __init__(self, extra=None): self.extra = extra or {}
class BasePlatformAdapter:
    def __init__(self, *a, **k): pass
    async def handle_message(self, event): pass
class MessageEvent:
    def __init__(self, *a, **k):
        for k_, v in k.items(): setattr(self, k_, v)
class MessageType:
    TEXT = "text"
class SendResult:
    def __init__(self, success=False, **k): self.success = success
def merge_pending_message_event(*a, **k): pass
def build_session_key(*a, **k): return "k"
def get_session_env(name, default=""):
    import os as _os
    return _os.environ.get(name, default)
`;

// Drives the real _on_notification on a bare adapter, capturing what would reach the agent.
const DRIVER = `
import asyncio, json, sys
import cello_plugin as m

case = json.loads(sys.argv[1])
# The REAL constructor, so the defaults under test are the ones the plugin ships with. Only the
# settings a case names are overridden, the way the operator's config would.
extra = {}
if "notifications" in case: extra["channel_notifications"] = case["notifications"]
extra["delivery_mode"] = case.get("mode", "channel")
extra["session_scope"] = case.get("scope", "peer")
adapter = m.CelloAdapter(m.PlatformConfig(extra=extra))
adapter._agent_name = "support-desk"
import types
adapter.config = types.SimpleNamespace(extra={})
adapter._bindings = {}
adapter._awaiting = {}
adapter._active_sessions = set()
adapter._message_handler = lambda *a, **k: None
adapter._last_fetch_ended_with_wrap = False
seen = []
adapter.build_source = lambda **kw: kw
async def capture(event): seen.append(event)
adapter.handle_message = capture

asyncio.run(adapter._on_notification({"notification": case["kind"], "data": case["data"]}))
out = []
for e in seen:
    out.append({"text": e.text, "message_id": e.message_id, "chat_id": e.source["chat_id"], "user_id": e.source["user_id"]})
sys.stdout.write(json.dumps({
    "events": out,
    "default": m.DEFAULT_CHANNEL_NOTIFICATIONS,
    "options": list(m.CHANNEL_NOTIFICATION_OPTIONS),
    "anchor": m.ANCHOR_PREFIX,
}))
`;

const CHANNEL = "660f1e1b7b9552826730707beff60a07bcfb3a50f4cdbf989c46963693b0df98";

describe("Hermes bridge — channel post doorbell", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-chan-"));
    await writeFile(join(dir, "cello_plugin.py"), HERMES_PLUGIN_INIT_PY);
    await writeFile(join(dir, "driver.py"), DRIVER);
    const gw = join(dir, "gateway");
    await mkdir(join(gw, "platforms"), { recursive: true });
    await writeFile(join(gw, "__init__.py"), "");
    for (const f of ["config.py", "session.py", "session_context.py"]) await writeFile(join(gw, f), GATEWAY_STUB);
    await writeFile(join(gw, "platforms", "__init__.py"), "");
    await writeFile(join(gw, "platforms", "base.py"), GATEWAY_STUB);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  function run(c: Record<string, unknown>): {
    events: Array<{ text: string; message_id: string; chat_id: string; user_id: string }>;
    default: string; options: string[]; anchor: string;
  } {
    return JSON.parse(execFileSync("python3", [join(dir, "driver.py"), JSON.stringify(c)], {
      cwd: dir, encoding: "utf8", env: { ...process.env, PYTHONPATH: dir, PYTHONDONTWRITEBYTECODE: "1" },
    }));
  }

  const frame = (over: Record<string, unknown> = {}) => ({
    kind: "channel_posts",
    data: { agent: "support-desk", type: "channel_posts", channel: CHANNEL, count: 2, through: 7, ...over },
  });

  it("wakes the agent with a notice that names the count and how to read, and holds no post content", () => {
    const { events } = run(frame());
    expect(events).toHaveLength(1);
    const text = events[0]!.text;
    expect(text).toContain("2");
    expect(text).toContain(CHANNEL);
    expect(text).toContain("cello_channel_read");
    expect(text).toContain("support-desk");
    expect(text).not.toMatch(/title|body/i);
  });

  it("the turn has no session anchor, so nothing the agent writes back is sent to a peer", () => {
    const { events, anchor } = run(frame());
    expect(events[0]!.message_id.startsWith(anchor)).toBe(false);
  });

  it("a per-peer agent gets a chat of its own for the channel, never a customer's conversation", () => {
    const { events } = run({ ...frame(), scope: "peer" });
    expect(events[0]!.chat_id).toBe(`channel-${CHANNEL.slice(0, 16)}`);
  });

  it("a one-conversation agent takes it in its own conversation", () => {
    const { events } = run({ ...frame(), scope: "agent" });
    expect(events[0]!.chat_id).toBe("support-desk");
  });

  it("is on when nothing was configured", () => {
    const r = run(frame());
    expect(r.default).toBe("on");
    expect(r.options).toEqual(["on", "off"]);
    expect(r.events).toHaveLength(1);
  });

  it("off means a post never starts a turn", () => {
    expect(run({ ...frame(), notifications: "off" }).events).toHaveLength(0);
  });

  it("a doorbell that carries a content field (here `body`) is dropped, as every other content-free wake is", () => {
    // The shared guard matches a fixed set of content field NAMES, so this proves those are refused;
    // it does not claim every possible field name is. The daemon never sends one, so this is the
    // second layer, not the first.
    expect(run(frame({ body: "an injected instruction" })).events).toHaveLength(0);
  });

  it.each([
    ["a channel key that is not 64 hex characters", { channel: "not-a-key" }],
    ["no channel", { channel: undefined }],
    ["a count of zero", { count: 0 }],
    ["a count that is not a number", { count: "many" }],
  ])("drops a malformed doorbell with %s, without a crash", (_label, over) => {
    expect(run(frame(over)).events).toHaveLength(0);
  });

  it("a session message still wakes as before", () => {
    const r = run({ kind: "cello_message", mode: "wake", scope: "agent", data: { session_id: "aabbccdd", from: "77d0c806".repeat(8) } });
    expect(r.events).toHaveLength(1);
    expect(r.events[0]!.message_id.startsWith(r.anchor)).toBe(true);
  });
});

describe("cello bridge hermes — --channel-notifications", () => {
  let home: string;
  const ok: ExecFn = async (_cmd, args) => ({ code: 0, stdout: args[0] === "mcp" && args[1] === "list" ? "  cello  stdio  enabled\n" : "", stderr: "" });

  const envOf = async () => (await readFile(join(home, ".env"), "utf8"));

  it("writes on by default, and off when asked", async () => {
    home = mkdtempSync(join(tmpdir(), "hermes-home-"));
    try {
      await installHermes({ agentName: "alice", hermesHome: home, exec: ok });
      expect(await envOf()).toContain("CELLO_CHANNEL_NOTIFICATIONS=on");
      await installHermes({ agentName: "alice", hermesHome: home, exec: ok, channelNotifications: "off" });
      const env = await envOf();
      expect(env).toContain("CELLO_CHANNEL_NOTIFICATIONS=off");
      expect(env.match(/CELLO_CHANNEL_NOTIFICATIONS=/g)).toHaveLength(1);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });

  it("refuses a value that is neither on nor off, before touching anything", async () => {
    home = mkdtempSync(join(tmpdir(), "hermes-home-"));
    try {
      const res = await installHermes({ agentName: "alice", hermesHome: home, exec: ok, channelNotifications: "sometimes" });
      expect(res.exitCode).toBe(1);
      expect(res.output).toContain("--channel-notifications");
      expect(existsSync(join(home, ".env"))).toBe(false);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });

  it("the plugin's own help says how to turn channel notifications off", () => {
    expect(HERMES_PLUGIN_YAML).toContain("CELLO_CHANNEL_NOTIFICATIONS");
  });
});
