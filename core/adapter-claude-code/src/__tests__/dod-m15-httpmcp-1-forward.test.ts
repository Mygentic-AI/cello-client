/**
 * 082-HTTPMCP — the doorbell/reconnect forwarder honours a permit: a restricted endpoint must not
 * announce an agent it does not serve, on the reconnect notice or on a doorbell, and frames keep
 * their arrival order when the permit is asynchronous.
 */
import { describe, it, expect } from "vitest";
import { forwardDaemonNotifications } from "../channel-forward.js";
import type { IpcProxy } from "../ipc-proxy.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

function rig(currentAgent: string | null, permit?: (f: Record<string, unknown>) => boolean | Promise<boolean>) {
  const sent: Array<{ method: string; params: Record<string, unknown> }> = [];
  let onReconnect: (() => void) | undefined;
  let onNotification: ((f: Record<string, unknown>) => void) | undefined;
  const proxy = {
    currentAgent,
    onReconnect: (h: () => void) => { onReconnect = h; },
    onNotification: (h: (f: Record<string, unknown>) => void) => { onNotification = h; },
  } as unknown as IpcProxy;
  const server = { server: { notification: async (n: { method: string; params: Record<string, unknown> }) => { sent.push(n); } } } as unknown as McpServer;
  forwardDaemonNotifications(proxy, server, permit);
  return { sent, reconnect: () => onReconnect!(), notify: (f: Record<string, unknown>) => onNotification!(f) };
}
const tick = () => new Promise((r) => setTimeout(r, 20));
const frame = (agent: string, n: number) => ({ notification: "agent_state_changed", data: { agent, type: "agent_state_changed", n } });

describe("082 notification forwarder permit", () => {
  it("reconnect notice for an unpermitted current agent is NOT sent; for a permitted one it is", async () => {
    const denied = rig("bob", async (f) => (f as { data: { agent: string } }).data.agent === "alice");
    denied.reconnect();
    await tick();
    expect(denied.sent.length).toBe(0);
    const allowed = rig("alice", async (f) => (f as { data: { agent: string } }).data.agent === "alice");
    allowed.reconnect();
    await tick();
    expect(allowed.sent.length).toBe(1);
    expect(allowed.sent[0]!.method).toBe("notifications/claude/channel");
  });

  it("reconnect with no current agent names nobody and is sent", async () => {
    const r = rig(null, async () => false);
    r.reconnect();
    await tick();
    expect(r.sent.length).toBe(1);
  });

  it("an asynchronous permit keeps arrival order and drops the frames it refuses", async () => {
    const r = rig("alice", async (f) => {
      const d = (f as { data: { agent: string; n: number } }).data;
      await new Promise((res) => setTimeout(res, d.n === 1 ? 30 : 1));
      return d.agent !== "bob";
    });
    r.notify(frame("alice", 1));
    r.notify(frame("bob", 2));
    r.notify(frame("carol", 3));
    await new Promise((res) => setTimeout(res, 120));
    expect(r.sent.length).toBe(2);
    expect(JSON.stringify(r.sent[0]!.params)).toContain("alice");
    expect(JSON.stringify(r.sent[1]!.params)).toContain("carol");
    expect(JSON.stringify(r.sent)).not.toContain("bob");
  });

  it("with no permit (the stdio shim) a doorbell is forwarded synchronously", () => {
    const r = rig("alice");
    r.notify(frame("bob", 1));
    return tick().then(() => expect(r.sent.length).toBe(1));
  });
});
