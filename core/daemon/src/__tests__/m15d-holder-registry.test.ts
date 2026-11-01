/**
 * M15D 001-DAEMON — the holder registry on its own: zero or one holder per agent, force, the
 * displaced mark, reachable-now, and what a closing socket releases.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { HolderRegistry, type Caller } from "../holder-registry.js";

const A: Caller = { key: "socket:conn-a", label: "Claude Code" };
const B: Caller = { key: "endpoint:oauth:chatgpt", label: "ChatGPT" };
const CLI: Caller = { key: "cli:host", label: "cli" };

describe("M15D holder registry", () => {
  let reg: HolderRegistry;
  let changes: Array<[string, boolean]>;
  const keys: Record<string, string> = { alice: "aa".repeat(32), bob: "bb".repeat(32) };

  beforeEach(() => {
    changes = [];
    reg = new HolderRegistry({ agentKey: (n) => keys[n], onReachability: (n, r) => changes.push([n, r]) });
  });

  it("a second caller is refused agent_held naming the holder; force takes it and marks the old holder displaced once", () => {
    expect(reg.take("alice", A, { channel: "conn-a" })).toEqual({ ok: true });
    const refused = reg.take("alice", B);
    expect(refused).toMatchObject({ ok: false, reason: "agent_held", holder: { label: "Claude Code" } });
    expect(reg.check("alice", B)).toMatchObject({ ok: false, reason: "agent_held", holder: { label: "Claude Code" } });

    const forced = reg.take("alice", B, { force: true });
    expect(forced).toMatchObject({ ok: true, displaced: { callerKey: "socket:conn-a", label: "Claude Code", channels: ["conn-a"] } });
    expect(reg.holderView("alice")?.label).toBe("ChatGPT");
    // The displaced caller is told who took it, on its next call; after that it is plainly held.
    // A read asks mayAct, which must not spend the displaced mark.
    expect(reg.mayAct("alice", A)).toBe(false);
    expect(reg.check("alice", A)).toMatchObject({ ok: false, reason: "agent_displaced", by_label: "ChatGPT" });
    expect(reg.check("alice", A)).toMatchObject({ ok: false, reason: "agent_held" });
    expect(reg.check("alice", B)).toEqual({ ok: true });
  });

  it("taking a second agent releases the first; a caller holds at most one", () => {
    reg.take("alice", B);
    reg.take("bob", B);
    expect(reg.holderView("alice")).toBeNull();
    expect(reg.heldBy(B.key)).toBe("bob");
  });

  it("reachable needs a channel, a waiting call, or a listener — a bare hold is not reachable", () => {
    reg.take("alice", B);
    expect(reg.isReachable("alice")).toBe(false);
    const end = reg.beginWait("alice", B, "conn-x");
    expect(reg.isReachable("alice")).toBe(true);
    end();
    expect(reg.isReachable("alice")).toBe(false);
    expect(changes).toEqual([["alice", true], ["alice", false]]);

    reg.setListener("bob", "hermes-1");
    expect(reg.isReachable("bob")).toBe(true);
    expect(reg.holderView("bob")).toBeNull(); // a listener never holds
    expect(reg.routeFor("bob")).toEqual(["hermes-1"]);
  });

  it("a wait on an unheld agent makes the waiter the holder", () => {
    reg.beginWait("alice", B, "conn-x");
    expect(reg.holderView("alice")?.label).toBe("ChatGPT");
  });

  it("closing a socket ends a socket caller's hold, but only that socket's channel for an endpoint or CLI caller", () => {
    reg.take("alice", A, { channel: "conn-a" });
    reg.dropConnection("conn-a");
    expect(reg.holderView("alice")).toBeNull();
    expect(changes).toEqual([["alice", true], ["alice", false]]);

    reg.take("bob", CLI, { channel: "cli-conn" });
    reg.dropConnection("cli-conn");
    expect(reg.holderView("bob")?.label).toBe("cli");
    expect(reg.isReachable("bob")).toBe(false);
  });

  it("release by a non-holder does nothing; clearAgent drops holder and listener", () => {
    reg.take("alice", A, { channel: "conn-a" });
    expect(reg.release("alice", B)).toBe(false);
    expect(reg.holderView("alice")?.label).toBe("Claude Code");
    reg.setListener("alice", "hermes-1");
    reg.clearAgent("alice");
    expect(reg.holderView("alice")).toBeNull();
    expect(reg.isReachable("alice")).toBe(false);
  });
});
