/**
 * Unit tests for summarizeInboundFrame — the inbound-frame trace.
 *
 * The trace exists to tell three failures apart that produce ONE symptom ("expected string,
 * received undefined"): the client dropped every argument, dropped one key, or sent the key
 * hollowed out. Each is asserted below, because a trace that blurred them would be worse than no
 * trace — it would look like evidence while answering nothing.
 */
import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { summarizeInboundFrame } from "../frame-trace.js";

setupV3Tests();

const SID = "accb504f272f4a60935d2551e27de2ed";

describe("summarizeInboundFrame — inbound MCP frame trace", () => {
  it("records a well-formed tools/call verbatim, including the session_id that arrived", () => {
    const t = summarizeInboundFrame({
      jsonrpc: "2.0", id: 7, method: "tools/call",
      params: { name: "cello_receive", arguments: { session_id: SID, timeout_ms: 30000 } },
    });
    expect(t.method).toBe("tools/call");
    expect(t.id).toBe(7);
    expect(t.tool).toBe("cello_receive");
    expect(t.hasArguments).toBe(true);
    expect(t.argKeys).toEqual(["session_id", "timeout_ms"]);
    expect(t.args?.["session_id"]).toBe(SID);
  });

  it("DISTINGUISHES a dropped argument object from a dropped key — the whole point of the trace", () => {
    // Whole object gone (the anthropics/claude-code#4188 shape).
    const noArgs = summarizeInboundFrame({
      jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "cello_send" },
    });
    expect(noArgs.hasArguments).toBe(false);
    expect(noArgs.argKeys).toBeUndefined();

    // Object present, one key gone (the Cowork bridge shape).
    const oneKeyGone = summarizeInboundFrame({
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params: { name: "cello_send", arguments: { content: "hi", signal: "over" } },
    });
    expect(oneKeyGone.hasArguments).toBe(true);
    expect(oneKeyGone.argKeys).toEqual(["content", "signal"]);
    expect(oneKeyGone.argKeys).not.toContain("session_id");
  });

  it("shows a hollowed-out value rather than reporting it as absent", () => {
    const t = summarizeInboundFrame({
      jsonrpc: "2.0", id: 3, method: "tools/call",
      params: { name: "cello_transcript", arguments: { session_id: null } },
    });
    expect(t.argKeys).toEqual(["session_id"]);
    expect(t.args?.["session_id"]).toBeNull();
  });

  it("NEVER records message content verbatim — only its type and length", () => {
    const secret = "the actual words of a private message";
    const t = summarizeInboundFrame({
      jsonrpc: "2.0", id: 4, method: "tools/call",
      params: { name: "cello_send", arguments: { session_id: SID, content: secret, signal: "over" } },
    });
    expect(t.args?.["content"]).toBe(`<string:${secret.length} chars>`);
    expect(JSON.stringify(t)).not.toContain(secret);
    // …while the routing fields the trace exists to inspect stay readable.
    expect(t.args?.["session_id"]).toBe(SID);
    expect(t.args?.["signal"]).toBe("over");
  });

  it("survives frames it does not understand — a malformed client is itself the evidence", () => {
    for (const bad of [null, undefined, 42, "not a frame", [], {}]) {
      const t = summarizeInboundFrame(bad);
      expect(t.event).toBe("mcp.frame.received");
      expect(t.tool).toBeUndefined();
    }
    // A non-tools/call frame records its method and stops there.
    const init = summarizeInboundFrame({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
    expect(init.method).toBe("initialize");
    expect(init.hasArguments).toBeUndefined();
  });
});
