/**
 * 049-BRIDGEREPLY Parts B & C — the agent replies on purpose, and the answer comes home.
 *
 * Part B: a CELLO session the Hermes agent OPENS belongs to the Hermes chat that opened it. The
 * adapter records "session X -> chat Y" from a post_tool_call hook on cello_initiate_session, then
 * routes an inbound answer on X back to Y instead of the sender's own chat.
 *
 * Part C: in explicit mode, a turn that ends without a cello_send gets exactly ONE reminder naming
 * the peer and session, so an escalation answer is never silently dropped.
 *
 * These tests EXECUTE the real Python out of HERMES_PLUGIN_INIT_PY through the SHARED driver
 * (helpers/hermes-python-driver.ts) — the same stub and driver hermes-channel-mode.test.ts uses.
 * Asserting on the TS template's substrings would pass for code that never runs.
 *
 * Written RED-first per SPARC Phase R.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  installHermesDriver,
  runDriver,
} from "./helpers/hermes-python-driver.js";

describe("049-BRIDGEREPLY Part B — a session the agent opens belongs to the chat that opened it", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-explicit-"));
    await installHermesDriver(dir);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const AGENT = "Ms_Chelly_Hermes";
  const SID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"; // 32 hex, the real initiate shape
  const PUB = "77d0c806".repeat(8);
  // The captured real initiate result shape (Newly discovered, 2026-09-28): the field is sessionId,
  // and under Hermes the MCP tool result reaches the hook as a JSON STRING.
  const INITIATE_RESULT = JSON.stringify({
    ok: true, sessionId: SID, transportMode: "relay", correlationId: "abc123",
  });

  function bpath(): string { return join(dir, `b-${Math.random().toString(36).slice(2)}.json`); }

  it("B1: a successful initiate from a cello turn stores the binding", () => {
    const p = bpath();
    const v = runDriver(dir, {
      op: "record", bindings_path: p, chat_env: "caller-chat-42", platform_env: "cello",
      tool_name: "mcp__cello__cello_initiate_session", hook_result: INITIATE_RESULT,
    });
    expect(v.bindings![SID]).toBe("caller-chat-42");
  });

  it("B2: an inbound message on a bound session goes to the BOUND chat, not the sender's own", () => {
    // Even though the sender has its own chat under peer scope, the answer must come home to the
    // chat that opened the session.
    const v = runDriver(dir, {
      op: "notify", delivery_mode: "explicit", session_scope: "peer",
      bindings: { [SID]: "caller-chat-42" }, bindings_path: bpath(),
      kind: "cello_message", data: { session_id: SID, from: PUB, who: "Coder_H1", whoKnown: true },
    });
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].chat_id).toBe("caller-chat-42");
    // The bound chat wins over the peer-scope key the sender would otherwise get.
    expect(v.delivered![0].chat_id).not.toBe(`${AGENT}/${PUB}`);
  });

  it("B3: an UNBOUND session routes exactly as before", () => {
    const v = runDriver(dir, {
      op: "notify", delivery_mode: "explicit", session_scope: "peer",
      bindings: {}, bindings_path: bpath(),
      kind: "cello_message", data: { session_id: SID, from: PUB },
    });
    expect(v.delivered![0].chat_id).toBe(`${AGENT}/${PUB}`);
  });

  it("B4: bindings survive a new adapter instance (gateway restart)", () => {
    const p = bpath();
    runDriver(dir, {
      op: "record", bindings_path: p, chat_env: "caller-chat-42",
      tool_name: "mcp__cello__cello_initiate_session", hook_result: INITIATE_RESULT,
    });
    const v = runDriver(dir, { op: "loadbindings", bindings_path: p });
    expect(v.bindings![SID]).toBe("caller-chat-42");
  });

  it("B5: a terminal-state notice is delivered to the bound chat and removes the binding", () => {
    const v = runDriver(dir, {
      op: "notify", delivery_mode: "explicit",
      bindings: { [SID]: "caller-chat-42" }, bindings_path: bpath(),
      kind: "session_state_changed",
      data: { session_id: SID, counterpartyPubkey: PUB, state: "sealed" },
    });
    expect(v.delivered![0].chat_id).toBe("caller-chat-42");
    expect(v.delivered![0].text).toContain("sealed");
    expect(v.bindings![SID]).toBeUndefined(); // binding gone
  });

  it("B6: a failed initiate, or one from a non-cello turn, stores nothing", () => {
    const failed = runDriver(dir, {
      op: "record", bindings_path: bpath(), chat_env: "caller-chat-42",
      tool_name: "mcp__cello__cello_initiate_session",
      hook_result: JSON.stringify({ ok: false, reason: "no_relay" }),
    });
    expect(Object.keys(failed.bindings ?? {})).toHaveLength(0);

    const desktop = runDriver(dir, {
      op: "record", bindings_path: bpath(), chat_env: "caller-chat-42", platform_env: "desktop",
      tool_name: "mcp__cello__cello_initiate_session", hook_result: INITIATE_RESULT,
    });
    expect(Object.keys(desktop.bindings ?? {})).toHaveLength(0);
  });

  it("B6: an empty HERMES_SESSION_CHAT_ID stores nothing — the bridge never guesses a chat", () => {
    const v = runDriver(dir, {
      op: "record", bindings_path: bpath(), platform_env: "cello",
      tool_name: "mcp__cello__cello_initiate_session", hook_result: INITIATE_RESULT,
    });
    expect(Object.keys(v.bindings ?? {})).toHaveLength(0);
  });

  it("B7: a bound session with nothing unread drops the wake — no notice, no turn", () => {
    // The asking turn read the answer itself; a second wake would start a turn about a message
    // already answered.
    const v = runDriver(dir, {
      op: "notify", delivery_mode: "explicit",
      bindings: { [SID]: "caller-chat-42" }, bindings_path: bpath(),
      kind: "cello_message", data: { session_id: SID, from: PUB },
      receive_queue: [],
    });
    expect(v.delivered ?? []).toHaveLength(0);
  });
});
