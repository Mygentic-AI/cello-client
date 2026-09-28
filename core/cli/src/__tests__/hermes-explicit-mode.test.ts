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
  type Verdict,
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

  // THE EXACT HERMES ENVELOPE (verified 2026-09-28, mcp_tool.py:5027-5041). Hermes wraps every MCP
  // tool result before a hook sees it: the hook gets json.dumps({"result": <text>}), where <text>
  // is the cello tool's OWN JSON string. A hook test that fed a bare dict/string tested a shape
  // production never sends — which is why Part B looked green and failed live.
  function envelope(inner: Record<string, unknown>): string {
    return JSON.stringify({ result: JSON.stringify(inner) });
  }
  // The structuredContent variant: some tools return machine JSON as structuredContent (a real
  // object), with the text half a human summary. The parser must prefer the object.
  function structuredEnvelope(inner: Record<string, unknown>): string {
    return JSON.stringify({ result: "human-readable summary", structuredContent: inner });
  }
  const INITIATE_RESULT = envelope({ ok: true, sessionId: SID, transportMode: "relay", correlationId: "abc123" });

  function bpath(): string { return join(dir, `b-${Math.random().toString(36).slice(2)}.json`); }

  it("B1: a successful initiate from a cello turn stores the binding (real Hermes envelope)", () => {
    const p = bpath();
    const v = runDriver(dir, {
      op: "record", bindings_path: p, chat_env: "caller-chat-42", platform_env: "cello",
      tool_name: "mcp__cello__cello_initiate_session", hook_result: INITIATE_RESULT,
    });
    expect(v.bindings![SID]).toBe("caller-chat-42");
  });

  it("B1: the structuredContent envelope variant also binds", () => {
    const p = bpath();
    const v = runDriver(dir, {
      op: "record", bindings_path: p, chat_env: "caller-chat-42", platform_env: "cello",
      tool_name: "mcp__cello__cello_initiate_session",
      hook_result: structuredEnvelope({ ok: true, sessionId: SID }),
    });
    expect(v.bindings![SID]).toBe("caller-chat-42");
  });

  it("B1: a result that does not unwrap to an ok-dict logs an ERROR and records nothing", () => {
    const v = runDriver(dir, {
      op: "record", bindings_path: bpath(), chat_env: "caller-chat-42", platform_env: "cello",
      tool_name: "mcp__cello__cello_initiate_session",
      hook_result: JSON.stringify({ result: "not json at all" }),
    });
    expect(Object.keys(v.bindings ?? {})).toHaveLength(0);
    const errs = (v.logs ?? []).filter((l) => l.level === "ERROR");
    expect(errs.length).toBeGreaterThan(0);
    expect(errs.some((l) => l.msg.includes("cello_initiate_session") && l.msg.includes("did not parse"))).toBe(true);
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

  it("B5a: a successful cello_close_session removes the binding, from any platform", () => {
    // The daemon never pushes a terminal state on session_state_changed (only created / interrupted
    // / counterparty_closing), so a notice can't be the unbind signal. A successful close is.
    // Applies from a non-cello turn too — the session may be closed from the desktop app.
    const v = runDriver(dir, {
      op: "record", bindings: { [SID]: "caller-chat-42" }, bindings_path: bpath(),
      platform_env: "desktop",
      tool_name: "mcp__cello__cello_close_session",
      args: { cello_session_id: SID }, hook_result: envelope({ ok: true }),
    });
    expect(v.bindings![SID]).toBeUndefined();
  });

  it("B5a: a FAILED close leaves the binding in place, and logs no error (ok:false parses fine)", () => {
    const v = runDriver(dir, {
      op: "record", bindings: { [SID]: "caller-chat-42" }, bindings_path: bpath(),
      tool_name: "mcp__cello__cello_close_session",
      args: { cello_session_id: SID }, hook_result: envelope({ ok: false, reason: "seal_in_progress" }),
    });
    expect(v.bindings![SID]).toBe("caller-chat-42");
    expect((v.logs ?? []).filter((l) => l.level === "ERROR")).toHaveLength(0);
  });

  it("B5b: the prune drops a link the daemon no longer lists as open, keeps one it does", () => {
    const OPEN = SID;
    const GONE = "ffff0000".repeat(4);
    const v = runDriver(dir, {
      op: "prune", bindings: { [OPEN]: "chat-open", [GONE]: "chat-gone" }, bindings_path: bpath(),
      sessions_result: { ok: true, sessions: [{ sessionId: OPEN, status: "active", category: "open" }] },
    });
    expect(v.bindings![OPEN]).toBe("chat-open");
    expect(v.bindings![GONE]).toBeUndefined();
  });

  it("B5b: an interrupted session still counts as open — its link survives the prune", () => {
    const v = runDriver(dir, {
      op: "prune", bindings: { [SID]: "chat-open" }, bindings_path: bpath(),
      sessions_result: { ok: true, sessions: [{ sessionId: SID, status: "interrupted", category: "open" }] },
    });
    expect(v.bindings![SID]).toBe("chat-open");
  });

  it("B5b: a failed cello_list_sessions KEEPS every binding — never wipes on error", () => {
    const raised = runDriver(dir, {
      op: "prune", bindings: { [SID]: "chat-open" }, bindings_path: bpath(),
      sessions_result: "raise",
    });
    expect(raised.bindings![SID]).toBe("chat-open");

    const notOk = runDriver(dir, {
      op: "prune", bindings: { [SID]: "chat-open" }, bindings_path: bpath(),
      sessions_result: { ok: false, reason: "no_current_agent" },
    });
    expect(notOk.bindings![SID]).toBe("chat-open");
  });

  it("B8: a counterparty_closing notice routes to the bound chat and KEEPS the link", () => {
    // counterparty_closing means THIS side still has to close, so the session is not over — the
    // binding must survive so the agent's close/reply still routes home.
    const v = runDriver(dir, {
      op: "notify", delivery_mode: "explicit",
      bindings: { [SID]: "caller-chat-42" }, bindings_path: bpath(),
      kind: "session_state_changed",
      data: { session_id: SID, counterpartyPubkey: PUB, state: "counterparty_closing" },
    });
    expect(v.delivered![0].chat_id).toBe("caller-chat-42");
    expect(v.delivered![0].text).toContain("counterparty_closing");
    expect(v.bindings![SID]).toBe("caller-chat-42"); // link kept
  });

  it("B6: a failed initiate, or one from a non-cello turn, stores nothing", () => {
    const failed = runDriver(dir, {
      op: "record", bindings_path: bpath(), chat_env: "caller-chat-42",
      tool_name: "mcp__cello__cello_initiate_session",
      hook_result: envelope({ ok: false, reason: "no_relay" }),
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

describe("049-BRIDGEREPLY Part C — a turn that ends without a reply gets one reminder", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-explicit-c-"));
    await installHermesDriver(dir);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const AGENT = "Ms_Chelly_Hermes";
  const SID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
  const PUB = "77d0c806".repeat(8);
  const MSG = { session_id: SID, from: PUB, who: "Coder_H1", whoKnown: true };

  // The real Hermes envelope, as Part B's helper builds it — the send hook sees the same wrapping.
  function envelope(inner: Record<string, unknown>): string {
    return JSON.stringify({ result: JSON.stringify(inner) });
  }

  function reminders(v: Verdict): string[] {
    return (v.delivered ?? []).map((d) => d.text).filter((t) => t.includes("have not replied"));
  }

  it("C1: a turn that ends with no cello_send gets exactly one reminder naming peer and session", () => {
    const v = runDriver(dir, {
      op: "cflow", delivery_mode: "explicit", bindings_path: join(dir, "c1.json"),
      frames: [{ kind: "cello_message", data: MSG }],
      hooks: [{ type: "llm", chat_id: AGENT }],
    });
    const rem = reminders(v);
    expect(rem).toHaveLength(1);
    expect(rem[0]).toContain(SID);
    expect(rem[0]).toContain("Coder_H1");
  });

  it("C2: a standby send counts as a reply — no reminder", () => {
    const v = runDriver(dir, {
      op: "cflow", delivery_mode: "explicit", bindings_path: join(dir, "c2.json"),
      frames: [{ kind: "cello_message", data: MSG }],
      hooks: [
        { type: "send", session_id: SID, result: envelope({ ok: true }) },
        { type: "llm", chat_id: AGENT },
      ],
    });
    expect(reminders(v)).toHaveLength(0);
  });

  it("C3: the reminder does not trigger a second reminder", () => {
    const v = runDriver(dir, {
      op: "cflow", delivery_mode: "explicit", bindings_path: join(dir, "c3.json"),
      frames: [{ kind: "cello_message", data: MSG }],
      hooks: [{ type: "llm", chat_id: AGENT }, { type: "llm", chat_id: AGENT }],
    });
    expect(reminders(v)).toHaveLength(1);
  });

  it("C4: no reminder in channel mode", () => {
    const v = runDriver(dir, {
      op: "cflow", delivery_mode: "channel", bindings_path: join(dir, "c4a.json"),
      frames: [{ kind: "cello_message", data: MSG }],
      hooks: [{ type: "llm", chat_id: AGENT }],
    });
    expect(reminders(v)).toHaveLength(0);
  });

  it("C4: no reminder in wake mode", () => {
    const v = runDriver(dir, {
      op: "cflow", delivery_mode: "wake", bindings_path: join(dir, "c4b.json"),
      frames: [{ kind: "cello_message", data: MSG }],
      hooks: [{ type: "llm", chat_id: AGENT }],
    });
    expect(reminders(v)).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 050-BRIDGEQUIET — no turn for a message already read, no reminder for a conversation over.
// All tests EXECUTE the real Python through the shared driver. Hook results use the EXACT Hermes
// envelope (json.dumps({"result": json.dumps({...})})) — the shape production sends (049 live).
// ─────────────────────────────────────────────────────────────────────────────────────────────

describe("050-BRIDGEQUIET Part A — a held notice is dropped if its message was already read", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-quiet-a-"));
    await installHermesDriver(dir);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const AGENT = "Ms_Chelly_Hermes";
  const SID = "645dc477a1b2c3d4e5f6a7b8c9d0e1f2";
  const PUB = "77d0c806".repeat(8);
  const MSG = { session_id: SID, from: PUB, who: "Coder_H1", whoKnown: true };
  const logMsgs = (v: Verdict) => (v.logs ?? []).map((l) => `${l.level} ${l.msg}`);

  it("A1: a held notice whose session reads unread_count 0 is DROPPED — no turn, INFO log, awaiting cleared", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99,
      awaiting: { [AGENT]: { [SID]: "Coder_H1" } },
      check_notifications: { ok: true, scope: "current", agents: [{ agent: AGENT, unread: [{ session_id: SID, unread_count: 0, last_seq: 4 }], total_unread: 0 }] },
    });
    expect(v.delivered).toHaveLength(0);                 // no wasted turn
    expect(Object.keys(v.pending ?? {})).toHaveLength(0); // and not queued as a notice
    expect(logMsgs(v).some((m) => m.includes("were already read"))).toBe(true);
    expect(v.awaiting![AGENT] ?? []).not.toContain(SID);  // nothing left to reply to
  });

  it("A1: a session ABSENT from the unread list is also dropped", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99,
      awaiting: { [AGENT]: { [SID]: "Coder_H1" } },
      check_notifications: { ok: true, scope: "current", agents: [{ agent: AGENT, unread: [], total_unread: 0 }] },
    });
    expect(v.delivered).toHaveLength(0);
    expect(v.awaiting![AGENT] ?? []).not.toContain(SID);
  });

  it("A2: a held notice whose session is still unread is HANDED OVER as today", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99,
      check_notifications: { ok: true, scope: "current", agents: [{ agent: AGENT, unread: [{ session_id: SID, unread_count: 1, last_seq: 4 }], total_unread: 1 }] },
    });
    expect(Object.values(v.pending!)[0]).toContain("CELLO wake"); // the manual-path notice
    expect(v.awaiting![AGENT]).toContain(SID);                    // a reply is still owed
  });

  it("A2: the drop path never CONSUMES — cello_receive is never called", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99,
      awaiting: { [AGENT]: { [SID]: "Coder_H1" } },
      check_notifications: { ok: true, scope: "current", agents: [{ agent: AGENT, unread: [], total_unread: 0 }] },
    });
    expect(v.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
    expect(v.calls.find((c) => c.method === "cello_check_notifications")).toBeDefined();
  });

  it("A3: a cello_check_notifications failure HANDS THE NOTICE OVER and logs a WARNING", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, busy: AGENT, busy_retries: 99,
      check_notifications: "raise",
    });
    expect(Object.values(v.pending!)[0]).toContain("CELLO wake");
    expect(logMsgs(v).some((m) => m.startsWith("WARNING") && m.includes("check unread"))).toBe(true);
  });
});

describe("050-BRIDGEQUIET Part B — no reminder for a conversation that has ended", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-quiet-b-"));
    await installHermesDriver(dir);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const AGENT = "Ms_Chelly_Hermes";
  const SID = "0279cbcca1b2c3d4e5f6a7b8c9d0e1f2";
  const PUB = "77d0c806".repeat(8);
  const MSG = { session_id: SID, from: PUB, who: "Mac_Coder_1", whoKnown: true };
  function envelope(inner: Record<string, unknown>): string {
    return JSON.stringify({ result: JSON.stringify(inner) });
  }
  function bpath(): string { return join(dir, `b-${Math.random().toString(36).slice(2)}.json`); }

  it("B1: a fetched message ending [[WRAP]] does NOT arm the reminder", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, delivery_mode: "explicit",
      receive_result: { ok: true, count: 1, messages: [{ sequence: 0, content: "All done, sealing now. [[WRAP]]" }] },
    });
    expect(v.delivered).toHaveLength(1);                 // the closing message is still shown
    expect(v.awaiting![AGENT] ?? []).not.toContain(SID); // but no reply is owed
  });

  it("B1: a [[WRAP]] message plus an undeliverable notice still does NOT arm — the notice must not hide the wrap", () => {
    // review LOW 1: undeliverable_guidance is appended AFTER the messages, so the JOINED turn no
    // longer ends with [[WRAP]]. The wrap must be read off the last MESSAGE, so a lost-message
    // notice riding in the turn cannot re-arm the reminder for a conversation that is over.
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, delivery_mode: "explicit",
      receive_result: {
        ok: true, count: 1,
        messages: [{ sequence: 0, content: "All done, sealing now. [[WRAP]]" }],
        undeliverable_guidance: "A message could not be saved to this machine and was skipped.",
      },
    });
    expect(v.delivered).toHaveLength(1);
    expect(v.delivered![0].text).toContain("[CELLO notice]"); // the notice still rides in the turn
    expect(v.awaiting![AGENT] ?? []).not.toContain(SID);        // yet the wrap is not hidden
  });

  it("B2: a fetched message ending [[OVER]] still arms the reminder", () => {
    const v = runDriver(dir, {
      op: "notify", kind: "cello_message", data: MSG, delivery_mode: "explicit",
      receive_result: { ok: true, count: 1, messages: [{ sequence: 0, content: "Your turn. [[OVER]]" }] },
    });
    expect(v.awaiting![AGENT]).toContain(SID);
  });

  it("B3: a cello_send refused with session_closed clears the owed reply (real Hermes envelope)", () => {
    const v = runDriver(dir, {
      op: "record", awaiting: { [AGENT]: { [SID]: "Mac_Coder_1" } }, bindings_path: bpath(),
      tool_name: "mcp__cello__cello_send", args: { session_id: SID },
      hook_result: envelope({ ok: false, reason: "session_closed", guidance: "This session is closed." }),
    });
    expect(v.awaiting![AGENT] ?? []).not.toContain(SID);
  });

  it("B3: session_terminal, session_identity_lost and session_not_found also clear it", () => {
    for (const reason of ["session_terminal", "session_identity_lost", "session_not_found"]) {
      const v = runDriver(dir, {
        op: "record", awaiting: { [AGENT]: { [SID]: "Mac_Coder_1" } }, bindings_path: bpath(),
        tool_name: "mcp__cello__cello_send", args: { session_id: SID },
        hook_result: envelope({ ok: false, reason }),
      });
      expect(v.awaiting![AGENT] ?? []).not.toContain(SID);
    }
  });

  it("B4: a cello_send refused for another reason (governance_warn) KEEPS it", () => {
    const v = runDriver(dir, {
      op: "record", awaiting: { [AGENT]: { [SID]: "Mac_Coder_1" } }, bindings_path: bpath(),
      tool_name: "mcp__cello__cello_send", args: { session_id: SID },
      hook_result: envelope({ ok: false, reason: "governance_warn", guidance: "held for a decision" }),
    });
    expect(v.awaiting![AGENT]).toContain(SID);
  });

  it("B5: a successful cello_close_session clears the owed reply (and unbinds)", () => {
    const v = runDriver(dir, {
      op: "record", awaiting: { [AGENT]: { [SID]: "Mac_Coder_1" } }, bindings: { [SID]: AGENT },
      bindings_path: bpath(), tool_name: "mcp__cello__cello_close_session", args: { session_id: SID },
      hook_result: envelope({ ok: true }),
    });
    expect(v.awaiting![AGENT] ?? []).not.toContain(SID);
    expect(v.bindings![SID]).toBeUndefined();
  });
});

describe("050-BRIDGEQUIET Part C — the 'merged' WARNING only in channel mode", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-quiet-c-"));
    await installHermesDriver(dir);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const AGENT = "Ms_Chelly_Hermes";
  const SID = "aabbccdd11223344";
  const PUB = "77d0c806".repeat(8);
  const MSG = { session_id: SID, from: PUB };
  const SID2 = "beef9999";
  const PUB2 = "99ff88ee".repeat(8);

  it("C1: explicit mode — two sessions merged log NO 'merged' WARNING and poison NO anchor", () => {
    const v = runDriver(dir, {
      op: "notify", delivery_mode: "explicit", busy: AGENT, busy_retries: 99,
      frames: [
        { kind: "cello_message", data: MSG },
        { kind: "cello_message", data: { session_id: SID2, from: PUB2 } },
      ],
    });
    const logs = (v.logs ?? []).map((l) => l.msg);
    expect(logs.some((m) => m.includes("merged into one pending turn"))).toBe(false);
    const anchor = Object.values(v.pending_anchors!)[0]!;
    expect(anchor.startsWith("cello-ambiguous-")).toBe(false);
    expect(anchor.startsWith("cello-wake-")).toBe(true); // a real, routable anchor is kept
    // review LOW 3: skipping the poison must NOT skip the merge — both sessions' text survives, so
    // neither peer's notice is lost when the agent answers each with cello_send.
    const merged = Object.values(v.pending!)[0]!;
    expect(merged).toContain(SID);
    expect(merged).toContain(SID2);
  });
});
