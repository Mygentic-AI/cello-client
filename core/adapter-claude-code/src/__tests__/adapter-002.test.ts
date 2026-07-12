/**
 * CELLO-ADAPTER-002 — Adapter M1 tests
 *
 * AC-002: the session-request doorbell carries exactly type, from, session_id — no extra fields
 * AC-008: SKILL.md references the live tools, not removed/renamed-away ones
 *
 * DOD-LEGACY-MCP-1 (2026-07-12): AC-001, AC-003, AC-004, AC-005, AC-006, AC-007, SI-002 and
 * CRITICAL-1 were DELETED. Every one of them asserted something about `createMcpServer` — the legacy
 * in-process MCP server, now gone: which tools its registry contained, its in-process `sessionEvents`
 * FIFO and `cello_await_session` timeout loop, its `cello_status` response shape, and a regression
 * test for a stale-resolver bug inside it. None of that code exists any more. The live equivalents
 * belong to the daemon (`cello_await_session` and `cello_status` are proxied by `bin/cello-mcp.ts`
 * and tested in core/daemon).
 *
 * AC-002 and SI-001 were RE-POINTED, not deleted: the payload contract they guard is built by the
 * LIVE `channel-params.ts`, which `bin/cello-mcp.ts` calls on every forwarded doorbell. The dead
 * server was only a driver.
 *
 * CORRECTION (review, 2026-07-12) — worth recording because the first attempt got it backwards.
 * I initially DELETED SI-001, reasoning that re-pointing it at `buildChannelParams` would be a
 * tautology ("asserting the absence of a field the test itself chose not to pass"). That is false:
 * `buildChannelParams` does not SELECT fields, it SPREADS them — every identifier-safe scalar on the
 * daemon's frame becomes an agent-visible `<channel>` attribute, with no allowlist. So SI-001 is the
 * one test here with real teeth, and the AC-002 I kept — which built three keys and asserted three
 * keys came back — was the actual tautology. Both are now written against the frame the daemon
 * genuinely dispatches. The lesson: verify what the producer DOES before judging what a test can catch.
 */

import {
  setupV3Tests,
  describe,
  it,
  expect,
} from "@claude-flow/testing";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildChannelParams } from "../channel-params.js";

setupV3Tests();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── AC-002 / SI-001: the doorbell carries ROUTING ONLY ───────────────────────
//
// READ THIS BEFORE CHANGING THESE TESTS. `buildChannelParams` is a SPREAD, not a select:
//
//     for (const [k, v] of Object.entries(data)) { ...; meta[k] = String(v); }
//
// There is no field allowlist — deliberately, because the shim must not silently DROP a routing
// field a newer daemon starts sending. The consequence is the mirror image: every identifier-safe
// SCALAR the daemon puts on a doorbell frame becomes a `<channel>` ATTRIBUTE the agent can read.
// INV-CONTENTFREE therefore does not hold by construction — it holds because of what the daemon
// chooses to send, plus two structural skips (the `content` key, and non-scalar values).
//
// So these tests are the enforcement point, and they are TRIPWIRES on purpose: they pin the EXACT
// meta key set of each real doorbell frame. If the daemon ever grows a new scalar on one of these
// frames — `genesis_prev_root`, a message `preview`, anything — it lands in the agent's channel
// attributes, and THIS TEST GOES RED and forces a human decision. That is the control. A test that
// merely asserted "no message text" would pass right through such a field.
//
// The frames below are the ones production actually dispatches (core/daemon notification-dispatcher:
// `session_state_changed` with data { agent, type, agentName, sessionId, state, counterpartyPubkey,
// who?, whoKnown? }). NOTE: `type: "cello_session_request"` — which the previous version of this test
// used — is emitted by NOTHING in production; only channel-params.ts still carries a branch for it.
// Testing that shape asserted a key set the daemon never sends, and could not fail.

describe("AC-002 + SI-001: the session-request doorbell carries routing only", () => {
  /** The frame core/daemon/src/notification-dispatcher.ts actually dispatches for a new session. */
  const realSessionCreatedFrame = () => ({
    agent: "agent-1",
    type: "session_state_changed",
    agentName: "Alice",
    sessionId: "ab".repeat(16),
    state: "created",
    counterpartyPubkey: "cd".repeat(32),
    who: "agent cdcdcdcd…",
    whoKnown: false,
  });

  it("AC-002: the doorbell renders a non-empty body and carries the routing fields", () => {
    const params = buildChannelParams(realSessionCreatedFrame());

    // Claude Code needs `content` to render the <channel> tag body; without it the doorbell is
    // silently dropped and the agent never wakes (BUILD-JOURNAL Entry 43).
    expect(typeof params.content).toBe("string");
    expect(params.content.length).toBeGreaterThan(0);

    expect(params.meta["type"]).toBe("session_state_changed");
    expect(params.meta["state"]).toBe("created");
    expect(params.meta["sessionId"]).toBe("ab".repeat(16));
    expect(params.meta["counterpartyPubkey"]).toBe("cd".repeat(32));
  });

  it("SI-001 TRIPWIRE: the doorbell's meta is EXACTLY the routing set — a new daemon field fails here", () => {
    const params = buildChannelParams(realSessionCreatedFrame());

    // If this fails because the daemon added a field: do NOT just add the key here. Ask first
    // whether that field is safe for an agent to read off a wake-up it did not ask for. `meta`
    // becomes <channel> attributes — it is agent-visible, and an agent-visible field is inside the
    // prompt-injection blast radius. Only then add it.
    expect(Object.keys(params.meta).sort()).toEqual([
      "agent",
      "agentName",
      "counterpartyPubkey",
      "sessionId",
      "state",
      "type",
      "who",
      "whoKnown",
    ]);
  });

  it("SI-001: message text and session secrets cannot ride the doorbell (structural skips)", () => {
    // The two skips that INV-CONTENTFREE actually rests on. Remove either one in channel-params.ts
    // and this test goes red.
    const params = buildChannelParams({
      ...realSessionCreatedFrame(),
      // A daemon (or an attacker upstream of the shim) tries to smuggle the message body through:
      content: "SECRET-MESSAGE-TEXT",
      // …and a non-scalar, e.g. the counterparty's multiaddrs.
      multiaddrs: ["/ip4/1.2.3.4/tcp/4001"],
    });

    // `content` is SYNTHESIZED here, never carried: the body is a fixed announcement.
    expect(params.content).not.toContain("SECRET-MESSAGE-TEXT");
    expect(params.meta).not.toHaveProperty("content");
    expect(JSON.stringify(params.meta)).not.toContain("SECRET-MESSAGE-TEXT");
    // Non-scalars are dropped, so multiaddrs cannot ride.
    expect(params.meta).not.toHaveProperty("multiaddrs");
    expect(JSON.stringify(params.meta)).not.toContain("1.2.3.4");
  });
});

// ─── AC-008: SKILL.md references the live tools ───────────────────────────────

describe("AC-008: SKILL.md references M1 tools and not M0-removed tools", () => {
  it("AC-008: SKILL.md mentions M1 tools and does not mention cello_connect_peer or cello_list_peers", async () => {
    const skillPath = join(__dirname, "../../SKILL.md");
    const content = await readFile(skillPath, "utf-8");

    // The live tools should be mentioned (post-DOD-ONBOARD-HELP-1 names).
    expect(content).toContain("cello_initiate_session");
    expect(content).toContain("cello_await_session");
    expect(content).toContain("cello_sessions"); // was cello_list_sessions

    // M0-removed tools must NOT be mentioned.
    expect(content).not.toContain("cello_connect_peer");
    expect(content).not.toContain("cello_list_peers");

    // DOD-ONBOARD-HELP-1: nor may the renamed-away / DELETED names. SKILL.md SHIPS inside the
    // connect tarball and tells an agent which tools to call, so a dead name here makes that agent
    // call a tool that does not exist. This test asserted only the M0 removals, so it sailed through
    // while SKILL.md still named cello_list_sessions, cello_get_sealed_receipt and
    // cello_receive_session — all of them gone. (The systematic version of this check, driven by
    // package.json's `files:`, lives in dod-onboard-help-1-tool-parity.test.ts.)
    expect(content).not.toContain("cello_list_sessions");
    expect(content).not.toContain("cello_get_sealed_receipt");
    expect(content).not.toContain("cello_receive_session");
  });
});
