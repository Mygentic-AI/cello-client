/**
 * CELLO-M6B-002: FROST ceremony error propagation — client tests
 *
 * Specification:
 *   AC-005: client.ts maps ceremony_timeout wire reason to InitiateSessionResult
 *   AC-006: client.ts maps ceremony_exhausted wire reason to InitiateSessionResult
 *   AC-007: types.ts includes new reasons in InitiateSessionResult union
 *   AC-009: mcp-server.ts returns ceremony_timeout with descriptive message;
 *           verified by calling the real tool handler via InMemoryTransport with
 *           a stub client whose initiateSession returns ceremony_timeout
 *   AC-010: mcp-server.ts returns ceremony_exhausted with 4-step re-registration recipe;
 *           verified by calling the real tool handler via InMemoryTransport with
 *           a stub client whose initiateSession returns ceremony_exhausted
 */

import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpSessionServer } from "../mcp-server.js";
import { mapSessionRequestErrorFrame } from "../client.js";
import type { InitiateSessionResult, CelloClient } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseResult(result: Awaited<ReturnType<Client["callTool"]>>): unknown {
  const text = (result.content as Array<{ type: string; text: string }>)
    .find((c) => c.type === "text")?.text;
  if (!text) throw new Error("No text content in tool result");
  return JSON.parse(text);
}

function makeStubNode(): CelloNode {
  return {
    listenAddresses: () => ["/ip4/127.0.0.1/tcp/9999"],
    getConnections: () => [],
    start: async () => {},
    stop: async () => {},
    dial: async () => ({ peerId: "12D3..." }),
    newStream: async () => { throw new Error("not implemented"); },
    handle: async () => {},
    unhandle: async () => {},
    getPeerId: () => "12D3KooWStub",
  } as unknown as CelloNode;
}

/**
 * Build a minimal stub CelloClient where initiateSession returns the provided result.
 * Stub is pre-registered with a known agent_id so registration guards pass.
 */
function makeStubClientWithInitiateSession(
  initiateSessionResult: InitiateSessionResult,
): CelloClient {
  return {
    addPeer: () => {},
    send: async () => ({ delivered: false, reason: "peer_not_connected" }),
    registerHandler: async () => {},
    receive: () => null,
    peekAll: () => [],
    receiveSessionAssignment: async () => ({ ok: false, reason: "relay_auth_error" }),
    listSessions: () => [],
    sendMessage: async () => ({ ok: false, reason: "session_not_found" }),
    receiveMessage: () => null,
    receiveAnyMessage: () => null,
    receiveSessionMessageAsync: async () => null,
    receiveMessageAsync: async () => ({ type: "timeout" as const }),
    initiateSessionSeal: async () => ({ ok: false, reason: "session_not_active" }),
    closeSession: () => {},
    onSessionAssignment: () => {},
    initiateSession: async (_targetPubkeyHex: string) => initiateSessionResult,
    getDirectoryPeerId: () => null,
    getRegistrationState: () => ({
      agent_id: "aabbccdd001122334455667788990011",
      primary_pubkey: "a".repeat(64),
      ml_dsa_pubkey: "b".repeat(64),
      registered_at: Date.now() - 1000,
      status: "active" as const,
    }),
    register: async () => ({ error: "already_registered" }),
    setPolicy: () => {},
    getPolicy: () => ({ mode: "open" as const, review_mode: "deterministic" as const, requirements: [] }),
    hasConnection: (_pubkeyHex: string) => "conn-stub-id",
    listConnections: () => [],
    acceptConnection: async () => ({ error: { reason: "no_pending_request" as const } }),
    rejectConnection: async () => ({ error: { reason: "no_pending_request" as const } }),
    requestMoreDisclosure: async () => ({ error: { reason: "no_pending_request" as const } }),
    awaitConnectionRequest: async () => ({ type: "timeout" as const }),
  } as unknown as CelloClient;
}

/**
 * Create a real MCP server + connected MCP SDK client pair wired via InMemoryTransport.
 * Returns both and a cleanup function.
 */
async function makeServerAndClient(
  initiateSessionResult: InitiateSessionResult,
): Promise<{ mcpClient: Client; ownPubkeyHex: string; cleanup: () => Promise<void> }> {
  const kp = generateKeypair();
  const ownPubkeyHex = Buffer.from(await kp.getPublicKey()).toString("hex");
  const node = makeStubNode();
  const celloClient = makeStubClientWithInitiateSession(initiateSessionResult);
  const server = createMcpSessionServer(node, celloClient, kp);

  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  const mcpClient = new Client({ name: "test-m6b002", version: "0.0.1" });
  await mcpClient.connect(clientTransport);

  const cleanup = async () => {
    try { await mcpClient.close(); } catch {}
    try { await server.close(); } catch {}
  };

  return { mcpClient, ownPubkeyHex, cleanup };
}

describe("CELLO-M6B-002: Client-side error propagation", () => {
  // ─── AC-005: client.ts ceremony_timeout mapping ──────────────────────────────
  // Tests the RUNTIME behavior of mapSessionRequestErrorFrame (extracted from
  // initiateSession). If lines 5394-5395 of client.ts were deleted or typo'd,
  // this test fails — unlike a pure compile-time type assertion.

  it("AC-005: mapSessionRequestErrorFrame maps ceremony_timeout wire reason to InitiateSessionResult", () => {
    const frame = { type: "session_request_error", reason: "ceremony_timeout" };
    const result = mapSessionRequestErrorFrame(frame);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ceremony_timeout");
      // Must NOT map to any existing reason
      expect(result.reason).not.toBe("directory_below_threshold");
      expect(result.reason).not.toBe("directory_unreachable");
    }
  });

  // ─── AC-006: client.ts ceremony_exhausted mapping ────────────────────────────

  it("AC-006: mapSessionRequestErrorFrame maps ceremony_exhausted wire reason to InitiateSessionResult", () => {
    const frame = { type: "session_request_error", reason: "ceremony_exhausted" };
    const result = mapSessionRequestErrorFrame(frame);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ceremony_exhausted");
      // Must NOT map to any existing reason
      expect(result.reason).not.toBe("directory_below_threshold");
      expect(result.reason).not.toBe("directory_unreachable");
    }
  });

  // ─── AC-007: types.ts union completeness ─────────────────────────────────────

  it("AC-007: InitiateSessionResult type allows ceremony_timeout and ceremony_exhausted", () => {
    // Compile-time check that both new reasons are valid members of InitiateSessionResult
    const timeout: InitiateSessionResult = { ok: false, reason: "ceremony_timeout" };
    const exhausted: InitiateSessionResult = { ok: false, reason: "ceremony_exhausted" };
    const existing: InitiateSessionResult = { ok: false, reason: "directory_below_threshold" };

    expect(timeout.ok).toBe(false);
    expect(exhausted.ok).toBe(false);
    expect(existing.ok).toBe(false);
  });

  // ─── AC-005/AC-006 companion: existing reasons still map correctly ───────────

  it("AC-005/AC-006: mapSessionRequestErrorFrame preserves all pre-existing reasons", () => {
    const cases: Array<[string, string]> = [
      ["target_offline", "target_offline"],
      ["relay_unavailable", "relay_unavailable"],
      ["frost_signer_not_configured", "frost_signer_not_configured"],
      ["directory_below_threshold", "directory_below_threshold"],
      ["ceremony_conflict", "ceremony_conflict"],
      ["no_connection", "no_connection"],
      ["unknown_future_reason", "directory_unreachable"],
    ];
    for (const [wireReason, expectedReason] of cases) {
      const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason: wireReason });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(expectedReason);
      }
    }
  });
});

// ─── AC-009/AC-010: mcp-server.ts tool response messages ─────────────────────
// These tests call the real mcp-server.ts cello_initiate_session tool handler
// via InMemoryTransport. The stub client's initiateSession returns the target reason.

describe("CELLO-M6B-002: MCP tool error messages", () => {
  // ─── AC-009: ceremony_timeout message ────────────────────────────────────────

  it("AC-009: cello_initiate_session returns ceremony_timeout with descriptive message", async () => {
    const { mcpClient, cleanup } = await makeServerAndClient({
      ok: false,
      reason: "ceremony_timeout",
    });

    try {
      const raw = await mcpClient.callTool({
        name: "cello_initiate_session",
        arguments: { target_pubkey: "ab".repeat(32) },
      });
      const result = parseResult(raw) as Record<string, unknown>;

      expect(result["ok"]).toBe(false);
      expect(result["reason"]).toBe("ceremony_timeout");
      expect(typeof result["message"]).toBe("string");
      expect(result["message"] as string).toContain("timed out");
      expect(result["message"] as string).toContain("MCP process");
    } finally {
      await cleanup();
    }
  });

  // ─── AC-010: ceremony_exhausted 4-step recipe ────────────────────────────────

  it("AC-010: cello_initiate_session returns ceremony_exhausted with 4-step re-registration recipe", async () => {
    const { mcpClient, ownPubkeyHex, cleanup } = await makeServerAndClient({
      ok: false,
      reason: "ceremony_exhausted",
    });

    try {
      const raw = await mcpClient.callTool({
        name: "cello_initiate_session",
        arguments: { target_pubkey: "ab".repeat(32) },
      });
      const result = parseResult(raw) as Record<string, unknown>;

      expect(result["ok"]).toBe(false);
      expect(result["reason"]).toBe("ceremony_exhausted");
      expect(typeof result["message"]).toBe("string");

      const msg = result["message"] as string;
      expect(msg).toContain("FROST ceremony exhausted");

      // The first SQL statement must use the K_local pubkey hex (64 chars), not the
      // 16-byte registration ID (32 chars). This is the fix for the bug where
      // agentIdHex (32-char reg ID) was used instead of ownPubkeyHex (64-char pubkey).
      expect(ownPubkeyHex).toHaveLength(64);
      expect(msg).toContain(`agent_id='${ownPubkeyHex}'`);

      expect(msg).toContain("2. DELETE FROM agent_profiles");
      expect(msg).toContain("3. Restart the directory ECS task");
      expect(msg).toContain("4. pkill -f cello-mcp");
      expect(msg).toContain("cello_register");

      // Must NOT contain staging-specific cluster names or bot names
      expect(msg).not.toContain("cello-directory-staging");
      expect(msg).not.toContain("@CelloConnectStagingBot");
      // Must NOT use the old generic error text
      expect(msg).not.toContain("below threshold");
    } finally {
      await cleanup();
    }
  });

  // ─── DOD-DIR-FAILCLOSED-1 (D2) cross-repo: the fail-closed reason must SURVIVE the mapper ───
  //
  // The directory now fails closed with session_request_error{counterparty_did_not_accept} instead
  // of FROST-signing an endpoint-less assignment. But every mapper keeps its OWN allowlist, and an
  // unlisted reason falls through to `directory_unreachable` — telling the operator the DIRECTORY
  // was unreachable when the directory was fine and the COUNTERPARTY simply never accepted. That
  // names the wrong subsystem, which is exactly what the debugging discipline forbids.
  // `agent_revoked` / `agent_suspended` were already being swallowed the same way.
  describe("DOD-DIR-FAILCLOSED-1: distinct directory reasons are not collapsed to directory_unreachable", () => {
    it("counterparty_did_not_accept survives the mapper (the counterparty refused — the directory is fine)", () => {
      const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason: "counterparty_did_not_accept" });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe("counterparty_did_not_accept");
        expect(result.reason).not.toBe("directory_unreachable");
      }
    });

    it("agent_revoked and agent_suspended survive the mapper (pre-existing collapse, same defect)", () => {
      for (const reason of ["agent_revoked", "agent_suspended"] as const) {
        const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason });
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.reason).toBe(reason);
      }
    });

    it("a genuinely unknown reason still falls back to directory_unreachable (the fallback is correct — just not for known reasons)", () => {
      const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason: "some_future_reason" });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("directory_unreachable");
    });
  });
});
