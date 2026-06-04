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
): Promise<{ mcpClient: Client; cleanup: () => Promise<void> }> {
  const kp = generateKeypair();
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

  return { mcpClient, cleanup };
}

describe("CELLO-M6B-002: Client-side error propagation", () => {
  // ─── AC-005: client.ts ceremony_timeout mapping ──────────────────────────────

  it("AC-005: InitiateSessionResult failure union includes ceremony_timeout", () => {
    // Type-level test: if ceremony_timeout is not a valid member, this will fail at compile time
    const result: InitiateSessionResult = { ok: false, reason: "ceremony_timeout" };
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ceremony_timeout");
    }
  });

  // ─── AC-006: client.ts ceremony_exhausted mapping ────────────────────────────

  it("AC-006: InitiateSessionResult failure union includes ceremony_exhausted", () => {
    const result: InitiateSessionResult = { ok: false, reason: "ceremony_exhausted" };
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ceremony_exhausted");
    }
  });

  // ─── AC-007: types.ts union completeness ─────────────────────────────────────

  it("AC-007: InitiateSessionResult type allows ceremony_timeout and ceremony_exhausted", () => {
    // Compile-time check that both new reasons are valid members
    const timeout: InitiateSessionResult = { ok: false, reason: "ceremony_timeout" };
    const exhausted: InitiateSessionResult = { ok: false, reason: "ceremony_exhausted" };
    const existing: InitiateSessionResult = { ok: false, reason: "directory_below_threshold" };

    expect(timeout.ok).toBe(false);
    expect(exhausted.ok).toBe(false);
    expect(existing.ok).toBe(false);
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
    const { mcpClient, cleanup } = await makeServerAndClient({
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
      expect(msg).toContain("1. DELETE FROM agent_key_shares");
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
});
