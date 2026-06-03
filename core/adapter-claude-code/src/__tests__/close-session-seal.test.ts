/**
 * cello_close_session — seal-before-close fix (0.0.25)
 *
 * Every completed session must end with a seal attempt.
 * cello_close_session must call initiateSessionSeal before closeSession,
 * and must include the seal outcome in its response.
 *
 * AC-001: seals before closing when session is active
 * AC-002: closes even when seal fails; response includes failure reason
 * AC-003: skips seal attempt when session is already sealing/sealed/seal_deferred
 */

import {
  setupV3Tests,
  createTestScope,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import type { TestScope } from "@claude-flow/testing";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { createMcpServer } from "../index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CelloClient, SessionRecord, SessionAssignmentEvent } from "@cello-protocol/client";

setupV3Tests();

// ─── helpers ──────────────────────────────────────────────────────────────────

function parseResult(result: Awaited<ReturnType<Client["callTool"]>>): unknown {
  const text = (result.content as Array<{ type: string; text: string }>)
    .find((c) => c.type === "text")?.text;
  if (!text) throw new Error("No text content in tool result");
  return JSON.parse(text);
}

const SESSION_ID = "a".repeat(64);

function makeSession(status: SessionRecord["status"]): SessionRecord {
  return {
    session_id: Buffer.from(SESSION_ID, "hex"),
    counterparty_pubkey: new Uint8Array(32),
    counterparty_peer_id: "12D3KooWTest",
    counterparty_multiaddrs: [],
    relay_endpoint: { peer_id: "relay", multiaddrs: [] },
    directory_endpoint: { peer_id: "dir", multiaddrs: [] },
    directory_pubkey: new Uint8Array(32),
    genesis_prev_root: new Uint8Array(32),
    last_seen_seq: 0,
    last_sent_seq: 0,
    status,
    local_tree_leaves: [],
  } as unknown as SessionRecord;
}

function makeStubClient(opts: {
  sessionStatus: SessionRecord["status"];
  sealResult: { ok: boolean; reason?: string };
}): { client: CelloClient; initiateSessionSealCalls: string[]; closeSessionCalls: string[] } {
  const initiateSessionSealCalls: string[] = [];
  const closeSessionCalls: string[] = [];

  const client: CelloClient = {
    addPeer() {},
    async send() { return { delivered: false, reason: "peer_not_connected" }; },
    async registerHandler() {},
    async announceToDirectory() {},
    receive() { return null; },
    peekAll() { return []; },
    async receiveSessionAssignment() { return { ok: false, reason: "frost_signature_invalid" }; },
    listSessions() { return [makeSession(opts.sessionStatus)]; },
    async sendMessage() { return { ok: false, reason: "session_not_found" }; },
    receiveMessage() { return null; },
    receiveAnyMessage() { return null; },
    async initiateSessionSeal(sessionId: string) {
      initiateSessionSealCalls.push(sessionId);
      return opts.sealResult as { ok: true } | { ok: false; reason: string };
    },
    closeSession(sessionId: string) { closeSessionCalls.push(sessionId); },
    onSessionAssignment(_: (event: SessionAssignmentEvent) => void) {},
    async initiateSession() { return { ok: false as const, reason: "directory_unreachable" as const }; },
  } as unknown as CelloClient;

  return { client, initiateSessionSealCalls, closeSessionCalls };
}

let scope: TestScope;
beforeEach(() => { scope = createTestScope(); });
afterEach(() => scope.run(async () => {}));

// ─── AC-001: seals before closing when session is active ──────────────────────

describe("AC-001: cello_close_session seals before closing", () => {
  it("calls initiateSessionSeal before closeSession for an active session", async () => {
    const kp = generateKeypair();
    const node = await createNode({ keyProvider: kp, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const { client, initiateSessionSealCalls, closeSessionCalls } = makeStubClient({
      sessionStatus: "active",
      sealResult: { ok: true },
    });

    const server = createMcpServer(node, client, kp);
    const [st, ct] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const mcpClient = new Client({ name: "test", version: "0.0.1" });
    await mcpClient.connect(ct);
    scope.addCleanup(async () => { try { await mcpClient.close(); } catch {} });
    scope.addCleanup(async () => { try { await server.close(); } catch {} });

    const result = parseResult(
      await mcpClient.callTool({ name: "cello_close_session", arguments: { session_id: SESSION_ID } }),
    ) as Record<string, unknown>;

    expect(initiateSessionSealCalls).toContain(SESSION_ID);
    expect(closeSessionCalls).toContain(SESSION_ID);
    expect(result.closed).toBe(true);
    expect(result.seal_status).toBe("initiated");
  }, 10_000);
});

// ─── AC-002: closes even when seal fails ──────────────────────────────────────

describe("AC-002: cello_close_session closes even when seal fails", () => {
  it("closes and returns seal failure reason when initiateSessionSeal fails", async () => {
    const kp = generateKeypair();
    const node = await createNode({ keyProvider: kp, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const { client, initiateSessionSealCalls, closeSessionCalls } = makeStubClient({
      sessionStatus: "active",
      sealResult: { ok: false, reason: "directory_unreachable" },
    });

    const server = createMcpServer(node, client, kp);
    const [st, ct] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const mcpClient = new Client({ name: "test", version: "0.0.1" });
    await mcpClient.connect(ct);
    scope.addCleanup(async () => { try { await mcpClient.close(); } catch {} });
    scope.addCleanup(async () => { try { await server.close(); } catch {} });

    const result = parseResult(
      await mcpClient.callTool({ name: "cello_close_session", arguments: { session_id: SESSION_ID } }),
    ) as Record<string, unknown>;

    expect(initiateSessionSealCalls).toContain(SESSION_ID);
    expect(closeSessionCalls).toContain(SESSION_ID);
    expect(result.closed).toBe(true);
    expect(result.seal_status).toBe("failed");
    expect(result.seal_reason).toBe("directory_unreachable");
  }, 10_000);
});

// ─── AC-003: skips seal when already sealed/sealing/deferred ─────────────────

describe("AC-003: cello_close_session skips seal when already sealing/sealed/deferred", () => {
  for (const status of ["sealing", "sealed", "seal_deferred"] as const) {
    it(`does not call initiateSessionSeal when session status is '${status}'`, async () => {
      const kp = generateKeypair();
      const node = await createNode({ keyProvider: kp, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
      await node.start();
      scope.addCleanup(async () => { try { await node.stop(); } catch {} });

      const { client, initiateSessionSealCalls, closeSessionCalls } = makeStubClient({
        sessionStatus: status,
        sealResult: { ok: true },
      });

      const server = createMcpServer(node, client, kp);
      const [st, ct] = InMemoryTransport.createLinkedPair();
      await server.connect(st);
      const mcpClient = new Client({ name: "test", version: "0.0.1" });
      await mcpClient.connect(ct);
      scope.addCleanup(async () => { try { await mcpClient.close(); } catch {} });
      scope.addCleanup(async () => { try { await server.close(); } catch {} });

      const result = parseResult(
        await mcpClient.callTool({ name: "cello_close_session", arguments: { session_id: SESSION_ID } }),
      ) as Record<string, unknown>;

      expect(initiateSessionSealCalls).toHaveLength(0);
      expect(closeSessionCalls).toContain(SESSION_ID);
      expect(result.closed).toBe(true);
    }, 10_000);
  }
});
