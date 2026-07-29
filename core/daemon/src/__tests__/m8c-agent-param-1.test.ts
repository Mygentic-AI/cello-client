/**
 * CELLO-M8C — DOD-AGENT-PARAM-1: one word for the agent selector.
 *
 * Ten handlers read an optional agent selector. Nine later ones already call it `agent`; these ten
 * called it `name`. This pins the rename AND the clean break:
 *
 * - AC-B1: all ten handlers resolve the agent from `agent`.
 * - AC-B3: `name` is no longer read as a selector by any of them — no compatibility alias.
 *
 * The two agents here are LOADED but NOT online and NOT selected, which is what makes the
 * assertion sharp: with no explicit selector, resolveCurrentAgent has nothing to fall back to
 * (no connection selection, no sole-online agent) and every one of these handlers answers
 * no_current_agent. So "not no_current_agent" means the selector was read, and nothing else can
 * produce that result.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";
import type { SessionNegotiator } from "../transport-selector.js";

/**
 * The ten handlers, with the minimum params each needs to get PAST its own validation, and the
 * agent each is asked to act as.
 *
 * `cello_refresh_shares` is the one asked for an agent that does not exist. Resolve a REAL agent
 * there and the handler goes on to wait 15 s for directory signaling — a slow test that proves
 * nothing extra, since resolution is one shared function. An unknown name refuses immediately, and
 * refuses BY NAME, which is the thing under test. The positive path (a named agent is the one acted
 * on) is proven below on cello_initiate_session and cello_get_relay_receipts.
 */
const SELECTOR_HANDLERS: Array<{ method: string; selector: string; params: Record<string, unknown> }> = [
  { method: "cello_refresh_shares", selector: "ghost", params: {} },
  { method: "cello_get_relay_receipts", selector: "alice", params: {} },
  { method: "cello_initiate_session", selector: "alice", params: { target_pubkey: "bb".repeat(32) } },
  { method: "cello_close_session", selector: "alice", params: { session_id: "cc".repeat(32) } },
  { method: "cello_get_sealed_receipt", selector: "alice", params: { session_id: "cc".repeat(32) } },
  { method: "cello_get_transcript", selector: "alice", params: { session_id: "cc".repeat(32) } },
  { method: "cello_list_sessions", selector: "alice", params: {} },
  { method: "cello_await_session", selector: "alice", params: { timeout_ms: 50 } },
  { method: "cello_send", selector: "alice", params: { session_id: "cc".repeat(32), content: "hi" } },
  { method: "cello_receive", selector: "alice", params: { session_id: "cc".repeat(32) } },
];

describe("DOD-AGENT-PARAM-1: the agent selector is `agent`, on all ten handlers", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];
  /** Records the agentName cello_initiate_session actually acted as. */
  let negotiatedAs: string[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-agentparam-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
    clients = [];
    negotiatedAs = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  /** Two agents on disk, neither started, neither selected — so there is no fallback to hide behind. */
  async function startWithTwoAgents(): Promise<IpcClient> {
    for (const name of ["alice", "bob"]) {
      await mkdir(join(tempDir, "agents", name), { recursive: true });
      await FileKeyProvider.load(join(tempDir, "agents", name, "key"));
    }
    const negotiator: SessionNegotiator = {
      negotiate: async ({ agentName }) => {
        negotiatedAs.push(agentName);
        return { ok: false, reason: "directory_unreachable", guidance: "test negotiator" };
      },
    };
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNegotiator: negotiator,
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  const reasonOf = (r: unknown) => (r as { reason?: string }).reason;

  it("AC-B1: every one of the ten handlers resolves the agent from `agent`", async () => {
    const client = await startWithTwoAgents();
    for (const { method, selector, params } of SELECTOR_HANDLERS) {
      const res = await client.send(method, { ...params, agent: selector });
      expect(reasonOf(res), `${method} ignored { agent } and fell through to no_current_agent`)
        .not.toBe("no_current_agent");
    }
  });

  it("AC-B3: `name` is NOT a selector on any of them — a clean break, not an alias", async () => {
    const client = await startWithTwoAgents();
    for (const { method, selector, params } of SELECTOR_HANDLERS) {
      const res = await client.send(method, { ...params, name: selector });
      expect(reasonOf(res), `${method} still honours the old \`name\` spelling`)
        .toBe("no_current_agent");
    }
  });

  it("the selector's VALUE is used, not merely its presence — the named agent is the one acted on", async () => {
    const client = await startWithTwoAgents();

    // cello_initiate_session carries the resolved name into the negotiator: alice, never bob.
    await client.send("cello_initiate_session", { target_pubkey: "bb".repeat(32), agent: "alice" });
    expect(negotiatedAs).toEqual(["alice"]);

    // An unknown selector names ITSELF in the refusal — proof the string is read, not just truthy.
    const res = await client.send("cello_get_relay_receipts", { agent: "ghost" }) as { reason?: string; guidance?: string };
    expect(res.reason).toBe("agent_not_found");
    expect(res.guidance).toContain("ghost");
  });

  it("the refusal names a gesture the caller can actually make — never a dead parameter", async () => {
    const client = await startWithTwoAgents();
    // These two own their own guidance string (the other eight share NO_CURRENT_AGENT_RESPONSE,
    // which names cello_use_agent and no param at all). Both told the caller to "pass { name }" —
    // a word that no longer works.
    //
    // The replacement is NOT "{ agent }". Neither handler is an MCP tool: the CLI is their only
    // caller, and its gesture is the positional `cello refresh <name>`, not a JSON param. Telling a
    // shell operator to pass an object is pointing them at a surface they do not have. So the
    // assertion is on the SHAPE of the advice, not on the new spelling.
    for (const [method, gesture] of [
      ["cello_refresh_shares", "cello refresh <name>"],
      ["cello_get_relay_receipts", "cello relay-receipts <name>"],
    ]) {
      const res = await client.send(method, {}) as { reason?: string; guidance?: string };
      expect(res.reason).toBe("no_current_agent");
      expect(res.guidance, `${method} must name the gesture its caller has`).toContain(gesture);
      expect(res.guidance, `${method} still advertises the dead spelling`).not.toContain("{ name }");
      expect(res.guidance, `${method} still advertises a param this surface cannot pass`).not.toContain("{ agent }");
      // The OTHER remedy survives: DOD-ONBOARD-HELP-1's renderForSurface rewrites this to
      // `cello use-agent` for a CLI caller, so dropping it would silently cost that rendering.
      expect(res.guidance).toContain("cello_use_agent");
    }
  });
});
