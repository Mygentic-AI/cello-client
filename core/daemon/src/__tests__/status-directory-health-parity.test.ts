/**
 * Launch triage item 6 — "online" does not mean reachable.
 *
 * What the operator lived through on 2026-07-31: every agent reported `online` with
 * `standing_receiver_ready: true` while not one directory endpoint could be resolved, so no session
 * could possibly form. It surfaced in sequence as `counterparty_offline`, then
 * `directory_below_threshold`, then `ceremony_exhausted` — three errors naming three different
 * subsystems, none of them the cause. It cost about an hour, and the first conclusion was "the
 * protocol is broken".
 *
 * The diagnosis existed the whole time. `directory_endpoints_unresolved` names the failing nodes and
 * the reason. It was on the MCP `cello_status` tool ONLY — not on the daemon-wide status the CLI
 * `cello status` prints, which is what an operator at a terminal actually runs, and what was run
 * during the incident.
 *
 * These tests boot a real daemon whose manifest names a node nothing is listening on, and assert the
 * block reaches BOTH surfaces. `127.0.0.1:1` refuses instantly — no DNS, no network, no flake.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type { IManifestProvider } from "@cello-protocol/transport";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";

/** A node whose /bootstrap cannot be reached — a closed local port, so the refusal is immediate. */
const DEAD_ENDPOINT = "http://127.0.0.1:1";

function makeManifest(): ConsortiumManifest {
  const hour = 3_600_000;
  return {
    version: 1,
    not_before: new Date(Date.now() - hour).toISOString(),
    expires: new Date(Date.now() + hour).toISOString(),
    nodes: [
      { nodeId: "dead-1", pubkey: "b".repeat(64), region: "us-east-1", provider: "aws", endpoint: DEAD_ENDPOINT },
    ],
    signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
  } as ConsortiumManifest;
}

function makeProvider(manifest: ConsortiumManifest): IManifestProvider {
  return {
    loadAndVerify: vi.fn(async () => manifest),
    getCurrentManifest: vi.fn(() => manifest),
    updateManifest: vi.fn(),
  } as unknown as IManifestProvider;
}

describe("launch triage item 6 — a daemon that cannot reach a directory must not look healthy", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-dirhealth-"));
    handle = null;
    clients = [];
    logger = { debug() {}, info() {}, warn() {}, error() {} };
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* already closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function bootWithUnreachableDirectory(): Promise<DaemonConfig> {
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      manifestProvider: makeProvider(makeManifest()),
      manifestRootKeys: ["a".repeat(64)],
      manifestThreshold: 1,
    };
    handle = await startDaemon(config);
    return config;
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  it("the CLI surface (`cello status`) names the unreachable directory and why", async () => {
    const config = await bootWithUnreachableDirectory();
    const client = await connect(config.socketPath);

    const status = (await client.send("status")) as Record<string, unknown>;

    // THE FIX. Without it this surface is silent, and the operator reads `daemon: running` plus a
    // list of online agents and concludes everything is fine.
    const block = status["directory_endpoints_unresolved"] as
      | { nodes: Array<{ node: string; reason: string }>; guidance: string }
      | undefined;
    expect(block).toBeDefined();
    expect(block!.nodes.map((n) => n.node)).toContain("dead-1");
    // The guidance has to name the errors the operator will actually be shown, or it does not close
    // the gap between "three misleading errors" and "the cause".
    expect(block!.guidance).toContain("counterparty_offline");
  }, 30_000);

  it("the MCP surface (`cello_status`) carries the identical block — the two must not drift", async () => {
    const config = await bootWithUnreachableDirectory();
    const client = await connect(config.socketPath);

    const cli = (await client.send("status")) as Record<string, unknown>;
    const mcp = (await client.send("cello_status")) as Record<string, unknown>;

    // Assert PRESENT before asserting equal — `undefined === undefined` would pass on the very bug
    // this test exists for, which is both surfaces being silent.
    expect(cli["directory_endpoints_unresolved"]).toBeDefined();
    expect(mcp["directory_endpoints_unresolved"]).toBeDefined();
    // The defect was a parity gap: the block existed on one surface only. Asserting both carry the
    // same value is what stops it reopening on whichever surface a future change forgets.
    expect(mcp["directory_endpoints_unresolved"]).toEqual(cli["directory_endpoints_unresolved"]);
  }, 30_000);

  it("the block is populated from STARTUP, before any ceremony has run", async () => {
    const config = await bootWithUnreachableDirectory();
    const client = await connect(config.socketPath);

    // Nothing has been asked of the directory yet — no session, no registration, no seal. The
    // startup sweep is the only thing that has resolved a roster, and it used to discard its
    // failures, so this surface stayed empty during exactly the window the incident happened in.
    const status = (await client.send("status")) as Record<string, unknown>;
    expect(status["directory_endpoints_unresolved"]).toBeDefined();
  }, 30_000);
});
