/**
 * CELLO-M7-TRANSPORT-001 — transport-composition.test.ts (AC-010 + C2)
 *
 * ─── Specification (Phase S) ──────────────────────────────────────────────────
 * AC-010 — the daemon composition root wires the transport selector by CELLO_ENV
 * (stub for 'local'|'test'; real for production variants, failing at STARTUP with
 * a clear error when the transport dialer is missing). The AutoNAT service is the
 * NodeAutoNatService wrapping the standing receiver node (resolved after init).
 *
 * AC-010(c) is exercised THROUGH cello_initiate_session (not a test-only getter):
 * calling it drives the wired transport selector and returns a defined result —
 * it never crashes with "adapter not wired". A stub SessionNegotiator supplies the
 * SessionAssignment that WIRE-001/SIGNAL-001 will produce in production.
 *
 * C2 — starting the daemon fires transport.autonat.result (INFO) and, because no
 * directory probers are connected (reconnecting), transport.autonat.unavailable
 * (WARN) for the standing receiver. This is the dead-code-adapter guard (L3): the
 * AutoNAT events only fire if the NodeAutoNatService is actually wired.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { resolveCelloEnv, createTransportSelector } from "../transport-composition.js";
import type { SessionNegotiator } from "../transport-selector.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

describe("AC-010: composition root wires transport adapters by CELLO_ENV", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];
  let prevEnv: string | undefined;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-transport-comp-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
    handle = null;
    clients = [];
    prevEnv = process.env["CELLO_ENV"];
  });

  afterEach(async () => {
    for (const c of clients) {
      try { c.close(); } catch { /* already closed */ }
    }
    if (handle) {
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
    }
    if (prevEnv === undefined) delete process.env["CELLO_ENV"];
    else process.env["CELLO_ENV"] = prevEnv;
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeConfig(overrides?: Partial<DaemonConfig>): DaemonConfig {
    return {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      ...overrides,
    };
  }

  async function setupAgent(name: string): Promise<void> {
    const agentsDir = join(tempDir, "agents", name);
    await mkdir(agentsDir, { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "key"));
  }

  function makeAssignment(transportMode: "direct" | "relay"): SessionAssignment {
    return {
      session_id: new Uint8Array(16).fill(9),
      participant_a: { pubkey: new Uint8Array(32).fill(1), peer_id: "12D3KooWA", multiaddrs: [] },
      participant_b: { pubkey: new Uint8Array(32).fill(2), peer_id: "12D3KooWB", multiaddrs: [] },
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/198.51.100.9/tcp/4001"] },
      directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/203.0.113.1/tcp/4001"] },
      session_timestamp: 1_700_000_000_000,
      directory_pubkey: new Uint8Array(32).fill(3),
      directory_signature: new Uint8Array(64).fill(4),
      signature_type: "frost",
      signer_pubkey: new Uint8Array(32).fill(5),
      counterparty_session_peer_id: "12D3KooWCounter",
      counterparty_session_addrs: ["/ip4/203.0.113.50/tcp/4001/p2p/12D3KooWCounter"],
      transport_mode: transportMode,
    };
  }

  /** Stub negotiator: returns a canned assignment (the WIRE-001/SIGNAL-001 seam). */
  function stubNegotiator(assignment: SessionAssignment): SessionNegotiator {
    return { negotiate: async () => ({ ok: true, assignment }) };
  }

  async function connectMcp(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  it("CELLO_ENV=local: daemon starts, logs transport.adapters.wired(stub), AutoNAT defaults to not dialable", async () => {
    process.env["CELLO_ENV"] = "local";
    handle = await startDaemon(makeConfig());

    // (a) daemon started
    expect(handle.getStatus()).toBeDefined();

    // wiring event fired with the stub selection
    const wired = logEvents.find((e) => e.event === "transport.adapters.wired");
    expect(wired).toBeDefined();
    expect(wired!.context).toMatchObject({ env: "local", selector: "stub" });

    // (b) AutoNAT service accessible, returns the conservative default (standing
    // receiver is loopback + no probers).
    expect(handle.getAutoNatService().getDialability()).toEqual({ dialable: false, publicAddr: null });
  });

  it("C2: starting the daemon emits transport.autonat.result and transport.autonat.unavailable", async () => {
    process.env["CELLO_ENV"] = "local";
    handle = await startDaemon(makeConfig());

    const result = logEvents.find((e) => e.event === "transport.autonat.result");
    expect(result).toBeDefined();
    expect(result!.level).toBe("info");
    expect(result!.context).toMatchObject({ dialable: false, publicAddr: null, nodeType: "standing_receiver" });

    // No directory probers connected → AutoNAT cannot run → unavailable WARN fires.
    const unavailable = logEvents.find((e) => e.event === "transport.autonat.unavailable");
    expect(unavailable).toBeDefined();
    expect(unavailable!.level).toBe("warn");
    expect(unavailable!.context).toMatchObject({ nodeType: "standing_receiver" });
  });

  it("AC-010(c): cello_initiate_session drives the wired transport selector (does not crash with 'adapter not wired')", async () => {
    process.env["CELLO_ENV"] = "local";
    await setupAgent("alice");
    // Inject a stub negotiator so the selector path is exercised end-to-end. The
    // LocalTransportSelectorStub (default) returns a successful relay selection.
    handle = await startDaemon(makeConfig({ sessionNegotiator: stubNegotiator(makeAssignment("relay")) }));

    const client = await connectMcp(join(tempDir, "daemon.sock"));
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const result = (await client.send("cello_initiate_session", {})) as {
      ok: boolean;
      transportMode?: string;
      reason?: string;
    };

    // The wired selector ran and returned a defined transport result — NOT a
    // not_implemented / adapter-not-wired crash.
    expect(result.ok).toBe(true);
    expect(result.transportMode).toBe("relay");
  });

  it("cello_initiate_session without a negotiator returns directory_signaling_not_configured (graceful, adapters still wired)", async () => {
    process.env["CELLO_ENV"] = "local";
    await setupAgent("alice");
    handle = await startDaemon(makeConfig());

    const client = await connectMcp(join(tempDir, "daemon.sock"));
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const result = (await client.send("cello_initiate_session", {})) as { ok: boolean; reason?: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("directory_signaling_not_configured");
  });

  it("production variant without a transport dialer fails at startup naming the missing config", async () => {
    process.env["CELLO_ENV"] = "production";
    await expect(startDaemon(makeConfig())).rejects.toThrow(/transport dialer/i);
  });

  it("resolveCelloEnv maps known values and defaults unknown/undefined to 'local'", () => {
    expect(resolveCelloEnv("dev")).toBe("dev");
    expect(resolveCelloEnv("staging")).toBe("staging");
    expect(resolveCelloEnv("production")).toBe("production");
    expect(resolveCelloEnv("local")).toBe("local");
    expect(resolveCelloEnv("test")).toBe("test");
    expect(resolveCelloEnv(undefined)).toBe("local");
    expect(resolveCelloEnv("bogus")).toBe("local");
  });

  it("createTransportSelector throws for production without a dialer; returns stub for local", () => {
    expect(() => createTransportSelector({ env: "production", logger })).toThrow(/transport dialer/i);
    const stub = createTransportSelector({ env: "local", logger });
    expect(stub).toBeDefined();
  });
});
