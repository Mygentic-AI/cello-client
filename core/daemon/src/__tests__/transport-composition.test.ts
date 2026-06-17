/**
 * CELLO-M7-TRANSPORT-001 — transport-composition.test.ts (AC-010)
 *
 * ─── Specification (Phase S) ──────────────────────────────────────────────────
 * AC-010 — the daemon composition root instantiates the IAutoNatService and
 * ITransportSelector adapters, selecting the in-process stubs when CELLO_ENV is
 * 'local'|'test' and the real implementations for 'dev'|'staging'|'production'.
 * A production variant missing required config fails at STARTUP with a clear error
 * naming the missing config — not at first session establishment.
 *
 * This binary/startDaemon-level test is the only test that catches a dead-code
 * adapter (M7 lesson L3): it starts the daemon and exercises the wired selector.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import {
  resolveCelloEnv,
  createTransportSelector,
  createAutoNatService,
} from "../transport-composition.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

describe("AC-010: composition root wires transport adapters by CELLO_ENV", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;
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
    prevEnv = process.env["CELLO_ENV"];
  });

  afterEach(async () => {
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

  function makeAssignment(): SessionAssignment {
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
      transport_mode: "relay",
    };
  }

  it("CELLO_ENV=local: daemon starts, logs transport.adapters.wired(stub), AutoNAT defaults to not dialable", async () => {
    process.env["CELLO_ENV"] = "local";
    handle = await startDaemon(makeConfig());

    // (a) daemon started
    expect(handle.getStatus()).toBeDefined();

    // wiring event fired with the stub selection
    const wired = logEvents.find((e) => e.event === "transport.adapters.wired");
    expect(wired).toBeDefined();
    expect(wired!.context).toMatchObject({ env: "local", selector: "stub", autonat: "stub" });

    // (b) AutoNAT service accessible, returns the stub default
    expect(handle.getAutoNatService().getDialability()).toEqual({ dialable: false, publicAddr: null });

    // (c) the transport selector path is exercisable — does NOT crash with "adapter not wired"
    const result = await handle.getTransportSelector().dial(makeAssignment(), { correlationId: "cid-010" });
    expect(result.ok).toBe(true);
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

  it("createAutoNatService throws for production without an adapter; returns stub for local", () => {
    expect(() => createAutoNatService({ env: "staging" })).toThrow(/AutoNAT service adapter/i);
    expect(createAutoNatService({ env: "test" }).getDialability()).toEqual({ dialable: false, publicAddr: null });
  });
});
