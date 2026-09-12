/**
 * 074-DOCSFLAG clauses 2, 5, 6 and 9 — what the DAEMON does not offer when the flag is off.
 *
 * Three surfaces live in this process: the IPC handler map the socket dispatches from, the
 * vocabulary registry, and the reconcile sweep timer. The CLI's help and the MCP shim's advertised
 * tool list are separate processes and are tested in their own packages, against their own binaries.
 *
 * ── THE COUNT IN THE ORDER IS FROM 2026-09-07 AND `main` HAS MOVED ────────────────────────────
 *
 * The order says the socket answers 80 verbs instead of 94. Remeasured here on 2026-09-12: the
 * daemon registers **87**, of which **14** are `cello_doc_*`, so the off state is **73**. The order's
 * figure is not wrong about anything that matters — it recorded a real total on a different day, and
 * seven verbs have come and gone since. So the numbers are asserted as measured AND the drop is
 * asserted as exactly fourteen, which is the property the clause is actually about: no document verb
 * is answerable, and nothing else went missing with them.
 *
 * ── WHY `getHandlers()` IS THE RIGHT TARGET AND A SOURCE SCAN IS NOT ──────────────────────────
 *
 * `getHandlers()` returns the LIVE map dispatch resolves from — its own doc note records that a
 * snapshot copy once made every `cello_doc_*` verb unreachable while the whole suite stayed green.
 * A `grep` for `handlers.set(` would count registrations in source and could not tell a registered
 * handler from a reachable one. So the count is taken from the map, and then one doc verb is CALLED
 * over the real socket and required to come back `method_not_found` — the socket's own answer, not
 * an inference from a data structure.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { DOCUMENTS_FLAG_ENV } from "../document-flag.js";
import type { Logger, DaemonConfig } from "../types.js";

/** Every document verb, spelled out — the list the clause is about. */
const DOC_VERBS = [
  "cello_doc_propose", "cello_doc_invite", "cello_doc_remove", "cello_doc_inbox",
  "cello_doc_accept", "cello_doc_refuse", "cello_doc_list", "cello_doc_read",
  "cello_doc_diff", "cello_doc_watch", "cello_doc_write", "cello_doc_publish",
  "cello_doc_close", "cello_doc_kill",
] as const;

interface Captured {
  event: string;
  fields: Record<string, unknown>;
}

describe("074-DOCSFLAG clauses 2/5/6/9 — the daemon's three document surfaces, gated", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];
  let events: Captured[];
  /** Every interval this daemon created, with its delay — see the sweep-timer clause below. */
  let intervals: number[];
  let realSetInterval: typeof setInterval;
  let savedFlag: string | undefined;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    savedFlag = process.env[DOCUMENTS_FLAG_ENV];
    tempDir = await mkdtemp(join(tmpdir(), "cello-docsflag-"));
    handle = null;
    clients = [];
    events = [];
    intervals = [];
    realSetInterval = globalThis.setInterval;
  });

  afterEach(async () => {
    globalThis.setInterval = realSetInterval;
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
    if (savedFlag === undefined) delete process.env[DOCUMENTS_FLAG_ENV];
    else process.env[DOCUMENTS_FLAG_ENV] = savedFlag;
  });

  function recordingLogger(): Logger {
    const push = (event: string, fields?: Record<string, unknown>) =>
      events.push({ event, fields: fields ?? {} });
    return {
      debug: (e: string, f?: Record<string, unknown>) => push(e, f),
      info: (e: string, f?: Record<string, unknown>) => push(e, f),
      warn: (e: string, f?: Record<string, unknown>) => push(e, f),
      error: (e: string, f?: Record<string, unknown>) => push(e, f),
    } as unknown as Logger;
  }

  async function config(): Promise<DaemonConfig> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: recordingLogger(),
    };
  }

  /** Start a daemon with the flag in the given state, recording every interval it creates. */
  async function start(flag: "on" | "off"): Promise<DaemonHandle> {
    if (flag === "on") process.env[DOCUMENTS_FLAG_ENV] = "1";
    else delete process.env[DOCUMENTS_FLAG_ENV];
    // Captured BEFORE startDaemon so the sweep interval — created inside it — is observed. The spy
    // records the delay and delegates: suppressing the timer would change what is being measured.
    globalThis.setInterval = ((fn: () => void, ms?: number, ...rest: unknown[]) => {
      intervals.push(ms ?? 0);
      return (realSetInterval as unknown as (...a: unknown[]) => unknown)(fn, ms, ...rest);
    }) as unknown as typeof setInterval;
    handle = await startDaemon(await config());
    globalThis.setInterval = realSetInterval;
    return handle;
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  // ── Clause 2: the IPC verb count, and no doc verb among them ────────────────────────────────

  it("OFF: the handler map is 73 verbs, exactly 14 fewer than ON, and none of them is a doc verb", async () => {
    const off = await start("off");
    const offKeys = [...off.getHandlers().keys()];
    expect(offKeys).toHaveLength(73);
    expect(offKeys.filter((k) => k.startsWith("cello_doc_"))).toEqual([]);
    for (const verb of DOC_VERBS) expect(offKeys).not.toContain(verb);

    await off.stop("switch");
    handle = null;

    const on = await start("on");
    const onKeys = [...on.getHandlers().keys()];
    expect(onKeys).toHaveLength(87);
    // The drop is the whole assertion: fourteen verbs left and nothing else did.
    expect(onKeys.length - offKeys.length).toBe(14);
    expect(onKeys.filter((k) => k.startsWith("cello_doc_")).sort()).toEqual([...DOC_VERBS].sort());
    expect(new Set(onKeys.filter((k) => !k.startsWith("cello_doc_")))).toEqual(new Set(offKeys));
  }, 120_000);

  it("OFF: the SOCKET answers method_not_found for a doc verb — not a disabled handler", async () => {
    await start("off");
    const client = await connect(join(tempDir, "daemon.sock"));
    for (const verb of DOC_VERBS) {
      // `send` surfaces the JSON-RPC error; a registered-but-disabled handler would answer with a
      // RESULT carrying a refusal instead, which is the thing the order forbids.
      await expect(client.send(verb, {})).rejects.toThrow(/method_not_found|Unknown method/);
    }
  }, 120_000);

  // ── Clause 9: the state is one grep, not an inference ───────────────────────────────────────

  it("the daemon says which state the document layer is in, at startup, on both settings", async () => {
    await start("off");
    const offLine = events.find((e) => e.event === "document.layer.state");
    expect(offLine, "no document.layer.state at startup").toBeDefined();
    expect(offLine?.fields["state"]).toBe("off");
    expect(offLine?.fields["flag"]).toBe(DOCUMENTS_FLAG_ENV);

    await handle?.stop("switch");
    handle = null;
    events = [];

    await start("on");
    expect(events.find((e) => e.event === "document.layer.state")?.fields["state"]).toBe("on");
  }, 120_000);

  // ── Clause 6: the sweep timer is never CREATED ──────────────────────────────────────────────

  it("OFF: no 120-second interval is created at all — and ON, exactly one is", async () => {
    await start("off");
    expect(intervals, "a 120s reconcile interval was created with documents off").not.toContain(120_000);

    await handle?.stop("switch");
    handle = null;
    intervals = [];

    await start("on");
    // THE POSITIVE CONTROL for the assertion above and for the log-absence test below: this proves
    // the spy can see the sweep interval being created, so its absence in the off run means the
    // timer was not created rather than that the measurement could not reach it.
    expect(intervals.filter((ms) => ms === 120_000)).toHaveLength(1);
  }, 120_000);

  it("OFF: no document.reconcile.* event is logged after the sweep boundary has passed", async () => {
    // The sweep period is overridden to 250ms so the boundary the clause names is crossed six times
    // in the window below instead of once every two minutes. What is measured is unchanged: whether
    // a timer fires at all.
    //
    // ⚠️ AN EMPTY EVENT LIST IS THE WEAKER HALF OF THIS TEST, SAID PLAINLY. With no agent online the
    // sweep's body walks an empty map and logs nothing anyway, so this assertion is ALSO green on
    // today's tree — it cannot, by itself, tell a timer that was never created from one that ticked
    // and found nothing to do. The interval assertion is what carries the clause, and it is repeated
    // here so a green in THIS test means the timer was absent rather than merely quiet. The ON run
    // at the end is the proof the measurement reaches: the same spy sees the same override.
    process.env["CELLO_DOCUMENT_RECONCILE_SWEEP_MS"] = "250";
    try {
      await start("off");
      await new Promise((r) => setTimeout(r, 1_500));
      expect(events.filter((e) => e.event.startsWith("document.reconcile.")).map((e) => e.event)).toEqual([]);
      expect(intervals, "a sweep interval was created with documents off").not.toContain(250);

      await handle?.stop("switch");
      handle = null;
      intervals = [];

      await start("on");
      expect(intervals.filter((ms) => ms === 250)).toHaveLength(1);
    } finally {
      delete process.env["CELLO_DOCUMENT_RECONCILE_SWEEP_MS"];
    }
  }, 120_000);
});

// ── Clause 5: the vocabulary registry ────────────────────────────────────────────────────────
//
// A SEPARATE describe with no daemon. The vocabulary is read at module load, and THE SUITE RUNS WITH
// THE FLAG ON (see `vitest.config.ts`), so reading the ambient value here would test the on state
// while claiming to test the off one. Each case therefore sets the variable and re-imports.
describe("074-DOCSFLAG clause 5 — the vocabulary registry", () => {
  let saved: string | undefined;

  beforeEach(() => { saved = process.env[DOCUMENTS_FLAG_ENV]; });
  afterEach(() => {
    if (saved === undefined) delete process.env[DOCUMENTS_FLAG_ENV];
    else process.env[DOCUMENTS_FLAG_ENV] = saved;
    vi.resetModules();
  });

  async function vocabulary(flag: "on" | "off") {
    if (flag === "on") process.env[DOCUMENTS_FLAG_ENV] = "1";
    else delete process.env[DOCUMENTS_FLAG_ENV];
    vi.resetModules();
    return import("../vocabulary.js");
  }

  it("OFF: no document entry, and no cello_doc_* name is a known tool", async () => {
    const { DUAL_SURFACE_VERBS, knownToolNames } = await vocabulary("off");
    // The search had reach before the negative is believed: a populated, real registry.
    expect(DUAL_SURFACE_VERBS.length).toBeGreaterThan(30);
    expect(DUAL_SURFACE_VERBS.map((v) => v.mcp)).toContain("cello_send");

    expect(DUAL_SURFACE_VERBS.filter((v) => v.mcp.startsWith("cello_doc_"))).toEqual([]);
    expect(DUAL_SURFACE_VERBS.filter((v) => v.cli.startsWith("cello doc"))).toEqual([]);
    expect([...knownToolNames()].filter((t) => t.startsWith("cello_doc_"))).toEqual([]);
  });

  it("ON: all fourteen rows are back, with their CLI names — nothing was deleted", async () => {
    const { DUAL_SURFACE_VERBS, knownToolNames } = await vocabulary("on");
    const docs = DUAL_SURFACE_VERBS.filter((v) => v.mcp.startsWith("cello_doc_"));
    expect(docs).toHaveLength(14);
    expect(docs.map((v) => v.mcp).sort()).toEqual([...DOC_VERBS].sort());
    for (const v of docs) expect(v.cli).toMatch(/^cello doc [a-z]+$/);
    expect([...knownToolNames()].filter((t) => t.startsWith("cello_doc_"))).toHaveLength(14);
  });
});
