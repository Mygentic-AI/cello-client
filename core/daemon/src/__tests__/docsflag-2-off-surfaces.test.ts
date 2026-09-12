/**
 * 074-DOCSFLAG clauses 2, 5, 6 and 9 — what the DAEMON does not offer when the flag is off.
 *
 * Three surfaces live in this process: the IPC handler map the socket dispatches from, the
 * vocabulary registry, and the reconcile sweep timer. The CLI's help and the MCP shim's advertised
 * tool list are separate processes and are tested in their own packages, against their own binaries.
 *
 * ── THE ORDER'S COUNT IS FROM 2026-09-07, AND NEITHER TOTAL IS THE PRODUCTION SURFACE ────────
 *
 * The order says the socket answers 80 verbs instead of 94. Two corrections, the second found by
 * review:
 *
 *  1. `main` has moved. Remeasured 2026-09-12: 87 registered, 14 of them `cello_doc_*`, so 73 off.
 *  2. **Every daemon in this file starts with `CELLO_ENV=test`, which registers 13 verbs from
 *     `test-handlers.ts` that an operator's socket never answers.** So neither 87 nor 73 is what an
 *     operator sees; the production surface is 74 on and 60 off.
 *
 * Pinning a clause to a test-env total is how a magic number gets "fixed" by editing it the next time
 * an unrelated verb is added. So the counts asserted below EXCLUDE the test-only verbs, and the three
 * load-bearing assertions are ones no unrelated change can make stale: the drop is exactly fourteen,
 * the fourteen that left are exactly the document verbs, and the non-document set is identical in both
 * states.
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

  /**
   * The verbs an OPERATOR's socket answers: everything except the test-only handlers.
   *
   * These daemons run with `CELLO_ENV=test`, which registers `test-handlers.ts`. Counting those would
   * pin the clause to a number no operator ever sees. The filter is by the two shapes that file uses —
   * the `__test_` prefix and six older debug verbs that predate it — and `productionVerbs` asserts it
   * actually removed something, so a rename in `test-handlers.ts` cannot silently make this a no-op.
   */
  const TEST_ONLY_VERBS = new Set([
    "queue_failed_send", "debug_inject_park_fault", "enqueue_awaiting_content",
    "mark_content_acked", "check_nonce", "drain_session",
  ]);
  function productionVerbs(h: DaemonHandle): string[] {
    const all = [...h.getHandlers().keys()];
    const kept = all.filter((k) => !k.startsWith("__test_") && !TEST_ONLY_VERBS.has(k));
    expect(
      all.length - kept.length,
      "the test-only filter matched nothing — test-handlers.ts was renamed and this count is now wrong",
    ).toBe(13);
    return kept;
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  // ── Clause 2: the IPC verb count, and no doc verb among them ────────────────────────────────

  it("OFF: the operator's socket answers 60 verbs, exactly 14 fewer than ON, and no doc verb", async () => {
    const off = await start("off");
    const offKeys = productionVerbs(off);
    expect(offKeys).toHaveLength(60);
    expect(offKeys.filter((k) => k.startsWith("cello_doc_"))).toEqual([]);
    for (const verb of DOC_VERBS) expect(offKeys).not.toContain(verb);

    await off.stop("switch");
    handle = null;

    const on = await start("on");
    const onKeys = productionVerbs(on);
    expect(onKeys).toHaveLength(74);
    // The three assertions that survive any unrelated verb being added or removed.
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

  /**
   * REVIEW FINDING F3 — the refusal named the wrong subsystem.
   *
   * `method_not_found` is correct: the verb genuinely is not registered, and registering one to say
   * "disabled" is what the order forbids. What was wrong was the GUIDANCE, which is generic and sends
   * the reader to check that cello-mcp and the daemon are the same version — for a flag that is off by
   * design.
   *
   * ⚠️ AND IT IS REACHABLE IN ORDINARY OPERATION, WHICH IS WHY IT IS NOT COSMETIC. The shim and the
   * daemon are separate processes with separate environments: the MCP client spawns one, `cello login`
   * starts the other. Set the flag for the shim only and it advertises fourteen tools against a daemon
   * that answers none of them; run an older `@cello-protocol/connect` and you land in the same place.
   * The only statement of the truth was a `document.layer.gated` line written at boot, possibly days
   * earlier.
   */
  it("OFF: a gated doc verb is refused by ITS OWN CAUSE, not by generic version-skew guidance", async () => {
    await start("off");
    const client = await connect(join(tempDir, "daemon.sock"));
    const err = await client.send("cello_doc_propose", {}).then(
      () => { throw new Error("a gated doc verb must not resolve"); },
      (e: unknown) => e as { message?: string; guidance?: string; code?: string },
    );
    const text = `${err.message ?? ""} ${err.guidance ?? ""}`;

    // The cause, named where it surfaced.
    expect(text).toContain("documents are disabled");
    // Invariant 4 — the next step is in the payload, and it names the REAL variable and the REAL
    // trap: both processes, or the tool stays advertised and unanswerable.
    expect(err.guidance).toContain(DOCUMENTS_FLAG_ENV);
    expect(err.guidance).toContain("cello-mcp");
    // And the wrong subsystem is GONE from this answer — the whole finding.
    expect(text, "still blames version skew for a flag that is off by design").not.toContain("same version");

    // The forensic half is kept: the response is the control, the log is the record, never one instead
    // of the other.
    const refusal = events.find((e) => e.event === "document.verb.refused");
    expect(refusal, "the refusal reached the caller but left no log line").toBeDefined();
    expect(refusal?.fields["method"]).toBe("cello_doc_propose");
    expect(refusal?.fields["reason"]).toBe("documents_disabled");
  }, 120_000);

  it("an unknown NON-document verb still gets the version-skew guidance — the fix did not widen", async () => {
    await start("off");
    const client = await connect(join(tempDir, "daemon.sock"));
    const err = await client.send("cello_not_a_verb", {}).then(
      () => { throw new Error("an unknown verb must not resolve"); },
      (e: unknown) => e as { guidance?: string },
    );
    // The exemplar is chosen from the PREDICATE: the branch keys on the `cello_doc_` prefix, so the
    // value that must take the other branch is a `cello_`-prefixed name that is not a doc verb.
    expect(err.guidance).toContain("same version");
    expect(err.guidance).not.toContain(DOCUMENTS_FLAG_ENV);
  }, 120_000);

  // ── Clause 9: the state is one grep, not an inference ───────────────────────────────────────

  it("the daemon says which state the document layer is in, at startup, on both settings", async () => {
    await start("off");
    const offLine = events.find((e) => e.event === "document.layer.gated");
    expect(offLine, "no document.layer.gated at startup").toBeDefined();
    expect(offLine?.fields["state"]).toBe("off");
    expect(offLine?.fields["flag"]).toBe(DOCUMENTS_FLAG_ENV);

    await handle?.stop("switch");
    handle = null;
    events = [];

    await start("on");
    expect(events.find((e) => e.event === "document.layer.gated")?.fields["state"]).toBe("on");
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
