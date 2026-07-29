/**
 * CELLO-M8C — DOD-SESSION-NAME-1: a human-readable, purely local name for a session.
 *
 * `cello sessions` lists 64 hex chars and a pubkey. The name is a sticky note on your own copy of
 * the folder: it lives in the daemon's SQLCipher `sessions` row and nowhere else — never on the
 * wire, never to the relay or directory, never in the transcript, never in the seal.
 *
 * The load-bearing constraints, each with a test below:
 *  - set OPTIONALLY at close (the moment the agent knows what the conversation was), never at open;
 *  - a bad name must never break a close — the seal is the valuable thing, so validate BEFORE it;
 *  - NULL is allowed to MEAN something (an unnamed closed session is a signal it did not close
 *    cleanly), so no auto-generated defaults;
 *  - renameable in ANY status, including long after the seal;
 *  - a rename is a local DB write: it cannot touch the sealed root.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig, SessionListEntry } from "../types.js";

describe("DOD-SESSION-NAME-1: naming a session", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  const SID = "a1".repeat(32);

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-sessionname-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  /** One agent, online and selected, holding one session row (`active`). */
  async function setup(): Promise<IpcClient> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });
    await handle.getSessionNodeManager().createSessionNode(SID, "alice", "cc".repeat(32), "peer-x", "corr-x");
    return client;
  }

  const listOne = async (client: IpcClient): Promise<SessionListEntry> => {
    const res = await client.send("cello_list_sessions", { filter: "all" }) as { sessions: SessionListEntry[] };
    const entry = res.sessions.find((s) => s.sessionId === SID);
    expect(entry, "the session row must be listed").toBeDefined();
    return entry!;
  };

  // ─── Schema + read surfaces (AC-A1, AC-A11) ───────────────────────────────────

  it("AC-A1/AC-A11: an existing row reads sessionName = null — unnamed is a value, not an absence", async () => {
    const client = await setup();
    const entry = await listOne(client);
    expect(entry).toHaveProperty("sessionName");
    expect(entry.sessionName).toBeNull();
  });

  // ─── Rename (AC-A8, AC-A9, AC-A4) ─────────────────────────────────────────────

  it("AC-A8: cello_name_session sets the name on THIS agent's row", async () => {
    const client = await setup();
    const res = await client.send("cello_name_session", { session_id: SID, session_name: "Q3 budget review with Bob" }) as { ok: boolean };
    expect(res.ok).toBe(true);
    expect((await listOne(client)).sessionName).toBe("Q3 budget review with Bob");
  });

  it("AC-A4: null CLEARS the name — and the cleared state is null, never a fabricated default", async () => {
    const client = await setup();
    await client.send("cello_name_session", { session_id: SID, session_name: "temporary" });
    const res = await client.send("cello_name_session", { session_id: SID, session_name: null }) as { ok: boolean };
    expect(res.ok).toBe(true);
    expect((await listOne(client)).sessionName).toBeNull();
  });

  it("AC-A9: a SEALED session can still be named — naming it long after the fact is the point", async () => {
    const client = await setup();
    const snm = handle!.getSessionNodeManager();
    snm.recordSealCertificate("alice", SID, "de".repeat(32), JSON.stringify({ ok: true }));

    const res = await client.send("cello_name_session", { session_id: SID, session_name: "The deploy postmortem" }) as { ok: boolean };
    expect(res.ok).toBe(true);
    expect((await listOne(client)).sessionName).toBe("The deploy postmortem");
  });

  it("AC-A10: renaming a sealed session leaves the sealed root BYTE-IDENTICAL", async () => {
    const client = await setup();
    const snm = handle!.getSessionNodeManager();
    const rootHex = "de".repeat(32);
    snm.recordSealCertificate("alice", SID, rootHex, JSON.stringify({ ok: true }));

    const before = await client.send("cello_get_sealed_receipt", { session_id: SID }) as { sealed_root?: string };
    await client.send("cello_name_session", { session_id: SID, session_name: "renamed after sealing" });
    const after = await client.send("cello_get_sealed_receipt", { session_id: SID }) as { sealed_root?: string };

    expect(before.sealed_root).toBe(rootHex);
    expect(after.sealed_root).toBe(before.sealed_root);
  });

  it("AC-A9: a session that is not THIS agent's is session_not_found — ownership is the only scope", async () => {
    const client = await setup();
    const res = await client.send("cello_name_session", { session_id: "ff".repeat(32), session_name: "nope" }) as { ok: boolean; reason?: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_not_found");
  });

  // ─── Validation (AC-A2, AC-A3) ────────────────────────────────────────────────

  it("AC-A2: a name is free text — punctuation, non-ASCII and emoji are all legal", async () => {
    const client = await setup();
    for (const name of ["Q3 budget review with Bob", "café — 中文 — 🎻", "re: invoice #42 (draft!)"]) {
      const res = await client.send("cello_name_session", { session_id: SID, session_name: name }) as { ok: boolean };
      expect(res.ok, `${name} must be accepted`).toBe(true);
      expect((await listOne(client)).sessionName).toBe(name);
    }
  });

  it("AC-A3: control characters are REJECTED by name — never silently stripped", async () => {
    const client = await setup();
    for (const bad of ["two\nlines", "carriage\rreturn", "tab\there", "nul\0byte", "bell\x07here", "c1\x85next"]) {
      const res = await client.send("cello_name_session", { session_id: SID, session_name: bad }) as { ok: boolean; reason?: string };
      expect(res.ok, `${JSON.stringify(bad)} must be refused`).toBe(false);
      expect(res.reason).toBe("session_name_control_chars");
    }
    // and nothing was written — a rejected name must not half-land
    expect((await listOne(client)).sessionName).toBeNull();
  });

  it("AC-A3: a 201-character name is REJECTED, not truncated — 200 is fine", async () => {
    const client = await setup();
    const tooLong = "x".repeat(201);
    const res = await client.send("cello_name_session", { session_id: SID, session_name: tooLong }) as { ok: boolean; reason?: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_name_too_long");
    expect((await listOne(client)).sessionName).toBeNull();

    const atLimit = "y".repeat(200);
    const ok = await client.send("cello_name_session", { session_id: SID, session_name: atLimit }) as { ok: boolean };
    expect(ok.ok).toBe(true);
    expect((await listOne(client)).sessionName).toBe(atLimit);
  });

  it("AC-A3: surrounding whitespace is trimmed; an all-whitespace name is a CLEAR, not an error", async () => {
    const client = await setup();
    const trimmed = await client.send("cello_name_session", { session_id: SID, session_name: "  spaced out  " }) as { ok: boolean };
    expect(trimmed.ok).toBe(true);
    expect((await listOne(client)).sessionName).toBe("spaced out");

    const blank = await client.send("cello_name_session", { session_id: SID, session_name: "   " }) as { ok: boolean };
    expect(blank.ok).toBe(true);
    expect((await listOne(client)).sessionName).toBeNull();
  });

  // ─── Close (AC-A5, AC-A6, AC-A7) ──────────────────────────────────────────────

  it("AC-A5/AC-A7: a force-abandoned session keeps the name it was closed with", async () => {
    const client = await setup();
    const res = await client.send("cello_close_session", {
      session_id: SID, force: true, session_name: "handshake the counterparty never joined",
    }) as { ok: boolean; status?: string };
    expect(res.ok).toBe(true);
    expect(res.status).toBe("abandoned");

    const entry = await listOne(client);
    expect(entry.sessionName).toBe("handshake the counterparty never joined");
    expect(entry.status).toBe("abandoned");
  });

  it("AC-A5: a close with NO name behaves exactly as before — and leaves the name null (the signal)", async () => {
    const client = await setup();
    const res = await client.send("cello_close_session", { session_id: SID, force: true }) as { ok: boolean; status?: string };
    expect(res.ok).toBe(true);
    expect(res.status).toBe("abandoned");
    expect((await listOne(client)).sessionName).toBeNull();
  });

  it("AC-A5: a name on a RETRIED close of an already-sealed session is APPLIED, not silently dropped", async () => {
    const client = await setup();
    const snm = handle!.getSessionNodeManager();

    // The realistic path this guards: the seal COMPLETED but the agent's call was interrupted (a
    // relay blip, a tool timeout), so the agent closes again with the name it had just decided on.
    // Being told "already sealed, no further action is needed" while the name silently goes nowhere
    // loses it at exactly the moment the agent believes it was saved.
    await snm.destroySessionNode("alice", SID, "sealed");
    snm.recordSealCertificate("alice", SID, "fa".repeat(32), JSON.stringify({ ok: true }));

    const res = await client.send("cello_close_session", {
      session_id: SID, session_name: "the one that got interrupted",
    }) as { ok: boolean; reason?: string; session_name?: string; guidance?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_already_sealed");
    // The name landed anyway, and the response SAYS SO rather than letting "no further action is
    // needed" imply otherwise.
    expect(res.session_name).toBe("the one that got interrupted");
    expect(res.guidance).toContain("WAS applied");
    expect((await listOne(client)).sessionName).toBe("the one that got interrupted");
  });

  it("a plain close of an ABANDONED session refuses — it does not fire a seal at a counterparty that was never there", async () => {
    const client = await setup();
    await client.send("cello_close_session", { session_id: SID, force: true });

    const res = await client.send("cello_close_session", { session_id: SID }) as { ok: boolean; reason?: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_abandoned");

    // force stays idempotent — that contract predates this and must not move.
    const forced = await client.send("cello_close_session", { session_id: SID, force: true }) as { ok: boolean; reason?: string };
    expect(forced.ok).toBe(true);
    expect(forced.reason).toBe("already_abandoned");
  });

  it("AC-A13: the name renders NEXT TO the id — key order is the layout in a JSON list", async () => {
    const client = await setup();
    await client.send("cello_name_session", { session_id: SID, session_name: "next to the id" });
    const res = await client.send("cello_list_sessions", { filter: "all" }) as { sessions: SessionListEntry[] };
    const entry = res.sessions.find((s) => s.sessionId === SID)!;
    const keys = Object.keys(entry);
    // Scanning a 50-session dump for "which one was the deploy" is the problem the name exists to
    // solve; eleven fields below the id it does not solve it.
    expect(keys[0]).toBe("sessionId");
    expect(keys[1]).toBe("sessionName");
  });

  it("AC-A6: an INVALID name is refused BEFORE the close — the session is untouched, not half-closed", async () => {
    const client = await setup();
    const res = await client.send("cello_close_session", {
      session_id: SID, force: true, session_name: "bad\nname",
    }) as { ok: boolean; reason?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_name_control_chars");

    // The close did NOT happen: the session is still active, and no name was written. A close that
    // half-lands and then fails on a cosmetic label would trade the seal for a sticky note.
    const entry = await listOne(client);
    expect(entry.status).toBe("active");
    expect(entry.sessionName).toBeNull();
  });

  // ─── Observability (AC-A16) ───────────────────────────────────────────────────

  it("AC-A16: the daemon logs the name's LENGTH and never its TEXT — it is private conversation content", async () => {
    const client = await setup();
    const secret = "Acquisition of Northwind Traders";
    await client.send("cello_name_session", { session_id: SID, session_name: secret });

    const set = logEvents.find((e) => e.event === "session.name.set");
    expect(set).toBeDefined();
    expect(set!.context.nameLength).toBe(secret.length);
    expect(set!.context.source).toBe("rename");
    expect(set!.context.sessionId).toBe(SID);
    expect(JSON.stringify(set!.context)).not.toContain("Northwind");

    await client.send("cello_name_session", { session_id: SID, session_name: null });
    expect(logEvents.some((e) => e.event === "session.name.cleared")).toBe(true);

    // The probe string must not be spellable in hex: the context carries a random UUID
    // agentId, and a name like "bad" collides with UUIDs such as "…-badf-…", failing
    // this assertion at random. "zqxw" cannot appear in a UUID.
    await client.send("cello_name_session", { session_id: SID, session_name: "zqxw\nname" });
    const rejected = logEvents.find((e) => e.event === "session.name.rejected");
    expect(rejected).toBeDefined();
    expect(rejected!.context.reason).toBe("session_name_control_chars");
    expect(JSON.stringify(rejected!.context)).not.toContain("zqxw");
  });

  it("AC-A16/close: a name set at close is logged with source 'close'", async () => {
    const client = await setup();
    await client.send("cello_close_session", { session_id: SID, force: true, session_name: "the deploy" });
    const set = logEvents.find((e) => e.event === "session.name.set");
    expect(set).toBeDefined();
    expect(set!.context.source).toBe("close");
  });

  // ─── Constraint 1: purely local. The one that cannot be walked back. ──────────

  it("the name reaches NO wire structure — protocol-types and transport never learn the word", () => {
    // The name is a sticky note on your own copy of the folder. Everything that can put bytes on the
    // wire lives in protocol-types (the encoders + TBS builders) and transport. If `session_name`
    // appears in either, something is about to be sent, signed, or hashed that must not be — and the
    // damage is not local: a counterparty would see the private subject of the conversation.
    //
    // A behavioural test cannot cover this the way a structural one can: it would have to enumerate
    // every frame the daemon can emit and prove a negative about each. The name's absence from the
    // encoders IS the guarantee, so that is what is asserted.
    const roots = [
      join(import.meta.dirname, "..", "..", "..", "protocol-types", "src"),
      join(import.meta.dirname, "..", "..", "..", "transport", "src"),
    ];
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        if (e.name === "__tests__" || e.name === "dist" || e.name === "node_modules") continue;
        const full = join(dir, e.name);
        if (e.isDirectory()) { walk(full); continue; }
        if (!e.name.endsWith(".ts")) continue;
        if (readFileSync(full, "utf8").includes("session_name")) offenders.push(full);
      }
    };
    for (const r of roots) walk(r);
    expect(offenders, "session_name must not appear in any wire-facing package").toEqual([]);
  });
});
