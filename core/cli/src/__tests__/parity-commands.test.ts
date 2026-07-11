/**
 * DOD-CLI-PARITY-1 Phases 1-2 — Group A (operator control / address book) and Group B (live
 * conversation) reachable from `cello`, so a bash-capable agent operates a CELLO node with no MCP.
 *
 * These run against a REAL spawned daemon over the REAL IPC socket (no mocks, no fake IPC server) —
 * the point is to prove each command reaches the SAME daemon handler its MCP tool calls, with the
 * same params, and honors the §3 contract: JSON on stdout, the daemon's structured error VERBATIM
 * on stderr, exit code branching on ok. A command that dressed a failed IPC call as success would
 * pass a shallower test; that is what the stdout-is-empty-on-failure assertions exist to prevent.
 *
 * The per-invocation connection problem (and why `use-agent` is not a no-op):
 *   the daemon's "current agent" is PER-CONNECTION state, and the CLI opens a fresh connection for
 *   every invocation. A naive `cello use-agent alice` pass-through would set that state on a socket
 *   that closes microseconds later — printing ok:true while having NO effect on the next command.
 *   So `use-agent` persists the selection, and every agent-scoped command REPLAYS cello_use_agent on
 *   its new connection before dispatching (the same replay the MCP proxy does after a reconnect —
 *   ipc-proxy.ts invariant 1). The cross-invocation tests below are what make that real.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startDaemon, type DaemonHandle, type DaemonConfig, type Logger } from "@cello-protocol/daemon";
import {
  listAgents,
  startAgent,
  stopAgent,
  useAgent,
  inbox,
  transcript,
  contactSetMoniker,
  initiate,
  send,
  receive,
  closeSession,
  awaitSession,
  receiveSession,
  sealedReceipt,
  readCurrentAgent,
} from "../parity-commands.js";
import { createAgent } from "../commands.js";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("DOD-CLI-PARITY-1: Group A + Group B against a REAL daemon", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;

  function makeConfig(): DaemonConfig {
    return {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: noopLogger,
    };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-parity-test-"));
    handle = await startDaemon(makeConfig());
  });

  afterEach(async () => {
    if (handle) {
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  // ─── Group A: agent lifecycle ────────────────────────────────────────────────────────────

  describe("Group A — agent lifecycle", () => {
    it("`cello agents` lists loaded agents as JSON on stdout, exit 0", async () => {
      await createAgent(tempDir, "alice");
      const out = await listAgents(tempDir, {});
      expect(out.exitCode).toBe(0);
      expect(out.stderr).toBe("");
      // cello_list_agents is payload-only — it returns { agents: [...] } with NO `ok` field. The
      // contract must treat that as the result it is (see json-out.ts), so assert the PAYLOAD.
      const parsed = JSON.parse(out.stdout);
      expect((parsed.agents as Array<{ name: string }>).map((a) => a.name)).toContain("alice");
    });

    it("`cello start-agent` / `stop-agent` reach the daemon handler and report its verdict", async () => {
      await createAgent(tempDir, "alice");
      const started = await startAgent(tempDir, "alice", {});
      // An unregistered agent may legitimately refuse to start — what must hold is that the CLI
      // reports the DAEMON's verdict, never a fabricated one, and routes it by ok.
      const startBody = JSON.parse(started.exitCode === 0 ? started.stdout : started.stderr);
      expect(typeof startBody.ok).toBe("boolean");
      expect(started.exitCode).toBe(startBody.ok ? 0 : 1);
      if (!startBody.ok) expect(started.stdout).toBe(""); // failure never lands on stdout

      const stopped = await stopAgent(tempDir, "alice", {});
      const stopBody = JSON.parse(stopped.exitCode === 0 ? stopped.stdout : stopped.stderr);
      expect(stopped.exitCode).toBe(stopBody.ok ? 0 : 1);
    });

    it("start-agent on an UNKNOWN agent fails loud — structured error verbatim on stderr, stdout empty", async () => {
      const out = await startAgent(tempDir, "nonexistent", {});
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
      const err = JSON.parse(out.stderr);
      expect(err.ok).toBe(false);
      expect(typeof err.reason).toBe("string"); // the daemon's own reason, not one we invented
    });
  });

  // ─── The per-invocation current-agent problem ────────────────────────────────────────────

  describe("`cello use-agent` is DURABLE (not a no-op that lies)", () => {
    it("persists the selection so a LATER, SEPARATE invocation acts on that agent", async () => {
      await createAgent(tempDir, "alice");
      const used = await useAgent(tempDir, "alice", {});
      expect(used.exitCode).toBe(0);
      expect(await readCurrentAgent(tempDir)).toBe("alice");

      // The proof: a NEW connection (new invocation) that names no agent still resolves to alice.
      // `inbox` (cello_check_notifications, scope=current) has NO name param in the daemon — it can
      // only work off the connection's current agent — so this passing means the replay really ran.
      const box = await inbox(tempDir, {});
      expect(box.exitCode).toBe(0);
      const parsed = JSON.parse(box.stdout);
      expect(parsed.ok).toBe(true);
    });

    it("does NOT persist a selection the daemon REJECTED (no fabricated state)", async () => {
      const out = await useAgent(tempDir, "nonexistent", {});
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
      // The failed selection must not be written — a later command would silently act as that agent.
      expect(await readCurrentAgent(tempDir)).toBeUndefined();
    });

    it("an explicit --agent overrides the persisted default", async () => {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await useAgent(tempDir, "alice", {});
      expect(await readCurrentAgent(tempDir)).toBe("alice");

      // Explicit wins for THIS invocation, and does not rewrite the persisted default.
      const box = await inbox(tempDir, { agent: "bob" });
      const body = JSON.parse(box.exitCode === 0 ? box.stdout : box.stderr);
      expect(typeof body.ok).toBe("boolean");
      expect(await readCurrentAgent(tempDir)).toBe("alice");
    });

    it("a selected agent the daemon can no longer resolve fails LOUD — never silently falls back", async () => {
      // The silent-fallback trap: if the replayed cello_use_agent fails and we shrug and continue,
      // the daemon's sole-online fallback could quietly run the command as a DIFFERENT agent.
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await inbox(tempDir, { agent: "ghost" }); // explicit, unknown
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
      expect(JSON.parse(out.stderr).ok).toBe(false);
    });
  });

  // ─── Group A: data surfaces ──────────────────────────────────────────────────────────────

  describe("Group A — transcript / inbox / contact", () => {
    it("`cello inbox --scope all` reaches cello_check_notifications with scope=all", async () => {
      await createAgent(tempDir, "alice");
      const out = await inbox(tempDir, { scope: "all" });
      expect(out.exitCode).toBe(0);
      const parsed = JSON.parse(out.stdout);
      expect(parsed.ok).toBe(true);
    });

    it("`cello transcript <session-id>` reports the daemon's verdict faithfully — whatever it is", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await transcript(tempDir, "deadbeef", {});
      // NOTE (observed, not assumed): the daemon answers an UNKNOWN session id with a successful,
      // EMPTY transcript rather than an error. That is the daemon's call, and the CLI's job is to
      // relay it — not to invent an error the daemon did not give, nor to hide one it did. So this
      // asserts faithful relaying + correct routing, and stays true if the daemon later tightens.
      const body = JSON.parse(out.exitCode === 0 ? out.stdout : out.stderr);
      expect(out.exitCode).toBe(body.ok === false ? 1 : 0);
      if (body.ok === false) expect(out.stdout).toBe(""); // an error never lands on stdout
      else expect(out.stderr).toBe("");
    });

    it("`cello contact set-moniker` reaches cello_contact_set_moniker (the per-CONTACT pet name)", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await contactSetMoniker(tempDir, "ab".repeat(32), "Sup", {});
      const body = JSON.parse(out.exitCode === 0 ? out.stdout : out.stderr);
      expect(typeof body.ok).toBe("boolean");
      expect(out.exitCode).toBe(body.ok ? 0 : 1);
    });
  });

  // ─── Group B: live conversation ──────────────────────────────────────────────────────────

  describe("Group B — session commands mirror the MCP tools exactly", () => {
    it("`cello send` honors read-before-write: the cursor error is surfaced VERBATIM, never auto-fixed", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await send(tempDir, "deadbeef", "hello", {});
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe(""); // a failed send NEVER looks like a delivered one (DOD-SENDRAW-1)
      const err = JSON.parse(out.stderr);
      expect(err.ok).toBe(false);
      // Every field the daemon sent survives — including a cursor, if this were session_not_current.
      expect(Object.keys(err)).toContain("reason");
    });

    it("`cello receive --since-seq N` passes since_seq through (catch-up mode, not a live wait)", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      // since_seq must reach the daemon: in catch-up mode the call returns promptly rather than
      // blocking for the timeout. An unknown session still errors — that is fine; what we assert is
      // that it did NOT hang, i.e. the param was honored rather than dropped.
      const started = Date.now();
      const out = await receive(tempDir, "deadbeef", { sinceSeq: 0, timeoutMs: 30_000 });
      expect(Date.now() - started).toBeLessThan(5_000);
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
    });

    it("`cello receive` honors --timeout-ms (mirrors the MCP timeout semantics)", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await receive(tempDir, "deadbeef", { timeoutMs: 500 });
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
    });

    it("`cello await-session --timeout-ms N` blocks then reports — no fabricated session", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const started = Date.now();
      const out = await awaitSession(tempDir, { timeoutMs: 600 });
      // It must actually WAIT (not return instantly claiming nothing), and must not invent a session.
      expect(Date.now() - started).toBeGreaterThanOrEqual(400);
      // The daemon's await_session is payload-only: { type: "timeout" } on expiry (no `ok`). Mirror
      // it EXACTLY, as the brief requires — a bash caller branches on `.type`, and a timeout is a
      // normal return, not an error. What must never happen is a fabricated session_request.
      expect(out.stderr).toBe("");
      expect(out.exitCode).toBe(0);
      expect(JSON.parse(out.stdout).type).toBe("timeout");
    });

    it("`cello initiate-session <target>` reaches cello_initiate_session with target_pubkey", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await initiate(tempDir, "ab".repeat(32), {});
      const body = JSON.parse(out.exitCode === 0 ? out.stdout : out.stderr);
      expect(typeof body.ok).toBe("boolean");
      expect(out.exitCode).toBe(body.ok ? 0 : 1);
      if (!body.ok) expect(out.stdout).toBe("");
    });

    it("`cello close` and `cello receive-session` reach their handlers and report verdicts", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const closed = await closeSession(tempDir, "deadbeef", {});
      expect(closed.exitCode).toBe(1);
      expect(closed.stdout).toBe("");

      const joined = await receiveSession(tempDir, "deadbeef", { timeoutMs: 500 });
      const body = JSON.parse(joined.exitCode === 0 ? joined.stdout : joined.stderr);
      expect(typeof body.ok).toBe("boolean");
    });
  });

  // ─── Unit-review fixes (F1, F2, F4, T1) ──────────────────────────────────────────────────

  describe("review fixes: the replay must not lie, misroute, or resurrect", () => {
    it("F1: `stop-agent` CLEARS the selection — a read-only command can never silently re-online it", async () => {
      // The defect: every agent-scoped command replays cello_use_agent, which AUTO-STARTS an offline
      // agent. So `stop-agent alice` followed by `cello inbox` brought alice back online — reachable
      // again — with no signal. Stopping an agent is kill-switch-adjacent; reading must never re-arm it.
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      expect(await readCurrentAgent(tempDir)).toBe("alice");

      await stopAgent(tempDir, "alice", {});
      expect(await readCurrentAgent(tempDir)).toBeUndefined(); // the durable mirror follows the daemon
    });

    it("F1: an OFFLINE selected agent fails LOUD rather than being auto-started by a read", async () => {
      await createAgent(tempDir, "alice");
      // Persist a selection, then take the agent offline WITHOUT going through stopAgent (so the
      // selection file survives — the exact state a crash or a direct MCP stop would leave).
      await useAgent(tempDir, "alice", {});
      // Take alice offline via the daemon's OWN handler, leaving the persisted selection in place —
      // exactly the state an MCP-side stop, or a crash, would leave behind.
      const { connectToDaemon, readLock } = await import("@cello-protocol/daemon");
      const lock = await readLock(join(tempDir, "daemon.lock"));
      const c = await connectToDaemon(lock!.socketPath);
      await c.send("ipc.connect", { clientType: "test" });
      await c.send("cello_stop_agent", { name: "alice" });
      c.close();
      expect(await readCurrentAgent(tempDir)).toBe("alice"); // selection still there, agent offline

      const out = await inbox(tempDir, {});
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe(""); // never a fabricated result
      const err = JSON.parse(out.stderr);
      expect(err.reason).toBe("selected_agent_offline");
      expect(String(err.guidance)).toContain("start-agent");
    });

    it("F2: an EMPTY --agent fails loud — it never runs as a different agent", async () => {
      // `cello send $SID msg --agent "$VAR"` with VAR unset yields --agent "". Before the fix this
      // suppressed the persisted selection AND skipped the replay, so the daemon's sole-online
      // fallback ran the command as whatever agent happened to be up — exit 0, wrong identity.
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});

      const out = await inbox(tempDir, { agent: "" });
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
      expect(JSON.parse(out.stderr).reason).toBe("missing_agent_value");
    });

    it("F4: an UNREADABLE selection file throws — it does not read as 'never selected'", async () => {
      // A blanket catch would swallow EISDIR/EACCES and let the sole-online fallback run the command
      // as a different agent. Only ENOENT ('never selected') is a non-error.
      const dir = await mkdtemp(join(tmpdir(), "cello-parity-badfile-"));
      try {
        await mkdir(join(dir, "current-agent")); // a DIRECTORY where the file should be → EISDIR
        await expect(readCurrentAgent(dir)).rejects.toThrow();
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("T1: `sealed-receipt` reaches cello_get_sealed_receipt — NOT cello_get_relay_receipts", async () => {
      // The command exists precisely because those two were confused. It had zero behavioral
      // coverage: swapping it to the relay-receipts handler would have kept every test green.
      // A bogus session id must produce the SEAL handler's own distinctive verdict.
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const out = await sealedReceipt(tempDir, "deadbeef", {});
      const body = JSON.parse(out.exitCode === 0 ? out.stdout : out.stderr);
      expect(body.ok).toBe(false);
      // cello_get_relay_receipts answers { ok:true, receipts:[] } for any agent — it would never say
      // this. These reasons belong to the sealed-receipt handler alone.
      expect(["session_not_found", "not_sealed", "session_id_too_short", "unknown_session", "not_sealed_yet"])
        .toContain(body.reason);
      expect(body.receipts).toBeUndefined(); // definitively not the relay-receipts shape
    });
  });

  // ─── The transport contract ──────────────────────────────────────────────────────────────

  describe("§3 contract at the transport edge", () => {
    it("with NO daemon running, every command still emits structured JSON on stderr and exits non-zero", async () => {
      await handle!.stop("test_no_daemon");
      handle = null;
      const out = await listAgents(tempDir, {});
      expect(out.exitCode).not.toBe(0);
      expect(out.stdout).toBe(""); // never a fake empty-but-successful result
      const err = JSON.parse(out.stderr); // still machine-parseable — a bash agent branches on it
      expect(err.ok).toBe(false);
      expect(typeof err.reason).toBe("string");
    });

    it("--pretty indents without changing the stream or the exit code", async () => {
      await createAgent(tempDir, "alice");
      const out = await listAgents(tempDir, { pretty: true });
      expect(out.exitCode).toBe(0);
      expect(out.stdout).toContain("\n  ");
      expect(JSON.parse(out.stdout).agents).toBeDefined();
    });
  });
});

/** The persisted-selection file is a plain, inspectable artifact — not hidden state. */
describe("current-agent persistence is a plain file", () => {
  it("readCurrentAgent returns undefined when nothing was ever selected", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-parity-empty-"));
    try {
      expect(await readCurrentAgent(dir)).toBeUndefined();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("the selection is stored as readable text a human can inspect and delete", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-parity-file-"));
    try {
      const handle2 = await startDaemon({
        celloDir: dir,
        socketPath: join(dir, "daemon.sock"),
        lockFilePath: join(dir, "daemon.lock"),
        maxConnections: 16,
        version: "0.0.1-test",
        logger: noopLogger,
      });
      try {
        await createAgent(dir, "alice");
        await useAgent(dir, "alice", {});
        const raw = await readFile(join(dir, "current-agent"), "utf8");
        expect(raw.trim()).toBe("alice");
      } finally {
        await handle2.stop("test_cleanup");
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
