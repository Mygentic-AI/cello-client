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
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import {
  IPC_METHODS,
  listAgents,
  startAgent,
  setAgentOffline,
  stopUsingAgent,
  useAgent,
  inbox,
  listSessions,
  transcript,
  contactSetMoniker,
  initiate,
  send,
  receive,
  closeSession,
  awaitSession,
  sealedReceipt,
  readCurrentAgent,
  settingsGet,
  settingsSet,
  monikerSet,
} from "../parity-commands.js";
import { createAgent } from "../commands.js";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("DOD-CLI-PARITY-1: Group A + Group B against a REAL daemon", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;

  function makeConfig(): DaemonConfig {
    return {
      securityGateway: new PassthroughGatewayClient(),
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

    it("`cello start-agent` / `set-agent-offline` reach the daemon handler and report its verdict", async () => {
      await createAgent(tempDir, "alice");
      const started = await startAgent(tempDir, "alice", {});
      // An unregistered agent may legitimately refuse to start — what must hold is that the CLI
      // reports the DAEMON's verdict, never a fabricated one, and routes it by ok.
      const startBody = JSON.parse(started.exitCode === 0 ? started.stdout : started.stderr);
      expect(typeof startBody.ok).toBe("boolean");
      expect(started.exitCode).toBe(startBody.ok ? 0 : 1);
      if (!startBody.ok) expect(started.stdout).toBe(""); // failure never lands on stdout

      const stopped = await setAgentOffline(tempDir, "alice", {});
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

    it("`cello close-session` reaches its handler and reports the verdict", async () => {
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      const closed = await closeSession(tempDir, "deadbeef", {});
      expect(closed.exitCode).toBe(1);
      expect(closed.stdout).toBe("");
    });
  });

  // ─── Unit-review fixes (F1, F2, F4, T1) ──────────────────────────────────────────────────

  describe("review fixes: the replay must not lie, misroute, or resurrect", () => {
    it("F1: `set-agent-offline` CLEARS the selection — a read-only command can never silently re-online it", async () => {
      // The defect: every agent-scoped command replays cello_use_agent, which AUTO-STARTS an offline
      // agent. So taking alice offline, then `cello inbox`, brought her back online — reachable
      // again — with no signal. Stopping an agent is kill-switch-adjacent; reading must never re-arm it.
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      expect(await readCurrentAgent(tempDir)).toBe("alice");

      await setAgentOffline(tempDir, "alice", {});
      expect(await readCurrentAgent(tempDir)).toBeUndefined(); // the durable mirror follows the daemon
    });

    // ─── DOD-RELEASE-1: `cello stop-using-agent` must report ITS OWN effect ───

    it("stop-using-agent forgets the persisted selection and NAMES the agent it forgot", async () => {
      // The version this replaces passed the daemon's reply straight through. Attendance is
      // per-connection and every CLI invocation is a fresh ephemeral connection starting with
      // currentAgent: null, so the handler ALWAYS took its idempotent branch: the operator saw
      // "This connection was not attending any agent. Nothing to release." exit 0 — while the
      // persisted selection was in fact deleted. A success message for the opposite of what
      // happened, which is the same class of defect as the name that started all of this.
      await createAgent(tempDir, "alice");
      await useAgent(tempDir, "alice", {});
      expect(await readCurrentAgent(tempDir)).toBe("alice");

      const out = await stopUsingAgent(tempDir, {});
      expect(out.exitCode).toBe(0);
      const body = JSON.parse(out.stdout) as { ok: boolean; cleared: string | null; guidance: string };
      expect(body.ok).toBe(true);
      expect(body.cleared).toBe("alice");
      expect(await readCurrentAgent(tempDir)).toBeUndefined();

      // It must NOT claim the away-message effect it cannot deliver from here: a live MCP session
      // attending this agent keeps attending it, and its away message stays suppressed.
      expect(body.guidance).toContain("NOT released");
    });

    it("stop-using-agent says nothing was persisted rather than inventing a release", async () => {
      const out = await stopUsingAgent(tempDir, {});
      expect(out.exitCode).toBe(0);
      const body = JSON.parse(out.stdout) as { ok: boolean; cleared: string | null };
      expect(body.ok).toBe(true);
      expect(body.cleared).toBeNull();
    });

    it("F1: an OFFLINE selected agent fails LOUD rather than being auto-started by a read", async () => {
      await createAgent(tempDir, "alice");
      // Persist a selection, then take the agent offline WITHOUT going through setAgentOffline (so the
      // selection file survives — the exact state a crash or a direct MCP stop would leave).
      await useAgent(tempDir, "alice", {});
      // Take alice offline via the daemon's OWN handler, leaving the persisted selection in place —
      // exactly the state an MCP-side stop, or a crash, would leave behind.
      const { connectToDaemon, readLock } = await import("@cello-protocol/daemon");
      const lock = await readLock(join(tempDir, "daemon.lock"));
      const c = await connectToDaemon(lock!.socketPath);
      await c.send("ipc.connect", { clientType: "test" });
      await c.send("cello_set_agent_offline", { name: "alice" });
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
  // ─── §1.3: ONE operator gesture, ONE agent-resolution rule ────────────────────────────────
  //
  // `cello use-agent alice` persists a selection. Every agent-scoped command must REPLAY it, because
  // the CLI opens a fresh connection per invocation and the daemon's per-connection current-agent is
  // gone the moment the socket closes.
  //
  // `cello contacts` replayed it. `cello settings set` and `cello moniker set` did NOT — they went
  // through a second, hand-rolled connection path that skipped the replay and fell through to the
  // daemon's sole-online-agent fallback. Same gesture, two rules. On a MULTI-AGENT machine that
  // fallback is ambiguous, so the command the operator explicitly scoped fails (or, with exactly one
  // agent online, silently runs as whoever happened to be up — which is worse).
  //
  // DOD-CLI-SESSIONS-SCOPE-1 — `cello sessions` answered for EVERY agent while `cello_sessions`
  // answered for one, so the two surfaces disagreed about what was open for the same selection. It
  // called the daemon-wide `list_sessions`, whose comment justified itself with "the CLI has no
  // current agent" — true when written, false since `use-agent` became durable.
  //
  // The discriminator below needs no sessions to exist. Two agents online means the daemon's
  // sole-online fallback cannot resolve, so a SCOPED call must answer no_current_agent without a
  // selection and succeed with one. The old daemon-wide handler ignored the agent entirely and would
  // have returned rows in both cases — it cannot pass either half.
  describe("§1.4 — `cello sessions` is scoped to the selected agent (not daemon-wide)", () => {
    it("refuses without a selection when several agents are online, and succeeds with one", async () => {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await startAgent(tempDir, "alice", {});
      await startAgent(tempDir, "bob", {});

      const unscoped = await listSessions(tempDir, {});
      expect(unscoped.exitCode, "an agent-scoped listing must not answer with no agent selected").toBe(1);
      expect(unscoped.stdout).toBe("");
      // The CLI refuses BEFORE dispatching (no_agent_selected, naming the candidates) rather than
      // letting the daemon answer no_current_agent — either is a refusal; assert the refusal, not
      // which layer produced it.
      expect(unscoped.stderr).toMatch(/no_agent_selected|no_current_agent/);

      await useAgent(tempDir, "alice", {});
      const scoped = await listSessions(tempDir, {});
      expect(scoped.exitCode, `sessions must honor use-agent, got: ${scoped.stderr}`).toBe(0);
      expect(JSON.parse(scoped.stdout).ok).toBe(true);
    });

    // The two tests here prove the PARITY PATH is used (agent replay, refusal without a selection).
    // They cannot prove the METHOD is the scoped one: with no sessions in the temp daemon, the
    // daemon-wide handler answers ok too, so pointing this back at `list_sessions` passes both. That
    // is exactly the regression to guard, so the wire name is asserted directly. Verified by
    // mutation: flipping the constant fails this and only this.
    it("dispatches to the AGENT-SCOPED daemon handler, not the daemon-wide one", () => {
      expect(IPC_METHODS.sessions).toBe("cello_list_sessions");
    });

    it("honors an explicit --agent, like every other agent-scoped command", async () => {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await startAgent(tempDir, "alice", {});
      await startAgent(tempDir, "bob", {});

      const out = await listSessions(tempDir, { agent: "bob" });
      expect(out.exitCode, `--agent must resolve without a persisted selection, got: ${out.stderr}`).toBe(0);
      expect(JSON.parse(out.stdout).ok).toBe(true);
    });
  });

  // These commands are agent-scoped and MUST resolve the agent the same way as every other one.
  describe("§1.3 — settings/moniker honor `use-agent` like every other agent-scoped command", () => {
    it("`cello settings set` applies to the SELECTED agent when several are online", async () => {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await startAgent(tempDir, "alice", {});
      await startAgent(tempDir, "bob", {});
      await useAgent(tempDir, "alice", {});

      // Two agents online → the daemon's sole-online fallback CANNOT resolve this. Only a replayed
      // selection can. If the command skips the replay, the daemon answers no_current_agent.
      const set = await settingsSet(tempDir, "away.default", "at lunch", {});
      expect(set.exitCode, `settings set must honor use-agent, got: ${set.stderr}`).toBe(0);
      expect(JSON.parse(set.stdout).ok).toBe(true);

      // ...and it landed on ALICE, not bob.
      const got = await settingsGet(tempDir, "away.default", { agent: "alice" });
      expect(JSON.parse(got.stdout).ok).toBe(true);
      const bobs = await settingsGet(tempDir, "away.default", { agent: "bob" });
      expect(JSON.parse(bobs.stdout)).not.toMatchObject({ value: "at lunch" });
    });

    it("`cello moniker set` applies to the SELECTED agent when several are online", async () => {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await startAgent(tempDir, "alice", {});
      await startAgent(tempDir, "bob", {});
      await useAgent(tempDir, "alice", {});

      const out = await monikerSet(tempDir, "ali", {});
      expect(out.exitCode, `moniker set must honor use-agent, got: ${out.stderr}`).toBe(0);
      expect(JSON.parse(out.stdout).ok).toBe(true);
    });

    // Found while fixing the above, and it is the more dangerous half.
    //
    // `cello set-agent-offline <selected>` CLEARS the persisted selection (parity-commands setAgentOffline) — on
    // its own, reasonable. But the daemon's fallback for "no selection" is "the sole ONLINE agent",
    // and it only refuses when TWO OR MORE are online. So with several agents registered and exactly
    // one up, the next command silently runs as that one.
    //
    // Observed before the fix, verbatim:
    //   use-agent alice → set-agent-offline alice → `cello settings set away.default …`
    //   → {"ok":true,"agent":"bob", …}, exit 0.
    // The operator selected alice; the write landed on BOB and reported success.
    it("no selection + several agents registered → REFUSE, never silently target whoever is online", async () => {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await startAgent(tempDir, "bob", {});
      await useAgent(tempDir, "alice", {});   // use-agent AUTO-STARTS alice (AUTOSTART-1)...
      await setAgentOffline(tempDir, "alice", {});  // ...so stop her. This also clears the selection.

      const out = await settingsSet(tempDir, "away.default", "must not land on bob", {});
      expect(out.exitCode, "a write with no selection must not silently pick an agent").toBe(1);
      expect(out.stdout).toBe("");
      const err = JSON.parse(out.stderr);
      expect(err.ok).toBe(false);
      expect(err.reason).toBe("no_agent_selected");

      // The proof it is not merely a different error: bob must be UNTOUCHED.
      const bobs = await settingsGet(tempDir, "away.default", { agent: "bob" });
      expect(bobs.stdout).not.toContain("must not land on bob");
    });

    // ...but the fallback must SURVIVE for the case it exists to serve: one agent, never selected.
    it("no selection + exactly ONE agent registered → still works (the fallback is unambiguous there)", async () => {
      await createAgent(tempDir, "solo");
      await startAgent(tempDir, "solo", {});
      // No use-agent, ever. A fresh operator with one agent must not be forced to select it.
      const out = await settingsSet(tempDir, "away.default", "fine", {});
      expect(out.exitCode, `the single-agent fallback must not regress: ${out.stderr}`).toBe(0);
      expect(JSON.parse(out.stdout).ok).toBe(true);
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
    securityGateway: new PassthroughGatewayClient(),
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
