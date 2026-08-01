/**
 * DOD-RECEPTIONIST-AGENT-1 (M8D) — the receptionist stops re-pointing other terminals.
 *
 * `~/.cello/current-agent` is ONE machine-wide file that every `cello` process in every terminal
 * shares. The receptionist subagent ran `cello use-agent "$AGENT_NAME"` and then polled
 * `cello inbox --scope current` every 10 seconds, each poll a fresh process re-reading that global
 * file. **Two receptionists staffing two desks fight over it** — whichever ran `use-agent` last owns
 * it, and both then report on that one agent. Their own guard comment named the symptom
 * (*"announcing another agent's callers as if they were this one's"*) and guarded the wrong cause:
 * it caught an empty name at STARTUP, never a concurrent overwrite MID-LOOP.
 *
 * THE SUBJECT UNDER TEST IS A MARKDOWN FILE, AND THAT IS THE POINT. `cello-receptionist.md` is not
 * code, but it ships in the plugin, lands on the operator's disk, and instructs an agent — so it is
 * shipped behavior and gets reviewed like code (M8D-PROCEDURE §5b, "audit what SHIPS, not what
 * compiles"). R1/R4b read the file the operator actually receives; R2/R3/R4a prove the mechanism it
 * now relies on really has the property the fix assumes.
 *
 * Clause coverage:
 * - R1 (AC1, what ships): the shipped script passes `--agent "$AGENT_NAME"` and no longer invokes
 *   `cello use-agent` — it writes nothing shared.
 * - R2 (AC4, the defect itself): two desks polled concurrently, each reports ONLY its own agent's
 *   callers. This is the assertion that fails on the old script's mechanism.
 * - R3 (AC1/AC3): `--agent` leaves `~/.cello/current-agent` untouched — it neither creates it nor
 *   overwrites an existing selection. That absence is the whole fix; without it R2 is luck.
 * - R4 (error fidelity): an offline desk fails LOUD naming the agent and the remedy (a), and the
 *   shipped script surfaces that cause rather than substituting "empty output" for it (b).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startDaemon, type DaemonHandle, type DaemonConfig, type Logger } from "@cello-protocol/daemon";
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import { inbox, useAgent, startAgent, readCurrentAgent } from "../parity-commands.js";
import { createAgent } from "../commands.js";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** The file as the OPERATOR receives it, through the plugin. */
const RECEPTIONIST_MD = join(
  import.meta.dirname, "..", "..", "..", "..",
  "plugins", "cello", "agents", "cello-receptionist.md",
);

describe("DOD-RECEPTIONIST-AGENT-1: two desks, two receptionists, no shared file", () => {
  describe("R1/R4b — the shipped subagent script", () => {
    let script: string;
    /** The bash the agent RUNS, with comment lines removed. */
    let code: string;

    beforeEach(async () => {
      script = await readFile(RECEPTIONIST_MD, "utf8");
      const block = /```bash\n([\s\S]*?)```/.exec(script);
      expect(block, "the subagent must still ship exactly one bash block").not.toBeNull();
      // Assert on what EXECUTES, not on prose. The banned command is named in a comment that
      // explains why it is banned, and that explanation is load-bearing — the next person to edit
      // this file needs to know that `use-agent` writes a machine-wide file. A regex over the whole
      // document would force deleting the reason in order to satisfy the rule about the cause.
      code = block![1].split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    });

    it("R1 (AC1): polls with --agent, and no longer RUNS `cello use-agent` at all", async () => {
      // The desk is named on THIS process's own connection...
      expect(code).toMatch(/cello inbox --agent "\$AGENT_NAME" --scope current/);
      // ...and nothing writes the machine-wide file. `cello use-agent` is its ONLY writer, so its
      // absence here is exactly "stops writing the shared file". Revert the fix and this goes red.
      expect(code).not.toMatch(/cello use-agent/);
      // ...and the reason it is gone stays written down, where the next editor will see it.
      expect(script).toMatch(/DO NOT run `cello use-agent`/);
    });

    it("R4b (error fidelity): a failed poll reports the daemon's CAUSE, not 'empty output'", async () => {
      // The old script ran `cello inbox --scope current 2>/dev/null` and, on empty stdout, reported
      // "cello inbox returned empty output". `cello` reports a refusal as structured JSON on
      // STDERR, so that discarded the one line naming the real reason and replaced it with a
      // symptom — ERROR SUBSTITUTION, which sends a competent operator to the wrong subsystem.
      expect(code).not.toMatch(/cello inbox[^\n]*2>\/dev\/null/);
      expect(code).toMatch(/ERR_LOG/);
      // The captured stderr must actually be surfaced, not merely captured.
      expect(code).toMatch(/cat "\$ERR_LOG"/);
    });

    it("R1 (AC3): the empty-name guard survives — an unsubstituted name still fails loud", async () => {
      // Dropping `use-agent` must not drop the guard with it. Without it the loop polls with
      // --agent "", which the CLI refuses (missing_agent_value) once every 10 seconds forever
      // instead of once, and never names the invocation as the problem.
      expect(code).toMatch(/\[ -z "\$AGENT_NAME" \]/);
      expect(code).toMatch(/\[ "\$AGENT_NAME" = "\[agent_name\]" \]/);
    });
  });

  describe("R2/R3/R4a — the mechanism the fix relies on, against a REAL daemon", () => {
    let tempDir: string;
    let handle: DaemonHandle | null;

    beforeEach(async () => {
      tempDir = await mkdtemp(join(tmpdir(), "cello-m8d-reception-"));
      handle = await startDaemon({
        securityGateway: new PassthroughGatewayClient(),
        celloDir: tempDir,
        socketPath: join(tempDir, "daemon.sock"),
        lockFilePath: join(tempDir, "daemon.lock"),
        maxConnections: 16,
        version: "0.0.1-test",
        logger: noopLogger,
      } as DaemonConfig);
    });

    afterEach(async () => {
      if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
      await rm(tempDir, { recursive: true, force: true });
    });

    async function twoOnlineDesks(): Promise<void> {
      await createAgent(tempDir, "alice");
      await createAgent(tempDir, "bob");
      await startAgent(tempDir, "alice", {});
      await startAgent(tempDir, "bob", {});
    }

    it("R2 (AC4): two desks polled CONCURRENTLY — each reports only its own agent", async () => {
      await twoOnlineDesks();

      // The receptionist's loop shape: repeated, interleaved, agent-scoped polls from independent
      // processes. Under the old mechanism both polls read one shared file, so both would answer
      // for whichever desk wrote it last. Run them interleaved rather than in sequence — a
      // sequential run cannot observe the overwrite this line exists to prevent.
      const rounds = await Promise.all([
        inbox(tempDir, { agent: "alice", scope: "current" }),
        inbox(tempDir, { agent: "bob", scope: "current" }),
        inbox(tempDir, { agent: "alice", scope: "current" }),
        inbox(tempDir, { agent: "bob", scope: "current" }),
      ]);

      const desks = ["alice", "bob", "alice", "bob"];
      rounds.forEach((out, i) => {
        expect(out.exitCode, `poll ${i} (${desks[i]}) failed: ${out.stderr}`).toBe(0);
        const names = (JSON.parse(out.stdout).agents as Array<{ agent: string }>).map((a) => a.agent);
        // `--scope current` answers for exactly the desk this poll named — and for no other.
        expect(names).toEqual([desks[i]]);
      });
    });

    it("R3 (AC1/AC3): an --agent poll never CREATES the machine-wide selection file", async () => {
      await twoOnlineDesks();

      await inbox(tempDir, { agent: "alice", scope: "current" });
      await inbox(tempDir, { agent: "bob", scope: "current" });

      // Nothing selected the desk globally, so nothing was written. This absence IS the fix: it is
      // why a second receptionist in another terminal cannot be re-pointed by this one.
      await expect(access(join(tempDir, "current-agent"))).rejects.toThrow();
      expect(await readCurrentAgent(tempDir)).toBeUndefined();
    });

    it("R3 (AC3): an --agent poll does not OVERWRITE an operator's existing selection either", async () => {
      await twoOnlineDesks();

      // The operator, in their own terminal, has chosen alice. The file stays a PREFERENCE — "the
      // last agent you chose" — and a receptionist staffing bob must not silently reassign it.
      const selected = await useAgent(tempDir, "alice", {});
      expect(selected.exitCode, selected.stderr).toBe(0);
      expect(await readCurrentAgent(tempDir)).toBe("alice");

      await inbox(tempDir, { agent: "bob", scope: "current" });
      await inbox(tempDir, { agent: "bob", scope: "current" });

      expect(await readCurrentAgent(tempDir)).toBe("alice");
    });

    it("R4a (error fidelity): an OFFLINE desk fails loud, naming the agent and the remedy", async () => {
      await createAgent(tempDir, "alice"); // created, never started — the desk is not online

      const out = await inbox(tempDir, { agent: "alice", scope: "current" });
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe(""); // a failure never lands on stdout and never reads as an empty inbox
      const err = JSON.parse(out.stderr);
      // Deliberate (spec §9 item 3): the replay refuses rather than auto-starting an offline agent,
      // because a read must never re-arm something the operator deliberately stopped. For a
      // receptionist that is the correct behavior — do not "fix" it.
      expect(err.reason).toBe("selected_agent_offline");
      expect(String(err.guidance)).toMatch(/alice/);
      expect(String(err.guidance)).toMatch(/start-agent/);
    });

    it("R4a: a poll for an UNKNOWN desk does not silently answer as somebody else", async () => {
      await twoOnlineDesks();

      const out = await inbox(tempDir, { agent: "carol", scope: "current" });
      expect(out.exitCode).toBe(1);
      expect(out.stdout).toBe("");
      // The hazard is not the error — it is answering with alice's or bob's inbox under carol's name.
      expect(out.stderr).not.toMatch(/alice|bob/);
    });
  });
});
