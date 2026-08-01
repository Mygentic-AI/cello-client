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
 * compiles"). The R1* clauses read the file the operator actually receives; R2/R3/R4a drive a real
 * daemon.
 *
 * WHICH CLAUSES ARE COVERAGE, AND WHICH ARE NOT — stated exactly, because the first version of this
 * file got it wrong and called a mechanism pin "the defect itself". Measured by reverting the
 * shipped script alone:
 *
 *   RED on revert (coverage of THIS diff): R1d, R1e, R1f, R1g, R1h — the five silent-death paths.
 *   GREEN either way: everything else. R1/R1c/R4b were fixed in the previous commit of this unit
 *     and cover that one. R2a/R2b/R2c/R3/R4a never read the shipped file at all — they test the
 *     CLI MECHANISM, and they were green before any of this work.
 *
 * That is not a weakness, but it must be named. The chain is: R2a proves the defect is real (the
 * shared file really does re-point another terminal's poll), R2b proves `--agent` is the remedy,
 * and R1/R1c prove the SHIPPED SCRIPT actually uses that remedy — including that the argv it types
 * parses. No single clause spans all three, so none of them may claim to.
 *
 * Clause coverage:
 * - R1  (AC1, what ships): the script passes `--agent "$AGENT_NAME"` and no longer RUNS
 *   `cello use-agent` — so it writes nothing shared.
 * - R1c (AC1): the argv the script literally types parses against the real CLI registry — the one
 *   hop that turns markdown into behavior, and the one nothing else covers.
 * - R1d/R1e/R1f/R1g: the three silent-death paths a review found in the shipped bash (exit code
 *   ignored in favour of empty stdout; `jq` failures swallowed; `sealed_unread` invisible to the
 *   poll) plus an unguarded `mktemp`. Each ended the same way — a receptionist that says it is
 *   monitoring, announces nobody, and prints nothing on any stream.
 * - R1h: the lost `use-agent` auto-start is written down, so the refusal does not read as a bug.
 * - R2a (AC4, THE DEFECT REPRODUCED): the OLD mechanism really does hand receptionist A the wrong
 *   desk's callers after B staffs its own. Deterministic, no race.
 * - R2b (AC4, THE FIX): the same overwrite, and an `--agent` poll is immune to it.
 * - R2c (AC4): four interleaved concurrent polls, each answering only its own desk.
 * - R3  (AC1/AC3) [control]: `--agent` leaves `~/.cello/current-agent` untouched — neither created
 *   nor overwritten. That absence is what makes R2b hold rather than be luck.
 * - R4a (AC2) [control]: an offline or unknown desk fails LOUD instead of answering as someone else.
 * - R4b (error fidelity): the script surfaces the daemon's cause instead of "empty output".
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startDaemon, type DaemonHandle, type DaemonConfig, type Logger } from "@cello-protocol/daemon";
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import { inbox, useAgent, startAgent, readCurrentAgent } from "../parity-commands.js";
import { checkArgs } from "../cli-args.js";
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
      // Assert the "exactly one" the extraction below ASSUMES. A regex that takes the first block
      // would let a second one ship unexamined — the one way a `cello use-agent` could hide from
      // every assertion in this describe (review MEDIUM: the old message claimed this property
      // while checking only that a block existed).
      expect(script.match(/```bash/g) ?? [], "the subagent ships exactly one bash block").toHaveLength(1);
      const block = /```bash\n([\s\S]*?)```/.exec(script);
      expect(block).not.toBeNull();
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

    it("R1c (AC1, the missing hop): the argv the script actually types PARSES against the real CLI", async () => {
      // R1 asserts a string is present in a markdown file; R2 calls the exported function with an
      // options OBJECT. Nothing connected the two, so if `--agent` were ever unregistered on
      // `inbox` the shipped script would die with "Unknown flag" while both stayed green — and
      // per HIGH-1 that death prints USAGE to stdout and the loop sleeps forever. This is the one
      // hop that turns markdown into behavior, so it gets an assertion.
      const invocation = /cello inbox ([^\n]*?)\s*2>/.exec(code);
      expect(invocation, "the poll must still shell out to `cello inbox`").not.toBeNull();
      const argv = invocation![1].replace(/"\$AGENT_NAME"/, "alice").split(/\s+/);
      expect(argv).toEqual(["--agent", "alice", "--scope", "current"]);
      expect(checkArgs("inbox", argv)).toEqual({ kind: "ok" });
    });

    it("R1d (HIGH-1): the poll branches on the EXIT CODE, not on empty stdout", async () => {
      // Empty stdout is only a PROXY for failure. `bin/cello.ts` prints help/USAGE to STDOUT and
      // exits 1 on an unknown flag or command, which sails past an `-z` check, fails the jq parse,
      // and leaves the loop sleeping forever with nothing on any stream.
      expect(code).toMatch(/if ! RESULT=\$\(cello inbox/);
    });

    it("R1e (HIGH-2): jq is required up front, and an unreadable response is loud", async () => {
      // jq absent → "command not found" swallowed → PENDING empty → the numeric test errors →
      // swallowed → false → sleep → forever. An answering service that never announces anyone.
      expect(code).toMatch(/command -v jq/);
      expect(code).not.toMatch(/jq [^\n]*2>\/dev\/null/);
      expect(code).not.toMatch(/-gt 0 \] 2>\/dev\/null/);
      // ...and a non-numeric count refuses rather than reporting an all-clear nobody confirmed.
      expect(code).toMatch(/\*\[!0-9\]\*/);
    });

    it("R1f (HIGH-3): the poll wakes for a SEALED message too — the answering-machine case", async () => {
      // `total_unread` counts ACTIVE sessions only (getUnreadSummary excludes terminal statuses),
      // so a caller who leaves a message and seals contributes zero to it and zero pending
      // requests. Polling total_unread alone slept through them indefinitely — and the SKILL
      // handles sealed_unread explicitly, so the subagent replacing it could not see what the
      // skill could.
      expect(code).toMatch(/sealed_unread/);
      expect(code).toMatch(/expired_session_requests/);
    });

    it("R1g (MEDIUM): mktemp is guarded — the script never polls blind to its own errors", async () => {
      expect(code).toMatch(/ERR_LOG=\$\(mktemp\) \|\|/);
    });

    it("R1h: the lost auto-start is written down, not left to read as a regression", async () => {
      // `use-agent` auto-started an offline agent; this poll deliberately does not. That is a
      // lifecycle change, and the next reader must not mistake the refusal for a bug.
      expect(script).toMatch(/ALREADY BE ONLINE/);
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

    it("R2a (AC4, THE DEFECT REPRODUCED): the OLD mechanism really does re-point another terminal's poll", async () => {
      // Without this, nothing in the suite ever runs the shape that was broken, and R2b passes
      // just as happily against an implementation that never had the bug (review: R2 was labelled
      // "the defect itself" and was green before the fix).
      //
      // Deterministic on purpose — no race needed. The old receptionist ran `use-agent` and then
      // polled `--scope current`, and BETWEEN those two steps a second receptionist in another
      // terminal ran its own `use-agent`. The file is machine-wide, so the second one wins and the
      // first one's very next poll answers as the wrong desk.
      await twoOnlineDesks();

      await useAgent(tempDir, "alice", {}); // receptionist A staffs alice, the old way
      await useAgent(tempDir, "bob", {});   // receptionist B staffs bob — overwrites the shared file

      const aPoll = await inbox(tempDir, { scope: "current" }); // A's next poll, exactly as before
      expect(aPoll.exitCode, aPoll.stderr).toBe(0);
      const answered = (JSON.parse(aPoll.stdout).agents as Array<{ agent: string }>).map((a) => a.agent);
      // A asked for its own desk and was handed BOB's. This is "announcing another agent's callers
      // as if they were this one's", reproduced. The mechanism is unchanged and still does this —
      // the fix is that the receptionist no longer uses it.
      expect(answered).toEqual(["bob"]);
    });

    it("R2b (AC4, THE FIX): the same overwrite, and an --agent poll is immune to it", async () => {
      await twoOnlineDesks();

      await useAgent(tempDir, "alice", {});
      await useAgent(tempDir, "bob", {}); // the shared file now says bob, as in R2a

      // The shipped invocation. It names the desk on its own connection, so the file is irrelevant.
      const aPoll = await inbox(tempDir, { agent: "alice", scope: "current" });
      expect(aPoll.exitCode, aPoll.stderr).toBe(0);
      const answered = (JSON.parse(aPoll.stdout).agents as Array<{ agent: string }>).map((a) => a.agent);
      expect(answered).toEqual(["alice"]);
      // ...and the operator's own selection is still bob afterwards — the poll read it, not wrote it.
      expect(await readCurrentAgent(tempDir)).toBe("bob");
    });

    it("R2c (AC4): two desks polled CONCURRENTLY — each reports only its own agent", async () => {
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
