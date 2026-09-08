/**
 * Launch triage item 5 — installing the plugin must not strand a first-time user.
 *
 * The failure this pins, in the order a new user lives it:
 *
 *   1. They run `/plugin install cello@cello-protocol`. The plugin's .mcp.json points at
 *      `npx @cello-protocol/connect`, so the MCP SHIM arrives — and nothing else does.
 *   2. Claude Code starts the shim. There is no daemon and no `~/.cello/daemon.sock`.
 *   3. The shim writes its recovery message — and, until 2026-09-08, exited 1.
 *   4. Claude Code reports a server that exits as `CONNECTION_CLOSED: "Connection closed"`,
 *      which names neither CELLO, nor the daemon, nor a next step.
 *
 * ## What changed, and why these tests were rewritten
 *
 * The message was always good. EXITING was the defect: it made that message unreachable, so the
 * only thing a new operator ever saw was a generic transport error. This file used to REQUIRE the
 * exit — it asserted `code === 1` and its helper rejected if the process stayed up — so it was
 * pinning the defect in place and would have failed anyone who fixed it. Same shape as the two
 * tests in the waitlist email that required 404 links.
 *
 * The behaviour now, which the `setup` skill already documented before the binary did ("Without the
 * daemon every tool returns `daemon_not_running`"): the shim STARTS, serves its tools, and answers
 * every call with `daemon_not_running` plus the recovery — so the guidance reaches the model's
 * context, where it can be acted on, instead of a log nobody opens.
 *
 * These tests speak MCP to the real built binary over stdio, because "the tools are reachable" is
 * the whole property and it cannot be observed from stderr.
 */

import { describe, it, expect } from "vitest";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
// Cross-package on purpose: this is THE helper for "a real daemon in its own process", and the
// re-dial cannot be proven against an in-process stub — the shim connects over a unix socket that
// only a separate process can be holding.
import { spawnRealDaemon, type SpawnedDaemon } from "../../../daemon/src/__tests__/helpers/spawn-real-daemon.js";

const here = dirname(fileURLToPath(import.meta.url));
const BIN = resolve(here, "../../dist/bin/cello-mcp.js");

interface Shim {
  proc: ChildProcessWithoutNullStreams;
  /** Send one JSON-RPC request and wait for the response with that id. */
  rpc(method: string, params: Record<string, unknown>, id: number): Promise<Record<string, unknown>>;
  stderr(): string;
  stop(): void;
}

/** Start the built shim against a CELLO_DIR with NO daemon — the state right after a plugin install. */
function startWithNoDaemon(): { shim: Shim; celloDir: string; cleanup: () => void } {
  const celloDir = mkdtempSync(resolve(tmpdir(), "cello-stranded-"));
  const proc = spawn(process.execPath, [BIN], {
    env: { ...process.env, CELLO_DIR: celloDir },
    stdio: ["pipe", "pipe", "pipe"],
  }) as ChildProcessWithoutNullStreams;

  let stderrBuf = "";
  proc.stderr.on("data", (c: Buffer) => { stderrBuf += c.toString(); });

  let stdoutBuf = "";
  const waiters = new Map<number, (v: Record<string, unknown>) => void>();
  proc.stdout.on("data", (c: Buffer) => {
    stdoutBuf += c.toString();
    // MCP stdio framing is one JSON object per line.
    for (;;) {
      const nl = stdoutBuf.indexOf("\n");
      if (nl < 0) break;
      const line = stdoutBuf.slice(0, nl).trim();
      stdoutBuf = stdoutBuf.slice(nl + 1);
      if (!line) continue;
      try {
        const frame = JSON.parse(line) as Record<string, unknown>;
        const w = waiters.get(frame.id as number);
        if (w) { waiters.delete(frame.id as number); w(frame); }
      } catch { /* not a complete frame; the shim also tees diagnostics to stderr, not stdout */ }
    }
  });

  const shim: Shim = {
    proc,
    rpc(method, params, id) {
      return new Promise((res, rej) => {
        const timer = setTimeout(() => rej(new Error(`no MCP response to ${method} within 10s`)), 10_000);
        waiters.set(id, (frame) => { clearTimeout(timer); res(frame); });
        proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });
    },
    stderr: () => stderrBuf,
    stop: () => proc.kill("SIGKILL"),
  };

  return {
    shim,
    celloDir,
    cleanup: () => {
      proc.kill("SIGKILL");
      rmSync(celloDir, { recursive: true, force: true });
    },
  };
}

/** Drive the MCP handshake so the server will answer tool calls. */
async function handshake(shim: Shim): Promise<void> {
  await shim.rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "stranded-shim-test", version: "0" },
  }, 1);
  shim.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
}

describe("launch triage item 5 — a plugin install must not dead-end at a missing daemon", () => {
  it("THE FIX: the shim stays up and serves its tools with no daemon, instead of exiting", async () => {
    const { shim, cleanup } = startWithNoDaemon();
    try {
      await handshake(shim);
      const listed = await shim.rpc("tools/list", {}, 2) as {
        result?: { tools?: Array<{ name: string }> };
      };
      const names = (listed.result?.tools ?? []).map((t) => t.name);

      // The regression in one assertion. When the shim exited, this list did not exist at all —
      // the server showed as failed and there was nothing to call.
      expect(names.length).toBeGreaterThan(0);
      expect(names).toContain("cello_status");

      // And it is still alive to answer them.
      expect(shim.proc.exitCode).toBeNull();
    } finally {
      cleanup();
    }
  }, 30_000);

  it("every tool answers `daemon_not_running` and carries the whole recovery", async () => {
    const { shim, cleanup } = startWithNoDaemon();
    try {
      await handshake(shim);
      const called = await shim.rpc("tools/call", { name: "cello_status", arguments: {} }, 2) as {
        result?: { content?: Array<{ text?: string }> };
      };
      const text = called.result?.content?.[0]?.text ?? "";
      const payload = JSON.parse(text) as { ok?: boolean; reason?: string; guidance?: string };

      // This is what the `setup` skill has always promised. It is now true of the binary.
      expect(payload.ok).toBe(false);
      expect(payload.reason).toBe("daemon_not_running");

      const guidance = payload.guidance ?? "";

      // The recovery must name the package that actually provides `cello`. Saying only
      // "run cello login" names a binary a plugin install does not provide — a dead end
      // pointing at a dead end.
      expect(guidance).toContain("npm i -g --prefer-online @cello-protocol/cli@latest");
      expect(guidance).toContain("cello login");

      // NOT connect: under the plugin route npx fetches the shim itself, verified on a wiped
      // machine whose npx cache repopulated with no global connect present. This message can only
      // be read BY the plugin route — the plugin's shim is what produced it.
      expect(guidance).not.toContain("@cello-protocol/connect");

      // --prefer-online and @latest are load-bearing and their absence is INVISIBLE: npm may serve
      // a cached tarball, the install reports success, and the operator is silently on an old
      // client — surfacing later as a protocol mismatch that looks nothing like an install problem.
      expect(guidance).toContain("--prefer-online");

      // Starting the daemon is not the whole job — they still have no agent and no registration.
      expect(guidance).toContain("setup");

      // Order: the install must come before the login in the text read top to bottom.
      expect(guidance.indexOf("npm i -g")).toBeLessThan(guidance.indexOf("cello login"));
    } finally {
      cleanup();
    }
  }, 30_000);

  it("tells the reader the shim re-dials, so starting the daemon is enough on its own", async () => {
    const { shim, cleanup } = startWithNoDaemon();
    try {
      await handshake(shim);
      const called = await shim.rpc("tools/call", { name: "cello_status", arguments: {} }, 2) as {
        result?: { content?: Array<{ text?: string }> };
      };
      const guidance = (JSON.parse(called.result?.content?.[0]?.text ?? "{}") as { guidance?: string }).guidance ?? "";

      // The compounding papercut: the first failure was opaque AND its recovery was unadvertised.
      // Nothing told anyone that after `cello login` the tools were still dead until they ran
      // /mcp → Reconnect. The shim now retries on the next tool call, so the honest instruction is
      // "just call a tool again" — and Reconnect survives only as the manual override.
      expect(guidance).toMatch(/re-dials/i);
      expect(guidance).toMatch(/Reconnect/i);
    } finally {
      cleanup();
    }
  }, 30_000);

  it("PROOF, not prose: starting the daemon is genuinely enough — the next tool call connects", async () => {
    /**
     * The three tests above assert the guidance SAYS the shim re-dials. That is a claim about text,
     * and a claim about text is exactly the kind of green test that proves less than it looks: if
     * the re-dial did not work, all three would still pass while a real operator sat with dead
     * tools after doing everything they were told.
     *
     * So this one runs the sequence: shim up with no daemon → tool refused → a REAL daemon starts
     * into the same CELLO_DIR → the same tool call now reaches it, with no /mcp Reconnect and no
     * restart in between.
     */
    const { shim, celloDir, cleanup } = startWithNoDaemon();
    let daemon: SpawnedDaemon | undefined;
    try {
      await handshake(shim);

      const before = await shim.rpc("tools/call", { name: "cello_status", arguments: {} }, 2) as {
        result?: { content?: Array<{ text?: string }> };
      };
      const beforePayload = JSON.parse(before.result?.content?.[0]?.text ?? "{}") as { reason?: string };
      expect(beforePayload.reason).toBe("daemon_not_running");

      // The one thing the guidance asks the operator to do.
      daemon = spawnRealDaemon(celloDir);
      await daemon.waitForEvent("daemon.started");

      const after = await shim.rpc("tools/call", { name: "cello_status", arguments: {} }, 3) as {
        result?: { content?: Array<{ text?: string }> };
      };
      const afterPayload = JSON.parse(after.result?.content?.[0]?.text ?? "{}") as { reason?: string };

      // Reached the daemon. Whatever cello_status reports about an empty install, the ONE answer
      // it must no longer give is "there is no daemon".
      expect(afterPayload.reason).not.toBe("daemon_not_running");
    } finally {
      daemon?.kill("SIGKILL");
      cleanup();
    }
  }, 60_000);

  it("the recovery is ALSO on stderr, for an operator reading the log rather than the agent", async () => {
    const { shim, cleanup } = startWithNoDaemon();
    try {
      await handshake(shim);
      await shim.rpc("tools/list", {}, 2);
      expect(shim.stderr()).toContain("npm i -g --prefer-online @cello-protocol/cli@latest");
    } finally {
      cleanup();
    }
  }, 30_000);
});
