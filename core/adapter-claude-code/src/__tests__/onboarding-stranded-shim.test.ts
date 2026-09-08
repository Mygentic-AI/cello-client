/**
 * Launch triage item 5 — installing the plugin must not strand a first-time user.
 *
 * The failure this pins, in the order a new user lives it:
 *
 *   1. They run `/plugin install cello@cello-protocol`. The plugin's .mcp.json points at
 *      `npx @cello-protocol/connect`, so the MCP SHIM arrives — and nothing else does.
 *   2. Claude Code starts the shim. There is no daemon and no `~/.cello/daemon.sock`.
 *   3. The shim writes one line to stderr and exits(1). The MCP server shows as FAILED, so there
 *      are no `cello_*` tools at all — the user never even reaches a tool call.
 *   4. That one line is the entire explanation they get.
 *
 * So the line has to carry the whole recovery. It used to say "run `cello login` to start it",
 * which names a binary this user does not have: `cello` ships in @cello-protocol/cli, a SEPARATE
 * package the plugin never installs. Following the instruction literally produced
 * `command not found: cello` — a dead end pointing at a dead end.
 *
 * There was no test on this path, which is how it survived. This is that test: it spawns the real
 * built binary against an empty CELLO_DIR and reads what an operator would actually see.
 */

import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const BIN = resolve(here, "../../dist/bin/cello-mcp.js");

/** Spawn the built shim against a CELLO_DIR with no daemon, and collect what the operator sees. */
async function runWithNoDaemon(): Promise<{ code: number | null; stderr: string }> {
  // A fresh empty dir — no daemon.sock, exactly the state right after a plugin install.
  const celloDir = mkdtempSync(resolve(tmpdir(), "cello-stranded-"));
  try {
    return await new Promise((resolvePromise, reject) => {
      const proc = spawn(process.execPath, [BIN], {
        env: { ...process.env, CELLO_DIR: celloDir },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stderr = "";
      proc.stderr.on("data", (c: Buffer) => { stderr += c.toString(); });
      proc.on("error", reject);
      const timer = setTimeout(() => {
        proc.kill("SIGKILL");
        reject(new Error("cello-mcp did not exit within 15s with no daemon running"));
      }, 15_000);
      proc.on("exit", (code) => {
        clearTimeout(timer);
        resolvePromise({ code, stderr });
      });
    });
  } finally {
    rmSync(celloDir, { recursive: true, force: true });
  }
}

describe("launch triage item 5 — a plugin install must not dead-end at a missing daemon", () => {
  it("names the install that provides `cello`, not just `cello login`", async () => {
    const { code, stderr } = await runWithNoDaemon();

    // It still fails — that part is correct. The shim cannot proxy to a daemon that is not there.
    expect(code).toBe(1);

    // THE FIX: the recovery must start with the package that actually provides the binary.
    // Without this line the user is told to run a command they have no way to have.
    //
    // This asserted BOTH packages until 2026-09-08, on the reasoning that someone reading this is
    // as likely to be on the manual `claude mcp add` route. Superseded by measurement: on a
    // genuinely wiped machine the npx cache was deleted and repopulated itself at first launch with
    // no global `connect` present, so under the plugin route npx fetches the shim on its own. And
    // this message can only be read BY the plugin route — it is the plugin's shim that printed it.
    // Naming a package the reader already has spends the only attention they will give this on a
    // no-op, in the one message they read while something is visibly broken.
    expect(stderr).toContain("npm i -g --prefer-online @cello-protocol/cli@latest");
    expect(stderr).not.toContain("@cello-protocol/connect");

    // --prefer-online and @latest are load-bearing and their absence is invisible: npm may serve a
    // cached tarball, the install reports success, and the operator is silently on an old client —
    // surfacing later as a protocol mismatch that looks nothing like an install problem.
    expect(stderr).toContain("--prefer-online");

    // And then the command that starts the daemon.
    expect(stderr).toContain("cello login");
  }, 20_000);

  it("points at the setup skill, so a first-time user has a next step beyond the daemon", async () => {
    const { stderr } = await runWithNoDaemon();

    // Starting the daemon is not the whole job — they still have no agent and no registration.
    // The `setup` skill is the only thing that covers that end to end, and nothing pointed at it.
    expect(stderr).toContain("setup");

    // The recovery after installing is a RECONNECT, not a restart (Andre, 2026-08-09). Reaching
    // this message means the plugin is already installed — the shim is running because the plugin
    // launched it — so asking for a Claude Code restart costs a session for no reason.
    expect(stderr).toContain("/mcp");
    expect(stderr).toMatch(/Reconnect/i);
  }, 20_000);

  it("teeth: `cello login` never appears as the first thing asked of the user", async () => {
    const { stderr } = await runWithNoDaemon();

    // The exact regression being pinned. If someone later trims this message back to the one-liner,
    // `cello login` becomes the first instruction again and the dead end returns. The install must
    // come first in the text a user reads top to bottom.
    const installAt = stderr.indexOf("npm i -g --prefer-online @cello-protocol/cli@latest");
    const loginAt = stderr.indexOf("cello login");
    expect(installAt).toBeGreaterThanOrEqual(0);
    expect(loginAt).toBeGreaterThan(installAt);
  }, 20_000);
});
