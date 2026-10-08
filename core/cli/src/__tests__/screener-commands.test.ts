/**
 * DOD-M9C-SCREENINSTALL-1 — `cello screener install` / `status` / `install --manual`.
 *
 * The operator-facing half of the screener. Every string an operator reads here is one Andre
 * approved on 2026-09-15/17, and the tests assert the CONTENT those strings must carry — the sizes,
 * both sources, the manual escape hatch — rather than their prose, so a reworded prompt that drops
 * the download size still fails.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import { mkdtemp, rm, writeFile, mkdir, truncate } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { SCREENER_MODEL, localPathOf } from "@cello-protocol/gateway";
import {
  screenerStatusCommand,
  screenerInstallCommand,
  screenerManualInstructions,
  npmInstallRuntime,
  mergeAllowScripts,
} from "../screener-commands.js";
import { screenerLoginLine } from "../commands.js";

async function writeVerifiedModel(dir: string): Promise<void> {
  for (const f of SCREENER_MODEL.files) {
    const dest = join(dir, localPathOf(f));
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, "");
    await truncate(dest, f.size);
  }
}

describe("SCREENINSTALL: cello screener", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-cli-screener-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  describe("status", () => {
    it("reports the state, exits 0, and names the fix when the classifier is absent", async () => {
      const r = await screenerStatusCommand({ dir, runtimePresent: false });
      expect(r.exitCode).toBe(0);
      expect(r.stdout).toContain("1 of 2 layers");
      expect(r.stdout).toContain("cello screener install");
    });

    it("distinguishes half-installed from not installed", async () => {
      const r = await screenerStatusCommand({ dir, runtimePresent: true });
      expect(r.stdout).toMatch(/model is missing/i);
    });
  });

  describe("install", () => {
    it("without consent, fetches nothing and prints the approved prompt", async () => {
      let fetched = 0;
      const r = await screenerInstallCommand({
        dir,
        runtimePresent: false,
        assumeYes: false,
        interactive: false,
        fetchImpl: (() => { fetched++; return Promise.reject(new Error("must not fetch")); }) as unknown as typeof fetch,
        installRuntime: async () => { throw new Error("must not install the runtime"); },
      });
      expect(fetched).toBe(0);
      expect(r.exitCode).toBe(1);
      // The content Andre's prompt must carry, asserted by substance not by wording.
      expect(r.stdout).toContain("two layers, and only one is active");
      expect(r.stdout).toContain("Patronus");
      expect(r.stdout).toContain("Hugging Face");
      expect(r.stdout).toContain("npm");
      expect(r.stdout).toMatch(/241 MB/);   // download
      expect(r.stdout).toMatch(/618 MB/);   // disk
      expect(r.stdout).toContain("cello screener install --manual");
    });

    it("with --yes, installs both halves and reports what it verified", async () => {
      let runtimeInstalled = false;
      const r = await screenerInstallCommand({
        dir,
        runtimePresent: false,
        assumeYes: true,
        interactive: false,
        installModelImpl: async () => { await writeVerifiedModel(dir); return { installed: true }; },
        installRuntime: async () => { runtimeInstalled = true; },
        runtimeCheckAfterInstall: async () => true,
        verifyDigests: false,
      });
      expect(runtimeInstalled).toBe(true);
      expect(r.exitCode).toBe(0);
      // 080-SCREENERCPU: an install proves the bytes, not the scores — "2 of 2" is the gateway's to claim.
      expect(r.stdout).toContain("installed and verified");
      expect(r.stdout).not.toContain("2 of 2");
      // 087 Part B: a running gateway loads the weights only at start, so the install ends by saying so.
      expect(r.stdout.trimEnd().split("\n").at(-1)).toBe(
        "Restart the daemon with  cello logout && cello login  to load it.",
      );
    });

    it("is a no-op when everything is already installed and verified", async () => {
      await writeVerifiedModel(dir);
      let fetched = 0;
      const r = await screenerInstallCommand({
        dir,
        runtimePresent: true,
        assumeYes: true,
        interactive: false,
        verifyDigests: false,
        installModelImpl: async () => { fetched++; return { installed: true }; },
        installRuntime: async () => { fetched++; },
      });
      expect(fetched).toBe(0);
      expect(r.exitCode).toBe(0);
      expect(r.stdout).toMatch(/already installed/i);
    });

    it("finishes the missing half rather than starting over", async () => {
      await writeVerifiedModel(dir);
      let modelFetches = 0, runtimeInstalls = 0;
      const r = await screenerInstallCommand({
        dir,
        runtimePresent: false,
        assumeYes: true,
        interactive: false,
        verifyDigests: false,
        installModelImpl: async () => { modelFetches++; return { installed: true }; },
        installRuntime: async () => { runtimeInstalls++; },
        runtimeCheckAfterInstall: async () => true,
      });
      expect(modelFetches).toBe(0);   // the model is there and verified — do not re-download 131 MB
      expect(runtimeInstalls).toBe(1);
      expect(r.exitCode).toBe(0);
    });

    it("fails loudly when the model install fails, and says what failed", async () => {
      const r = await screenerInstallCommand({
        dir,
        runtimePresent: true,
        assumeYes: true,
        interactive: false,
        installModelImpl: async () => ({ installed: false, error: "checksum mismatch for config.json — removed" }),
        installRuntime: async () => { /* not reached */ },
      });
      expect(r.exitCode).toBe(1);
      expect(r.stderr).toContain("checksum mismatch");
      expect(r.stderr).toContain("config.json");
    });

    it("never prompts when there is no terminal — it prints the command and exits", async () => {
      const r = await screenerInstallCommand({ dir, runtimePresent: false, assumeYes: false, interactive: false });
      expect(r.exitCode).toBe(1);
      expect(r.stdout).toContain("--yes");
      // 087 Part C: a stop, not a failure — nothing installed, nothing went wrong.
      expect(r.stdout).toContain("Nothing was installed and nothing went wrong");
    });
  });

  describe("--manual", () => {
    it("prints every file with its size and digest, the runtime command, and the target directory", () => {
      const text = screenerManualInstructions(dir);
      for (const f of SCREENER_MODEL.files) {
        expect(text).toContain(f.path);
        expect(text).toContain(f.sha256);
        expect(text).toContain(String(f.size));
      }
      expect(text).toContain(SCREENER_MODEL.baseUrl);
      expect(text).toContain("@huggingface/transformers");
      expect(text).toContain(dir);
      expect(text).toContain("cello screener status");
    });

    it("reads the digests from the manifest, so a manifest change moves them", () => {
      // Hand-copied digests are the defect this guards: they drift the first time the model moves.
      const text = screenerManualInstructions(dir);
      expect(text).toContain(SCREENER_MODEL.files[0]!.sha256);
      expect(text).toContain(SCREENER_MODEL.revision);
    });
  });
});

describe("SCREENINSTALL: the login line", () => {
  it("appears when the classifier is absent, naming the command and the size", async () => {
    const line = await screenerLoginLine(async () => ({ state: "not_installed" }));
    expect(line).toContain("cello screener install");
    expect(line).toContain("241 MB");
    expect(line).toContain("1 of 2");
  });

  it("appears again for a half-installed or broken screener — postponing is not deciding", async () => {
    expect(await screenerLoginLine(async () => ({ state: "half_installed" }))).not.toBe("");
    expect(await screenerLoginLine(async () => ({ state: "broken", problem: "x" }))).not.toBe("");
  });

  it("is silent once the classifier is installed and verified", async () => {
    expect(await screenerLoginLine(async () => ({ state: "ready" }))).toBe("");
  });

  it("reports a failed check as UNKNOWN rather than falling silent", async () => {
    // Silence would be indistinguishable from "installed", so a broken check would quietly stop the
    // nag for the one operator who most needs it.
    const line = await screenerLoginLine(async () => { throw new Error("disk on fire"); });
    expect(line).toContain("UNKNOWN");
    expect(line).toContain("disk on fire");
  });

  it("points a BROKEN classifier at --repair, not at the plain install", async () => {
    const line = await screenerLoginLine(async () => ({ state: "broken", problem: "config.json does not match" }));
    expect(line).toContain("--repair");
    expect(line).toContain("config.json");
  });
});

describe("SCREENINSTALL: observability and the fetch boundary", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-obs-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("names every event domain.noun.verb and threads ONE correlationId through the install", async () => {
    const events: Array<{ event: string; fields?: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, fields?: Record<string, unknown>) => events.push({ event, fields }),
      error: (event: string, fields?: Record<string, unknown>) => events.push({ event, fields }),
    };
    await screenerInstallCommand({
      dir, runtimePresent: false, assumeYes: true, interactive: false, verifyDigests: false, logger,
      installModelImpl: async () => { await writeVerifiedModel(dir); return { installed: true }; },
      installRuntime: async () => {},
      runtimeCheckAfterInstall: async () => true,
    });
    expect(events.map((e) => e.event)).toEqual(["screener.install.started", "screener.install.complete"]);
    for (const e of events) expect(e.event).toMatch(/^[a-z]+\.[a-z_]+\.[a-z_]+$/);
    const ids = new Set(events.map((e) => e.fields?.["correlationId"]));
    expect(ids.size).toBe(1);
    expect([...ids][0]).toBeTypeOf("string");
  });

  it("names the CAUSE when the model install fails, not just the exit point", async () => {
    const events: Array<{ event: string; fields?: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, fields?: Record<string, unknown>) => events.push({ event, fields }),
      error: (event: string, fields?: Record<string, unknown>) => events.push({ event, fields }),
    };
    await screenerInstallCommand({
      dir, runtimePresent: true, assumeYes: true, interactive: false, logger,
      installModelImpl: async () => ({ installed: false, error: "checksum mismatch for config.json" }),
      installRuntime: async () => {},
    });
    const failure = events.find((e) => e.event === "screener.model.install.failed");
    expect(failure).toBeDefined();
    expect(String(failure!.fields?.["error"])).toContain("checksum mismatch");
  });

  it("requests ONLY the manifest's files — nothing else from the repository", async () => {
    // The upstream repo also holds a GPL-3.0 l2/ directory. A fetch that walked the repo, or a
    // manifest someone extended carelessly, would pull it in; this records every URL asked for.
    const requested: string[] = [];
    await screenerInstallCommand({
      dir, runtimePresent: true, assumeYes: true, interactive: false, verifyDigests: false,
      fetchImpl: (async (url: string) => {
        requested.push(String(url));
        const f = SCREENER_MODEL.files.find((x) => String(url).endsWith(x.path))!;
        await mkdir(dirname(join(dir, localPathOf(f))), { recursive: true });
        await writeFile(join(dir, localPathOf(f)), "");
        await truncate(join(dir, localPathOf(f)), f.size);
        return new Response("");
      }) as unknown as typeof fetch,
      installRuntime: async () => {},
      runtimeCheckAfterInstall: async () => true,
    });
    expect(requested.length).toBeGreaterThan(0);
    for (const url of requested) {
      expect(url.startsWith(SCREENER_MODEL.baseUrl), url).toBe(true);
      expect(SCREENER_MODEL.files.some((f) => url === SCREENER_MODEL.baseUrl + f.path), url).toBe(true);
      expect(url).not.toContain("/l2/");
    }
  });
});

describe("SCREENINSTALL: repairing a broken install", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-repair-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("refuses without --repair, and names the command instead of asking for homework", async () => {
    await writeVerifiedModel(dir); // right sizes, wrong bytes: verification fails
    const r = await screenerInstallCommand({ dir, runtimePresent: true, assumeYes: true, interactive: false });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("BROKEN");
    expect(r.stderr).toContain("--repair");
    expect(r.stderr).not.toMatch(/delete .* by hand/i);
  });

  it("with --repair, removes the failed files and fetches them again", async () => {
    await writeVerifiedModel(dir);
    let refetched = 0;
    // Digest verification stays ON: this fixture can never satisfy it, so the command must re-fetch
    // AND then refuse to claim success — which is the honest outcome for a mirror serving bad bytes.
    const r = await screenerInstallCommand({
      dir, runtimePresent: true, assumeYes: true, repair: true, interactive: false,
      installModelImpl: async () => {
        // installModel no-ops when every path exists, so repair must have DELETED them first.
        const { access } = await import("node:fs/promises");
        await expect(access(join(dir, "config.json"))).rejects.toThrow();
        refetched++;
        await writeVerifiedModel(dir);
        return { installed: true };
      },
      installRuntime: async () => {},
      runtimeCheckAfterInstall: async () => true,
    });
    expect(refetched).toBe(1);
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("Install did not complete");
  });
});

describe("SCREENINSTALL: the prompt accepts an answer", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-ask-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  const run = (askImpl: (q: string) => Promise<string>, onInstall: () => void) =>
    screenerInstallCommand({
      dir, runtimePresent: false, assumeYes: false, interactive: true, verifyDigests: false, askImpl,
      installModelImpl: async () => { onInstall(); await writeVerifiedModel(dir); return { installed: true }; },
      installRuntime: async () => {},
      runtimeCheckAfterInstall: async () => true,
    });

  it("asks the approved question, and 'y' installs", async () => {
    let asked = "";
    let installed = false;
    const r = await run(async (q) => { asked = q; return "y"; }, () => { installed = true; });
    expect(asked).toContain("Install now? [Y/n]");
    expect(installed).toBe(true);
    expect(r.exitCode).toBe(0);
  });

  it("treats a bare Enter as yes — the capital Y in [Y/n] is a promise", async () => {
    let installed = false;
    await run(async () => "", () => { installed = true; });
    expect(installed).toBe(true);
  });

  it("'n' downloads nothing and says how to come back", async () => {
    let installed = false;
    const r = await run(async () => "n", () => { installed = true; });
    expect(installed).toBe(false);
    expect(r.exitCode).toBe(1);
    expect(r.stdout).toContain("Nothing was downloaded");
  });

  it("never asks when there is no terminal", async () => {
    let asked = false;
    const r = await screenerInstallCommand({
      dir, runtimePresent: false, assumeYes: false, interactive: false,
      askImpl: async () => { asked = true; return "y"; },
    });
    expect(asked).toBe(false);
    expect(r.stdout).toContain("--yes");
  });
});

describe("SCREENINSTALL: npmInstallRuntime", () => {
  let runtimeDir: string;
  const originalEnv = process.env["CELLO_SCREENER_RUNTIME_DIR"];

  beforeEach(async () => {
    runtimeDir = await mkdtemp(join(tmpdir(), "cello-runtime-"));
    process.env["CELLO_SCREENER_RUNTIME_DIR"] = runtimeDir;
  });

  afterEach(async () => {
    if (originalEnv !== undefined) {
      process.env["CELLO_SCREENER_RUNTIME_DIR"] = originalEnv;
    } else {
      delete process.env["CELLO_SCREENER_RUNTIME_DIR"];
    }
    await rm(runtimeDir, { recursive: true, force: true });
  });

  it("writes .npmrc with allow-scripts and passes shell option appropriately for default platform", async () => {
    let spawnedCmd = "";
    let spawnedArgs: string[] | undefined = undefined;
    let spawnedOptions: Record<string, unknown> = {};

    const mockSpawn = (cmd: string, argsOrOptions?: unknown, options?: unknown) => {
      spawnedCmd = cmd;
      if (Array.isArray(argsOrOptions)) {
        spawnedArgs = argsOrOptions;
        spawnedOptions = (options as Record<string, unknown>) || {};
      } else {
        spawnedArgs = undefined;
        spawnedOptions = (argsOrOptions as Record<string, unknown>) || {};
      }
      const ee = new EventEmitter();
      process.nextTick(() => ee.emit("exit", 0));
      return ee;
    };

    const { readFile } = await import("node:fs/promises");
    await npmInstallRuntime({ spawnImpl: mockSpawn as unknown as typeof import("node:child_process").spawn });

    const npmrcContent = await readFile(join(runtimeDir, ".npmrc"), "utf8");
    expect(npmrcContent).toContain("allow-scripts=onnxruntime-node,protobufjs");
    expect(spawnedOptions["cwd"]).toBe(runtimeDir);
    if (process.platform === "win32") {
      expect(spawnedCmd).toBe("npm install @huggingface/transformers");
      expect(spawnedOptions["shell"]).toBe(true);
    } else {
      expect(spawnedCmd).toBe("npm");
      expect(spawnedArgs).toEqual(["install", "@huggingface/transformers"]);
      expect(spawnedOptions["shell"]).toBe(false);
    }
  });

  it("exercises Windows-specific spawning directly inside target cwd without path arguments", async () => {
    let spawnedCmd = "";
    let spawnedOptions: Record<string, unknown> = {};

    const mockSpawn = (cmd: string, options?: unknown) => {
      spawnedCmd = cmd;
      spawnedOptions = (options as Record<string, unknown>) || {};
      const ee = new EventEmitter();
      process.nextTick(() => ee.emit("exit", 0));
      return ee;
    };

    await npmInstallRuntime({
      spawnImpl: mockSpawn as unknown as typeof import("node:child_process").spawn,
      platform: "win32",
      runtimeDir,
    });

    expect(spawnedCmd).toBe("npm install @huggingface/transformers");
    expect(spawnedOptions["cwd"]).toBe(runtimeDir);
    expect(spawnedOptions["shell"]).toBe(true);
  });

  it("exercises POSIX-specific spawning when platform is linux or darwin", async () => {
    let spawnedCmd = "";
    let spawnedArgs: string[] = [];
    let spawnedOptions: Record<string, unknown> = {};

    const mockSpawn = (cmd: string, args: string[], options: Record<string, unknown>) => {
      spawnedCmd = cmd;
      spawnedArgs = args;
      spawnedOptions = options;
      const ee = new EventEmitter();
      process.nextTick(() => ee.emit("exit", 0));
      return ee;
    };

    await npmInstallRuntime({
      spawnImpl: mockSpawn as unknown as typeof import("node:child_process").spawn,
      platform: "linux",
      runtimeDir,
    });

    expect(spawnedCmd).toBe("npm");
    expect(spawnedArgs).toEqual(["install", "@huggingface/transformers"]);
    expect(spawnedOptions["cwd"]).toBe(runtimeDir);
    expect(spawnedOptions["shell"]).toBe(false);
  });

  it("safely preserves and updates existing .npmrc file", async () => {
    const { writeFile, readFile } = await import("node:fs/promises");
    await writeFile(join(runtimeDir, ".npmrc"), "legacy-peer-deps=true\n", "utf8");

    const mockSpawn = () => {
      const ee = new EventEmitter();
      process.nextTick(() => ee.emit("exit", 0));
      return ee;
    };

    await npmInstallRuntime({ spawnImpl: mockSpawn as unknown as typeof import("node:child_process").spawn });

    const npmrcContent = await readFile(join(runtimeDir, ".npmrc"), "utf8");
    expect(npmrcContent).toContain("legacy-peer-deps=true");
    expect(npmrcContent).toContain("allow-scripts=onnxruntime-node,protobufjs");
  });
});

describe("SCREENINSTALL: mergeAllowScripts helper", () => {
  it("creates allow-scripts when file is empty", () => {
    const res = mergeAllowScripts("");
    expect(res).toBe("allow-scripts=onnxruntime-node,protobufjs\n");
  });

  it("preserves other settings and appends allow-scripts", () => {
    const input = "legacy-peer-deps=true\nregistry=https://registry.npmjs.org/\n";
    const res = mergeAllowScripts(input);
    expect(res).toContain("legacy-peer-deps=true");
    expect(res).toContain("registry=https://registry.npmjs.org/");
    expect(res).toContain("allow-scripts=onnxruntime-node,protobufjs");
  });

  it("merges with existing allow-scripts without duplicating", () => {
    const input = "allow-scripts=foo,onnxruntime-node\nother-key=1";
    const res = mergeAllowScripts(input);
    expect(res).toContain("allow-scripts=foo,onnxruntime-node,protobufjs");
    expect(res).toContain("other-key=1");
  });

  it("consolidates multiple allow-scripts lines into a single line", () => {
    const input = [
      "legacy-peer-deps=true",
      "allow-scripts=foo,bar",
      "registry=https://registry.npmjs.org/",
      "allow-scripts=baz,onnxruntime-node",
      "other-setting=yes",
    ].join("\n");
    const res = mergeAllowScripts(input);
    expect(res).toContain("legacy-peer-deps=true");
    expect(res).toContain("registry=https://registry.npmjs.org/");
    expect(res).toContain("other-setting=yes");
    // Exactly one allow-scripts line
    const allowLines = res.split("\n").filter((l) => l.startsWith("allow-scripts="));
    expect(allowLines).toHaveLength(1);
    expect(allowLines[0]).toBe("allow-scripts=foo,bar,baz,onnxruntime-node,protobufjs");
  });

  it("is idempotent across repeated invocations without accumulating blank lines", () => {
    const input = "allow-scripts=foo\n";
    const once = mergeAllowScripts(input);
    expect(once).toBe("allow-scripts=foo,onnxruntime-node,protobufjs\n");
    const twice = mergeAllowScripts(once);
    expect(twice).toBe(once);
    const thrice = mergeAllowScripts(twice);
    expect(thrice).toBe(once);
  });
});
