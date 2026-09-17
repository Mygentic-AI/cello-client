/**
 * DOD-M9C-SCREENINSTALL-1 — `cello screener install` / `status` / `install --manual`.
 *
 * The operator-facing half of the screener. Every string an operator reads here is one Andre
 * approved on 2026-09-15/17, and the tests assert the CONTENT those strings must carry — the sizes,
 * both sources, the manual escape hatch — rather than their prose, so a reworded prompt that drops
 * the download size still fails.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir, truncate } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { SCREENER_MODEL } from "@cello-protocol/gateway";
import { screenerStatusCommand, screenerInstallCommand, screenerManualInstructions } from "../screener-commands.js";

async function writeVerifiedModel(dir: string): Promise<void> {
  for (const f of SCREENER_MODEL.files) {
    const dest = join(dir, f.path);
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
      expect(r.stdout).toContain("2 of 2 layers");
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
