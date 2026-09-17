/**
 * DOD-M9C-SCREENINSTALL-1 — screener state.
 *
 * Four states that must never collapse into each other. The dangerous one is "half installed": a
 * model with no runtime cannot screen anything, and reporting that as "not installed" hides a fault
 * behind a choice the operator never made.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir, truncate } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { SCREENER_MODEL, localPathOf } from "../detect/screener-model-manifest.js";
import { screenerState, describeScreenerState, screenerModelDir, runtimeAvailable, resolveScreenerRuntime, SCREENER_RUNTIME_MODULE } from "../detect/screener-state.js";
import { classifierLoadable } from "../detect/screener-state.js";

/**
 * Write every manifest file at its exact declared size (sparse, so the 96 MB graph costs nothing).
 * The point is that SIZE alone cannot distinguish these from the real model — only the digest can.
 */
async function writeRightSizedFiles(dir: string): Promise<void> {
  for (const f of SCREENER_MODEL.files) {
    const dest = join(dir, localPathOf(f));
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, "");
    await truncate(dest, f.size);
  }
}

describe("SCREENINSTALL: screener state", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-screener-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("reports not_installed when nothing is there", async () => {
    const s = await screenerState({ dir, runtimePresent: false });
    expect(s.state).toBe("not_installed");
    expect(s.model.filesPresent).toBe(0);
    expect(s.model.filesExpected).toBe(SCREENER_MODEL.files.length);
  });

  it("reports half_installed when the runtime is there and the model is not", async () => {
    const s = await screenerState({ dir, runtimePresent: true });
    expect(s.state).toBe("half_installed");
    expect(s.missing).toContain("model");
  });

  it("reports half_installed when the model is there and the runtime is not", async () => {
    await writeRightSizedFiles(dir);
    const s = await screenerState({ dir, runtimePresent: false, verifyDigests: false });
    expect(s.state).toBe("half_installed");
    expect(s.missing).toContain("runtime");
  });

  it("reports broken — naming the file — when a model file fails its digest", async () => {
    await writeRightSizedFiles(dir);
    const s = await screenerState({ dir, runtimePresent: true });
    expect(s.state).toBe("broken");
    expect(s.problem).toContain(localPathOf(SCREENER_MODEL.files[0]!));
  });

  it("reports broken — naming the file — when one model file is missing", async () => {
    await writeRightSizedFiles(dir);
    await rm(join(dir, "config.json"));
    const s = await screenerState({ dir, runtimePresent: true, verifyDigests: false });
    expect(s.state).toBe("broken");
    expect(s.problem).toContain("config.json");
  });

  it("carries the pinned revision so two installs can be told apart", async () => {
    const s = await screenerState({ dir, runtimePresent: false });
    expect(s.revision).toBe(SCREENER_MODEL.revision);
  });

  it("keys the install directory by the pinned revision, so revisions cannot mix", () => {
    const prev = process.env["CELLO_GATEWAY_MODEL_DIR"];
    delete process.env["CELLO_GATEWAY_MODEL_DIR"];
    expect(screenerModelDir()).toContain(SCREENER_MODEL.revision);
    process.env["CELLO_GATEWAY_MODEL_DIR"] = "/tmp/elsewhere";
    expect(screenerModelDir()).toBe("/tmp/elsewhere");
    if (prev === undefined) delete process.env["CELLO_GATEWAY_MODEL_DIR"]; else process.env["CELLO_GATEWAY_MODEL_DIR"] = prev;
  });

  it("runtimeAvailable reports absence as absence, never as a throw", async () => {
    expect(await runtimeAvailable(async () => { throw new Error("Cannot find module"); })).toBe(false);
    expect(await runtimeAvailable(async () => ({}))).toBe(true);
    expect(SCREENER_RUNTIME_MODULE).toBe("@huggingface/transformers");
  });

  it("describes every state in a sentence that names the next step", async () => {
    for (const [state, needle] of [["not_installed", "cello screener install"], ["half_installed", "cello screener install"], ["broken", "cello screener install"]] as const) {
      const text = describeScreenerState({ state, revision: SCREENER_MODEL.revision, model: { filesPresent: 0, filesExpected: 5, verified: false }, runtimePresent: false, missing: ["model"], problem: "x" });
      expect(text, state).toContain(needle);
    }
    const ready = describeScreenerState({ state: "ready", revision: SCREENER_MODEL.revision, model: { filesPresent: 5, filesExpected: 5, verified: true }, runtimePresent: true, missing: [], problem: undefined });
    expect(ready).toMatch(/2 of 2|both layers/i);
  });
});

describe("SCREENINSTALL: the runtime is resolved by FILE, not by bare specifier", () => {
  it("returns null when nothing is installed in CELLO's runtime directory", () => {
    const prev = process.env["CELLO_SCREENER_RUNTIME_DIR"];
    process.env["CELLO_SCREENER_RUNTIME_DIR"] = "/tmp/definitely-not-installed-here";
    expect(resolveScreenerRuntime()).toBeNull();
    if (prev === undefined) delete process.env["CELLO_SCREENER_RUNTIME_DIR"]; else process.env["CELLO_SCREENER_RUNTIME_DIR"] = prev;
  });

  it("resolves through the package's exports map, never to its directory", async () => {
    // Importing the package DIRECTORY picks its CommonJS main with no conditions applied, and Node
    // refuses that with ERR_AMBIGUOUS_MODULE_SYNTAX — which is how a correctly installed runtime
    // read as 'missing' with the model verified 5/5. The resolved value must be a FILE.
    const prev = process.env["CELLO_SCREENER_RUNTIME_DIR"];
    const fake = await mkdtemp(join(tmpdir(), "cello-rt-"));
    const pkgDir = join(fake, "node_modules", "@huggingface", "transformers");
    await mkdir(join(pkgDir, "dist"), { recursive: true });
    await writeFile(join(pkgDir, "dist", "transformers.node.cjs"), "module.exports={pipeline(){}};");
    await writeFile(join(pkgDir, "package.json"), JSON.stringify({
      name: "@huggingface/transformers", version: "0.0.0", type: "module",
      main: "./dist/transformers.node.cjs",
      exports: { node: { require: "./dist/transformers.node.cjs", import: "./dist/transformers.node.cjs" } },
    }));
    process.env["CELLO_SCREENER_RUNTIME_DIR"] = fake;
    const resolved = resolveScreenerRuntime();
    expect(resolved).toContain("transformers.node.cjs");
    expect(await runtimeAvailable()).toBe(true);
    await rm(fake, { recursive: true, force: true });
    if (prev === undefined) delete process.env["CELLO_SCREENER_RUNTIME_DIR"]; else process.env["CELLO_SCREENER_RUNTIME_DIR"] = prev;
  });
});

describe("SCREENINSTALL: a corrupt model is never loaded", () => {
  it("refuses to load from a BROKEN install, naming the file — presence is not integrity", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-corrupt-"));
    for (const f of SCREENER_MODEL.files) {
      const dest = join(dir, localPathOf(f));
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, "");
      await truncate(dest, f.size); // right size, wrong bytes — what a swapped mirror looks like
    }
    // `loadInjectionClassifier` gates on EXISTENCE, so it would load these happily and the gateway
    // would announce layer2=active over a model nobody verified. The composition root asks this
    // first, and this is the decision it asks.
    const decision = classifierLoadable(await screenerState({ dir, runtimePresent: true }));
    expect(decision.load).toBe(false);
    expect(decision.reason).toContain("FAILED verification");
    expect(decision.reason).toContain(localPathOf(SCREENER_MODEL.files[0]!));
    await rm(dir, { recursive: true, force: true });
  });

  it("loads only from a ready install, and says which state stopped it otherwise", async () => {
    const ready = { state: "ready" as const, revision: SCREENER_MODEL.revision, runtimePresent: true,
      model: { filesPresent: 5, filesExpected: 5, verified: true }, missing: [] };
    expect(classifierLoadable(ready)).toEqual({ load: true });
    const absent = { ...ready, state: "not_installed" as const, model: { filesPresent: 0, filesExpected: 5, verified: false }, missing: ["model" as const, "runtime" as const] };
    expect(classifierLoadable(absent).load).toBe(false);
    expect(classifierLoadable(absent).reason).toContain("not_installed");
    const half = { ...absent, state: "half_installed" as const };
    expect(classifierLoadable(half).reason).toContain("half_installed");
  });
});
