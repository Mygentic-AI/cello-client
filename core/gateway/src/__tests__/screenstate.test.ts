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
import { SCREENER_MODEL } from "../detect/screener-model-manifest.js";
import { screenerState, describeScreenerState, screenerModelDir, runtimeAvailable, SCREENER_RUNTIME_MODULE } from "../detect/screener-state.js";

/**
 * Write every manifest file at its exact declared size (sparse, so the 96 MB graph costs nothing).
 * The point is that SIZE alone cannot distinguish these from the real model — only the digest can.
 */
async function writeRightSizedFiles(dir: string): Promise<void> {
  for (const f of SCREENER_MODEL.files) {
    const dest = join(dir, f.path);
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
    expect(s.problem).toContain(SCREENER_MODEL.files[0]!.path);
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
