/**
 * M9-IN-002 — the DeBERTa model installer: SHA verification, present-check, the consent gate, and
 * checksum-mismatch rejection. The actual ~568 MB download is exercised on operator opt-in (and the
 * gated real-inference test); here the network is an injected fake so the logic is fast + offline.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { sha256File, isModelInstalled, installModel } from "../detect/model-installer.js";
import { DEBERTA_MODEL } from "../detect/deberta-model-manifest.js";

describe("M9-IN-002 model installer", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-deberta-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("the manifest lists the model weights with a committed size — the integrity baseline", () => {
    const model = DEBERTA_MODEL.files.find((f) => f.path === "onnx/model.onnx");
    expect(model).toBeDefined();
    expect(model!.size).toBeGreaterThan(100_000_000); // ~568 MB; full SHA-pin is the intended hardening
  });

  it("sha256File streams the correct digest", async () => {
    const p = join(dir, "f.bin");
    await writeFile(p, "hello cello");
    expect(await sha256File(p)).toBe(createHash("sha256").update("hello cello").digest("hex"));
  });

  it("isModelInstalled: false on an empty dir, true once every model file is present", async () => {
    expect(await isModelInstalled(dir)).toBe(false);
    for (const f of DEBERTA_MODEL.files) {
      const dest = join(dir, f.path);
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, "");
    }
    expect(await isModelInstalled(dir)).toBe(true);
  });

  it("withholding consent downloads nothing and asks for consent", async () => {
    let fetched = 0;
    const fakeFetch = (async () => { fetched++; return new Response("x"); }) as unknown as typeof fetch;
    const r = await installModel({ dir, consent: false, fetchImpl: fakeFetch });
    expect(r.needsConsent).toBe(true);
    expect(r.installed).toBe(false);
    expect(fetched).toBe(0);
  });

  it("a wrong-sized download fails the install and removes the untrusted file (integrity baseline)", async () => {
    const fakeFetch = (async () => new Response("not the real model bytes")) as unknown as typeof fetch;
    // allowUnpinnedDigests: this test is about the SIZE check, which sits downstream of the
    // digest gate added by DOD-DOC-SCREEN-CLASSIFIER-1. Without it the install stops earlier and
    // this assertion would pass for the wrong reason.
    const r = await installModel({ dir, consent: true, allowUnpinnedDigests: true, fetchImpl: fakeFetch });
    expect(r.installed).toBe(false);
    expect(r.error).toMatch(/size mismatch/);
  });
});
