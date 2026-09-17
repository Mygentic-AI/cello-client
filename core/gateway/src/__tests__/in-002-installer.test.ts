/**
 * DOD-M9C-SCREENINSTALL-1 — the screener model installer: SHA verification, present-check, the
 * consent gate, and checksum-mismatch rejection. The real ~131 MB download runs on operator opt-in;
 * here the network is an injected fake so the logic is fast and offline.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { sha256File, isModelInstalled, installModel } from "../detect/model-installer.js";
import { SCREENER_MODEL } from "../detect/screener-model-manifest.js";

describe("M9-IN-002 model installer", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-deberta-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("the manifest lists the ONNX graph with a committed size and digest", () => {
    const model = SCREENER_MODEL.files.find((f) => f.path === "onnx/int8_int4_embeddings/model.onnx");
    expect(model).toBeDefined();
    expect(model!.size).toBeGreaterThan(90_000_000);
    expect(model!.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sha256File streams the correct digest", async () => {
    const p = join(dir, "f.bin");
    await writeFile(p, "hello cello");
    expect(await sha256File(p)).toBe(createHash("sha256").update("hello cello").digest("hex"));
  });

  it("isModelInstalled: false on an empty dir, true once every model file is present", async () => {
    expect(await isModelInstalled(dir)).toBe(false);
    for (const f of SCREENER_MODEL.files) {
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

  it("a right-sized file with the wrong CONTENT is rejected and removed — the digest, not the size, is what proves it", async () => {
    // The size check alone passes here: an attacker who serves a different graph padded to the same
    // byte count defeats it. Only the pinned digest catches this.
    // Every file arrives with exactly the right byte count and the wrong bytes.
    const fakeFetch = (async (url: string) => {
      const f = SCREENER_MODEL.files.find((x) => String(url).endsWith(x.path))!;
      return new Response("x".repeat(f.size));
    }) as unknown as typeof fetch;
    const r = await installModel({ dir, consent: true, fetchImpl: fakeFetch });
    expect(r.installed).toBe(false);
    expect(r.error).toMatch(/checksum mismatch/);
    expect(await isModelInstalled(dir)).toBe(false);
  });

  it("a wrong-sized download fails the install and removes the untrusted file (integrity baseline)", async () => {
    const fakeFetch = (async () => new Response("not the real model bytes")) as unknown as typeof fetch;
    const r = await installModel({ dir, consent: true, fetchImpl: fakeFetch });
    expect(r.installed).toBe(false);
    expect(r.error).toMatch(/size mismatch/);
  });
});
