/**
 * DOD-M9C-SCREENINSTALL-1 — the screener model manifest.
 *
 * The bytes we verified must be the bytes the operator gets, so every claim in the manifest is
 * asserted here rather than trusted: an immutable commit revision (never a moving `main`), a real
 * SHA-256 per file, and a file list that stops at the files we need. The last one is load-bearing:
 * the upstream repository's `l2/` directory is GPL-3.0, and a fetch that walks the repo would pull
 * it in.
 */
import { describe, it, expect } from "vitest";
import { SCREENER_MODEL, screenerModelTotalBytes } from "../detect/screener-model-manifest.js";

describe("SCREENINSTALL: the screener model manifest", () => {
  it("names the model Andre ruled, pinned to an immutable commit", () => {
    expect(SCREENER_MODEL.repo).toBe("patronus-studio/wolf-defender-prompt-injection-small");
    expect(SCREENER_MODEL.revision).toMatch(/^[0-9a-f]{40}$/);
    expect(SCREENER_MODEL.revision).not.toBe("main");
    expect(SCREENER_MODEL.baseUrl).toContain(SCREENER_MODEL.revision);
  });

  it("pins a real SHA-256 for every file — no file may be size-only", () => {
    for (const f of SCREENER_MODEL.files) {
      expect(f.sha256, `${f.path} has no digest`).toMatch(/^[0-9a-f]{64}$/);
      expect(f.size).toBeGreaterThan(0);
    }
  });

  it("fetches the ONNX graph, its tokenizer and configs — and nothing else", () => {
    expect(SCREENER_MODEL.files.map((f) => f.path).sort()).toEqual([
      "config.json",
      "onnx/int8_int4_embeddings/model.onnx",
      "special_tokens_map.json",
      "tokenizer.json",
      "tokenizer_config.json",
    ]);
  });

  it("never lists a file from the GPL-3.0 l2/ directory", () => {
    for (const f of SCREENER_MODEL.files) expect(f.path.startsWith("l2/")).toBe(false);
  });

  it("reports the download size the consent prompt quotes", () => {
    // ~131 MB: the 96 MB graph plus the 34 MB tokenizer. The prompt's number comes from here, so a
    // manifest change moves the quoted size instead of leaving the operator a stale figure.
    expect(screenerModelTotalBytes()).toBe(SCREENER_MODEL.files.reduce((n, f) => n + f.size, 0));
    expect(Math.round(screenerModelTotalBytes() / 1_000_000)).toBe(131);
  });

  it("states the window the model was trained on, not its positional maximum", () => {
    // config.json says max_position_embeddings 8192; the card trains and benchmarks at 2,048 with
    // 64-token overlap. Screening at 8,192 would run the model outside what it was measured on.
    expect(SCREENER_MODEL.windowTokens).toBe(2048);
    expect(SCREENER_MODEL.windowOverlapTokens).toBe(64);
  });
});
