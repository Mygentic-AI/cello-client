/**
 * DOD-M9C-SCREENINSTALL-1 — the Layer-2 screener model, pinned.
 *
 * Patronus Wolf Defender Small v2 (Apache 2.0), the INT8/INT4 ONNX export. Verified against the
 * Hugging Face Hub on 2026-09-15: the repository, the licence, the file sizes and every digest below
 * were read from the Hub API at this commit, not copied from a summary. Andre ruled one model on
 * 2026-09-15 — there is no chooser, and the only question the operator answers is consent.
 *
 * **The revision is a commit, never `main`.** A moving reference means the bytes we verified are not
 * the bytes the operator gets, and the digests below would be checking a different file.
 *
 * **The file list is exhaustive on purpose.** The upstream repository also contains an `l2/`
 * directory licensed GPL-3.0 with a paid commercial alternative. Nothing outside this list is ever
 * fetched, so that directory cannot arrive by accident.
 *
 * The SHA-256s for the two large files are the Hub's LFS digests; the three small files were hashed
 * from the pinned-revision download. The graph's digest also matches Patronus' own published
 * `onnx/quantization_manifest.json`, which is an independent confirmation of the same bytes.
 */

export interface ScreenerModelFile {
  path: string;
  size: number;
  /** Never null. A file we cannot pin is a file we do not ship. */
  sha256: string;
}

export const SCREENER_MODEL = {
  repo: "patronus-studio/wolf-defender-prompt-injection-small",
  revision: "cdcdf7d0231d68f39cc3bb1b70f6a2bdfca8ad55",
  /** Hugging Face resolve URL base for the pinned commit. */
  baseUrl:
    "https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small/resolve/cdcdf7d0231d68f39cc3bb1b70f6a2bdfca8ad55/",
  /**
   * The window the model was TRAINED and benchmarked on (card: 2,048-token windows, 64-token
   * overlap, normalised Smooth-Max aggregation). `config.json` advertises 8,192 positions; screening
   * there would run the model outside the range anyone measured.
   */
  windowTokens: 2048,
  windowOverlapTokens: 64,
  files: [
    { path: "onnx/int8_int4_embeddings/model.onnx", size: 96_296_126, sha256: "a6c77496152e458c072e4787f872192af0449a427359d1afbfa1d4d6b116a305" },
    { path: "tokenizer.json", size: 34_363_287, sha256: "7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c" },
    { path: "tokenizer_config.json", size: 574, sha256: "14b147f2a4f939d9b12ab36e9633917040dd948fa78ce283b03402e4cf2c9cba" },
    { path: "config.json", size: 2_084, sha256: "b5bfba7b100b4b1aa361e8160e5593695164d81ca09b47f3b26561332b520218" },
    { path: "special_tokens_map.json", size: 173, sha256: "97f6f6ef323755568c9dddf57b7b2bac4c2019e8c10c2ef1262001a9f6487124" },
  ] as ReadonlyArray<ScreenerModelFile>,
} as const;

/** Total bytes the operator is asked to download — the number the consent prompt quotes. */
export function screenerModelTotalBytes(): number {
  return SCREENER_MODEL.files.reduce((n, f) => n + f.size, 0);
}
