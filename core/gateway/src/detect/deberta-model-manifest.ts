/**
 * GENERATED (scripts/gen-deberta-manifest.py) — the M9-IN-002 model manifest.
 * The big ONNX weights + the SentencePiece model carry a pinned content SHA-256 (from
 * Hugging Face LFS). NOTE: the SHA-256 values are not committed here — this dev environment's
 * secret-redaction rewrites any 64-hex digest to asterisks, even in generated files. Integrity is
 * the committed file SIZE plus, in production, verification against Hugging Face's HTTPS LFS API.
 * Committing the pinned digests (TUF-style, so a compromised mirror cannot swap the model) is the
 * intended hardening and must be added out-of-band (CI / a non-redacting path).
 */
export interface ModelFile { path: string; size: number; sha256: string | null }

export const DEBERTA_MODEL = {
  repo: "protectai/deberta-v3-small-prompt-injection-v2",
  revision: "main",
  /** Hugging Face resolve URL base for the pinned revision. */
  baseUrl: "https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2/resolve/main/",
  files: [
    { path: "config.json", size: 994, sha256: null },
    { path: "tokenizer.json", size: 8656722, sha256: null },
    { path: "tokenizer_config.json", size: 1284, sha256: null },
    { path: "special_tokens_map.json", size: 286, sha256: null },
    { path: "added_tokens.json", size: 23, sha256: null },
    { path: "spm.model", size: 2464616, sha256: null },
    { path: "onnx/model.onnx", size: 568027819, sha256: null },
    { path: "onnx/config.json", size: 1031, sha256: null },
  ] as const,
} as const;
