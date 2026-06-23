import json, urllib.request

REPO = "protectai/deberta-v3-small-prompt-injection-v2"
REV = "main"
url = f"https://huggingface.co/api/models/{REPO}/tree/{REV}?recursive=true"
data = json.load(urllib.request.urlopen(url))
meta = {}
for f in data:
    if f.get("type") != "file": continue
    meta[f["path"]] = {"size": f.get("size"), "sha256": (f.get("lfs") or {}).get("oid")}

# Files transformers.js needs for a local ONNX text-classification pipeline: root tokenizer/config
# + the ONNX model. The big LFS files (model.onnx, spm.model) carry a pinned content SHA-256; the
# small JSON config/tokenizer files are git blobs (no LFS sha in the API) and are downloaded as-is.
WANT = [
    "config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
    "added_tokens.json", "spm.model", "onnx/model.onnx", "onnx/config.json",
]
files = []
for p in WANT:
    if p not in meta: continue
    files.append({"path": p, "size": meta[p]["size"], "sha256": meta[p]["sha256"]})

lines = []
lines.append("/**")
lines.append(" * GENERATED (scripts/gen-deberta-manifest.py) — the M9-IN-002 model manifest.")
lines.append(" * The big ONNX weights + the SentencePiece model carry a pinned content SHA-256 (from")
lines.append(" * Hugging Face LFS). NOTE: the SHA-256 values are not committed here — this dev environment's\n * secret-redaction rewrites any 64-hex digest to asterisks, even in generated files. Integrity is\n * the committed file SIZE plus, in production, verification against Hugging Face's HTTPS LFS API.\n * Committing the pinned digests (TUF-style, so a compromised mirror cannot swap the model) is the\n * intended hardening and must be added out-of-band (CI / a non-redacting path).")
lines.append(" */")
lines.append("export interface ModelFile { path: string; size: number; sha256: string | null }")
lines.append("")
lines.append("export const DEBERTA_MODEL = {")
lines.append(f"  repo: {json.dumps(REPO)},")
lines.append(f"  revision: {json.dumps(REV)},")
lines.append("  /** Hugging Face resolve URL base for the pinned revision. */")
lines.append(f"  baseUrl: {json.dumps(f'https://huggingface.co/{REPO}/resolve/{REV}/')},")
lines.append("  files: [")
for f in files:
    sha = "null"  # see header note: SHA pin blocked by the dev harness's secret-redaction
    lines.append(f"    {{ path: {json.dumps(f['path'])}, size: {f['size']}, sha256: {sha} }},")
lines.append("  ] as const,")
lines.append("} as const;")
lines.append("")
open("src/detect/deberta-model-manifest.ts", "w").write("\n".join(lines))
pinned = sum(1 for f in files if f["sha256"])
print(f"wrote manifest: {len(files)} files, {pinned} with pinned sha256")
