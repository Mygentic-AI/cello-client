/**
 * 001-PQPRIM decision 13 — Node's ExperimentalWarnings for the five post-quantum Web Crypto APIs are
 * dropped, and ONLY those.
 *
 * Runs a child `node` over the BUILT modules (dist/), because a warning filter is a process-level
 * side effect: it has to be proven in a fresh process that loads the primitives the way an operator's
 * CLI does. Each module is loaded ALONE in its own child, so the test proves each one installs the
 * filter itself — a child that imported both would stay green with the import removed from either.
 *
 * Needs `tsc --build` to have run (the gate runs typecheck, which emits). A missing dist fails loudly.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DIST = fileURLToPath(new URL("../../dist/", import.meta.url));

function child(script: string) {
  return spawnSync(process.execPath, ["--input-type=module", "-e", script + "\nawait new Promise((r) => setImmediate(r));"], {
    encoding: "utf8",
  });
}

// ML-KEM alone: the ML-KEM-768 algorithm, encapsulateBits, decapsulateBits, and getPublicKey.
const KEM_ONLY = `
const { mlKemGenerateSeed, mlKemKeypairFromSeed, mlKemEncapsulate, mlKemDecapsulate } = await import(${JSON.stringify(DIST + "ml-kem.js")});
const seed = mlKemGenerateSeed();
const { publicKey } = await mlKemKeypairFromSeed(seed);
const { ciphertext } = await mlKemEncapsulate(publicKey);
await mlKemDecapsulate(seed, ciphertext);
const k = await globalThis.crypto.subtle.importKey("raw-seed", seed, { name: "ML-KEM-768" }, false, ["decapsulateBits"]);
await globalThis.crypto.subtle.getPublicKey(k, ["encapsulateBits"]);
process.emitWarning("m9d-canary");
`;

// ML-DSA alone: the ML-DSA-44 algorithm.
const DSA_ONLY = `
const { mlDsaGenerateSeed, mlDsaProviderFromSeed } = await import(${JSON.stringify(DIST + "ml-dsa.js")});
const p = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
await p.sign(new Uint8Array(1));
process.emitWarning("m9d-canary");
`;

describe("001-PQPRIM decision 13 — the post-quantum ExperimentalWarning filter", () => {
  it("the built modules exist (run the typecheck/build first)", () => {
    expect(existsSync(DIST + "ml-kem.js")).toBe(true);
    expect(existsSync(DIST + "ml-dsa.js")).toBe(true);
  });

  it("ml-kem.js ALONE: ML-KEM-768, getPublicKey, encapsulateBits, decapsulateBits print nothing; the canary prints", () => {
    const r = child(KEM_ONLY);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toContain("m9d-canary");
    expect(r.stderr).not.toContain("ExperimentalWarning");
  });

  it("ml-dsa.js ALONE: ML-DSA-44 prints nothing; the canary prints", () => {
    const r = child(DSA_ONLY);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toContain("m9d-canary");
    expect(r.stderr).not.toContain("ExperimentalWarning");
  });

  it("an unrelated ExperimentalWarning still prints (the filter matches the five API names, not the class)", () => {
    const r = child(`
await import(${JSON.stringify(DIST + "ml-kem.js")});
process.emitWarning("The frobnicate API is an experimental feature", "ExperimentalWarning");
`);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toContain("ExperimentalWarning: The frobnicate API");
  });

  it("a second, separate instance of the filter module (two installed copies) neither double-prints nor drops", () => {
    // The query string makes Node load a distinct module instance, as a second copy of the package would.
    const r = child(`
await import(${JSON.stringify(DIST + "ml-kem.js")});
await import(${JSON.stringify("file://" + DIST + "pq-warnings.js?copy=2")});
process.emitWarning("m9d-once");
`);
    expect(r.stderr.split("m9d-once").length - 1).toBe(1);
  });
});
