/**
 * 001-PQPRIM decision 13 — Node's ExperimentalWarnings for the five post-quantum Web Crypto APIs are
 * dropped, and ONLY those.
 *
 * Runs a child `node` over the BUILT modules (dist/), because a warning filter is a process-level
 * side effect: it has to be proven in a fresh process that loads the primitives the way an operator's
 * CLI does. The child uses all five APIs and emits a canary warning; stderr must carry the canary
 * (other warnings still print) and no ExperimentalWarning (the five are dropped).
 *
 * Needs `tsc --build` to have run (the gate runs typecheck, which emits). A missing dist fails loudly.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DIST = fileURLToPath(new URL("../../dist/", import.meta.url));

const CHILD = `
const { mlKemGenerateSeed, mlKemKeypairFromSeed, mlKemEncapsulate, mlKemDecapsulate } = await import(${JSON.stringify(DIST + "ml-kem.js")});
const { mlDsaGenerateSeed, mlDsaProviderFromSeed } = await import(${JSON.stringify(DIST + "ml-dsa.js")});
const seed = mlKemGenerateSeed();
const { publicKey } = await mlKemKeypairFromSeed(seed);
const { ciphertext } = await mlKemEncapsulate(publicKey);
await mlKemDecapsulate(seed, ciphertext);
const s = globalThis.crypto.subtle;
const k = await s.importKey("raw-seed", seed, { name: "ML-KEM-768" }, false, ["decapsulateBits"]);
await s.getPublicKey(k, ["encapsulateBits"]);
const p = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
await p.sign(new Uint8Array(1));
process.emitWarning("m9d-canary");
await new Promise((r) => setImmediate(r));
`;

describe("001-PQPRIM decision 13 — the post-quantum ExperimentalWarning filter", () => {
  it("the built modules exist (run the typecheck/build first)", () => {
    expect(existsSync(DIST + "ml-kem.js")).toBe(true);
    expect(existsSync(DIST + "ml-dsa.js")).toBe(true);
  });

  it("a child using all five APIs prints the canary and no ExperimentalWarning", () => {
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", CHILD], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toContain("m9d-canary");
    expect(r.stderr).not.toContain("ExperimentalWarning");
  });

  it("an unrelated ExperimentalWarning still prints (the filter matches the five API names, not the class)", () => {
    const script = `
await import(${JSON.stringify(DIST + "ml-kem.js")});
process.emitWarning("The frobnicate API is an experimental feature", "ExperimentalWarning");
await new Promise((r) => setImmediate(r));
`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toContain("ExperimentalWarning: The frobnicate API");
  });

  it("a second, separate instance of the filter module (two installed copies) neither double-prints nor drops", () => {
    // The query string makes Node load a distinct module instance, as a second copy of the package would.
    const script = `
await import(${JSON.stringify(DIST + "ml-kem.js")});
await import(${JSON.stringify("file://" + DIST + "pq-warnings.js?copy=2")});
process.emitWarning("m9d-once");
await new Promise((r) => setImmediate(r));
`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
    expect(r.stderr.split("m9d-once").length - 1).toBe(1);
  });
});
