/**
 * 001-PQPRIM decision 5 — `pq_runtime_unsupported` is what an operator on Node < 24.7 sees, and it
 * must not be mistaken for a bad key.
 *
 * The two shapes below are copied from a real Node 24.6.0 run (journal, 001-PQPRIM): 24.6 rejects the
 * `raw-seed`/`raw-public` KEY FORMAT before it ever looks at the algorithm, with a TypeError — not the
 * NotSupportedError an unknown algorithm name gives. Classifying only NotSupportedError reported
 * "ML-KEM-768 seed import failed" (ml_kem_seed_invalid) to an operator whose key was fine.
 */
import { describe, it, expect } from "vitest";
import { isUnsupportedAlgorithm } from "../pq-errors.js";

function nodeTypeError(message: string, code: string): Error {
  const e = new TypeError(message) as TypeError & { code: string };
  e.code = code;
  return e;
}

describe("isUnsupportedAlgorithm — the runtime-too-old shapes", () => {
  it("Node 24.6: raw-seed / raw-public is not a KeyFormat (TypeError ERR_INVALID_ARG_VALUE)", () => {
    const e = nodeTypeError(
      "Failed to execute 'importKey' on 'SubtleCrypto': 1st argument value 'raw-seed' is not a valid enum value of type KeyFormat.",
      "ERR_INVALID_ARG_VALUE",
    );
    expect(isUnsupportedAlgorithm(e)).toBe(true);
  });

  it("an unknown algorithm name (DOMException NotSupportedError)", () => {
    expect(isUnsupportedAlgorithm(new DOMException("Unrecognized algorithm name", "NotSupportedError"))).toBe(true);
  });

  it("a genuine data error is NOT a runtime problem", () => {
    expect(isUnsupportedAlgorithm(new DOMException("Invalid keyData", "DataError"))).toBe(false);
    expect(isUnsupportedAlgorithm(nodeTypeError("The \"data\" argument must be of type ArrayBuffer", "ERR_INVALID_ARG_TYPE"))).toBe(false);
    expect(isUnsupportedAlgorithm("not an error")).toBe(false);
  });
});
