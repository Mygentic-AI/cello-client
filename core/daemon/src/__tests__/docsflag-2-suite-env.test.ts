/**
 * 074-DOCSFLAG — the suite's own environment key actually arrived.
 *
 * `vitest.config.ts` sets `test.env.CELLO_DOCUMENTS = "1"` so that every existing document test runs
 * against the layer it was written for (clause 7). A vitest config key that DOES NOT EXIST is ignored
 * in silence — that exact failure mode is on this milestone's record, where a misspelled
 * `globalTeardown` let a deliberately poisoned database pass. If `env` were the wrong key, every
 * document test would fail loudly, which is fine; but if the key were merely IGNORED at the project
 * level the twenty-odd files would fail for a reason nobody would connect to this order.
 *
 * So the key is asserted directly, in the package whose tests depend on it most.
 */
import { describe, it, expect } from "vitest";
import { documentsEnabled, DOCUMENTS_FLAG_ENV } from "../document-flag.js";

describe("074-DOCSFLAG — the suite runs with documents ON, and the config key proves it", () => {
  it(`${DOCUMENTS_FLAG_ENV} reached this test process from vitest.config.ts`, () => {
    expect(process.env[DOCUMENTS_FLAG_ENV]).toBe("1");
    expect(documentsEnabled()).toBe(true);
  });
});
