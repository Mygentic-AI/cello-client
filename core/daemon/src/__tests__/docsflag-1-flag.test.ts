/**
 * 074-DOCSFLAG clause 1 — one flag, default off, and absent configuration reads as OFF.
 *
 * The clause names its cases and this test uses THOSE values: absent, and then every spelling that
 * must NOT turn the layer on. The exemplar check applies — the interesting values here are the ones
 * that look affirmative to a human and are not on the affirmative list, because that is the branch
 * where a default-tight parser earns its keep.
 */
import { describe, it, expect } from "vitest";
import { documentsEnabled, documentLayerState, DOCUMENTS_FLAG_ENV } from "../document-flag.js";

describe("074-DOCSFLAG clause 1 — the flag", () => {
  it("names one variable, and it is the one the whole product agrees on", () => {
    expect(DOCUMENTS_FLAG_ENV).toBe("CELLO_DOCUMENTS");
  });

  it("ABSENT configuration reads as off — the clause's own case", () => {
    expect(documentsEnabled({})).toBe(false);
    expect(documentLayerState({})).toBe("off");
  });

  it("an explicitly empty value reads as off, not as present-therefore-on", () => {
    expect(documentsEnabled({ [DOCUMENTS_FLAG_ENV]: "" })).toBe(false);
  });

  it.each(["1", "true", "on", "yes", "TRUE", " on ", "Yes"])(
    "%s turns the layer on",
    (raw) => {
      expect(documentsEnabled({ [DOCUMENTS_FLAG_ENV]: raw })).toBe(true);
      expect(documentLayerState({ [DOCUMENTS_FLAG_ENV]: raw })).toBe("on");
    },
  );

  it.each(["0", "off", "false", "no", "enabled", "maybe", "ON!", "truthy"])(
    "%s does NOT turn the layer on — a misread must never loosen",
    (raw) => {
      expect(documentsEnabled({ [DOCUMENTS_FLAG_ENV]: raw })).toBe(false);
      expect(documentLayerState({ [DOCUMENTS_FLAG_ENV]: raw })).toBe("off");
    },
  );

  it("reads the real process environment when given nothing, so production has no second path", () => {
    const saved = process.env[DOCUMENTS_FLAG_ENV];
    try {
      delete process.env[DOCUMENTS_FLAG_ENV];
      expect(documentsEnabled()).toBe(false);
      process.env[DOCUMENTS_FLAG_ENV] = "1";
      expect(documentsEnabled()).toBe(true);
    } finally {
      if (saved === undefined) delete process.env[DOCUMENTS_FLAG_ENV];
      else process.env[DOCUMENTS_FLAG_ENV] = saved;
    }
  });
});
