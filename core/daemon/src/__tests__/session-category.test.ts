import { describe, it, expect } from "vitest";
import { classifySession } from "../session-category.js";

/**
 * The operator-facing session taxonomy (open / closed / failed) derived from the raw status +
 * message count. This is the single source of truth for the `cello status` filter and the
 * `cello sessions` / cello_list_sessions flags, so the bucket boundaries must be pinned.
 */
describe("classifySession", () => {
  it("active → open", () => {
    expect(classifySession("active", 0)).toBe("open");
    expect(classifySession("active", 7)).toBe("open");
  });

  it("interrupted WITH messages → open (resumable)", () => {
    expect(classifySession("interrupted", 1)).toBe("open");
    expect(classifySession("interrupted", 42)).toBe("open");
  });

  it("interrupted with ZERO messages → failed (a dead handshake — never resumable)", () => {
    expect(classifySession("interrupted", 0)).toBe("failed");
  });

  it("sealed / seal_interrupted_pending → closed", () => {
    expect(classifySession("sealed", 4)).toBe("closed");
    expect(classifySession("seal_interrupted_pending", 4)).toBe("closed");
  });
});
