/**
 * 080-SCREENERCPU T5 — `cello status` reports what the running gateway PROVED, not what is on disk.
 *
 * Verified files said "2 of 2 layers active" on Support while every message scored ~0.98. The
 * summary now comes from the gateway's reported `layer2`.
 */
import { describe, it, expect } from "vitest";
import { SCREENER_MODEL, type ScreenerStatus } from "@cello-protocol/gateway";
import { screeningInfoFrom, screeningSessionNoticeFrom } from "../screening-status.js";

const n = SCREENER_MODEL.files.length;
const ready: ScreenerStatus = {
  state: "ready", revision: SCREENER_MODEL.revision, runtimePresent: true, missing: [],
  model: { filesPresent: n, filesExpected: n, verified: true },
};
const OFF = "off:classifier failed its self-check on this machine (native: benign 0.980, hostile 0.980; wasm: benign 0.500, hostile 0.500)";

describe("080-SCREENERCPU T5: status reflects the gateway", () => {
  it("layer2=active:wasm → the summary names WASM", () => {
    const info = screeningInfoFrom(ready, "active:wasm");
    expect(info.classifier).toBe("ready");
    expect(info.summary).toContain("2 of 2 layers active");
    expect(info.summary).toContain("running on WASM");
  });

  it("layer2=off after a failed self-check → BROKEN, never 2 of 2, and the notice fires", async () => {
    const info = screeningInfoFrom(ready, OFF);
    expect(info.classifier).toBe("broken");
    expect(info.summary).toContain("BROKEN");
    expect(info.summary).not.toContain("2 of 2");
    expect(info.problem).toContain("self-check");
    const notice = await screeningSessionNoticeFrom(async () => info);
    expect(notice).toContain("did NOT judge");
    // --repair reinstalls the same verified files; it cannot change what this CPU computes.
    expect(notice).not.toContain("--repair");
  });

  it("no gateway report → verified files alone never read as 2 of 2", () => {
    expect(screeningInfoFrom(ready, undefined).summary).not.toContain("2 of 2");
  });
});
