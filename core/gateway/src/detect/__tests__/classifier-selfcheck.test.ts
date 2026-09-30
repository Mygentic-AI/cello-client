/**
 * 080-SCREENERCPU — the classifier must prove it works on this machine.
 *
 * On x86 CPUs without AVX512-VNNI the native int8 model scores EVERY message about 0.98, and the
 * gateway used to report Layer 2 active anyway. These tests hold the selection: a backend is used
 * only after it scores a fixed benign sentence low AND a fixed hostile one high.
 */
import { describe, it, expect } from "vitest";
import { selectClassifierBackend, SELFCHECK, type SelfCheckResult } from "../classifier-selfcheck.js";
import type { ClassifierLoad } from "../injection-classifier-onnx.js";
import { describeScreenerState, type ScreenerStatus } from "../screener-state.js";
import { SCREENER_MODEL } from "../screener-model-manifest.js";

/** The broken-CPU shape measured on the Support VM: the same score whatever the text. */
const constant = (p: number): ClassifierLoad => ({ classifier: { classify: async () => ({ injectionProbability: p }) } });
/** A classifier that tells the two self-check sentences apart, as a working backend does. */
const working: ClassifierLoad = {
  classifier: { classify: async (t: string) => ({ injectionProbability: t === SELFCHECK.hostile ? 0.999 : 0.0001 }) },
};

describe("080-SCREENERCPU: backend selection", () => {
  it("T1: native fails its self-check → WASM is used, and each backend's check is logged", async () => {
    const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const sel = await selectClassifierBackend({
      native: async () => constant(0.98),
      wasm: async () => working,
      log: (event, fields) => events.push({ event, fields }),
    });
    expect(sel.layer2).toBe("active:wasm");
    expect(sel.backend).toBe("wasm");
    expect(sel.classifier).not.toBeNull();
    const checks = events.filter((e) => e.event === "security.gateway.layer2.selfcheck");
    expect(checks.map((c) => [c.fields["backend"], c.fields["passed"]])).toEqual([["native", false], ["wasm", true]]);
    expect(checks[0]!.fields["benignP"]).toBe(0.98);
    expect(checks[0]!.fields["hostileP"]).toBe(0.98);
    expect(typeof checks[0]!.fields["ms"]).toBe("number");
    const backend = events.filter((e) => e.event === "security.gateway.layer2.backend");
    expect(backend).toHaveLength(1);
    expect(backend[0]!.fields["backend"]).toBe("wasm");
    expect(sel.checks.map((c: SelfCheckResult) => c.backend)).toEqual(["native", "wasm"]);
  });

  it("T2: both backends fail → Layer 2 is OFF, naming both backends' scores", async () => {
    const sel = await selectClassifierBackend({ native: async () => constant(0.98), wasm: async () => constant(0.5), log: () => {} });
    expect(sel.classifier).toBeNull();
    expect(sel.backend).toBe("off");
    expect(sel.layer2).toMatch(/^off:classifier failed its self-check on this machine \(native: benign 0\.980, hostile 0\.980; wasm: benign 0\.500, hostile 0\.500\)$/);
    // And the status line an operator reads never says "2 of 2" for it.
    const text = describeScreenerState(ready(), sel.layer2);
    expect(text).toContain("BROKEN");
    expect(text).not.toContain("2 of 2");
  });

  it("T2b: WASM that cannot even load is named as unavailable, with its reason", async () => {
    const sel = await selectClassifierBackend({
      native: async () => constant(0.98),
      wasm: async () => ({ classifier: null, reason: "onnxruntime-web is not installed" }),
      log: () => {},
    });
    expect(sel.layer2).toContain("wasm: unavailable — onnxruntime-web is not installed");
  });

  it("T2c: a hostile sentence scored LOW fails too — both conditions, not one", async () => {
    const sel = await selectClassifierBackend({ native: async () => constant(0.0001), wasm: async () => constant(0.0001), log: () => {} });
    expect(sel.backend).toBe("off");
  });

  it("T3: native passes → WASM is never built", async () => {
    let wasmBuilt: boolean | undefined;
    const sel = await selectClassifierBackend({
      native: async () => working,
      wasm: async () => { wasmBuilt = true; return working; },
      log: () => {},
    });
    expect(sel.layer2).toBe("active:native");
    expect(wasmBuilt).toBeUndefined();
  });

  it("a native load that never produced a classifier stays off with its own reason, and tries nothing else", async () => {
    let wasmBuilt: boolean | undefined;
    const sel = await selectClassifierBackend({
      native: async () => ({ classifier: null, reason: "no model at /x" }),
      wasm: async () => { wasmBuilt = true; return working; },
      log: () => {},
    });
    expect(sel.layer2).toBe("off:no model at /x");
    expect(wasmBuilt).toBeUndefined();
  });
});

function ready(): ScreenerStatus {
  const n = SCREENER_MODEL.files.length;
  return { state: "ready", revision: SCREENER_MODEL.revision, model: { filesPresent: n, filesExpected: n, verified: true }, runtimePresent: true, missing: [] };
}

describe("080-SCREENERCPU: the status line comes from what the gateway proved", () => {
  const rev = SCREENER_MODEL.revision.slice(0, 8);
  it("active:native reads exactly as before", () => {
    expect(describeScreenerState(ready(), "active:native")).toBe(`Screening: 2 of 2 layers active (classifier ${rev} verified).`);
  });
  it("active:wasm names WASM and why", () => {
    expect(describeScreenerState(ready(), "active:wasm")).toBe(
      `Screening: 2 of 2 layers active (classifier ${rev} verified, running on WASM — this CPU's native path gives wrong scores; long messages screen more slowly).`,
    );
  });
  it("files verified but no gateway report never claims 2 of 2", () => {
    for (const l2 of [undefined, "unreported", "active"]) {
      expect(describeScreenerState(ready(), l2)).not.toContain("2 of 2");
    }
  });
});
