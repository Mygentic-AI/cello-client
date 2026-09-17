/**
 * DOD-M9C-SCREENWIRE-1 — the classifier reads the WHOLE message, and knows this model's labels.
 *
 * Two defects this file holds down:
 *
 * 1. **Labels.** The classifier understood `INJECTION`/`SAFE`. Patronus emits `injection`/`benign`,
 *    so every benign message threw "classifier returned no INJECTION or SAFE label" — which the
 *    scanner turns into Layer 2 degraded. The screener would have reported itself broken on every
 *    ordinary message, which is the loudest possible way to be useless.
 * 2. **Truncation.** One pipeline call truncates at the model's window, so an attack past the cut is
 *    not screened — and nothing says so. A message longer than a window is split into overlapping
 *    windows and every one is scored.
 */
import { describe, it, expect } from "vitest";
import { buildWindows, aggregateWindowScores } from "../detect/injection-windows.js";
import { SCREENER_MODEL } from "../detect/screener-model-manifest.js";
import { injectionProbabilityOf } from "../detect/injection-classifier-onnx.js";

/** Token ids stand in for text: the real tokenizer's output is a number[] of exactly this shape. */
const ids = (n: number): number[] => Array.from({ length: n }, (_, i) => i);

describe("SCREENWIRE: windowing", () => {
  it("a message inside one window is one window — no needless splitting", () => {
    expect(buildWindows(ids(10), SCREENER_MODEL.windowTokens, SCREENER_MODEL.windowOverlapTokens)).toHaveLength(1);
    expect(buildWindows(ids(SCREENER_MODEL.windowTokens), 2048, 64)).toHaveLength(1);
  });

  it("splits a longer message into overlapping windows and drops NOTHING", () => {
    const tokens = ids(5000);
    const windows = buildWindows(tokens, 2048, 64);
    expect(windows.length).toBeGreaterThan(1);
    for (const w of windows) expect(w.length).toBeLessThanOrEqual(2048);
    // Every token is inside some window: truncation is exactly the defect this exists to prevent.
    const covered = new Set<number>();
    for (const w of windows) for (const t of w) covered.add(t);
    expect(covered.size).toBe(tokens.length);
  });

  it("overlaps by the card's 64 tokens, so an attack across a boundary is intact in one window", () => {
    const windows = buildWindows(ids(4096), 2048, 64);
    expect(windows[0]![2047]).toBe(2047);
    // The second window starts 64 tokens BEFORE the first one ended.
    expect(windows[1]![0]).toBe(2048 - 64);
  });

  it("never loops forever, whatever the overlap", () => {
    expect(buildWindows(ids(100), 10, 9).length).toBeLessThan(100);
    // An overlap >= the window would advance zero tokens per step; the builder must refuse it.
    expect(() => buildWindows(ids(100), 10, 10)).toThrow(/overlap/i);
  });

  it("scores the message by its WORST window — one hostile window is a hostile message", () => {
    // The card aggregates with normalised Smooth-Max; taking the maximum is the conservative form of
    // the same idea, and it is what 002's numbers are measured against. Averaging would let a long
    // benign preamble bury the injection it carries.
    expect(aggregateWindowScores([0.01, 0.99, 0.02])).toBeCloseTo(0.99);
    expect(aggregateWindowScores([0.1])).toBeCloseTo(0.1);
  });

  it("refuses to score no windows rather than inventing a zero", () => {
    // A fabricated 0 reads as "screened and clean" for content nothing looked at.
    expect(() => aggregateWindowScores([])).toThrow(/no window/i);
  });
});

describe("SCREENWIRE: this model's labels", () => {
  it("reads Patronus' own labels — injection / benign", () => {
    expect(injectionProbabilityOf([{ label: "injection", score: 0.97 }, { label: "benign", score: 0.03 }]).probability).toBeCloseTo(0.97);
    // Benign text: the complement, NOT benign's own score, which would read as low-injection for
    // the same reason it read as high. This threw before DOD-M9C-SCREENWIRE-1, on every ordinary
    // message, and the scanner reported Layer 2 degraded.
    const benignOnly = injectionProbabilityOf([{ label: "benign", score: 0.99 }]);
    expect(benignOnly.probability).toBeCloseTo(0.01);
    expect(benignOnly.label).toBe("benign");
  });

  it("still reads the older INJECTION / SAFE set", () => {
    expect(injectionProbabilityOf([{ label: "SAFE", score: 0.8 }]).probability).toBeCloseTo(0.2);
    expect(injectionProbabilityOf([{ label: "INJECTION", score: 0.6 }]).probability).toBeCloseTo(0.6);
  });

  it("THROWS on a label set it does not know rather than inventing a score", () => {
    expect(() => injectionProbabilityOf([{ label: "LABEL_0", score: 0.5 }])).toThrow(/no INJECTION, BENIGN or SAFE/);
  });
});
