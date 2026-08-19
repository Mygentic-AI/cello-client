/**
 * Tier SCREEN — THE WIRING IS THE UNIT, so the wiring is what gets asserted.
 *
 * The review that produced this file reverted each of the three composition-root lines in turn and
 * found 2451 daemon tests and 178 gateway tests still green. Each of those lines is the single thing
 * that makes its unit real in production — and shipping a correct, well-tested layer that no code
 * constructs is the EXACT defect DOD-DOC-SCREEN-CLASSIFIER-1 exists to fix. Reproducing it in the
 * commits that fix it is not acceptable.
 *
 * These assert against the BUILT ARTIFACT rather than the source tree, because that is the thing an
 * operator runs, and because a stale `dist/` has shipped deleted code in this repo before. They are
 * deliberately narrow: they prove the call site EXISTS in what ships, not that it behaves — the
 * behaviour is covered by the unit suites. What they catch is the failure mode those suites cannot:
 * a feature switched off by deleting one argument.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = join(PKG_ROOT, "..", "..");
const DAEMON_DIST = join(PKG_ROOT, "dist", "daemon.js");
const GATEWAY_DIST = join(REPO_ROOT, "core", "gateway", "dist", "bin", "cello-gateway.js");

let daemon = "";
let gateway = "";

beforeAll(async () => {
  // A missing artifact must FAIL, never skip. "The build was not run" is indistinguishable from
  // "the wiring is gone" if the assertion quietly passes.
  expect(existsSync(DAEMON_DIST), `${DAEMON_DIST} — run pnpm build`).toBe(true);
  expect(existsSync(GATEWAY_DIST), `${GATEWAY_DIST} — run pnpm build`).toBe(true);
  daemon = await readFile(DAEMON_DIST, "utf8");
  gateway = await readFile(GATEWAY_DIST, "utf8");
});

describe("the shipped daemon wires document classification into the inbound screen", () => {
  it("passes isDocumentFrame to setOnDocumentFrame — without it, every document frame takes a screen that destroys it", () => {
    expect(daemon).toContain("setOnDocumentFrame(documentLayer.onDocumentFrame, isDocumentFrame)");
  });

  it("imports the classifier from the router rather than re-deriving it", () => {
    // A second copy of the discriminator is how the ingest and the router come to disagree about
    // what a document frame is — one skipping a screen the other does not.
    expect(daemon).toContain("isDocumentFrame");
    expect(daemon).toContain("document-frame-router.js");
  });
});

describe("the shipped daemon wires the semantic screen into the document layer", () => {
  it("passes screenProjected to createDocumentLayer — without it, Layer 2 never sees document text", () => {
    expect(daemon).toContain("screenProjected");
    // The bridge must reach the real gateway, not a local stand-in.
    expect(daemon).toMatch(/screenProjected[\s\S]{0,2000}securityGateway\.screenInbound/);
  });

  it("names the degradation when the gateway cannot answer", () => {
    // A weaker guarantee that looks identical to the stronger one at every surface is how this
    // class of defect survives; the log line is the whole difference.
    expect(daemon).toContain("document.inbound.screen.unavailable");
  });
});

describe("the shipped gateway constructs the injection scanner", () => {
  it("passes an injectionScanner to InboundScreener — the line whose absence turned Layer 2 off in every build", () => {
    expect(gateway).toContain("injectionScanner");
    expect(gateway).toContain("InboundScreener");
  });

  it("announces which state semantic screening is in, at startup", () => {
    // "Is it on?" must be answerable from a log line rather than by reading a composition root.
    expect(gateway).toContain("semantic injection screening ACTIVE");
    expect(gateway).toContain("semantic injection screening OFF");
  });
});
