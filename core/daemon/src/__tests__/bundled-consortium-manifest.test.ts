/**
 * FINDING-4 — bundled consortium roster + default manifest wiring.
 *
 * Covers:
 *  - The COMPILED-IN manifest constant is well-formed and verifies against its pinned root keys
 *    (so the daemon's default path always has a valid roster + step-6 anchor; a bad regeneration is
 *    caught here rather than bricking every daemon at startup).
 *  - EmbeddedManifestProvider verifies the in-memory manifest and fails CLOSED on a bad root key.
 *  - buildManifestDeps default path (no CELLO_CONSORTIUM_MANIFEST) returns the bundled roster with
 *    step-6 (challengeVerifier) ON and no poll scheduler; the override (env) path still works.
 *
 * Crypto reference: RFC 8032 (Ed25519 threshold signatures via verifyManifest).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { verifyManifest } from "@cello-protocol/crypto";
import {
  makeTestManifest,
  TEST_CONSORTIUM_ROOT_KEYS,
  TEST_CONSORTIUM_THRESHOLD,
} from "@cello-protocol/crypto";
import {
  BUNDLED_CONSORTIUM_MANIFEST,
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
} from "../bundled-consortium-manifest.js";
import { EmbeddedManifestProvider } from "../file-manifest-provider.js";
import { buildManifestDeps } from "../manifest-deps.js";
import type { Logger } from "../types.js";

function nullLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

const MANIFEST_ENV_KEYS = [
  "CELLO_CONSORTIUM_MANIFEST",
  "CELLO_CONSORTIUM_ROOT_KEYS",
  "CELLO_CONSORTIUM_THRESHOLD",
  "CELLO_MANIFEST_POLL_MIN_MS",
  "CELLO_MANIFEST_POLL_MAX_MS",
  // CELLO_DIRECTORY_URL gates the bundled default: unset → production default (a bundled node) →
  // bundle loads; a non-bundled URL → M6 path. Cleared here so the "no env" case is deterministic.
  "CELLO_DIRECTORY_URL",
] as const;

describe("FINDING-4: bundled consortium manifest constant", () => {
  it("verifies against its pinned root keys at the pinned threshold", () => {
    const res = verifyManifest(
      BUNDLED_CONSORTIUM_MANIFEST,
      BUNDLED_CONSORTIUM_ROOT_KEYS,
      BUNDLED_CONSORTIUM_THRESHOLD,
    );
    expect(res.ok).toBe(true);
  });

  it("lists the three sovereign directories with well-formed nodes", () => {
    const ids = BUNDLED_CONSORTIUM_MANIFEST.nodes.map((n) => n["nodeId"]);
    expect(ids).toEqual(["us-east-1", "eu-central-1", "ap-northeast-1"]);
    for (const node of BUNDLED_CONSORTIUM_MANIFEST.nodes) {
      expect(String(node["pubkey"])).toMatch(/^[0-9a-f]{64}$/);
      expect(String(node["endpoint"])).toMatch(/^http:\/\/directory-/);
      expect(node["provider"]).toBe("aws");
      // nodeId MUST equal region (the directory reports NODE_ID = its AWS region; step-6 looks up by nodeId)
      expect(node["nodeId"]).toBe(node["region"]);
    }
  });

  it("has a sane, non-degenerate validity window", () => {
    const nb = Date.parse(BUNDLED_CONSORTIUM_MANIFEST.not_before);
    const ex = Date.parse(BUNDLED_CONSORTIUM_MANIFEST.expires);
    expect(Number.isNaN(nb)).toBe(false);
    expect(Number.isNaN(ex)).toBe(false);
    expect(ex).toBeGreaterThan(nb);
  });
});

describe("FINDING-4: EmbeddedManifestProvider", () => {
  it("loadAndVerify caches the manifest when signatures verify", async () => {
    const p = new EmbeddedManifestProvider(BUNDLED_CONSORTIUM_MANIFEST);
    expect(p.getCurrentManifest()).toBeNull();
    const m = await p.loadAndVerify(BUNDLED_CONSORTIUM_ROOT_KEYS, BUNDLED_CONSORTIUM_THRESHOLD);
    expect(m.nodes).toHaveLength(3);
    expect(p.getCurrentManifest()).not.toBeNull();
  });

  it("fails CLOSED (throws) when verified against a wrong root key", async () => {
    const p = new EmbeddedManifestProvider(BUNDLED_CONSORTIUM_MANIFEST);
    const wrongKey = "00".repeat(32);
    await expect(p.loadAndVerify([wrongKey], 1)).rejects.toThrow(/manifest_signature_invalid/);
    expect(p.getCurrentManifest()).toBeNull();
  });
});

describe("FINDING-4: buildManifestDeps default (bundled) vs override (env) path", () => {
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    saved = {};
    for (const k of MANIFEST_ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of MANIFEST_ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("with no env: loads the bundled roster with step-6 ON and no poll scheduler", async () => {
    const deps = buildManifestDeps(nullLogger());
    expect(deps.manifestProvider).toBeDefined();
    expect(deps.challengeVerifier).toBeDefined();
    expect(deps.manifestRootKeys).toEqual(BUNDLED_CONSORTIUM_ROOT_KEYS);
    expect(deps.manifestThreshold).toBe(BUNDLED_CONSORTIUM_THRESHOLD);
    expect(deps.manifestPollScheduler).toBeUndefined();
    // the provider actually verifies + exposes the 3-node roster
    const m = await deps.manifestProvider!.loadAndVerify(deps.manifestRootKeys!, deps.manifestThreshold!);
    expect(m.nodes).toHaveLength(3);
  });

  it("with no env: does NOT load the bundle when pointed at a non-bundled directory (M6 path)", () => {
    // local dev / e2e spine harness point CELLO_DIRECTORY_URL at their own local directory, which
    // the bundled roster cannot authenticate — must fall through to M6 (no roster, no step-6) rather
    // than force step-6 and reject every connection.
    process.env.CELLO_DIRECTORY_URL = "http://127.0.0.1:9099";
    const deps = buildManifestDeps(nullLogger());
    expect(deps.manifestProvider).toBeUndefined();
    expect(deps.challengeVerifier).toBeUndefined();
    expect(deps.manifestRootKeys).toBeUndefined();
  });

  it("with no env but CELLO_DIRECTORY_URL pointed at a bundled node: loads the bundle", () => {
    process.env.CELLO_DIRECTORY_URL = "http://directory-eu1.cello.mygentic.ai";
    const deps = buildManifestDeps(nullLogger());
    expect(deps.manifestProvider).toBeDefined();
    expect(deps.challengeVerifier).toBeDefined();
  });

  it("with CELLO_CONSORTIUM_MANIFEST but missing root keys: throws (fails loud)", () => {
    process.env.CELLO_CONSORTIUM_MANIFEST = "/tmp/does-not-matter.json";
    expect(() => buildManifestDeps(nullLogger())).toThrow(/ROOT_KEYS|THRESHOLD/);
  });

  it("with a valid override manifest file: returns a file-backed provider + step-6", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-manifest-"));
    try {
      const path = join(dir, "manifest.json");
      const manifest = makeTestManifest([
        { nodeId: "us-east-1", pubkey: "aa".repeat(32), region: "us-east-1", provider: "aws", endpoint: "http://d.example" },
      ]);
      await writeFile(path, JSON.stringify(manifest), "utf8");
      process.env.CELLO_CONSORTIUM_MANIFEST = path;
      process.env.CELLO_CONSORTIUM_ROOT_KEYS = TEST_CONSORTIUM_ROOT_KEYS.join(",");
      process.env.CELLO_CONSORTIUM_THRESHOLD = String(TEST_CONSORTIUM_THRESHOLD);
      const deps = buildManifestDeps(nullLogger());
      expect(deps.manifestProvider).toBeDefined();
      expect(deps.challengeVerifier).toBeDefined();
      const m = await deps.manifestProvider!.loadAndVerify(deps.manifestRootKeys!, deps.manifestThreshold!);
      expect(m.nodes).toHaveLength(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
