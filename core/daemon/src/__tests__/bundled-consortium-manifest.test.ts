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
import { PRODUCTION_DIRECTORY_URL } from "../directory-bootstrap.js";
import { validatorNodes } from "@cello-protocol/protocol-types";
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
    expect(ids).toEqual(["gcp-use1", "gcp-usc1", "gcp-euw1"]);
    for (const node of BUNDLED_CONSORTIUM_MANIFEST.nodes) {
      expect(String(node["pubkey"])).toMatch(/^[0-9a-f]{64}$/);
      expect(node["provider"]).toBe("gcp");
      // The HTTP port that serves /bootstrap. 8080 speaks the libp2p WebSocket upgrade and answers
      // plain HTTP with 400, which resolves as zero reachable nodes from a valid manifest — so the
      // port is asserted, not just the scheme.
      expect(String(node["endpoint"])).toMatch(/^http:\/\/[\d.]+:9090$/);
      // The dial address is STATED, not derived from `endpoint`: they are different listeners on
      // different ports, and inferring one from the other is how anti-entropy broke.
      expect(String(node["multiaddr"])).toMatch(/^\/ip4\/[\d.]+\/tcp\/8080\/ws$/);
      expect(String(node["peerId"])).toMatch(/^12D3Koo/);
      // nodeId is `<cloud>-<region>` and the region is its second segment — step-6 looks up by
      // nodeId, so a node whose id and region disagree is unaddressable.
      expect(node["nodeId"]).toBe(`gcp-${node["region"]}`);
    }
  });

  it("is a THREE-VALIDATOR roster with distinct keys and distinct regions", () => {
    // Counted through validatorNodes(), the same helper the quorum is derived from — an earlier
    // version of this test computed `Math.floor(n / 2) + 1` and asserted it equalled 2, which is
    // arithmetic on a literal that no production code runs. It would have stayed green against a
    // client demanding all three nodes.
    const validators = validatorNodes(BUNDLED_CONSORTIUM_MANIFEST.nodes as never);
    expect(validators).toHaveLength(3);
    // Distinct signing keys — two nodes sharing one would let a single host answer as two members
    // of the quorum, which is the redundancy invariant defeated while looking satisfied.
    expect(new Set(validators.map((x) => x.pubkey)).size).toBe(validators.length);
    // Distinct regions: one region going down must not be able to take the rest with it.
    expect(new Set(validators.map((x) => x.region)).size).toBe(validators.length);
  });

  it("carries the intake key, so a cold-boot daemon can seal its first submission", () => {
    // Without this the signature test is the only thing standing between a v1 manifest and every
    // trust-signal submission refusing with `intake_key_absent` — and that test fails with
    // "expected false to be true", which names nothing. This one names the field.
    const intake = (BUNDLED_CONSORTIUM_MANIFEST as unknown as {
      intake_key?: { key_id?: string; pubkey?: string };
    }).intake_key;
    expect(intake, "a manifest with no intake_key refuses every submission").toBeDefined();
    expect(intake?.key_id).toBe("intake-dev-1");
    expect(String(intake?.pubkey)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("PRODUCTION_DIRECTORY_URL is one of the bundled endpoints — or cold boot loses step-6", () => {
    // The regression this catches is silent and security-relevant. buildManifestDeps loads the
    // bundled roster ONLY when the resolved directory URL matches a node endpoint; anything else
    // falls through to the pre-roster path with directory authentication OFF. Pointing the fallback
    // at a DNS name for the same machine looks harmless, reaches the same node, and disables the
    // defense against a MITM redirecting /bootstrap — with no error anywhere.
    const endpoints = BUNDLED_CONSORTIUM_MANIFEST.nodes.map((n) => String(n["endpoint"]));
    expect(endpoints).toContain(PRODUCTION_DIRECTORY_URL);
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

  it("WARNS when the skipped directory is public, and only informs for local dev", () => {
    // The two cases are not equivalent and must not read alike. 127.0.0.1 is the e2e harness and is
    // designed; a public host here is a client running against a real directory with identity
    // authentication off — weaker than the operator believes, and previously the ONLY signal was the
    // absence of a different log line.
    const lines: Array<{ level: string; event: string; detail: Record<string, unknown> }> = [];
    const rec = (level: string) => (event: string, detail?: Record<string, unknown>) =>
      lines.push({ level, event, detail: detail ?? {} });
    const logger = { info: rec("info"), warn: rec("warn"), error: rec("error"), debug: rec("debug") };

    process.env.CELLO_DIRECTORY_URL = "http://127.0.0.1:9099";
    buildManifestDeps(logger as never);
    expect(lines.at(-1)?.level, "loopback is designed — must not cry wolf").toBe("info");

    lines.length = 0;
    process.env.CELLO_DIRECTORY_URL = "http://directory-use1.cello.mygentic.ai:9090";
    buildManifestDeps(logger as never);
    const last = lines.at(-1);
    expect(last?.level, "a public directory outside the roster is a downgrade").toBe("warn");
    expect(last?.detail["step6"]).toBe("disabled");
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
    process.env.CELLO_DIRECTORY_URL = "http://34.34.166.245:9090"; // gcp-euw1, as it appears in the bundle
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
