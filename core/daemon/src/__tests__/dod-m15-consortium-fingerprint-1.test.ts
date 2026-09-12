/**
 * DOD-M15-CONSORTIUM-FINGERPRINT-1 — the client knows which network is ours and now says so.
 *
 * The defence already existed: a manifest not signed by `BUNDLED_CONSORTIUM_ROOT_KEYS` is refused.
 * What was missing is that its answer never reached a human, so "am I on the real network?" was a
 * judgement call instead of a command.
 *
 * The hollow test this suite is written to avoid is clause 2's: asserting the printed fingerprint
 * equals a hardcoded literal passes even when the printed value and the ENFORCED constant have
 * drifted apart, which is the one failure that matters — a status line reassuring an operator who is
 * on a fake network. So the tracking test substitutes a DIFFERENT root key set into the module the
 * verifier reads and asserts the printed value moves with it.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import {
  BUNDLED_CONSORTIUM_MANIFEST,
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
} from "../bundled-consortium-manifest.js";
import {
  consortiumFingerprintFull,
  consortiumFingerprintPreimage,
  consortiumFingerprintShort,
  consortiumPosture,
  describeConsortiumFingerprint,
} from "../consortium-fingerprint.js";
import { EmbeddedManifestProvider } from "../file-manifest-provider.js";
import {
  makeTestManifest,
  TEST_CONSORTIUM_ROOT_KEYS,
  TEST_CONSORTIUM_THRESHOLD,
} from "@cello-protocol/crypto";
import type { ConsortiumManifestInput } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

const EXPECTED_SHORT = consortiumFingerprintShort(
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
);
const EXPECTED_FULL = consortiumFingerprintFull(
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
);

describe("DOD-M15-CONSORTIUM-FINGERPRINT-1: the printed value tracks the ENFORCED key set", () => {
  /**
   * Clause 2, stated as a relationship rather than a value, and pointed at the thing that is
   * actually enforced.
   *
   * The block is handed the root keys the daemon gives `loadAndVerify`. Feeding it a DIFFERENT set —
   * what a fork's operator would have — must move the printed value. A second hardcoded copy of the
   * real fingerprint anywhere in the display path survives every value-equality assertion and dies
   * here.
   */
  it("a different enforced key set produces a different printed fingerprint", () => {
    const forkKeys = ["f".repeat(64)];

    const block = describeConsortiumFingerprint({ rootKeys: forkKeys, threshold: 1 });

    expect(block["consortium_root_fingerprint"]).toBe(consortiumFingerprintShort(forkKeys, 1));
    expect(block["consortium_root_fingerprint"]).not.toBe(EXPECTED_SHORT);
    expect(block["consortium_root_fingerprint_state"]).toBe("overridden");
    // And the genuine value is shown BESIDE it, so the reader can see what they are not on.
    expect(block["consortium_root_fingerprint_bundled"]).toBe(EXPECTED_SHORT);
  });

  /** The bundled posture is the one an ordinary operator is in, and it says so without hedging. */
  it("the compiled-in key set reports the bundled posture and the published value", () => {
    const block = describeConsortiumFingerprint({
      rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS,
      threshold: BUNDLED_CONSORTIUM_THRESHOLD,
    });

    expect(block["consortium_root_fingerprint"]).toBe(EXPECTED_SHORT);
    expect(block["consortium_root_fingerprint_state"]).toBe("bundled");
    // Not repeated when it would be the same number twice — comparing a value with itself is how a
    // reader concludes something from nothing.
    expect(block).not.toHaveProperty("consortium_root_fingerprint_bundled");
  });

  /**
   * The posture review found: `buildManifestDeps` returns `{}` when the directory URL is not a
   * bundled endpoint, so NOTHING is verified. A fingerprint here would describe a check that is not
   * running — the reassurance-on-a-fake-network failure this whole order exists to prevent.
   */
  it("with no enforced key set it reports NO fingerprint, and says why", () => {
    for (const enforced of [
      { rootKeys: undefined, threshold: undefined },
      { rootKeys: [], threshold: 1 },
      { rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS, threshold: undefined },
      { rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS, threshold: 0 },
    ]) {
      const block = describeConsortiumFingerprint(enforced);
      expect(block["consortium_root_fingerprint"]).toBeNull();
      expect(block["consortium_root_fingerprint_state"]).toBe("not_anchored");
      expect(block).not.toHaveProperty("consortium_root_fingerprint_full");
      expect(String(block["consortium_root_fingerprint_guidance"])).toContain("verifying NO consortium manifest");
    }
  });

  /** Ours is recognised as ours however it is spelled, so a reorder is not reported as an override. */
  it("a reordered, differently-cased copy of our own key set is still `bundled`", () => {
    expect(
      consortiumPosture({
        rootKeys: [...BUNDLED_CONSORTIUM_ROOT_KEYS].map((k) => k.toUpperCase()).reverse(),
        threshold: BUNDLED_CONSORTIUM_THRESHOLD,
      }),
    ).toBe("bundled");
  });

  /** The threshold is enforced alongside the keys, so it is inside the preimage. */
  it("the same keys at a different threshold fingerprint differently, and read as an override", () => {
    expect(consortiumFingerprintFull(BUNDLED_CONSORTIUM_ROOT_KEYS, 1)).not.toBe(
      consortiumFingerprintFull(BUNDLED_CONSORTIUM_ROOT_KEYS, 2),
    );
    expect(consortiumPosture({ rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS, threshold: 2 })).toBe("overridden");
  });

  /** Order is not identity: a cosmetic reordering must not read as a different consortium. */
  it("key ORDER and case do not change the fingerprint", () => {
    const keys = ["b".repeat(64), "a".repeat(64)];
    expect(consortiumFingerprintFull(keys, 1)).toBe(
      consortiumFingerprintFull(["A".repeat(64), "B".repeat(64)], 1),
    );
  });

  /** The short form is what an eye compares, so its shape is asserted, not its value. */
  it("the short form is four groups of four hex characters", () => {
    expect(EXPECTED_SHORT).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
    expect(EXPECTED_SHORT.replace(/-/g, "")).toBe(EXPECTED_FULL.slice(0, 16));
  });
});

describe("DOD-M15-CONSORTIUM-FINGERPRINT-1: both status surfaces answer the question", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];
  let logger: Logger;
  let events: Array<{ event: string; ctx: Record<string, unknown> }>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-fingerprint-"));
    handle = null;
    clients = [];
    events = [];
    logger = {
      debug() {}, warn() {}, error() {},
      info(event: string, ctx?: Record<string, unknown>) { events.push({ event, ctx: ctx ?? {} }); },
    } as unknown as Logger;
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* already closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  /**
   * ⚠️ THE MANIFEST DEPS ARE REAL, and the first cut of this suite omitted them.
   *
   * A daemon booted with no `manifestProvider` verifies no manifest at all — the `not_anchored`
   * posture. Asserting "the fingerprint is printed" there certifies the one state in which a
   * fingerprint would be a lie. Every surface test now boots a daemon that is actually verifying
   * something, and says which key set it is verifying against.
   */
  async function boot(enforced?: { manifest: ConsortiumManifestInput; rootKeys: readonly string[]; threshold: number }): Promise<DaemonConfig> {
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      ...(enforced
        ? {
            manifestProvider: new EmbeddedManifestProvider(enforced.manifest),
            manifestRootKeys: enforced.rootKeys,
            manifestThreshold: enforced.threshold,
          }
        : {}),
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return config;
  }

  const bundled = () => ({
    manifest: BUNDLED_CONSORTIUM_MANIFEST,
    rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS,
    threshold: BUNDLED_CONSORTIUM_THRESHOLD,
  });

  /**
   * The CLI surface. An operator asking "is this the real CELLO?" runs `cello status`, and this is
   * what it renders.
   */
  it("`cello status` prints the fingerprint beside the roster", async () => {
    await boot(bundled());
    const status = (await clients[0]!.send("status")) as Record<string, unknown>;

    expect(status["consortium_root_fingerprint"]).toBe(EXPECTED_SHORT);
    expect(status["consortium_root_fingerprint_full"]).toBe(EXPECTED_FULL);
    expect(status["consortium_root_fingerprint_state"]).toBe("bundled");
    expect(String(status["consortium_root_fingerprint_guidance"])).toContain(
      "https://cello.mygentic.ai/fingerprint",
    );
  });

  /** The agent-facing surface. An agent asked the same question must be able to answer it too. */
  it("`cello_status` carries the same fingerprint", async () => {
    await boot(bundled());
    const status = (await clients[0]!.send("cello_status")) as Record<string, unknown>;

    expect(status["consortium_root_fingerprint"]).toBe(EXPECTED_SHORT);
    expect(status["consortium_root_fingerprint_full"]).toBe(EXPECTED_FULL);
    expect(status["consortium_root_fingerprint_state"]).toBe("bundled");
  });

  /**
   * THE BYPASS THIS CLOSES: a hardcoded copy of the real fingerprint added in either status module
   * passes every assertion above, because they compare against the real value. Here the daemon is
   * verifying a DIFFERENT consortium, so both surfaces must print a value that is not ours — and a
   * literal cannot.
   */
  for (const surface of ["status", "cello_status"] as const) {
    it(`${surface} prints the OVERRIDING key set, not the compiled-in one`, async () => {
      await boot({
        manifest: makeTestManifest([
          {
            nodeId: "test-1",
            pubkey: "a".repeat(64),
            region: "use1",
            provider: "gcp",
            endpoint: "http://127.0.0.1:1",
          },
        ]),
        rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
        threshold: TEST_CONSORTIUM_THRESHOLD,
      });
      const status = (await clients[0]!.send(surface)) as Record<string, unknown>;

      const expected = consortiumFingerprintShort(TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD);
      expect(status["consortium_root_fingerprint"]).toBe(expected);
      expect(status["consortium_root_fingerprint"]).not.toBe(EXPECTED_SHORT);
      expect(status["consortium_root_fingerprint_state"]).toBe("overridden");
      expect(status["consortium_root_fingerprint_bundled"]).toBe(EXPECTED_SHORT);
      expect(String(status["consortium_root_fingerprint_guidance"])).toContain("CELLO_CONSORTIUM_ROOT_KEYS");
    });
  }

  /**
   * And the posture where nothing is verified: no provider, no root keys. Printing our fingerprint
   * here would tell an operator pointed at a fork that they are on CELLO.
   */
  for (const surface of ["status", "cello_status"] as const) {
    it(`${surface} reports NO fingerprint when this daemon verifies no manifest`, async () => {
      await boot();
      const status = (await clients[0]!.send(surface)) as Record<string, unknown>;

      expect(status["consortium_root_fingerprint"]).toBeNull();
      expect(status["consortium_root_fingerprint_state"]).toBe("not_anchored");
      expect(String(status["consortium_root_fingerprint_guidance"])).toContain("verifying NO consortium manifest");
    });
  }

  /**
   * Clause 6 — one grep answers "which network is this daemon on".
   *
   * The startup event carries the fingerprint, so the question is answerable from a log file days
   * later, when the daemon that printed the status is gone. It reports the ENFORCED set, so the
   * grep cannot come back reassuring about a daemon that was anchored to nothing.
   */
  it("a startup log event names the enforced fingerprint and posture", async () => {
    await boot(bundled());

    const emitted = events.find((e) => e.event === "daemon.consortium.anchored");
    expect(emitted, "no daemon.consortium.anchored event was emitted at startup").toBeDefined();
    expect(emitted!.ctx["fingerprint"]).toBe(EXPECTED_SHORT);
    expect(emitted!.ctx["fingerprintFull"]).toBe(EXPECTED_FULL);
    expect(emitted!.ctx["posture"]).toBe("bundled");
  });

  it("the startup event says `not_anchored` rather than naming CELLO when nothing is verified", async () => {
    await boot();

    const emitted = events.find((e) => e.event === "daemon.consortium.anchored");
    expect(emitted).toBeDefined();
    expect(emitted!.ctx["posture"]).toBe("not_anchored");
    expect(emitted!.ctx["fingerprint"]).toBeNull();
    // The bundled value is still carried, so one grep tells you which client BINARY it was.
    expect(emitted!.ctx["bundledFingerprint"]).toBe(EXPECTED_SHORT);
  });
});

describe("DOD-M15-CONSORTIUM-FINGERPRINT-1: the published copies cannot drift", () => {
  /**
   * Clause 3 + 4. The fingerprint has to be obtainable by someone who has installed NOTHING, which
   * means it lives in files a stranger can read from the public repo and the site. Every one of
   * those is GENERATED from the constant, and this test is what catches the day one of them is not
   * regenerated.
   */
  const publishedIn = [
    "consortium-fingerprint.json",
    "README.md",
    "plugins/cello/skills/setup/SKILL.md",
  ];

  for (const rel of publishedIn) {
    it(`${rel} publishes the fingerprint the client enforces`, async () => {
      const text = await readFile(join(REPO_ROOT, rel), "utf8");
      // Positive control: prove the read reached the intended file before believing what it lacks.
      expect(text.length, `${rel} is empty — the read did not reach the file`).toBeGreaterThan(0);
      expect(text).toContain(EXPECTED_SHORT);
      expect(text).toContain(EXPECTED_FULL);
      /**
       * And on the MARKDOWN surfaces the recompute command has to be RUNNABLE as printed. The
       * README's first cut had a placeholder the reader was expected to fill in, which is not a
       * check anyone performs — the whole argument for publishing it is that a stranger can paste
       * it. The JSON copy carries the same command escaped for JSON and has its own assertion
       * below, against the same preimage.
       */
      if (rel.endsWith(".md")) {
        const recompute = /printf '([^']*)' \| shasum -a 256/.exec(text);
        expect(recompute, `${rel} carries no runnable recompute command`).not.toBeNull();
        expect(recompute![1]!.replace(/\\n/g, "\n")).toBe(
          consortiumFingerprintPreimage(BUNDLED_CONSORTIUM_ROOT_KEYS, BUNDLED_CONSORTIUM_THRESHOLD),
        );
      }
    });
  }

  /** The machine-readable copy is the one a pre-install checker fetches, so its shape is pinned. */
  it("consortium-fingerprint.json carries the root keys and threshold it was derived from", async () => {
    const raw = await readFile(join(REPO_ROOT, "consortium-fingerprint.json"), "utf8");
    const doc = JSON.parse(raw) as Record<string, unknown>;

    expect(doc["fingerprint"]).toBe(EXPECTED_SHORT);
    expect(doc["fingerprint_full"]).toBe(EXPECTED_FULL);
    expect(doc["root_keys"]).toEqual([...BUNDLED_CONSORTIUM_ROOT_KEYS]);
    expect(doc["threshold"]).toBe(BUNDLED_CONSORTIUM_THRESHOLD);
    // Recomputable by a stranger with sha256 and nothing else — that is what makes it checkable
    // before install rather than a value they have to take on faith.
    expect(String(doc["recompute"])).toContain("cello-consortium-root-v1");

    /**
     * The recipe has to RECOMPUTE the value, not merely mention the domain string. A published
     * command that produces a different digest sends a stranger checking us to the conclusion that
     * they are on a fake network — the false alarm that costs the most, because after it nobody
     * checks again.
     *
     * The payload is compared against the preimage the client itself hashes, so the two cannot
     * drift; the shell is not invoked, only the bytes it would print.
     */
    const payload = /printf '([^']*)'/.exec(String(doc["recompute"]));
    expect(payload, "the recompute recipe is not a printf of the preimage").not.toBeNull();
    expect(payload![1]!.replace(/\\n/g, "\n")).toBe(
      consortiumFingerprintPreimage(BUNDLED_CONSORTIUM_ROOT_KEYS, BUNDLED_CONSORTIUM_THRESHOLD),
    );
  });
});

describe("DOD-M15-CONSORTIUM-FINGERPRINT-1: the refusal is untouched and names its cause", () => {
  /**
   * Clause 5. This order makes the answer visible; it must not weaken the thing being answered
   * about. A manifest signed by a different root key is still refused, and the refusal says why.
   */
  it("a manifest signed by a different root key is refused by name", async () => {
    const provider = new EmbeddedManifestProvider(BUNDLED_CONSORTIUM_MANIFEST);

    await expect(
      provider.loadAndVerify(["9".repeat(64)], BUNDLED_CONSORTIUM_THRESHOLD),
    ).rejects.toThrow(/manifest_signature_invalid/);
    // And nothing was adopted — a refusal that leaves the manifest loaded is not a refusal.
    expect(provider.getCurrentManifest()).toBeNull();
  });

  it("the genuine root keys still load it", async () => {
    const provider = new EmbeddedManifestProvider(BUNDLED_CONSORTIUM_MANIFEST);
    await expect(
      provider.loadAndVerify(BUNDLED_CONSORTIUM_ROOT_KEYS, BUNDLED_CONSORTIUM_THRESHOLD),
    ).resolves.toBeDefined();
  });
});

describe("DOD-M15-CONSORTIUM-FINGERPRINT-1: the value is not configurable", () => {
  /** A fingerprint an operator can override is one an attacker can talk them into overriding. */
  it("no environment variable changes the printed fingerprint", () => {
    const enforced = { rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS, threshold: BUNDLED_CONSORTIUM_THRESHOLD };
    const before = describeConsortiumFingerprint(enforced);
    const saved = { ...process.env };
    try {
      process.env["CELLO_CONSORTIUM_ROOT_KEYS"] = "e".repeat(64);
      process.env["CELLO_CONSORTIUM_THRESHOLD"] = "9";
      process.env["CELLO_CONSORTIUM_FINGERPRINT"] = "0000-0000-0000-0000";
      expect(describeConsortiumFingerprint(enforced)).toEqual(before);
    } finally {
      process.env = saved;
    }
  });
});
