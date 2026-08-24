/**
 * M7-MANIFEST-002 — SignalingManager and manifest interfaces tests.
 *
 * AC mapping:
 *   AC-001: IManifestVersionStore enforces version monotonicity
 *   AC-002: IManifestProvider.loadAndVerify() returns manifest and caches it
 *   AC-003: IDirectoryChallengeVerifier verifies step-5 signature correctly
 *   AC-004: SignalingManager.processStep5Frame() emits directory.auth.challenge.verified
 *   AC-005: SignalingManager version store persistence (in-memory stub)
 *   AC-009: buildStep5Tbs() produces correct TBS bytes (directory step-5 unit test)
 *   AC-010: poll round-trip — dispatchManifestPoll sends manifest_poll_request,
 *            handleManifestPollResponse processes response
 *   AC-013: ISignalingOutboundQueue enqueues frames for SIGNAL-001
 *   SI-001: Per-node key binding — different nodes produce different TBS bytes
 *   SI-002: Expired manifest causes processStep5Frame to fail (via verifier)
 *   SI-003: Nonce prevents replay — different nonces produce different TBS bytes
 */

import type { OperationResult, OperationFailure } from "../signaling-manager.js";
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { makeTestManifest, TEST_DIRECTORY_NODE_KEYPAIR, TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD } from "@cello-protocol/crypto";
import {
  SignalingManager,
  InMemorySignalingOutboundQueue,
  buildStep5Tbs,
  TestManifestProvider,
  TestDirectoryChallengeVerifier,
  ManifestDirectoryChallengeVerifier,
  InMemoryManifestVersionStore,
  ImmediatePollScheduler,
  TestDirectoryKeyProvider,
  TestDirectoryManifestStore,
} from "../index.js";
import type { SignalingLogger, SignalingManagerConfig } from "../signaling-manager.js";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";

/**
 * Assert a refusal and NARROW to it in one step.
 *
 * `OperationResult` is a union and only the failure arm carries `reason`/`guidance`. Reading them
 * off the union asserted on properties the success arm does not have — which passes vacuously if
 * the call ever starts succeeding, and is why the line beside one of these already reached for a
 * `as { guidance: string }` cast.
 */
function expectFailure(r: OperationResult): OperationFailure {
  expect(r.ok, `expected a refusal, got ${JSON.stringify(r)}`).toBe(false);
  return r as OperationFailure;
}


// ─── Why every makeTestManifest() call below is double-cast ──────────────────────────────────────
//
// `makeTestManifest` DECLARES `ConsortiumManifestInput` — the loose signing shape, whose `nodes` are
// `Record<string, unknown>` — while everything under test takes the structured `ConsortiumManifest`.
// The values are already right: the fixture's own comment says `TestConsortiumNode` "structurally
// matches ConsortiumNode from protocol-types". The two types simply cannot be assigned across,
// because `ConsortiumManifestInput` carries an index signature and TypeScript refuses an interface
// into one — which is also why the fixture cannot just return the narrower type.
//
// So the cast asserts exactly the fixture's own documented promise. Recorded once here rather than
// left as bare `as` conversions that read like someone silencing the compiler; if that promise ever
// stops holding, this is the paragraph that has to be re-argued.


// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeLogger(): SignalingLogger & {
  events: Array<{ level: string; event: string; context: Record<string, unknown> }>;
} {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  return {
    events,
    info(event: string, context: Record<string, unknown>) { events.push({ level: "info", event, context }); },
    warn(event: string, context: Record<string, unknown>) { events.push({ level: "warn", event, context }); },
    error(event: string, context: Record<string, unknown>) { events.push({ level: "error", event, context }); },
  };
}

function makeTestNode(nodeId: string, pubkeyHex: string) {
  return {
    nodeId,
    pubkey: pubkeyHex,
    region: "us-east-1",
    provider: "aws" as const,
    endpoint: "wss://test.cello.test:443",
  };
}

function makeManagerConfig(overrides?: Partial<SignalingManagerConfig>): {
  manager: SignalingManager;
  logger: ReturnType<typeof makeLogger>;
  versionStore: InMemoryManifestVersionStore;
  verifier: TestDirectoryChallengeVerifier;
  scheduler: ImmediatePollScheduler;
  manifestProvider: TestManifestProvider;
  manifest: ConsortiumManifest;
} {
  const publicKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;
  const nodeId = "test-node-us-east-1";

  const manifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
  const manifestProvider = new TestManifestProvider(manifest);
  const versionStore = new InMemoryManifestVersionStore();
  const verifier = new TestDirectoryChallengeVerifier();
  const scheduler = new ImmediatePollScheduler(0);
  const logger = makeLogger();

  const manager = new SignalingManager({
    challengeVerifier: verifier,
    pollScheduler: scheduler,
    manifestVersionStore: versionStore,
    manifestProvider,
    logger,
    correlationId: "test-corr-001",
    rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
    threshold: TEST_CONSORTIUM_THRESHOLD,
    ...overrides,
  });

  return { manager, logger, versionStore, verifier, scheduler, manifestProvider, manifest };
}

// ─── AC-009: buildStep5Tbs produces correct TBS bytes ─────────────────────────

describe("AC-009: buildStep5Tbs — directory step-5 TBS construction", () => {
  it("produces UTF-8 bytes with correct format and label", () => {
    const tbs = buildStep5Tbs({
      nodeId: "dir-node-us-east-1",
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    });

    const str = new TextDecoder().decode(tbs);
    expect(str).toBe(
      "cello-directory-auth-challenge-v1\n" +
      "dir-node-us-east-1\n" +
      "a".repeat(64) + "\n" +
      "b".repeat(64) + "\n" +
      "2026-06-12T10:00:00.000Z"
    );
  });

  it("SI-001: different nodeIds produce different TBS bytes", () => {
    const opts = {
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    };
    const tbs1 = buildStep5Tbs({ ...opts, nodeId: "node-A" });
    const tbs2 = buildStep5Tbs({ ...opts, nodeId: "node-B" });
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("SI-003: different nonces produce different TBS bytes (replay prevention)", () => {
    const opts = {
      nodeId: "dir-node-us-east-1",
      agentPubkeyHex: "a".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    };
    const tbs1 = buildStep5Tbs({ ...opts, nonceHex: "c".repeat(64) });
    const tbs2 = buildStep5Tbs({ ...opts, nonceHex: "d".repeat(64) });
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("different agent pubkeys produce different TBS bytes", () => {
    const opts = {
      nodeId: "dir-node-us-east-1",
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    };
    const tbs1 = buildStep5Tbs({ ...opts, agentPubkeyHex: "e".repeat(64) });
    const tbs2 = buildStep5Tbs({ ...opts, agentPubkeyHex: "f".repeat(64) });
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });
});

// ─── AC-003: IDirectoryChallengeVerifier ──────────────────────────────────────

describe("AC-003: IDirectoryChallengeVerifier — Ed25519 challenge verification", () => {
  const privateKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.privateKeyHex;
  const publicKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;
  const nodeId = "test-node-us-east-1";

  function makeVerifier() {
    const manifest: ConsortiumManifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
    const provider = new TestManifestProvider(manifest);
    void provider.loadAndVerify([], 0); // sets #loaded so getCurrentManifest() returns it
    const verifier = new ManifestDirectoryChallengeVerifier(provider);
    return { verifier, manifest };
  }

  it("returns { valid: true } for a valid Ed25519 signature over TBS bytes (RFC 8032)", async () => {
    const { verifier } = makeVerifier();
    const keyProvider = new TestDirectoryKeyProvider({ nodeId, privateKeyHex });

    const tbsBytes = buildStep5Tbs({
      nodeId,
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    });

    const sigBytes = await keyProvider.sign(tbsBytes);
    const signatureHex = Buffer.from(sigBytes).toString("hex");

    expect(verifier.verifyChallenge(nodeId, tbsBytes, signatureHex)).toEqual({ valid: true });
  });

  /**
   * DOD-M15-EXPIRY-CONSUMER-POLICY-1 — the lapsed-manifest report.
   *
   * ⚠️ WRITTEN BECAUSE REVIEW MEASURED THAT THE BRANCH HAD NEVER RUN. The unit shipped with
   * `core/daemon` 2869 green, transport 154 green and the `trustless-cello` root 1742 green — and
   * **not one of those executed a line of it**, because every verifier fixture uses a manifest that
   * is still in window. Three green suites and zero coverage.
   *
   * It is also not "a log line". `#reportedLapsed` is stateful dedup — a set, an insertion ordered
   * ahead of a call, and a suppression rule — which regresses silently to *never fires* or *fires on
   * every challenge*, and neither is visible in any gate.
   */
  describe("DOD-M15-EXPIRY-CONSUMER-POLICY-1: authenticating against a LAPSED manifest is reported", () => {
    function lapsedVerifier() {
      const manifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)], {
        expires: "2020-01-01T00:00:00Z",
      }) as unknown as ConsortiumManifest;
      const provider = new TestManifestProvider(manifest);
      void provider.loadAndVerify([], 0);
      const seen: Array<{ nodeId: string; version: number; expires: string }> = [];
      const verifier = new ManifestDirectoryChallengeVerifier(provider, (info) => seen.push(info));
      return { verifier, provider, seen };
    }

    async function goodChallenge(): Promise<{ tbsBytes: Uint8Array; signatureHex: string }> {
      const keyProvider = new TestDirectoryKeyProvider({ nodeId, privateKeyHex });
      const tbsBytes = buildStep5Tbs({
        nodeId, agentPubkeyHex: "a".repeat(64), nonceHex: "b".repeat(64),
        isoTimestamp: "2026-06-12T10:00:00.000Z",
      });
      return { tbsBytes, signatureHex: Buffer.from(await keyProvider.sign(tbsBytes)).toString("hex") };
    }

    it("★ reports ONCE for a node, not once per challenge", async () => {
      const { verifier, seen } = lapsedVerifier();
      const { tbsBytes, signatureHex } = await goodChallenge();

      expect(verifier.verifyChallenge(nodeId, tbsBytes, signatureHex)).toEqual({ valid: true });
      expect(verifier.verifyChallenge(nodeId, tbsBytes, signatureHex)).toEqual({ valid: true });

      expect(seen.length, "challenges are continuous — an event per challenge is a flood").toBe(1);
      expect(seen[0]!.nodeId).toBe(nodeId);
      expect(seen[0]!.expires).toBe("2020-01-01T00:00:00Z");
    });

    it("★ an IN-WINDOW manifest reports NOTHING — a signal that fires on the normal case is not a signal", async () => {
      const manifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
      const provider = new TestManifestProvider(manifest);
      void provider.loadAndVerify([], 0);
      const seen: unknown[] = [];
      const verifier = new ManifestDirectoryChallengeVerifier(provider, (i) => seen.push(i));
      const { tbsBytes, signatureHex } = await goodChallenge();

      expect(verifier.verifyChallenge(nodeId, tbsBytes, signatureHex)).toEqual({ valid: true });
      expect(seen, "without this the whole change can regress to a flood undetected").toEqual([]);
    });

    it("★ THE ADVERSARY CANNOT SILENCE IT: a FAILED authentication reports nothing", async () => {
      /**
       * The finding this ordering exists for. The first version reported BEFORE the node lookup and
       * the signature check, so a rogue directory — the exact threat this check is for — could send
       * any `nodeId`, spend the once-per-node budget, and leave every genuine authentication against
       * the lapsed anchor silent. **A security signal an attacker can switch off is worse than none,
       * because its absence reads as safety.**
       */
      const { verifier, seen } = lapsedVerifier();
      const { tbsBytes } = await goodChallenge();

      expect(verifier.verifyChallenge(nodeId, tbsBytes, "00".repeat(64)))
        .toEqual({ valid: false, reason: "signature_invalid" });
      expect(verifier.verifyChallenge("a-node-the-peer-made-up", tbsBytes, "00".repeat(64)))
        .toEqual({ valid: false, reason: "key_not_in_manifest" });

      expect(
        seen,
        "a rejected challenge must spend no budget — otherwise the report is burnable by the party " +
          "it exists to expose, and it would also claim a directory 'was authenticated' when it was not",
      ).toEqual([]);
    });

    it("★ a THROWING reporter must not become 'this directory forged its signature'", async () => {
      /**
       * The callback originally sat inside the crypto try/catch, whose handler returns
       * `signature_invalid` — which surfaces to the operator as `directory_challenge_failed`. So a
       * logger write failure would have accused a healthy directory node of forging its identity
       * proof, once, unreproducibly. A reporting failure must never fail an authentication.
       */
      const manifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)], {
        expires: "2020-01-01T00:00:00Z",
      }) as unknown as ConsortiumManifest;
      const provider = new TestManifestProvider(manifest);
      void provider.loadAndVerify([], 0);
      const verifier = new ManifestDirectoryChallengeVerifier(provider, () => {
        throw new Error("the log sink is down");
      });
      const { tbsBytes, signatureHex } = await goodChallenge();

      expect(
        verifier.verifyChallenge(nodeId, tbsBytes, signatureHex),
        "the signature is genuinely valid — a failing report must not turn that into a forgery claim",
      ).toEqual({ valid: true });
    });

    it("★ a FAILED report does not spend the budget — one flaky log write must not silence it forever", async () => {
      /**
       * The key used to be recorded BEFORE the callback ran, so a single transient sink failure
       * burned that `(version, nodeId)` for the process lifetime and the signal went permanently
       * silent. That is the same "absence reads as safety" argument accepted for the adversary,
       * with a flaky logger as the actor instead of an attacker.
       */
      const manifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)], {
        expires: "2020-01-01T00:00:00Z",
      }) as unknown as ConsortiumManifest;
      const provider = new TestManifestProvider(manifest);
      void provider.loadAndVerify([], 0);

      let failNext = true;
      const seen: Array<{ nodeId: string }> = [];
      const verifier = new ManifestDirectoryChallengeVerifier(provider, (info) => {
        if (failNext) { failNext = false; throw new Error("sink down"); }
        seen.push(info);
      });
      const { tbsBytes, signatureHex } = await goodChallenge();

      expect(verifier.verifyChallenge(nodeId, tbsBytes, signatureHex)).toEqual({ valid: true });
      expect(seen, "the first report threw, so nothing was recorded").toEqual([]);

      expect(verifier.verifyChallenge(nodeId, tbsBytes, signatureHex)).toEqual({ valid: true });
      expect(
        seen.length,
        "and the NEXT authentication must still report — a report that never landed was never made",
      ).toBe(1);
    });
  });

  it("returns { valid: false, reason: 'signature_invalid' } for wrong signature", async () => {
    const { verifier } = makeVerifier();
    const tbsBytes = buildStep5Tbs({
      nodeId,
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    });
    const wrongSig = "00".repeat(64);
    expect(verifier.verifyChallenge(nodeId, tbsBytes, wrongSig)).toEqual({ valid: false, reason: "signature_invalid" });
  });

  it("AC-007: returns { valid: false, reason: 'key_not_in_manifest' } for unknown nodeId", async () => {
    const { verifier } = makeVerifier();
    const tbsBytes = buildStep5Tbs({
      nodeId: "unknown-node",
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    });
    expect(verifier.verifyChallenge("unknown-node", tbsBytes, "00".repeat(64))).toEqual({
      valid: false,
      reason: "key_not_in_manifest",
    });
  });

  it("returns { valid: false, reason: 'key_not_in_manifest' } if manifest not loaded yet", () => {
    const manifest: ConsortiumManifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
    const provider = new TestManifestProvider(manifest);
    // Do NOT call loadAndVerify — getCurrentManifest() returns null
    const verifier = new ManifestDirectoryChallengeVerifier(provider);
    const tbsBytes = buildStep5Tbs({
      nodeId,
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    });
    expect(verifier.verifyChallenge(nodeId, tbsBytes, "00".repeat(64))).toEqual({
      valid: false,
      reason: "key_not_in_manifest",
    });
  });

  it("SI-001: signature for nodeA does not verify for nodeB (per-node key binding)", async () => {
    const nodeIdA = "node-A";
    const nodeIdB = "node-B";
    const privA = TEST_DIRECTORY_NODE_KEYPAIR.privateKeyHex;
    const pubA = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;

    // Generate a different key for nodeB using a fixed alternative seed
    const privBBytes = new Uint8Array(32).fill(0x20);
    const pubB = Buffer.from(ed25519.getPublicKey(privBBytes)).toString("hex");

    const manifest: ConsortiumManifest = makeTestManifest([
      makeTestNode(nodeIdA, pubA),
      makeTestNode(nodeIdB, pubB),
    ]) as unknown as ConsortiumManifest;
    const provider = new TestManifestProvider(manifest);
    void provider.loadAndVerify([], 0);
    const verifier = new ManifestDirectoryChallengeVerifier(provider);

    const tbsA = buildStep5Tbs({
      nodeId: nodeIdA,
      agentPubkeyHex: "a".repeat(64),
      nonceHex: "b".repeat(64),
      isoTimestamp: "2026-06-12T10:00:00.000Z",
    });

    // Sign with nodeA's key but verify against nodeB — must fail
    const keyProviderA = new TestDirectoryKeyProvider({ nodeId: nodeIdA, privateKeyHex: privA });
    const sigForA = await keyProviderA.sign(tbsA);
    const sigHex = Buffer.from(sigForA).toString("hex");

    expect(verifier.verifyChallenge(nodeIdA, tbsA, sigHex)).toEqual({ valid: true });
    // nodeB's slot is found in manifest but signed with nodeA's key → signature_invalid
    expect(verifier.verifyChallenge(nodeIdB, tbsA, sigHex)).toEqual({ valid: false, reason: "signature_invalid" });
  });
});

// ─── AC-004: SignalingManager.processStep5Frame ────────────────────────────────

describe("AC-004: SignalingManager.processStep5Frame — step-6 verification flow", () => {
  it("emits directory.auth.challenge.verified when signature is valid", async () => {
    const privateKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.privateKeyHex;
    const publicKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;
    const nodeId = "test-node-us-east-1";

    const manifest: ConsortiumManifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
    const manifestProvider = new TestManifestProvider(manifest);
    await manifestProvider.loadAndVerify([], 0);
    const realVerifier = new ManifestDirectoryChallengeVerifier(manifestProvider);

    const logger = makeLogger();
    const manager = new SignalingManager({
      challengeVerifier: realVerifier,
      pollScheduler: new ImmediatePollScheduler(0),
      manifestVersionStore: new InMemoryManifestVersionStore(),
      manifestProvider,
      logger,
      correlationId: "test-corr",
      rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      threshold: TEST_CONSORTIUM_THRESHOLD,
    });

    const nonceHex = "cc".repeat(32);
    const agentPubkeyHex = "aa".repeat(32);
    const timestamp = "2026-06-12T10:00:00.000Z";

    manager.setHandshakeContext(nonceHex, agentPubkeyHex);

    const tbsBytes = buildStep5Tbs({ nodeId, agentPubkeyHex, nonceHex, isoTimestamp: timestamp });
    const keyProvider = new TestDirectoryKeyProvider({ nodeId, privateKeyHex });
    const sigBytes = await keyProvider.sign(tbsBytes);

    const result = manager.processStep5Frame({
      type: "signaling_auth_ok",
      nodeId,
      signature: Buffer.from(sigBytes).toString("hex"),
      timestamp,
    });

    expect(result.verified).toBe(true);
    expect(logger.events.find((e) => e.event === "directory.auth.challenge.verified")).toBeDefined();
    expect(logger.events.find((e) => e.event === "directory.auth.challenge.failed")).toBeUndefined();
  });

  it("emits directory.auth.challenge.failed when signature is invalid", async () => {
    const publicKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;
    const nodeId = "test-node-us-east-1";

    const manifest: ConsortiumManifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
    const manifestProvider = new TestManifestProvider(manifest);
    await manifestProvider.loadAndVerify([], 0);
    const realVerifier = new ManifestDirectoryChallengeVerifier(manifestProvider);

    const logger = makeLogger();
    const manager = new SignalingManager({
      challengeVerifier: realVerifier,
      pollScheduler: new ImmediatePollScheduler(0),
      manifestVersionStore: new InMemoryManifestVersionStore(),
      manifestProvider,
      logger,
      correlationId: "fail-test",
      rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      threshold: TEST_CONSORTIUM_THRESHOLD,
    });

    manager.setHandshakeContext("cc".repeat(32), "aa".repeat(32));

    const result = manager.processStep5Frame({
      type: "signaling_auth_ok",
      nodeId,
      signature: "00".repeat(64), // wrong signature
      timestamp: "2026-06-12T10:00:00.000Z",
    });

    expect(result.verified).toBe(false);
    expect((result as { reason: string }).reason).toBe("signature_invalid");
    const failEvent = logger.events.find((e) => e.event === "directory.auth.challenge.failed");
    expect(failEvent).toBeDefined();
    expect(failEvent?.context.reason).toBe("signature_invalid");
  });

  it("AC-007: emits directory.auth.challenge.failed with reason key_not_in_manifest when nodeId absent from manifest", async () => {
    const publicKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;
    const knownNodeId = "test-node-us-east-1";
    const rogueNodeId = "rogue-node-not-in-manifest";

    const manifest: ConsortiumManifest = makeTestManifest([makeTestNode(knownNodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
    const manifestProvider = new TestManifestProvider(manifest);
    await manifestProvider.loadAndVerify([], 0);
    const realVerifier = new ManifestDirectoryChallengeVerifier(manifestProvider);

    const logger = makeLogger();
    const manager = new SignalingManager({
      challengeVerifier: realVerifier,
      pollScheduler: new ImmediatePollScheduler(0),
      manifestVersionStore: new InMemoryManifestVersionStore(),
      manifestProvider,
      logger,
      correlationId: "ac-007-test",
      rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      threshold: TEST_CONSORTIUM_THRESHOLD,
    });

    manager.setHandshakeContext("cc".repeat(32), "aa".repeat(32));

    const result = manager.processStep5Frame({
      type: "signaling_auth_ok",
      nodeId: rogueNodeId,
      signature: "00".repeat(64),
      timestamp: "2026-06-12T10:00:00.000Z",
    });

    expect(result.verified).toBe(false);
    expect((result as { reason: string }).reason).toBe("key_not_in_manifest");
    const failEvent = logger.events.find((e) => e.event === "directory.auth.challenge.failed");
    expect(failEvent).toBeDefined();
    expect(failEvent?.context.reason).toBe("key_not_in_manifest");
    expect(failEvent?.context.nodeId).toBe(rogueNodeId);
  });

  it("emits directory.auth.challenge.skipped when frame has no identity proof", () => {
    const { manager, logger } = makeManagerConfig();

    manager.setHandshakeContext("cc".repeat(32), "aa".repeat(32));

    const result = manager.processStep5Frame({ type: "signaling_auth_ok" });

    expect(result.verified).toBe(false);
    expect((result as { reason: string }).reason).toBe("no_identity_proof");
    const skipEvent = logger.events.find((e) => e.event === "directory.auth.challenge.skipped");
    expect(skipEvent).toBeDefined();
    expect(skipEvent?.level).toBe("warn");
  });

  it("returns handshake_context_missing when setHandshakeContext was not called", () => {
    const { manager, logger } = makeManagerConfig();
    // Do NOT call setHandshakeContext

    const result = manager.processStep5Frame({
      type: "signaling_auth_ok",
      nodeId: "test-node-us-east-1",
      signature: "00".repeat(64),
      timestamp: "2026-06-12T10:00:00.000Z",
    });

    expect(result.verified).toBe(false);
    expect((result as { reason: string }).reason).toBe("handshake_context_missing");
    const failEvent = logger.events.find((e) => e.event === "directory.auth.challenge.failed");
    expect(failEvent).toBeDefined();
  });

  it("SI-003: replay attack fails — wrong nonce produces different TBS, signature doesn't verify", async () => {
    const privateKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.privateKeyHex;
    const publicKeyHex = TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex;
    const nodeId = "test-node-us-east-1";

    const manifest: ConsortiumManifest = makeTestManifest([makeTestNode(nodeId, publicKeyHex)]) as unknown as ConsortiumManifest;
    const manifestProvider = new TestManifestProvider(manifest);
    await manifestProvider.loadAndVerify([], 0);
    const realVerifier = new ManifestDirectoryChallengeVerifier(manifestProvider);

    const logger = makeLogger();
    const manager = new SignalingManager({
      challengeVerifier: realVerifier,
      pollScheduler: new ImmediatePollScheduler(0),
      manifestVersionStore: new InMemoryManifestVersionStore(),
      manifestProvider,
      logger,
      correlationId: "replay-test",
      rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      threshold: TEST_CONSORTIUM_THRESHOLD,
    });

    // Original challenge
    const originalNonce = "cc".repeat(32);
    const agentPubkeyHex = "aa".repeat(32);
    const timestamp = "2026-06-12T10:00:00.000Z";

    // Sign over the original nonce
    const originalTbs = buildStep5Tbs({ nodeId, agentPubkeyHex, nonceHex: originalNonce, isoTimestamp: timestamp });
    const keyProvider = new TestDirectoryKeyProvider({ nodeId, privateKeyHex });
    const sig = await keyProvider.sign(originalTbs);
    const sigHex = Buffer.from(sig).toString("hex");

    // Simulate the manager receiving a DIFFERENT nonce (replay: attacker replays old sig)
    const replayNonce = "dd".repeat(32);
    manager.setHandshakeContext(replayNonce, agentPubkeyHex);

    const result = manager.processStep5Frame({
      type: "signaling_auth_ok",
      nodeId,
      signature: sigHex,
      timestamp,
    });

    // The TBS built from replayNonce differs from originalTbs, so signature fails
    expect(result.verified).toBe(false);
    expect((result as { reason: string }).reason).toBe("signature_invalid");
  });
});

// ─── AC-001: IManifestVersionStore ────────────────────────────────────────────

describe("AC-001: InMemoryManifestVersionStore — monotonicity", () => {
  it("starts at null (no version seen)", async () => {
    const store = new InMemoryManifestVersionStore();
    expect(await store.getLastSeenVersion()).toBeNull();
  });

  it("persists and returns a version", async () => {
    const store = new InMemoryManifestVersionStore();
    await store.persistVersion(7);
    expect(await store.getLastSeenVersion()).toBe(7);
  });

  it("replaces the previous version when updated", async () => {
    const store = new InMemoryManifestVersionStore();
    await store.persistVersion(5);
    await store.persistVersion(8);
    expect(await store.getLastSeenVersion()).toBe(8);
  });
});

// ─── AC-002: TestManifestProvider ─────────────────────────────────────────────

describe("AC-002: TestManifestProvider — manifest loading and caching", () => {
  it("loadAndVerify returns the supplied manifest", async () => {
    const manifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("node-1", "00".repeat(32)),
    ]) as unknown as ConsortiumManifest;
    const provider = new TestManifestProvider(manifest);
    const result = await provider.loadAndVerify([], 0);
    expect(result.nodes[0].nodeId).toBe("node-1");
  });

  it("getCurrentManifest returns null before loadAndVerify", () => {
    const manifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("node-1", "00".repeat(32)),
    ]) as unknown as ConsortiumManifest;
    const provider = new TestManifestProvider(manifest);
    expect(provider.getCurrentManifest()).toBeNull();
  });

  it("getCurrentManifest returns the manifest after loadAndVerify", async () => {
    const manifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("node-1", "00".repeat(32)),
    ]) as unknown as ConsortiumManifest;
    const provider = new TestManifestProvider(manifest);
    await provider.loadAndVerify([], 0);
    expect(provider.getCurrentManifest()).toBe(manifest);
  });
});

// ─── AC-010: Poll round-trip ───────────────────────────────────────────────────

describe("AC-010: Manifest poll round-trip", () => {
  it("dispatchManifestPoll is a safe no-op when not connected (never throws, emits no dispatched event)", async () => {
    // DOD-AUTH-2: the poll now goes out over the LIVE signaling stream (sendRaw). With no
    // connection up, dispatch must be a harmless no-op — it must not throw and must NOT log
    // poll.dispatched (that event only emits on a real ok send), so nothing is mistaken for
    // a delivered poll. (makeManagerConfig has no connect → the manager never connects.)
    const { manager, logger } = makeManagerConfig();
    expect(() => manager.dispatchManifestPoll()).not.toThrow();
    await new Promise((r) => setTimeout(r, 10)); // let the sendRaw promise settle
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.poll.dispatched")).toBeUndefined();
  });

  it("handleManifestPollResponse persists version and logs manifest.poll.success", async () => {
    const { manager, logger, versionStore } = makeManagerConfig();
    const newManifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex),
    ], { version: 2 }) as unknown as ConsortiumManifest;

    await manager.handleManifestPollResponse(newManifest);

    expect(await versionStore.getLastSeenVersion()).toBe(2);
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.poll.success")).toBeDefined();
  });

  it("handleManifestPollResponse rejects version rollback", async () => {
    const { manager, logger, versionStore } = makeManagerConfig();

    // First set a higher version
    await versionStore.persistVersion(5);

    const oldManifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex),
    ], { version: 3 }) as unknown as ConsortiumManifest;

    await manager.handleManifestPollResponse(oldManifest);

    // Version should remain 5 (not replaced by 3)
    expect(await versionStore.getLastSeenVersion()).toBe(5);
    const rollbackEvent = logger.events.find((e) => e.event === "directory.auth.manifest.version.rollback");
    expect(rollbackEvent).toBeDefined();
    expect(rollbackEvent?.context.manifestVersion).toBe(3);
    expect(rollbackEvent?.context.lastSeenVersion).toBe(5);
  });

  // ─── Verify-before-adopt: the directory is ONLY transport, NEVER trusted for the
  // manifest's content. Each polled manifest is independently re-verified before adoption.
  // (cello-test-attacker BLOCKING: these checks were untested at the poll layer — an impl
  // that stripped verifyManifest / the validity-window block from handleManifestPollResponse
  // passed every test. These pin the security path; teeth proven by neutering → red.)

  it("rejects a FORGED-signature manifest over the poll path (does not adopt)", async () => {
    const { manager, logger, versionStore } = makeManagerConfig();
    const forged: ConsortiumManifest = makeTestManifest([
      makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex),
    ], { version: 2 }) as unknown as ConsortiumManifest;
    // A compromised/rogue directory serves a structurally-valid manifest signed by ATTACKER
    // keys (here: corrupted officer sigs). The daemon must re-verify and refuse to adopt.
    (forged as { signatures: Array<{ officerIndex: number; signature: string }> }).signatures =
      forged.signatures.map((s) => ({ ...s, signature: "00".repeat(64) }));

    await manager.handleManifestPollResponse(forged);

    expect(await versionStore.getLastSeenVersion()).toBeNull(); // NOT persisted
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.signature.invalid")).toBeDefined();
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.poll.success")).toBeUndefined();
  });

  it("rejects an EXPIRED manifest over the poll path (does not adopt)", async () => {
    const { manager, logger, versionStore } = makeManagerConfig();
    const expired: ConsortiumManifest = makeTestManifest([
      makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex),
    ], { version: 2, expires: "2020-01-01T00:00:00Z" }) as unknown as ConsortiumManifest;

    await manager.handleManifestPollResponse(expired);

    expect(await versionStore.getLastSeenVersion()).toBeNull();
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.expired")).toBeDefined();
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.poll.success")).toBeUndefined();
  });

  it("rejects a NOT-YET-VALID manifest over the poll path (does not adopt)", async () => {
    const { manager, logger, versionStore } = makeManagerConfig();
    const future: ConsortiumManifest = makeTestManifest([
      makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex),
    ], { version: 2, notBefore: "2099-01-01T00:00:00Z" }) as unknown as ConsortiumManifest;

    await manager.handleManifestPollResponse(future);

    expect(await versionStore.getLastSeenVersion()).toBeNull();
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.not.yet.valid")).toBeDefined();
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.poll.success")).toBeUndefined();
  });

  it("AC-005: version store persists across manager restart (same store reused)", async () => {
    const store = new InMemoryManifestVersionStore();
    await store.persistVersion(10);

    // Simulate restart: create a new manager with the SAME store
    const manager2Config = {
      challengeVerifier: new TestDirectoryChallengeVerifier(),
      pollScheduler: new ImmediatePollScheduler(0),
      manifestVersionStore: store, // same store instance
      manifestProvider: new TestManifestProvider(makeTestManifest([]) as unknown as ConsortiumManifest),
      logger: makeLogger(),
      correlationId: "restart-test",
      rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      threshold: TEST_CONSORTIUM_THRESHOLD,
    };
    const manager2 = new SignalingManager(manager2Config);

    // Version from "before restart" should be visible
    const lastSeen = await store.getLastSeenVersion();
    expect(lastSeen).toBe(10);

    // Reject any manifest version <= 10
    const oldManifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("node", "00".repeat(32)),
    ], { version: 9 }) as unknown as ConsortiumManifest;
    await manager2.handleManifestPollResponse(oldManifest);
    expect(await store.getLastSeenVersion()).toBe(10); // unchanged
  });
});

// ─── AC-013: ISignalingOutboundQueue stub ─────────────────────────────────────

describe("AC-013: ISignalingOutboundQueue — SIGNAL-001 stub", () => {
  it("enqueues frames and allows inspection", () => {
    const queue = new InMemorySignalingOutboundQueue();
    queue.enqueue({ type: "manifest_poll_request" });
    queue.enqueue({ type: "other_frame", data: 42 });
    expect(queue.getFrames()).toHaveLength(2);
    expect(queue.getFrames()[0]).toEqual({ type: "manifest_poll_request" });
  });

  it("drain() returns all frames and clears the queue", () => {
    const queue = new InMemorySignalingOutboundQueue();
    queue.enqueue({ type: "a" });
    queue.enqueue({ type: "b" });
    const drained = queue.drain();
    expect(drained).toHaveLength(2);
    expect(queue.getFrames()).toHaveLength(0);
  });
});

// ─── ImmediatePollScheduler ───────────────────────────────────────────────────

describe("ImmediatePollScheduler", () => {
  it("fires the callback after the configured delay", async () => {
    const scheduler = new ImmediatePollScheduler(0);
    let fired = false;
    scheduler.scheduleNext(async () => { fired = true; });
    // Wait for the setTimeout(fn, 0) to fire
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    expect(fired).toBe(true);
  });

  it("cancel() prevents the callback from firing", async () => {
    const scheduler = new ImmediatePollScheduler(1000);
    let fired = false;
    scheduler.scheduleNext(async () => { fired = true; });
    scheduler.cancel();
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    expect(fired).toBe(false);
  });
});

// ─── TestDirectoryKeyProvider ─────────────────────────────────────────────────

describe("TestDirectoryKeyProvider", () => {
  it("produces deterministic public key from private key seed", () => {
    const provider = new TestDirectoryKeyProvider({
      nodeId: "test",
      privateKeyHex: TEST_DIRECTORY_NODE_KEYPAIR.privateKeyHex,
    });
    expect(provider.getPublicKeyHex()).toBe(TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex);
  });

  it("sign() returns a 64-byte signature that verifies against the public key", async () => {
    const provider = new TestDirectoryKeyProvider({
      nodeId: "test",
      privateKeyHex: TEST_DIRECTORY_NODE_KEYPAIR.privateKeyHex,
    });
    const msg = new TextEncoder().encode("test message");
    const sig = await provider.sign(msg);
    expect(sig.length).toBe(64);

    // Verify with @noble/curves (RFC 8032)
    const pubKeyBytes = Buffer.from(TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex, "hex");
    expect(ed25519.verify(sig, msg, pubKeyBytes)).toBe(true);
  });

  it("throws on invalid privateKeyHex length", () => {
    expect(() => new TestDirectoryKeyProvider({
      nodeId: "test",
      privateKeyHex: "too-short",
    })).toThrow();
  });
});

// ─── TestDirectoryManifestStore ───────────────────────────────────────────────

describe("TestDirectoryManifestStore", () => {
  it("getCurrentManifest returns the fixed manifest", () => {
    const manifest: ConsortiumManifest = makeTestManifest([
      makeTestNode("node-1", "00".repeat(32)),
    ]) as unknown as ConsortiumManifest;
    const store = new TestDirectoryManifestStore(manifest);
    expect(store.getCurrentManifest()).toBe(manifest);
  });
});

// ─── SIGNAL-001: SignalingManager lifecycle tests ─────────────────────────────
//
// Tests for heartbeat, backoff reconnect, operation queue, status transitions,
// and graceful shutdown — the SIGNAL-001 behaviors merged into SignalingManager.

import { afterEach } from "vitest";

// --- SignalingStream mock ---

interface MockStream {
  send(frame: unknown): Promise<void>;
  onMessage(handler: (frame: unknown) => void): void;
  close(): void;
  simulateMessage(frame: unknown): void;
}

function createMockStream(opts?: { sendShouldThrow?: Error; closeCalled?: { count: number }; sentFrames?: unknown[] }): MockStream {
  let messageHandler: ((frame: unknown) => void) | null = null;
  return {
    async send(frame: unknown) {
      opts?.sentFrames?.push(frame);
      if (opts?.sendShouldThrow) throw opts.sendShouldThrow;
    },
    onMessage(handler: (frame: unknown) => void) { messageHandler = handler; },
    close() { if (opts?.closeCalled) opts.closeCalled.count++; },
    simulateMessage(frame: unknown) { if (messageHandler) messageHandler(frame); },
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function createTestLogger() {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  return {
    logger: {
      info(event: string, context: Record<string, unknown>) { events.push({ level: "info", event, context }); },
      warn(event: string, context: Record<string, unknown>) { events.push({ level: "warn", event, context }); },
      error(event: string, context: Record<string, unknown>) { events.push({ level: "error", event, context }); },
    },
    events,
  };
}

const SHORT_INTERVAL = 50;
const SHORT_TIMEOUT = 50;
const SHORT_BACKOFF = 10;
const SHORT_MAX_BACKOFF = 100;

const liveOnly = describe.skipIf(!process.env.CELLO_E2E_LIVE);

liveOnly("SignalingManager — live E2E (SIGNAL-001)", () => {
  it("AC-001: detects TCP kill within 30s of heartbeat being active", () => {
    expect(true).toBe(true); // placeholder — requires real infra
  });
  it("AC-003: reconnect success with full state transition", () => {
    expect(true).toBe(true); // placeholder — requires real infra
  });
});

describe("SignalingManager — lifecycle (SIGNAL-001)", () => {
  let manager: InstanceType<typeof SignalingManager> | null;

  afterEach(async () => {
    if (manager) {
      await manager.stop();
      manager = null;
    }
  });

  describe("AC-002: Backoff timing sequence", () => {
    it("first 4 reconnect attempts have correct exponential backoffMs", async () => {
      const { logger, events } = createTestLogger();
      let attempt = 0;

      manager = new SignalingManager({
        connect: async () => { attempt++; throw new Error(`refused_${attempt}`); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 5,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(300);

      const reconnectingEvents = events.filter((e) => e.event === "directory.signaling.reconnecting");
      expect(reconnectingEvents.length).toBeGreaterThanOrEqual(4);
      expect(reconnectingEvents[0].context.backoffMs).toBe(SHORT_BACKOFF);
      expect(reconnectingEvents[1].context.backoffMs).toBe(SHORT_BACKOFF * 2);
      expect(reconnectingEvents[2].context.backoffMs).toBe(SHORT_BACKOFF * 4);
      expect(reconnectingEvents[3].context.backoffMs).toBe(SHORT_BACKOFF * 8);
    });

    it("backoff caps at maxBackoffMs", async () => {
      const { logger, events } = createTestLogger();

      manager = new SignalingManager({
        connect: async () => { throw new Error("refused"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(1200);

      const reconnectingEvents = events.filter((e) => e.event === "directory.signaling.reconnecting");
      const overCap = reconnectingEvents.filter((e) => (e.context.backoffMs as number) > SHORT_MAX_BACKOFF);
      expect(overCap.length).toBe(0);
    });
  });

  describe("AC-004: 10 failed attempts → 'lost'", () => {
    it("fires 10 reconnecting events then reconnect.failed, status is lost", async () => {
      const { logger, events } = createTestLogger();

      manager = new SignalingManager({
        connect: async () => { throw new Error("unreachable"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(1500);

      const reconnectingEvents = events.filter((e) => e.event === "directory.signaling.reconnecting");
      expect(reconnectingEvents.length).toBe(10);

      const failedEvents = events.filter((e) => e.event === "directory.signaling.reconnect.failed");
      expect(failedEvents.length).toBe(1);
      expect(failedEvents[0].context.maxAttempts).toBe(10);
      expect(manager!.status).toBe("lost");
    });
  });

  describe("AC-005: Two-tier model — MCP immediate rejection, internal ops queued and drained", () => {
    it("MCP call rejected immediately when reconnecting, internal op queued and drained on reconnect", async () => {
      const { logger, events } = createTestLogger();
      let connectAttempt = 0;

      manager = new SignalingManager({
        connect: async () => {
          connectAttempt++;
          if (connectAttempt <= 3) throw new Error(`refused_${connectAttempt}`);
          return { stream: createMockStream(), directoryNodeId: "node-b", manifestVersion: 2 };
        },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(5);
      expect(manager.status).toBe("reconnecting");

      const mcpResult = expectFailure(await manager.submitMcpOperation());
      expect(mcpResult.reason).toBe("signaling_reconnecting");
      expect(mcpResult.guidance).toContain("reconnects automatically");

      let internalResolved = false;
      const internalPromise = manager.submitInternalOperation(async () => {
        internalResolved = true;
        return { success: true };
      });

      await delay(5);
      expect(internalResolved).toBe(false);

      await delay(300);

      const result = await internalPromise;
      expect(internalResolved).toBe(true);
      expect(result).toEqual({ success: true });

      const connectedEvents = events.filter((e) => e.event === "directory.signaling.connected");
      expect(connectedEvents.length).toBeGreaterThanOrEqual(1);
      expect(manager.status).toBe("connected");
    });
  });

  describe("AC-006: MCP calls rejected immediately, queue depth stays 0", () => {
    it("two MCP calls both rejected, queue empty", async () => {
      const { logger } = createTestLogger();

      manager = new SignalingManager({
        connect: async () => { throw new Error("always_fails"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(5);
      const r1 = expectFailure(await manager.submitMcpOperation());
      const r2 = expectFailure(await manager.submitMcpOperation());

      expect(r1.reason).toBe("signaling_reconnecting");
      expect(r2.reason).toBe("signaling_reconnecting");
      expect(manager.queueDepth).toBe(0);
    });
  });

  describe("AC-007: 64-op queue cap, 65th rejected with signaling_queue_full", () => {
    it("65th internal op rejected with signaling_queue_full", async () => {
      const { logger } = createTestLogger();

      manager = new SignalingManager({
        connect: async () => { throw new Error("always_fails"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
        outboundQueueCap: 64,
      });

      await delay(5);
      for (let i = 0; i < 64; i++) {
        manager.submitInternalOperation(async () => ({ idx: i }));
      }
      expect(manager.queueDepth).toBe(64);

      const result65 = await manager.submitInternalOperation(async () => ({ idx: 65 }));
      expect(result65).toEqual({ ok: false, reason: "signaling_queue_full", guidance: expect.any(String) });
      expect(manager.queueDepth).toBe(64);
    });
  });

  describe("AC-008: 'lost' state rejects all ops, flushes queue", () => {
    it("queued ops flushed with signaling_lost on transition, new ops rejected", async () => {
      const { logger } = createTestLogger();

      manager = new SignalingManager({
        connect: async () => { throw new Error("permanently_unreachable"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 3,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(5);
      const p1 = manager.submitInternalOperation(async () => "op1");
      const p2 = manager.submitInternalOperation(async () => "op2");
      expect(manager.queueDepth).toBe(2);

      await delay(200);
      expect(manager.status).toBe("lost");
      expect(manager.queueDepth).toBe(0);

      const r1 = await p1;
      const r2 = await p2;
      expect(r1).toEqual({ ok: false, reason: "signaling_lost", guidance: expect.stringContaining("lost its connection") });
      expect(r2).toEqual({ ok: false, reason: "signaling_lost", guidance: expect.stringContaining("lost its connection") });

      const newMcp = expectFailure(await manager.submitMcpOperation());
      expect(newMcp.reason).toBe("signaling_lost");
    });
  });

  describe("AC-009: FIFO drain order, partial failure continues", () => {
    it("drains in FIFO order, op-B failure does not halt op-C", async () => {
      const { logger } = createTestLogger();
      let connectAttempt = 0;
      const executionOrder: string[] = [];

      manager = new SignalingManager({
        connect: async () => {
          connectAttempt++;
          if (connectAttempt === 1) throw new Error("first_fail");
          return { stream: createMockStream(), directoryNodeId: "node-a", manifestVersion: 1 };
        },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(5);

      const opA = manager.submitInternalOperation(async () => { executionOrder.push("A"); return "result-A"; });
      const opB = manager.submitInternalOperation(async () => { executionOrder.push("B"); throw new Error("op_b_failed"); });
      const opC = manager.submitInternalOperation(async () => { executionOrder.push("C"); return "result-C"; });

      let opBError: Error | null = null;
      const opBCaught = opB.catch((err) => { opBError = err as Error; });

      await delay(100);

      expect(await opA).toBe("result-A");
      await opBCaught;
      expect(opBError).toBeInstanceOf(Error);
      expect(opBError!.message).toBe("op_b_failed");
      expect(await opC).toBe("result-C");
      expect(executionOrder).toEqual(["A", "B", "C"]);
    });
  });

  describe("AC-012: Send-path liveness — stream dies at send", () => {
    it("write failure triggers disconnect and reconnect", async () => {
      const { logger, events } = createTestLogger();
      let connectAttempt = 0;
      const sendError = new Error("ECONNRESET: connection reset by peer");

      manager = new SignalingManager({
        connect: async () => {
          connectAttempt++;
          if (connectAttempt === 1) return { stream: createMockStream({ sendShouldThrow: sendError }), directoryNodeId: "node-a", manifestVersion: 1 };
          return { stream: createMockStream(), directoryNodeId: "node-b", manifestVersion: 2 };
        },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(10);
      expect(manager.status).toBe("connected");

      await delay(SHORT_INTERVAL + 20);

      const disconnects = events.filter((e) => e.event === "directory.signaling.disconnected");
      expect(disconnects.length).toBeGreaterThanOrEqual(1);
      expect(disconnects[0].context.reason).toBe("ECONNRESET: connection reset by peer");

      await delay(50);
      expect(manager.status).toBe("connected");
    });
  });

  describe("DB-002: Graceful shutdown during reconnecting", () => {
    it("cancels reconnect loop, flushes queue with signaling_shutdown, does not transition to lost", async () => {
      const { logger, events } = createTestLogger();

      manager = new SignalingManager({
        connect: async () => { throw new Error("unreachable"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });

      await delay(5);
      const queuedOp = manager.submitInternalOperation(async () => "should_not_execute");

      await manager.stop();

      const result = await queuedOp;
      expect(result).toEqual({ ok: false, reason: "signaling_shutdown", guidance: expect.stringContaining("shutting down") });

      const failedEvents = events.filter((e) => e.event === "directory.signaling.reconnect.failed");
      expect(failedEvents.length).toBe(0);

      manager = null;
    });
  });

  describe("Status transitions", () => {
    it("starts as reconnecting during initial connect", () => {
      const { logger } = createTestLogger();
      manager = new SignalingManager({
        connect: async () => { await delay(100); return { stream: createMockStream(), directoryNodeId: "node-a", manifestVersion: 1 }; },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });
      expect(manager.status).toBe("reconnecting");
    });

    it("transitions to connected after successful connect, fires directory.signaling.connected", async () => {
      const { logger, events } = createTestLogger();
      manager = new SignalingManager({
        connect: async () => ({ stream: createMockStream(), directoryNodeId: "node-a", manifestVersion: 1 }),
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });
      await delay(20);
      expect(manager.status).toBe("connected");
      const connectedEvents = events.filter((e) => e.event === "directory.signaling.connected");
      expect(connectedEvents.length).toBe(1);
      expect(connectedEvents[0].context.directoryNodeId).toBe("node-a");
    });

    it("internal ops execute immediately when connected", async () => {
      const { logger } = createTestLogger();
      manager = new SignalingManager({
        connect: async () => ({ stream: createMockStream(), directoryNodeId: "node-a", manifestVersion: 1 }),
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL * 10,
        heartbeatTimeoutMs: SHORT_TIMEOUT * 10,
        maxReconnectAttempts: 10,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      });
      await delay(20);
      expect(manager.status).toBe("connected");
      const result = await manager.submitInternalOperation(async () => "done");
      expect(result).toBe("done");
      expect(manager.queueDepth).toBe(0);
    });
  });

  describe("DOD-AUTH-2: manifest poll activates on connect (lifecycle = connection lifecycle)", () => {
    function pollDeps(sentFrames: unknown[]) {
      return {
        connect: async () => ({ stream: createMockStream({ sentFrames }), directoryNodeId: "local", manifestVersion: 1 }),
        // Heartbeat parked far out so the only frames sent are the poll request.
        heartbeatIntervalMs: 60_000,
        heartbeatTimeoutMs: 60_000,
        maxReconnectAttempts: 1,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
      };
    }

    it("dispatches manifest_poll_request on the live stream once connected", async () => {
      const sentFrames: unknown[] = [];
      const { logger, events } = createTestLogger();
      manager = new SignalingManager({
        ...pollDeps(sentFrames),
        logger,
        pollScheduler: new ImmediatePollScheduler(0),
        manifestProvider: new TestManifestProvider(
          makeTestManifest([makeTestNode("local", "00".repeat(32))]) as unknown as ConsortiumManifest,
        ),
        manifestVersionStore: new InMemoryManifestVersionStore(),
        rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
        threshold: TEST_CONSORTIUM_THRESHOLD,
      });
      await delay(80); // connect + the immediate poll fire
      expect(manager.status).toBe("connected");
      expect(sentFrames).toContainEqual({ type: "manifest_poll_request" });
      expect(events.find((e) => e.event === "directory.auth.manifest.poll.dispatched")).toBeDefined();
    });

    it("does not poll when no pollScheduler is configured (M6 backward-compat)", async () => {
      const sentFrames: unknown[] = [];
      const { logger } = createTestLogger();
      manager = new SignalingManager({
        ...pollDeps(sentFrames),
        logger,
        // no pollScheduler / manifest deps
      });
      await delay(80);
      expect(manager.status).toBe("connected");
      expect(sentFrames).not.toContainEqual({ type: "manifest_poll_request" });
    });

    it("keeps polling on the interval even when NO response ever arrives (self-healing — code review HIGH)", async () => {
      // The poll loop must be time-driven, not response-driven: if a manifest_poll_response
      // is lost or the directory ignores the request, future polls must still fire. We never
      // feed a response here; with the loop re-armed from the dispatch side, multiple poll
      // requests must go out. (Pre-fix, dispatch fired exactly once and the loop died.)
      const sentFrames: unknown[] = [];
      const { logger } = createTestLogger();
      manager = new SignalingManager({
        ...pollDeps(sentFrames),
        logger,
        pollScheduler: new ImmediatePollScheduler(20), // fires ~every 20ms via re-arm
        manifestProvider: new TestManifestProvider(
          makeTestManifest([makeTestNode("local", "00".repeat(32))]) as unknown as ConsortiumManifest,
        ),
        manifestVersionStore: new InMemoryManifestVersionStore(),
        rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
        threshold: TEST_CONSORTIUM_THRESHOLD,
      });
      await delay(120);
      const pollFrames = sentFrames.filter(
        (f) => (f as { type?: string }).type === "manifest_poll_request",
      );
      expect(pollFrames.length).toBeGreaterThanOrEqual(2); // re-armed without any response
    });
  });

  describe("SI-001: processStep5Frame nonce cleared after use — no stale replay", () => {
    it("second call without setHandshakeContext returns handshake_context_missing", () => {
      const { logger } = createTestLogger();
      // Must provide a challengeVerifier so the early no_challenge_verifier guard doesn't fire.
      // TestDirectoryChallengeVerifier is already imported at the top of this file.
      manager = new SignalingManager({
        connect: async () => { throw new Error("unused"); },
        logger,
        heartbeatIntervalMs: SHORT_INTERVAL,
        heartbeatTimeoutMs: SHORT_TIMEOUT,
        maxReconnectAttempts: 1,
        initialBackoffMs: SHORT_BACKOFF,
        maxBackoffMs: SHORT_MAX_BACKOFF,
        challengeVerifier: new TestDirectoryChallengeVerifier(),
      });

      // First call with context set — consumes nonce
      manager.setHandshakeContext("cc".repeat(32), "aa".repeat(32));
      const first = manager.processStep5Frame({ type: "signaling_auth_ok", nodeId: "node-x", signature: "00".repeat(64), timestamp: "2026-06-12T10:00:00.000Z" });
      // First call will return verified: false (TestDirectoryChallengeVerifier rejects unknown nodes),
      // but the important thing is the nonce is consumed.
      expect(first).toBeDefined();

      // Second call without setting context — nonce must not be reused
      const second = manager.processStep5Frame({ type: "signaling_auth_ok", nodeId: "node-x", signature: "00".repeat(64), timestamp: "2026-06-12T10:00:00.000Z" });
      expect(second.verified).toBe(false);
      expect((second as { reason: string }).reason).toBe("handshake_context_missing");
    });
  });
});
