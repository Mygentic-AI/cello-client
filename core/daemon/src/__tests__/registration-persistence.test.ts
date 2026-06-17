/**
 * CELLO-M7-REGISTRATION — daemon registration persistence (step b)
 *
 * The daemon owns its agents' registration material (ML-DSA keypair, FROST key
 * share, registration state) as per-agent files under ~/.cello/agents/<name>/.
 * This mirrors the existing `key`-file model (agent-loader) rather than dragging
 * the client's SQLCipher ClientStatePersistence into the daemon.
 *
 * What these tests pin:
 * - All three persist methods round-trip every field exactly (bytes included).
 * - Known case 2 (persistence serialization): the reloaded ML-DSA secret is
 *   exercised in real use — the reconstructed provider signs a message that
 *   verifies against the stored public key. Byte-equality alone is not enough.
 * - Fresh agent → all load methods return null.
 * - A newer FROST share supersedes the prior active share.
 * - Per-agent isolation: two agent dirs never see each other's material.
 * - SI-001/SI-002: secret bytes never appear in any log event.
 * - Secret files are written 0o600.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, stat, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mlDsaKeygenWithBytes, mlDsaVerify, InMemoryMlDsaKeyProvider } from "@cello-protocol/crypto";
import { FileRegistrationPersistence } from "../registration-persistence.js";
import type { Logger } from "../types.js";

describe("registration-persistence (daemon)", () => {
  let root: string;
  let agentDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "cello-reg-persist-"));
    agentDir = join(root, "agents", "alice");
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  // ─── Registration state ──────────────────────────────────────────────────

  it("round-trips registration state with every field", async () => {
    const p = new FileRegistrationPersistence({ agentDir, logger });
    await p.persistRegistrationState({
      agentId: "agent-123",
      primaryPubkey: "aa".repeat(32),
      mlDsaPubkey: "bb".repeat(32),
      registeredAt: 1781725000000,
    });

    const loaded = await p.loadRegistrationState();
    expect(loaded).not.toBeNull();
    expect(loaded!.agentId).toBe("agent-123");
    expect(loaded!.primaryPubkey).toBe("aa".repeat(32));
    expect(loaded!.mlDsaPubkey).toBe("bb".repeat(32));
    expect(loaded!.registeredAt).toBe(1781725000000);
    expect(loaded!.status).toBe("active");
  });

  it("loadRegistrationState returns null for a fresh agent", async () => {
    const p = new FileRegistrationPersistence({ agentDir, logger });
    expect(await p.loadRegistrationState()).toBeNull();
    expect(await p.loadMlDsaKeypair()).toBeNull();
    expect(await p.loadActiveFrostKeyShare()).toBeNull();
  });

  // ─── ML-DSA keypair (Known case 2 — exercise the reloaded key) ────────────

  it("round-trips the ML-DSA keypair AND the reloaded secret signs verifiably", async () => {
    const { provider, secretKeyBlob } = await mlDsaKeygenWithBytes();
    const pubkey = await provider.getPublicKey();
    const pubkeyHex = Buffer.from(pubkey).toString("hex");

    const p = new FileRegistrationPersistence({ agentDir, logger });
    await p.persistMlDsaKeypair({ mlDsaPubkey: pubkeyHex, secretKeyBlob });

    const loaded = await p.loadMlDsaKeypair();
    expect(loaded).not.toBeNull();
    expect(loaded!.mlDsaPubkey).toBe(pubkeyHex);
    expect(Buffer.from(loaded!.secretKeyBlob).equals(Buffer.from(secretKeyBlob))).toBe(true);

    // Real use: reconstruct a provider from the reloaded bytes, sign, verify.
    const reconstructed = new InMemoryMlDsaKeyProvider(pubkey, loaded!.secretKeyBlob);
    const msg = new TextEncoder().encode("daemon registration round-trip");
    const sig = await reconstructed.sign(msg);
    expect(mlDsaVerify(pubkey, msg, sig)).toBe(true);
  });

  // ─── FROST key share ──────────────────────────────────────────────────────

  it("round-trips the FROST key share including every byte field", async () => {
    const signingShare = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const commitmentsCbor = new Uint8Array([10, 20, 30, 40]);
    const verifyingSharesCbor = new Uint8Array([99, 98, 97]);

    const p = new FileRegistrationPersistence({ agentDir, logger });
    await p.persistFrostKeyShare({
      epochId: "epoch:1",
      primaryPubkey: "cc".repeat(32),
      identifier: "client:abcd",
      signingShare,
      threshold: 2,
      participants: 2,
      commitmentsCbor,
      verifyingSharesCbor,
      dkgMethod: "network_dkg",
    });

    const loaded = await p.loadActiveFrostKeyShare();
    expect(loaded).not.toBeNull();
    expect(loaded!.epochId).toBe("epoch:1");
    expect(loaded!.primaryPubkey).toBe("cc".repeat(32));
    expect(loaded!.identifier).toBe("client:abcd");
    expect(loaded!.threshold).toBe(2);
    expect(loaded!.participants).toBe(2);
    expect(loaded!.dkgMethod).toBe("network_dkg");
    expect(Buffer.from(loaded!.signingShare).equals(Buffer.from(signingShare))).toBe(true);
    expect(Buffer.from(loaded!.commitmentsCbor).equals(Buffer.from(commitmentsCbor))).toBe(true);
    expect(Buffer.from(loaded!.verifyingSharesCbor).equals(Buffer.from(verifyingSharesCbor))).toBe(true);
  });

  it("a newer FROST share supersedes the previously active one", async () => {
    const p = new FileRegistrationPersistence({ agentDir, logger });
    await p.persistFrostKeyShare({
      epochId: "epoch:1", primaryPubkey: "11".repeat(32), identifier: "id1",
      signingShare: new Uint8Array([1]), threshold: 2, participants: 2,
      commitmentsCbor: new Uint8Array([1]), verifyingSharesCbor: new Uint8Array([1]),
      dkgMethod: "network_dkg",
    });
    await p.persistFrostKeyShare({
      epochId: "epoch:2", primaryPubkey: "22".repeat(32), identifier: "id2",
      signingShare: new Uint8Array([2]), threshold: 2, participants: 2,
      commitmentsCbor: new Uint8Array([2]), verifyingSharesCbor: new Uint8Array([2]),
      dkgMethod: "network_dkg",
    });

    const loaded = await p.loadActiveFrostKeyShare();
    expect(loaded!.epochId).toBe("epoch:2");
    expect(loaded!.primaryPubkey).toBe("22".repeat(32));
  });

  // ─── Multi-agent isolation ────────────────────────────────────────────────

  it("keeps two agents' material isolated by directory", async () => {
    const alice = new FileRegistrationPersistence({ agentDir: join(root, "agents", "alice"), logger });
    const bob = new FileRegistrationPersistence({ agentDir: join(root, "agents", "bob"), logger });

    await alice.persistRegistrationState({
      agentId: "alice-id", primaryPubkey: "aa".repeat(32), mlDsaPubkey: "a1".repeat(32), registeredAt: 1,
    });

    expect((await alice.loadRegistrationState())!.agentId).toBe("alice-id");
    expect(await bob.loadRegistrationState()).toBeNull();
  });

  // ─── Security invariants ──────────────────────────────────────────────────

  it("never logs secret bytes (SI-001 signing_share, SI-002 secret_key_blob)", async () => {
    const { provider, secretKeyBlob } = await mlDsaKeygenWithBytes();
    const pubkeyHex = Buffer.from(await provider.getPublicKey()).toString("hex");
    const signingShare = new Uint8Array([7, 7, 7, 7]);

    const p = new FileRegistrationPersistence({ agentDir, logger });
    await p.persistMlDsaKeypair({ mlDsaPubkey: pubkeyHex, secretKeyBlob });
    await p.persistFrostKeyShare({
      epochId: "epoch:1", primaryPubkey: "cc".repeat(32), identifier: "id",
      signingShare, threshold: 2, participants: 2,
      commitmentsCbor: new Uint8Array([1]), verifyingSharesCbor: new Uint8Array([1]),
      dkgMethod: "network_dkg",
    });

    const secretHex = Buffer.from(secretKeyBlob).toString("hex");
    const shareHex = Buffer.from(signingShare).toString("hex");
    const serialized = JSON.stringify(logEvents);
    expect(serialized).not.toContain(secretHex);
    expect(serialized).not.toContain(shareHex);
    // Persist events should still have been emitted (observability).
    expect(logEvents.some((e) => e.event.includes("persisted"))).toBe(true);
  });

  it("writes secret files with 0o600 permissions", async () => {
    const { provider, secretKeyBlob } = await mlDsaKeygenWithBytes();
    const pubkeyHex = Buffer.from(await provider.getPublicKey()).toString("hex");
    const p = new FileRegistrationPersistence({ agentDir, logger });
    await p.persistMlDsaKeypair({ mlDsaPubkey: pubkeyHex, secretKeyBlob });
    await p.persistFrostKeyShare({
      epochId: "epoch:1", primaryPubkey: "cc".repeat(32), identifier: "id",
      signingShare: new Uint8Array([1]), threshold: 2, participants: 2,
      commitmentsCbor: new Uint8Array([1]), verifyingSharesCbor: new Uint8Array([1]),
      dkgMethod: "network_dkg",
    });

    const entries = await readdir(agentDir);
    const secretFiles = entries.filter((f) => f.includes("ml-dsa") || f.includes("frost"));
    expect(secretFiles.length).toBeGreaterThanOrEqual(2);
    for (const f of secretFiles) {
      const s = await stat(join(agentDir, f));
      expect(s.mode & 0o777).toBe(0o600);
    }
  });
});
