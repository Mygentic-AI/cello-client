/**
 * CELLO-M7-REGISTRATION — daemon registration persistence, against the SQLCipher `agents` row.
 *
 * M9D 002-PQKEYS deleted `FileRegistrationPersistence` (a plaintext JSON store no production code
 * constructed); the tests that exercised only it went with it. The byte-for-byte bundle round trip
 * lives in persist-002-identity.test.ts. What this file pins:
 *
 * - The post-quantum identity round-trips AND the reloaded seeds are exercised in real use: the ML-DSA
 *   seed signs a message that verifies under the stored public key, and the ML-KEM seed decapsulates
 *   what was encapsulated to the stored public key. Byte-equality alone is not enough.
 * - A persist failure names which half did not land.
 * - The two seeds are never logged.
 * - M16: channel facts default, round-trip, and are immutable.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  mlDsaGenerateSeed, mlDsaProviderFromSeed, mlKemGenerateSeed, mlKemKeypairFromSeed,
  mlKemEncapsulate, mlKemDecapsulate, signMlDsa, verifyMlDsa,
} from "@cello-protocol/crypto";
import { DbIdentityStore, DbRegistrationPersistence } from "../db-identity-store.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { PqIdentityRecord } from "../registration-persistence.js";
import type { Logger } from "../types.js";

async function freshPqIdentity(): Promise<PqIdentityRecord> {
  const mlDsaSeed = mlDsaGenerateSeed();
  const mlKemSeed = mlKemGenerateSeed();
  return {
    mlDsaSeed,
    mlDsaPubkey: Buffer.from(await (await mlDsaProviderFromSeed(mlDsaSeed)).getPublicKey()).toString("hex"),
    mlKemSeed,
    mlKemPubkey: Buffer.from((await mlKemKeypairFromSeed(mlKemSeed)).publicKey).toString("hex"),
  };
}

describe("registration-persistence (daemon, SQLCipher)", () => {
  let root: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "cello-reg-persist-"));
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

  const REG = {
    primaryPubkey: "aa".repeat(32), mlDsaPubkey: "bb".repeat(1312), mlKemPubkey: "cc".repeat(1184),
    registeredAt: 1, keyBinding: "cd".repeat(64), keyBindingPq: "de".repeat(2420),
  };
  const ADMIN = "ef".repeat(32);

  function dbPersistenceFor(...names: string[]) {
    const db = openTestDb(join(root, "sessions.db"));
    const store = new DbIdentityStore(db, logger);
    for (const n of names) store.createAgent(n, new Uint8Array(32).fill(names.indexOf(n) + 1), `${n}-pubkey`);
    return { db, store, persistenceFor: (n: string) => new DbRegistrationPersistence({ db, agentName: n, logger }) };
  }

  // ─── M9D 002-PQKEYS: the post-quantum identity ────────────────────────────

  it("a fresh agent has no post-quantum identity: every field reads null", async () => {
    const { db, persistenceFor } = dbPersistenceFor("alice");
    try {
      expect(await persistenceFor("alice").loadPqIdentity())
        .toEqual({ mlDsaSeed: null, mlDsaPubkey: null, mlKemSeed: null, mlKemPubkey: null });
    } finally {
      db.close();
    }
  });

  it("round-trips the PQ identity, and the RELOADED seeds sign and decapsulate for the stored keys", async () => {
    const { db, persistenceFor } = dbPersistenceFor("alice");
    try {
      const id = await freshPqIdentity();
      await persistenceFor("alice").persistPqIdentity(id);
      const back = await persistenceFor("alice").loadPqIdentity();
      expect(back.mlDsaPubkey).toBe(id.mlDsaPubkey);
      expect(back.mlKemPubkey).toBe(id.mlKemPubkey);
      expect(back.mlDsaSeed!.length).toBe(32);
      expect(back.mlKemSeed!.length).toBe(64);

      // Real use of the reloaded ML-DSA seed.
      const provider = await mlDsaProviderFromSeed(back.mlDsaSeed!);
      const msg = new TextEncoder().encode("daemon registration round-trip");
      const sig = await signMlDsa(provider, "cello-mldsa-key-binding-v1", msg);
      expect(await verifyMlDsa(new Uint8Array(Buffer.from(id.mlDsaPubkey, "hex")), "cello-mldsa-key-binding-v1", msg, sig)).toBe(true);

      // Real use of the reloaded ML-KEM seed.
      const { ciphertext, sharedSecret } = await mlKemEncapsulate(new Uint8Array(Buffer.from(id.mlKemPubkey, "hex")));
      expect(Buffer.from(await mlKemDecapsulate(back.mlKemSeed!, ciphertext))).toEqual(Buffer.from(sharedSecret));
    } finally {
      db.close();
    }
  });

  it("two agents' post-quantum identities stay on their own rows", async () => {
    const { db, persistenceFor } = dbPersistenceFor("alice", "bob");
    try {
      const a = await freshPqIdentity();
      const b = await freshPqIdentity();
      await persistenceFor("alice").persistPqIdentity(a);
      await persistenceFor("bob").persistPqIdentity(b);
      expect((await persistenceFor("alice").loadPqIdentity()).mlKemPubkey).toBe(a.mlKemPubkey);
      expect((await persistenceFor("bob").loadPqIdentity()).mlKemPubkey).toBe(b.mlKemPubkey);
    } finally {
      db.close();
    }
  });

  it("a persist against a missing row fails and NAMES the half that did not land (ml_dsa first)", async () => {
    const { db } = dbPersistenceFor();
    try {
      const ghost = new DbRegistrationPersistence({ db, agentName: "ghost", logger });
      await expect(ghost.persistPqIdentity(await freshPqIdentity())).rejects.toThrow(/^ml_dsa_persist_failed/);
    } finally {
      db.close();
    }
  });

  it("never logs either seed", async () => {
    const { db, persistenceFor } = dbPersistenceFor("alice");
    try {
      const id = await freshPqIdentity();
      await persistenceFor("alice").persistPqIdentity(id);
      const serialized = JSON.stringify(logEvents);
      expect(serialized).not.toContain(Buffer.from(id.mlDsaSeed).toString("hex"));
      expect(serialized).not.toContain(Buffer.from(id.mlKemSeed).toString("hex"));
      expect(logEvents.some((e) => e.event === "registration.pq_keys.persisted")).toBe(true);
    } finally {
      db.close();
    }
  });

  it("registration state carries the ML-KEM key and the ML-DSA binding half", async () => {
    const { db, persistenceFor } = dbPersistenceFor("alice");
    try {
      await persistenceFor("alice").persistRegistrationState({ agentId: "agent-a", ...REG });
      const back = await persistenceFor("alice").loadRegistrationState();
      expect(back!.mlKemPubkey).toBe(REG.mlKemPubkey);
      expect(back!.keyBindingPq).toBe(REG.keyBindingPq);
    } finally {
      db.close();
    }
  });

  // ─── M16 004-IDENTITY-WIRE: the daemon knows which of its own identities are channels ──────────

  it("records default to non-channel", async () => {
    const { db, persistenceFor } = dbPersistenceFor("alice");
    try {
      await persistenceFor("alice").persistRegistrationState({ agentId: "agent-d", ...REG });
      const dbLoaded = await persistenceFor("alice").loadRegistrationState();
      expect(dbLoaded!.channel).toBe(false);
      expect(dbLoaded!.adminPubkey).toBe("");
    } finally {
      db.close();
    }
  });

  it("channel fields round-trip", async () => {
    const { db, store, persistenceFor } = dbPersistenceFor("news", "alice");
    try {
      await persistenceFor("news").persistRegistrationState({ agentId: "agent-n", ...REG, channel: true, adminPubkey: ADMIN });
      await persistenceFor("alice").persistRegistrationState({ agentId: "agent-a", ...REG });
      const dbLoaded = await persistenceFor("news").loadRegistrationState();
      expect(dbLoaded!.channel).toBe(true);
      expect(dbLoaded!.adminPubkey).toBe(ADMIN);
      expect(store.isChannelAgent("news")).toBe(true);
      expect(store.isChannelAgent("alice")).toBe(false);
      expect(store.isChannelAgent("nobody"), "an unknown agent is not a channel").toBe(false);
    } finally {
      db.close();
    }
  });

  it("channel fields are immutable once registered", async () => {
    // Review F1: a second registration write must not flip a channel back to an agent, or swap its
    // admin. It throws; it does not silently keep the old value either.
    const OTHER_ADMIN = "12".repeat(32);
    const { db, store, persistenceFor } = dbPersistenceFor("news", "alice");
    try {
      await persistenceFor("news").persistRegistrationState({ agentId: "agent-n", ...REG, channel: true, adminPubkey: ADMIN });
      await expect(persistenceFor("news").persistRegistrationState({ agentId: "agent-n", ...REG }))
        .rejects.toThrow(/channel_fields_immutable/);
      await expect(
        persistenceFor("news").persistRegistrationState({ agentId: "agent-n", ...REG, channel: true, adminPubkey: OTHER_ADMIN }),
      ).rejects.toThrow(/channel_fields_immutable/);
      expect(store.isChannelAgent("news")).toBe(true);
      expect((await persistenceFor("news").loadRegistrationState())!.adminPubkey).toBe(ADMIN);
      // The same values again are not a change.
      await persistenceFor("news").persistRegistrationState({ agentId: "agent-n", ...REG, channel: true, adminPubkey: ADMIN });
      // An ordinary agent cannot be turned INTO a channel by a later write either.
      await persistenceFor("alice").persistRegistrationState({ agentId: "agent-a", ...REG });
      await expect(
        persistenceFor("alice").persistRegistrationState({ agentId: "agent-a", ...REG, channel: true, adminPubkey: ADMIN }),
      ).rejects.toThrow(/channel_fields_immutable/);
      expect(store.isChannelAgent("alice")).toBe(false);
    } finally {
      db.close();
    }
  });

  it("a channel without an admin pubkey is refused", async () => {
    // Review F3.
    const { db, persistenceFor } = dbPersistenceFor("news");
    try {
      await expect(persistenceFor("news").persistRegistrationState({ agentId: "agent-n", ...REG, channel: true, adminPubkey: "" }))
        .rejects.toThrow(/admin/);
    } finally {
      db.close();
    }
  });
});
