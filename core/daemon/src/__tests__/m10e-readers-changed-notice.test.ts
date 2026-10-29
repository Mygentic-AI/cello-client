/**
 * M10E 013 review fix — an `attestation_readers_changed` pickup is a plain CBOR notice, not a
 * trust-signal envelope. Decoding it as an envelope threw, so it was never acked and never shown:
 * the owner and readers never learned of a change, and the directory re-delivered the row forever.
 * Real SQLCipher database (never node:sqlite).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureSessionSchema } from "../session-schema.js";
import { AttestationNotices } from "../attestation-notices.js";
import type { Logger } from "../types.js";

const OWNER = "a1".repeat(32);
const READER = "b2".repeat(32);
const quiet: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const notice = (version: number, extra: Record<string, unknown> = {}): Uint8Array =>
  encodeCbor({ type: "attestation_readers_changed", owner: OWNER, namespace: "support.qa", version, added: [], removed: [READER], ...extra });

describe("013 fix — readers_changed notices reach the receive surface", () => {
  let dir: string;
  let db: DaemonDatabase;
  let store: AttestationNotices;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "readers-notice-"));
    db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
    ensureSessionSchema(db, quiet, () => {});
    store = new AttestationNotices({ db: () => db, logger: quiet, now: () => 1_800_000_000_000 });
  });
  afterEach(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });

  it("R1. a valid notice is stored, then surfaces once in the next receive", () => {
    expect(store.noteReaderChange("agent-1", notice(2))).toBe("stored");
    const first = store.takeUndelivered("agent-1");
    expect(first).toEqual([expect.objectContaining({ kind: "readers_changed", owner: OWNER, namespace: "support.qa", version: 2, added: [], removed: [READER] })]);
    expect(store.takeUndelivered("agent-1")).toEqual([]);
  });

  it("R2. a re-delivered notice for the same version is stored once (so the ack can be resent safely)", () => {
    expect(store.noteReaderChange("agent-1", notice(3))).toBe("stored");
    expect(store.noteReaderChange("agent-1", notice(3))).toBe("stored");
    expect(store.takeUndelivered("agent-1")).toHaveLength(1);
  });

  it("R3. a malformed notice is reported malformed (acked, never retried) and nothing is shown", () => {
    expect(store.noteReaderChange("agent-1", new Uint8Array([0xff, 0x00]))).toBe("malformed");
    expect(store.noteReaderChange("agent-1", notice(4, { removed: ["not-hex"] }))).toBe("malformed");
    expect(store.noteReaderChange("agent-1", notice(0))).toBe("malformed");
    expect(store.takeUndelivered("agent-1")).toEqual([]);
  });

  it("R4. with no database the notice is store_failed, so the pickup is NOT acked and is re-delivered", () => {
    const none = new AttestationNotices({ db: () => null, logger: quiet, now: () => 0 });
    expect(none.noteReaderChange("agent-1", notice(5))).toBe("store_failed");
  });
});
