/**
 * DOD-DOC-REJECT-SQLCIPHER-1 — the rejection audit row must WRITE on the driver production uses.
 *
 * ── WHY THIS FILE EXISTS AT ALL, AND WHY IT DOES NOT USE `node:sqlite` ────────────────────────────
 *
 * Every other daemon test opens `node:sqlite` under the test-file allowance. That allowance is fine
 * for logic. It is NOT fine here, because the defect this file pins is a DIFFERENCE BETWEEN THE TWO
 * DRIVERS, and a `node:sqlite` test cannot see it by construction:
 *
 *                          node:sqlite        @signalapp/sqlcipher (production)
 *   empty Uint8Array  →        OK             NOT NULL constraint failed
 *   empty Buffer      →        OK             NOT NULL constraint failed
 *   1-byte blob       →        OK             OK
 *
 * SQLCipher binds a ZERO-LENGTH BLOB AS NULL. `node:sqlite` binds it as an empty blob.
 *
 * `DocumentRejections.reject` writes its audit row with `stateVector: new Uint8Array(0)` —
 * deliberately empty, because a rejection asserts nothing about document state. On the test driver
 * that inserts cleanly and every unit test passes. On the real driver it violates
 * `state_vector BLOB NOT NULL` and the insert THROWS.
 *
 * ── WHAT THAT COST ───────────────────────────────────────────────────────────────────────────────
 *
 * The throw escaped `reject()` before it wrote the quarantine, signed the refusal, or answered the
 * peer. So the receiver held NOTHING from that sender — `knownCount: 0`, `ourHead: null` — and every
 * later envelope was refused `document_chain_broken` forever. One gate refusal permanently broke the
 * document, and §3.2's supersede-then-converge protocol could never run.
 *
 * The live enforcer for it (`repeated refusals STALL the document`) sat SKIPPED through FOUR
 * attempted fixes, all of which reasoned about chain-bridging logic. The chain logic was correct
 * the whole time. The row simply never existed, because writing it threw — on a driver no test ran.
 *
 * ── WHY THE COLUMN WAS NOT MADE NULLABLE INSTEAD ─────────────────────────────────────────────────
 *
 * That is the more honest schema — a rejection genuinely has no state vector, and the table already
 * carries `CHECK (kind = 'update' OR payload IS NULL)` for exactly this shape. But SQLCipher is
 * SQLite 3.50.4 and SQLite has never supported dropping NOT NULL in place (verified: both
 * `ALTER TABLE … ALTER COLUMN … DROP NOT NULL` and `MODIFY` are syntax errors). Relaxing it means a
 * full table rebuild against operators' live document logs, and a client-side migration is a
 * heavier risk than a documented one-byte placeholder.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { DocumentStore } from "../document-store.js";
import { DocumentRejections } from "../document-rejection.js";
import type { Logger } from "../types.js";

const AGENT = "aa".repeat(32);
const PEER = "bb".repeat(32);
const DOC = "cc".repeat(32);
const NOW = 1_700_000_000_000;

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function silentLogger(): Logger {
  const noop = () => {};
  const l = { debug: noop, info: noop, warn: noop, error: noop, child: () => l } as unknown as Logger;
  return l;
}

/** A REAL encrypted database, on disk, opened the way the daemon opens its own. */
function newRealStore() {
  const dir = mkdtempSync(join(tmpdir(), "cello-reject-sqlcipher-"));
  dirs.push(dir);
  // The daemon mints this at first login; a test standing up a real encrypted store must too.
  const keyPath = join(dir, "cello.key");
  writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
  const db = openEncryptedDatabaseAtPath(join(dir, "cello.db"), keyPath);
  const logger = silentLogger();
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: { append_only: true }, status: "active", createdAtMs: 1,
  });
  return { store, rejections: new DocumentRejections(store, logger) };
}

describe("a rejection is RECORDED on the production driver, not just decided", () => {
  it("writes the audit row — an empty state vector binds as NULL under SQLCipher", async () => {
    const { store, rejections } = newRealStore();

    const outcome = await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ee".repeat(32),
      quarantined: new Uint8Array([1, 2, 3]),
      reason: "document_append_only_violation",
      detail: "the update deletes 1 existing range(s)",
      senderAgentId: PEER,
      rejectedDocPrevHash: null,
      sign: async () => new Uint8Array(64).fill(7),
      nowMs: NOW,
    });

    // It must not throw, and it must actually have written — `round` advancing is the store
    // reporting a row, not this function reporting its own intent.
    expect(outcome.round).toBe(1);
    expect(store.getEnvelopeLog(AGENT, DOC).some((e) => e.kind === "rejection")).toBe(true);
  });

  it("puts the refused envelope in the KNOWN set, which is what lets the peer's chain bridge it", async () => {
    // The consequence the whole stall path turned on. A refused envelope is deliberately never
    // written to `document_envelopes`, so the quarantine is the only record that it was ever seen —
    // and the sender's NEXT envelope links to it. With the write throwing, `knownCount` stayed 0 and
    // every supersession was refused `document_chain_broken`, forever.
    const { store, rejections } = newRealStore();
    const refused = "ee".repeat(32);

    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: refused,
      quarantined: new Uint8Array([1, 2, 3]),
      reason: "document_append_only_violation",
      detail: "d",
      senderAgentId: PEER,
      rejectedDocPrevHash: null,
      sign: async () => new Uint8Array(64).fill(7),
      nowMs: NOW,
    });

    expect(
      store.knownEnvelopeHashesBySender(AGENT, DOC, PEER).has(refused),
      "the refused envelope is not known, so the peer's next link cannot resolve",
    ).toBe(true);
  });

  it("SQLCipher really does reject a zero-length blob — the premise, pinned", () => {
    // Stated as its own case so the reason for the placeholder cannot be quietly "cleaned up" by
    // someone who tries an empty Uint8Array locally on node:sqlite and sees it work.
    const dir = mkdtempSync(join(tmpdir(), "cello-blob-"));
    dirs.push(dir);
    const keyPath = join(dir, "b.key");
    writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
    const db = openEncryptedDatabaseAtPath(join(dir, "b.db"), keyPath);
    db.exec("CREATE TABLE probe (id INTEGER PRIMARY KEY, sv BLOB NOT NULL)");

    expect(() => db.prepare("INSERT INTO probe (sv) VALUES (?)").run(new Uint8Array(0))).toThrow(
      /NOT NULL/,
    );
    expect(() => db.prepare("INSERT INTO probe (sv) VALUES (?)").run(new Uint8Array([0]))).not.toThrow();
  });
});
