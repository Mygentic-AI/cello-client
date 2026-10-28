/**
 * The daemon's pairing state: its daemon key and the credential a directory signed for it.
 *
 * One row per daemon, in the SQLCipher-encrypted daemon DB. The daemon key is an Ed25519 seed that
 * never leaves this table: it signs pairing polls and, for every agent registered here, a proof over
 * that agent's key. The credential binds the daemon key to an account; a copy of it is useless on
 * another machine because the proof needs the seed.
 */
import { InMemoryKeyProvider, generateKLocalSeed } from "@cello-protocol/crypto";
import type { DaemonCredential, KeyProvider } from "@cello-protocol/crypto";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Idempotent schema. An existing daemon DB gains the table at first start; no other table is touched. */
export function ensurePairingSchema(db: DaemonDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS daemon_pairing (
      id                 INTEGER PRIMARY KEY CHECK (id = 1),
      daemon_seed        BLOB    NOT NULL,
      daemon_pubkey      TEXT    NOT NULL,
      credential         TEXT,
      pairing_code       TEXT,
      pairing_base       TEXT,
      pairing_expires_at INTEGER,
      pairing_approve_url TEXT,
      paired_at          INTEGER
    )
  `);
}

export interface PendingPairing {
  code: string;
  base: string;
  /** Epoch milliseconds. */
  expiresAt: number;
  /** The portal link the directory returned, kept so a restarted daemon can show the same code. */
  approveUrl: string;
}

export interface DaemonKey {
  keyProvider: KeyProvider;
  pubkeyHex: string;
}

interface PairingRow {
  daemon_seed: Uint8Array;
  daemon_pubkey: string;
  credential: string | null;
  pairing_code: string | null;
  pairing_base: string | null;
  pairing_expires_at: number | null;
  pairing_approve_url: string | null;
}

export class DbPairingStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;
  #key: DaemonKey | null = null;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    ensurePairingSchema(db);
  }

  #row(): PairingRow | undefined {
    return this.#db
      .prepare("SELECT daemon_seed, daemon_pubkey, credential, pairing_code, pairing_base, pairing_expires_at, pairing_approve_url FROM daemon_pairing WHERE id = 1")
      .get() as PairingRow | undefined;
  }

  /** The daemon key. Created on the first call, then the same key on every call and every restart. */
  daemonKey(): DaemonKey {
    if (this.#key) return this.#key;
    let row = this.#row();
    if (!row) {
      const seed = generateKLocalSeed();
      const pubkeyHex = new InMemoryKeyProvider(seed).toJSON()["publicKey"]!;
      this.#db
        .prepare("INSERT INTO daemon_pairing (id, daemon_seed, daemon_pubkey) VALUES (1, ?, ?) ON CONFLICT(id) DO NOTHING")
        .run(seed, pubkeyHex);
      this.#logger.info("pairing.daemon_key.created", { daemonPubkey: pubkeyHex });
      row = this.#row();
      if (!row) throw new Error("pairing_store_write_failed: the daemon_pairing row was not written");
    }
    const seed = new Uint8Array(row.daemon_seed);
    this.#key = { keyProvider: new InMemoryKeyProvider(seed), pubkeyHex: row.daemon_pubkey };
    return this.#key;
  }

  credential(): DaemonCredential | null {
    const raw = this.#row()?.credential;
    return raw ? (JSON.parse(raw) as DaemonCredential) : null;
  }

  saveCredential(c: DaemonCredential): void {
    this.daemonKey();
    this.#db
      .prepare("UPDATE daemon_pairing SET credential = ?, paired_at = ? WHERE id = 1")
      .run(JSON.stringify(c), Date.now());
  }

  /** Forget the credential. The daemon key stays, so a re-pairing presents the same key. */
  clearCredential(): void {
    this.#db.prepare("UPDATE daemon_pairing SET credential = NULL, paired_at = NULL WHERE id = 1").run();
  }

  savePending(p: PendingPairing): void {
    this.daemonKey();
    this.#db
      .prepare("UPDATE daemon_pairing SET pairing_code = ?, pairing_base = ?, pairing_expires_at = ?, pairing_approve_url = ? WHERE id = 1")
      .run(p.code, p.base, p.expiresAt, p.approveUrl);
  }

  pending(): PendingPairing | null {
    const row = this.#row();
    if (!row || row.pairing_code === null || row.pairing_base === null || row.pairing_expires_at === null || row.pairing_approve_url === null) return null;
    return { code: row.pairing_code, base: row.pairing_base, expiresAt: Number(row.pairing_expires_at), approveUrl: row.pairing_approve_url };
  }

  clearPending(): void {
    this.#db
      .prepare("UPDATE daemon_pairing SET pairing_code = NULL, pairing_base = NULL, pairing_expires_at = NULL, pairing_approve_url = NULL WHERE id = 1")
      .run();
  }
}
