/**
 * M15C 002-KEYPATH — the daemon reads its database key from a given path.
 *
 * A hosted daemon's key lives in tmpfs, never beside the database on the user's volume. With
 * CELLO_DB_KEY_FILE set, every opener of sessions.db and gateway.db uses that path, and a missing
 * file is REFUSED — a key minted into tmpfs vanishes on restart and takes the database with it.
 * Unset (or empty), behaviour is exactly as before.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, readdir, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import {
  sessionsDbKeyPath,
  resolveDbKey,
  openEncryptedDatabase,
  DbEncryptionError,
  DB_KEY_FILE_ENV,
} from "../sqlcipher-db.js";
import { prepareGatewayStoreEnv } from "../gateway-store-env.js";
import { registerGatewayConfigHandlers } from "../gateway-config-handlers.js";
import { createBackup, restoreBackup } from "../backup-restore.js";
import type { IpcHandler } from "../ipc-server.js";
import { migrateToEncryptedIfNeeded } from "../identity-migration.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { DatabaseSync } from "node:sqlite";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_config: SessionNodeConfig): Promise<CelloNode> {
    throw new Error("not used in DB-only tests");
  }
}

function recordingLogger(): { logger: Logger; events: Array<{ event: string; ctx: Record<string, unknown> }> } {
  const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
  const push = (event: string, ctx?: Record<string, unknown>) => events.push({ event, ctx: ctx ?? {} });
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
}

let dir = "";
let tmpfs = "";
let saved: string | undefined;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "m15c-keypath-vol-"));
  tmpfs = await mkdtemp(join(tmpdir(), "m15c-keypath-tmpfs-"));
  saved = process.env[DB_KEY_FILE_ENV];
  delete process.env[DB_KEY_FILE_ENV];
});
afterEach(async () => {
  if (saved === undefined) delete process.env[DB_KEY_FILE_ENV];
  else process.env[DB_KEY_FILE_ENV] = saved;
  await rm(dir, { recursive: true, force: true });
  await rm(tmpfs, { recursive: true, force: true });
});

async function initManager(dbPath: string, logger: Logger = silent): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger, dbPath });
  await mgr.initialize();
  return mgr;
}

async function configuredKey(): Promise<string> {
  const keyFile = join(tmpfs, "db.key");
  await writeFile(keyFile, randomBytes(32), { mode: 0o600 });
  process.env[DB_KEY_FILE_ENV] = keyFile;
  return keyFile;
}

describe("002-KEYPATH — the key path", () => {
  it("1. unset: the key lives beside the database, and a fresh start creates it there (unchanged)", async () => {
    const dbPath = join(dir, "sessions.db");
    expect(sessionsDbKeyPath(dbPath)).toBe(`${dbPath}.key`);
    const mgr = await initManager(dbPath);
    await mgr.shutdown?.();
    expect(existsSync(`${dbPath}.key`)).toBe(true);
  });

  it('2. CELLO_DB_KEY_FILE="" is unset, never "a path in the current directory"', async () => {
    process.env[DB_KEY_FILE_ENV] = "";
    const dbPath = join(dir, "sessions.db");
    expect(sessionsDbKeyPath(dbPath)).toBe(`${dbPath}.key`);
  });

  it("3. set to an existing key: sessions.db opens with it and NOTHING appears beside the database", async () => {
    const keyFile = await configuredKey();
    const dbPath = join(dir, "sessions.db");
    expect(sessionsDbKeyPath(dbPath)).toBe(keyFile);
    const mgr = await initManager(dbPath);
    await mgr.shutdown?.();
    expect(existsSync(dbPath), "the database was created").toBe(true);
    const onVolume = await readdir(dir);
    expect(onVolume.filter((f) => f.endsWith(".key")), "a key file reached the volume").toEqual([]);
  });

  it("4. set to a MISSING file: startup refuses, and no key and no database are created anywhere", async () => {
    const keyFile = join(tmpfs, "db.key");
    process.env[DB_KEY_FILE_ENV] = keyFile;
    const dbPath = join(dir, "sessions.db");
    const err = await initManager(dbPath).then(() => undefined, (e: unknown) => e);
    expect(err).toBeInstanceOf(DbEncryptionError);
    expect((err as DbEncryptionError).code).toBe("db_key_file_missing");
    expect(String((err as Error).message) + String((err as DbEncryptionError).guidance)).toContain(keyFile);
    expect(existsSync(keyFile), "a key was minted at the configured path").toBe(false);
    expect(existsSync(`${dbPath}.key`), "a key was minted beside the database").toBe(false);
    expect(existsSync(dbPath), "a database was created without its key").toBe(false);
  });

  it("4b. resolveDbKey itself refuses to mint at a configured path", () => {
    const keyFile = join(tmpfs, "db.key");
    expect(() => resolveDbKey(join(dir, "sessions.db"), keyFile, { configured: true })).toThrow(DbEncryptionError);
    expect(existsSync(keyFile)).toBe(false);
  });

  it("5. a configured key of the wrong length is the existing malformed-key refusal", async () => {
    const keyFile = join(tmpfs, "db.key");
    await writeFile(keyFile, randomBytes(31), { mode: 0o600 });
    process.env[DB_KEY_FILE_ENV] = keyFile;
    const err = await initManager(join(dir, "sessions.db")).then(() => undefined, (e: unknown) => e);
    expect((err as DbEncryptionError).code).toBe("db_encryption_key_mismatch");
  });

  it("6a. the gateway sidecar is handed the CONFIGURED path, and the daemon mints nothing on the volume", async () => {
    const keyFile = await configuredKey();
    const env = prepareGatewayStoreEnv(dir);
    expect(env.CELLO_GATEWAY_STORE_KEY_FILE).toBe(keyFile);
    expect(env.CELLO_GATEWAY_STORE_DB).toBe(join(dir, "gateway.db"));
    expect(existsSync(join(dir, "sessions.db.key"))).toBe(false);
  });

  it("6a'. with the configured file missing, preparing the sidecar refuses rather than minting", () => {
    process.env[DB_KEY_FILE_ENV] = join(tmpfs, "db.key");
    expect(() => prepareGatewayStoreEnv(dir)).toThrow(DbEncryptionError);
    expect(existsSync(join(tmpfs, "db.key"))).toBe(false);
  });

  it("6b. the daemon's own gateway.db openers (config + screening log) use the configured key", async () => {
    await configuredKey();
    const handlers = new Map<string, IpcHandler>();
    const dispose = registerGatewayConfigHandlers({
      handlers,
      celloDir: dir,
      logger: silent,
      getClientType: () => "cli",
      restartSecurityGateway: async () => {},
    });
    try {
      const list = (await handlers.get("cello_config_list")!({}, "c")) as Record<string, unknown>;
      expect(list.ok, `config store did not open: ${JSON.stringify(list)}`).toBe(true);
      const log = (await handlers.get("cello_screening_log")!({}, "c")) as Record<string, unknown>;
      expect(log.ok, `record store did not open: ${JSON.stringify(log)}`).toBe(true);
    } finally {
      dispose();
    }
    expect(existsSync(join(dir, "sessions.db.key"))).toBe(false);
  });

  it("7. a backup from a configured daemon carries the configured key and opens on a machine without the setting", async () => {
    const keyFile = await configuredKey();
    const dbPath = join(dir, "sessions.db");
    const db = openEncryptedDatabase(dbPath, resolveDbKey(dbPath, keyFile, { configured: true }));
    db.exec("CREATE TABLE probe (m TEXT)");
    db.prepare("INSERT INTO probe (m) VALUES (?)").run("hosted-agent");
    db.close();

    const archive = join(dir, "agent.cello-backup");
    const made = await createBackup({ dbPath, outPath: archive, logger: silent });
    expect(made.ok, JSON.stringify(made)).toBe(true);

    delete process.env[DB_KEY_FILE_ENV];
    const laptop = join(tmpfs, "laptop");
    await mkdir(laptop, { recursive: true });
    const dst = join(laptop, "sessions.db");
    const restored = await restoreBackup({ archivePath: archive, dbPath: dst, logger: silent });
    expect(restored.ok, JSON.stringify(restored)).toBe(true);
    const back = openEncryptedDatabase(dst, resolveDbKey(dst, `${dst}.key`));
    const row = back.prepare("SELECT m FROM probe").get() as { m: string } | undefined;
    back.close();
    expect(row?.m).toBe("hosted-agent");
  });

  it("8. upgrade: a populated directory from before this change opens unchanged with no setting", async () => {
    const dbPath = join(dir, "sessions.db");
    const first = await initManager(dbPath);
    await first.shutdown?.();
    const keyBefore = existsSync(`${dbPath}.key`);
    const second = await initManager(dbPath);
    await second.shutdown?.();
    expect(keyBefore).toBe(true);
    expect(existsSync(`${dbPath}.key`)).toBe(true);
  });

  it("9a. migrating a legacy flat-file identity with the setting: the key stays off the volume", async () => {
    const keyFile = await configuredKey();
    const dbPath = join(dir, "sessions.db");
    await FileKeyProvider.load(join(dir, "key")); // legacy single-file key → in-place import path
    expect(migrateToEncryptedIfNeeded(dbPath, silent).migrated).toBe(true);
    expect((await readdir(dir)).filter((f) => f.endsWith(".key")), "a key file reached the volume").toEqual([]);
    const db = openEncryptedDatabase(dbPath, resolveDbKey(dbPath, keyFile, { configured: true }));
    db.close();
  });

  it("9b. migrating a legacy PLAINTEXT database with the setting: the swapped-in DB opens with the configured key", async () => {
    const keyFile = await configuredKey();
    const dbPath = join(dir, "sessions.db");
    const old = new DatabaseSync(dbPath);
    old.exec("CREATE TABLE probe (m TEXT)");
    old.close();
    expect(migrateToEncryptedIfNeeded(dbPath, silent).migrated).toBe(true);
    expect((await readdir(dir)).filter((f) => f.endsWith(".key")), "a key file reached the volume").toEqual([]);
    const db = openEncryptedDatabase(dbPath, resolveDbKey(dbPath, keyFile, { configured: true }));
    db.close();
  });

  it("logs the key's SOURCE once, and never the key or its path", async () => {
    const keyFile = await configuredKey();
    const { logger, events } = recordingLogger();
    const mgr = await initManager(join(dir, "sessions.db"), logger);
    await mgr.shutdown?.();
    const src = events.filter((e) => e.event === "daemon.db_key.source");
    expect(src).toHaveLength(1);
    expect(src[0]!.ctx).toEqual({ source: "configured" });
    expect(JSON.stringify(events)).not.toContain(keyFile);
  });
});
