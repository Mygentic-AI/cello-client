#!/usr/bin/env node
/**
 * cello-mcp — single-identity CELLO MCP server
 *
 * One key file. One libp2p node. One client. One MCP server.
 * Two agents = two separate processes, each running this binary with their own CELLO_KEY_FILE.
 *
 * Environment variables:
 *   CELLO_KEY_FILE            Path to Ed25519 key file (default: ~/.cello/key)
 *   CELLO_LISTEN_ADDR         libp2p listen address (default: /ip4/0.0.0.0/tcp/0)
 *   CELLO_DIRECTORY_URL       Production directory HTTP endpoint (default: http://directory-us1.cello.mygentic.ai)
 *                             Overridable for local/staging deployments. Relay multiaddr is
 *                             dynamically assigned per-session — no relay constant is baked in.
 *   CELLO_DIRECTORY_MULTIADDR Directory libp2p multiaddr (optional; used when dialing libp2p directly)
 *   NODE_ENV                  (unused — FROST bootstrap runs whenever CELLO_DIRECTORY_MULTIADDR is set)
 *   CELLO_ENV                 Deployment environment: local | dev | staging | production
 *   CELLO_DB_PATH             Path to local SQLCipher database (default: ~/.cello/client.db)
 *   BACKUP_S3_BUCKET          S3 bucket for encrypted backups (required for S3 backup)
 *   CELLO_AWS_REGION          AWS region for S3 (default: eu-west-1; falls back to AWS_REGION)
 *
 * Backup selection (PERSIST-022):
 *   CELLO_ENV=local                        → LocalCloudStorageProvider (filesystem)
 *   CELLO_ENV != local + BACKUP_S3_BUCKET  → S3CloudStorageProvider (uses CELLO_AWS_REGION or AWS_REGION)
 *   CELLO_ENV != local + no BACKUP_S3_BUCKET → null (no backup; client.backup.not.configured logged)
 */

import { homedir } from "node:os";
import { createWriteStream, readFileSync } from "node:fs";

// Tee stderr to a log file for diagnostics (especially [sigstream] instrumentation)
const stderrLog = createWriteStream("/tmp/cello-mcp-stderr.log", { flags: "a" });
const origWrite = process.stderr.write.bind(process.stderr) as typeof process.stderr.write;
// Override stderr.write to tee output to the log file.
// We handle only the most common call signature (string/Buffer + optional encoding/callback).
process.stderr.write = (
  chunk: string | Uint8Array,
  encodingOrCb?: BufferEncoding | ((err?: Error | null) => void),
  cb?: (err?: Error | null) => void,
): boolean => {
  stderrLog.write(chunk);
  if (typeof encodingOrCb === "function") {
    return origWrite(chunk as string, encodingOrCb);
  } else if (encodingOrCb !== undefined) {
    return origWrite(chunk as string, encodingOrCb, cb);
  }
  return origWrite(chunk as string);
};
import { join } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { FileKeyProvider, FrostThresholdSigner } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { createClient, createMcpSessionServer, NetworkDirectoryNode, bootstrapNetworkKeyShares, ClientBackup, S3CloudStorageProvider, SQLCipherClientStore, ClientStatePersistence, AgentHashQueue, deriveDbKey } from "@cello-protocol/client";
import { LocalCloudStorageProvider, LocalClientStore } from "@cello-protocol/interfaces/stubs";
import type { CloudStorageProvider } from "@cello-protocol/interfaces";
import { pushChannelNotification } from "../notifications.js";
import { resolveDirectoryUrl, fetchBootstrapMultiaddr } from "../config.js";

const keyPath = process.env["CELLO_KEY_FILE"] ?? join(homedir(), ".cello", "key");
const listenAddr = process.env["CELLO_LISTEN_ADDR"] ?? "/ip4/0.0.0.0/tcp/0";
// AC-003 (REPOSPLIT-002): production directory endpoint baked in as default; overridable by env.
// Relay multiaddr is dynamically assigned per-session — no relay constant is baked in.
const directoryUrl = resolveDirectoryUrl(process.env);
const directoryMultiaddr = process.env["CELLO_DIRECTORY_MULTIADDR"];
const celloEnv = process.env["CELLO_ENV"] ?? "local";
const dbPath = process.env["CELLO_DB_PATH"] ?? join(homedir(), ".cello", "client.db");
const backupS3Bucket = process.env["BACKUP_S3_BUCKET"];
// CELLO_AWS_REGION is the operator-settable variable (AWS_REGION is reserved by ECS/Lambda)
const awsRegion = process.env["CELLO_AWS_REGION"] ?? process.env["AWS_REGION"] ?? "eu-west-1";

// Load key
let kp: FileKeyProvider;
try {
  kp = await FileKeyProvider.load(keyPath);
} catch (err: unknown) {
  const msg = typeof err === "object" && err !== null && "message" in err
    ? (err as { message: string }).message
    : String(err);
  process.stderr.write(`cello-mcp: key file error: ${msg}\n`);
  process.exit(1);
}

// PERSIST-022: Read identity key (Ed25519 seed) from the key file for backup derivation.
// Key file format (from packages/crypto/src/ed25519.ts):
//   Magic[0..3] = [0xce, 0x11, 0x0e, 0x01]  ("CELLO\x01" marker)
//   version[4]  = 0x01
//   seed[5..36] = 32-byte Ed25519 seed
//   Total: 37 bytes (KEY_FILE_SIZE)
// The seed is used only for HKDF derivation (backup_key and db_key).
// It is never stored, never logged, and is zeroed after ClientBackup construction.
const KEY_FILE_MAGIC = new Uint8Array([0xce, 0x11, 0x0e, 0x01]);
const KEY_FILE_VERSION = 0x01;
const KEY_FILE_SIZE = 37; // Magic(4) + version(1) + seed(32)
const SEED_OFFSET = 5;    // KEY_FILE_MAGIC.length + 1
const SEED_LENGTH = 32;

let identityKeyBytes: Uint8Array | null = null;
try {
  const rawKeyFile = readFileSync(keyPath);
  // Validate exact file size
  if (rawKeyFile.length === KEY_FILE_SIZE) {
    // Validate magic bytes to ensure this is a valid CELLO key file
    const magicOk = KEY_FILE_MAGIC.every((b, i) => rawKeyFile[i] === b);
    // Validate version byte
    const versionOk = rawKeyFile[KEY_FILE_MAGIC.length] === KEY_FILE_VERSION;
    if (magicOk && versionOk) {
      identityKeyBytes = new Uint8Array(rawKeyFile.slice(SEED_OFFSET, SEED_OFFSET + SEED_LENGTH));
    } else {
      process.stderr.write(`cello-mcp: key file has invalid magic bytes or version — backup disabled\n`);
    }
  } else {
    process.stderr.write(`cello-mcp: key file has unexpected size (${rawKeyFile.length} bytes, expected ${KEY_FILE_SIZE}) — backup disabled\n`);
  }
} catch {
  // Non-fatal: if the key file can't be read for backup derivation, backup is disabled
  process.stderr.write(`cello-mcp: could not read identity key for backup derivation — backup disabled\n`);
}

// PERSIST-022: Derive agentId from the public key
const ownPubkeyForBackup = await kp.getPublicKey();
const agentId = Buffer.from(ownPubkeyForBackup).toString("hex");

// PERSIST-022: Select CloudStorageProvider based on CELLO_ENV and BACKUP_S3_BUCKET
let cloudStorageForBackup: CloudStorageProvider | null = null;
if (celloEnv === "local") {
  // Local: use filesystem-backed provider in ~/.cello/backups
  const localBackupDir = join(homedir(), ".cello", "backups");
  cloudStorageForBackup = new LocalCloudStorageProvider(localBackupDir);
  process.stderr.write(`cello-mcp: backup: using LocalCloudStorageProvider at ${localBackupDir}\n`);
} else if (backupS3Bucket) {
  // Non-local with bucket configured: use S3
  cloudStorageForBackup = new S3CloudStorageProvider({ bucket: backupS3Bucket, region: awsRegion });
  process.stderr.write(`cello-mcp: backup: using S3CloudStorageProvider, bucket=${backupS3Bucket}, region=${awsRegion}\n`);
} else {
  // Non-local without bucket: no backup configured — ClientBackup will log client.backup.not.configured
  process.stderr.write(`cello-mcp: backup: BACKUP_S3_BUCKET not set — backup not configured\n`);
}

// PERSIST-022: Construct ClientBackup (only if identity key is available)
// A minimal logger for the composition root backup instance that writes to stderr.
// In production deployments the full structured logger is wired in via server.ts.
const backupLogger = {
  debug: (event: string, ctx?: Record<string, unknown>) =>
    process.stderr.write(`cello-mcp: [debug] ${event} ${JSON.stringify(ctx ?? {})}\n`),
  info: (event: string, ctx?: Record<string, unknown>) =>
    process.stderr.write(`cello-mcp: [info] ${event} ${JSON.stringify(ctx ?? {})}\n`),
  warn: (event: string, ctx?: Record<string, unknown>) =>
    process.stderr.write(`cello-mcp: [warn] ${event} ${JSON.stringify(ctx ?? {})}\n`),
  error: (event: string, ctx?: Record<string, unknown>) =>
    process.stderr.write(`cello-mcp: [error] ${event} ${JSON.stringify(ctx ?? {})}\n`),
};

// PERSIST-024 (CRIT-1): Derive dbKey for SQLCipher from identity key before zeroing.
// The dbKey is derived via HKDF (RFC 5869) from the Ed25519 seed (SI-003: never stored).
let dbKey: Uint8Array | null = null;
if (identityKeyBytes) {
  dbKey = deriveDbKey(identityKeyBytes, agentId);
}

// PERSIST-024 (MED-2): clientPersistence is declared later (after SQLCipher store opens).
// The setMetadata callback closes over the variable reference so it picks up the value
// that is assigned later, at the point backup() is actually called.
let clientPersistenceRef: ClientStatePersistence | undefined;

let clientBackupInstance: ClientBackup | undefined;
if (identityKeyBytes) {
  clientBackupInstance = new ClientBackup({
    agentId,
    identityKey: identityKeyBytes,
    dbPath,
    cloudStorage: cloudStorageForBackup,
    logger: backupLogger,
    destinationType: celloEnv === "local" ? "local" : (backupS3Bucket ? "s3" : "local"),
    // PERSIST-024 (MED-2): persist backup metadata to structured DB table after successful upload.
    setMetadata: async (_key: string, value: Uint8Array) => {
      if (!clientPersistenceRef) return;
      try {
        const meta = JSON.parse(Buffer.from(value).toString("utf8")) as {
          timestamp: number;
          destinationUrl: string;
          checksum: string;
        };
        await clientPersistenceRef.persistBackupMetadata({
          completedAt: new Date(meta.timestamp).toISOString(),
          destinationUrl: meta.destinationUrl,
          checksum: meta.checksum,
        });
      } catch {
        // Non-fatal: metadata write failure does not affect the backup blob
      }
    },
    // PERSIST-024 (MED-2): read backup metadata from structured DB table for restore.
    getMetadata: async (_key: string): Promise<Uint8Array | undefined> => {
      if (!clientPersistenceRef) return undefined;
      try {
        const row = await clientPersistenceRef.loadBackupMetadata();
        if (!row) return undefined;
        const meta = {
          timestamp: new Date(row.completed_at).getTime(),
          destinationUrl: row.destination_url,
          checksum: row.checksum,
        };
        return new Uint8Array(Buffer.from(JSON.stringify(meta), "utf8"));
      } catch {
        return undefined;
      }
    },
  });
  // Zero the identity key bytes immediately after construction — it must not linger in memory (SI-001)
  identityKeyBytes.fill(0);
  identityKeyBytes = null;
}

// Parse directory endpoint from CELLO_DIRECTORY_MULTIADDR (if set).
// When not set, auto-fetch the multiaddr from GET /bootstrap on the directory HTTP endpoint.
// Pseudocode:
//   1. If CELLO_DIRECTORY_MULTIADDR is set → use it directly (existing behaviour)
//   2. Else → GET ${directoryUrl}/bootstrap with 5s timeout
//      a. Success + valid multiaddr → use it as if CELLO_DIRECTORY_MULTIADDR was set
//      b. 503 / network error / invalid JSON → log warning, continue without threshold signing

let resolvedDirectoryMultiaddr: string | undefined = directoryMultiaddr;

if (!resolvedDirectoryMultiaddr) {
  process.stderr.write(`cello-mcp: auto-discovering directory multiaddr from ${directoryUrl}/bootstrap\n`);
  // fetchFn defaults to global fetch; injectable in tests via config.ts
  const discovered = await fetchBootstrapMultiaddr(directoryUrl);
  if (discovered) {
    resolvedDirectoryMultiaddr = discovered;
    process.stderr.write(`cello-mcp: bootstrap fetch succeeded — multiaddr=${resolvedDirectoryMultiaddr}\n`);
  } else {
    process.stderr.write(`cello-mcp: bootstrap fetch failed — threshold signing unavailable\n`);
  }
}

let directoryEndpoint: { peer_id: string; multiaddrs: string[] } | undefined = undefined;
if (resolvedDirectoryMultiaddr) {
  const parts = resolvedDirectoryMultiaddr.split("/");
  const p2pIndex = parts.findIndex((p) => p === "p2p");
  const peerId = p2pIndex !== -1 ? parts[p2pIndex + 1] : null;
  if (peerId) {
    directoryEndpoint = { peer_id: peerId, multiaddrs: [resolvedDirectoryMultiaddr] };
  } else {
    process.stderr.write("cello-mcp: directory multiaddr must include /p2p/<peer-id>\n");
  }
}

// Create and start single node
const node = await createNode({ keyProvider: kp, listenAddresses: [listenAddr] });
await node.start();

// Bootstrap FROST key shares (test-only shortcut)
// In production (M3+), real DKG ceremony replaces this.
let thresholdSigner: FrostThresholdSigner | undefined;
let primaryPubkey: Uint8Array | undefined;

process.stderr.write(`cello-mcp: NODE_ENV=${process.env.NODE_ENV ?? "(unset)"} CELLO_DIRECTORY_URL=${directoryUrl} CELLO_DIRECTORY_MULTIADDR=${resolvedDirectoryMultiaddr ?? "(unset)"}\n`);

{
  const ownPubkey = await kp.getPublicKey();

  if (resolvedDirectoryMultiaddr && directoryEndpoint) {
    process.stderr.write(`cello-mcp: bootstrapping FROST via network directory...\n`);
    try {
      await node.dial(directoryEndpoint.multiaddrs[0]!);
      process.stderr.write(`cello-mcp: node dialed directory OK\n`);

      const networkNodes = [new NetworkDirectoryNode({
        id: `cello-test-node-0000`,
        node,
        directoryPeerId: directoryEndpoint.peer_id,
        directoryMultiaddrs: directoryEndpoint.multiaddrs,
      })];

      const bootstrap = await bootstrapNetworkKeyShares(ownPubkey, {
        threshold: 2,
        participants: 1,
        directoryNodes: networkNodes,
      });
      thresholdSigner = bootstrap.signer;
      primaryPubkey = bootstrap.primaryPubkey;
      process.stderr.write(`cello-mcp: FROST bootstrap OK, primaryPubkey=${Buffer.from(primaryPubkey).toString("hex").slice(0, 16)}...\n`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? `${err.name}: ${err.message}\n${err.stack}` : JSON.stringify(err);
      process.stderr.write(`cello-mcp: FROST bootstrap FAILED: ${msg}\n`);
      process.stderr.write(`cello-mcp: continuing without threshold signer (already-registered agents use persistent signaling stream)\n`);
    }
  } else {
    process.stderr.write(`cello-mcp: no directory multiaddr configured — threshold signing unavailable\n`);
  }
}

// PERSIST-024 (CRIT-1): Construct and open the SQLCipher store, then wire ClientStatePersistence.
// dbKey is derived from identityKeyBytes before it is zeroed (see above).
let clientPersistence: ClientStatePersistence | undefined;
let sqlCipherStore: SQLCipherClientStore | undefined;
if (dbKey) {
  try {
    sqlCipherStore = new SQLCipherClientStore(dbKey, {
      dbPath,
      agentId,
      env: celloEnv,
      logger: backupLogger,
    });
    await sqlCipherStore.open();
    clientPersistence = new ClientStatePersistence({
      store: sqlCipherStore,
      agentPubkey: agentId,
      keyFilePath: keyPath,
      logger: backupLogger,
    });
    // PERSIST-024 (MED-2): expose to backup setMetadata/getMetadata callbacks (late binding)
    clientPersistenceRef = clientPersistence;
    // Note: upsertAgent() is NOT called here. loadPersistedState() calls it after all
    // state loading completes — that is the authoritative call site that updates last_seen_at
    // only on a fully successful startup.
    process.stderr.write(`cello-mcp: persistence: SQLCipher store opened at ${dbPath}\n`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    // Detect native module load failures (missing pre-built binary, ABI mismatch, missing system libs).
    const isNativeModuleError =
      msg.includes("Cannot find module") ||
      msg.includes("was compiled against a different Node.js version") ||
      msg.includes("NODE_MODULE_VERSION") ||
      msg.includes("invalid ELF header") ||
      msg.includes("dlopen") ||
      msg.includes("libcrypto") ||
      msg.includes("libssl");
    if (isNativeModuleError) {
      const platform = process.platform;
      process.stderr.write(`cello-mcp: SQLCipher failed to load: ${msg}\n`);
      if (platform === "win32") {
        process.stderr.write(`cello-mcp: Windows requires a manual SQLCipher install.\n`);
        process.stderr.write(`cello-mcp: Download and install SQLCipher from https://www.zetetic.net/sqlcipher/\n`);
        process.stderr.write(`cello-mcp: Then re-run: npx @cello-protocol/connect\n`);
      } else if (platform === "linux") {
        process.stderr.write(`cello-mcp: Missing OpenSSL build dependencies on Linux.\n`);
        process.stderr.write(`cello-mcp: Run: sudo apt-get install build-essential libssl-dev\n`);
        process.stderr.write(`cello-mcp: Then re-run: npx @cello-protocol/connect\n`);
      } else {
        // macOS: Xcode Command Line Tools (~500MB) are required to compile SQLCipher.
        process.stderr.write(`cello-mcp: Xcode Command Line Tools are required on macOS.\n`);
        process.stderr.write(`cello-mcp: Run: xcode-select --install\n`);
        process.stderr.write(`cello-mcp: Then re-run: npx @cello-protocol/connect\n`);
      }
      process.stderr.write(`cello-mcp: Continuing without persistence — data will not survive restarts.\n`);
    } else {
      process.stderr.write(`cello-mcp: persistence: failed to open SQLCipher store — ${msg}\n`);
    }
    // Non-fatal: client continues without persistence
    clientPersistence = undefined;
    sqlCipherStore = undefined;
  }
} else {
  process.stderr.write(`cello-mcp: persistence: identity key not available — SQLCipher store disabled\n`);
}

// Late-bound server reference — set after createMcpServer returns.
// The closure captures the box; notifications fired before server is assigned are dropped.
let mcpServer: McpServer | undefined;

// Create single client
const client = createClient(node, kp, {
  thresholdSigner,
  directoryEndpoint,
  persistence: clientPersistence,
  onMessageQueued: (senderHex) => {
    if (mcpServer) void pushChannelNotification(mcpServer, senderHex);
  },
});

if (primaryPubkey) {
  client.setPrimaryPubkey(primaryPubkey);
}

// Create server with single identity.
// PERSIST-017: checkpointStatusProvider is not available in the cello-mcp binary
// (the client binary has no access to the directory's MmrStore). The provider is
// wired in directory-facing deployments via the server.ts composition root.
// Passing undefined is a safe fallback — the tools return M1 stub responses.
// PERSIST-022: clientBackupInstance passed so cello_backup/cello_restore are registered
// inside createMcpSessionServer (single canonical registration path).
const server = createMcpSessionServer(node, client, kp, { clientBackup: clientBackupInstance });
mcpServer = server;

// PERSIST-024 (CRIT-1): Load persisted state before accepting any MCP tool calls.
// This must happen before server.connect() so the first tool call sees restored state.
await client.loadPersistedState();

// PERSIST-024 AC-008: Build an in-memory AgentHashQueue and populate it from the pending_hashes
// DB table. Using LocalClientStore (in-memory) avoids the SQLCipherClientStore.set() throw.
// The queue is wired into the client so #reconnectRelayStream can check it on relay reconnect.
const loadedPendingHashes = client.getLoadedPendingHashes();
const hashQueue = new AgentHashQueue({
  store: new LocalClientStore(),
  agentId,
  logger: backupLogger,
});
if (loadedPendingHashes.length > 0) {
  await hashQueue.loadPending(loadedPendingHashes);
  process.stderr.write(`cello-mcp: ${loadedPendingHashes.length} pending hash(es) loaded into AgentHashQueue — relay resubmission will occur on reconnect\n`);
}
// Wire queue into client so relay reconnect can access pending hashes (AC-008)
(client as unknown as { setHashQueue(q: AgentHashQueue): void }).setHashQueue(hashQueue);

// Connect stdio transport and register handler
await server.connect(new StdioServerTransport());
await client.registerHandler();
