#!/usr/bin/env node
/**
 * cello-mcp — single-identity CELLO MCP server
 *
 * One key file. One libp2p node. One client. One MCP server.
 * Two agents = two separate processes, each running this binary with their own CELLO_KEY_FILE.
 *
 * AC-002 (DX-001): TTY detection — if stdin is a TTY, print install instructions and exit.
 * AC-009 (DX-001): Lazy startup — MCP server connects and registers tools immediately;
 *   bootstrap fetch, directory dial, SQLCipher open, and loadPersistedState move to background.
 * AC-001 (DX-001): Startup progress lines emitted to stderr at each step.
 *
 * Environment variables:
 *   CELLO_KEY_FILE            Path to Ed25519 key file (default: ~/.cello/key)
 *   CELLO_AGENT_NAME          Named agent identifier (M7+); lock file is per-agent
 *                             (default: null → ~/.cello/cello-mcp.pid; with name → ~/.cello/agents/<name>/cello-mcp.pid)
 *   CELLO_LOCK_FILE_PATH      Override lock file path (test only; default: computed from CELLO_AGENT_NAME)
 *   CELLO_LISTEN_ADDR         libp2p listen address (default: /ip4/0.0.0.0/tcp/0)
 *   CELLO_ANNOUNCE_ADDRS      comma-separated libp2p announce multiaddrs (optional)
 *                             Required when the node is behind NAT/EIP and must advertise
 *                             its public address (e.g. /ip4/32.196.100.165/tcp/4001 on EC2)
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
import { join, normalize } from "node:path";
import { createWriteStream, readFileSync } from "node:fs";

// AC-002 (DX-001): TTY detection — BEFORE anything else.
// If stdin is a TTY, the binary was run directly in a terminal, not as an MCP subprocess.
// Print install instructions to stdout and exit cleanly.
if (process.stdin.isTTY) {
  process.stdout.write(
    "This is a CELLO MCP server. It is designed to run as a subprocess of Claude Code.\n" +
    "\n" +
    "To install, run:\n" +
    "  claude mcp add cello npx --yes @cello-protocol/connect\n" +
    "\n" +
    "Then restart Claude Code to activate CELLO.\n",
  );
  process.exit(0);
}

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
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { FileKeyProvider, FrostThresholdSigner } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { createClient, createMcpSessionServer, NetworkDirectoryNode, bootstrapNetworkKeyShares, ClientBackup, S3CloudStorageProvider, SQLCipherClientStore, ClientStatePersistence, AgentHashQueue, deriveDbKey } from "@cello-protocol/client";
import { LocalCloudStorageProvider, LocalClientStore } from "@cello-protocol/interfaces/stubs";
import type { CloudStorageProvider } from "@cello-protocol/interfaces";
import { pushChannelNotification } from "../notifications.js";
import { resolveDirectoryUrl, fetchBootstrapMultiaddr } from "../config.js";
import { acquireLockFile, getLockFilePath } from "../lock-file.js";

// AC-001 (DX-001): Startup progress — emit one line per step to stderr.
// Format: 'cello: <step>... <outcome>'
process.stderr.write("cello: starting...\n");

// CELLO-M6B-001: Acquire PID lock file BEFORE any DB operations.
// This kills any prior cello-mcp process holding the same lock, ensuring exactly
// one cello-mcp per agent at all times. The cleanup function is registered to
// release the lock on SIGTERM/SIGINT/normal exit.
const agentName = process.env["CELLO_AGENT_NAME"] ?? null;
let lockFilePath = process.env["CELLO_LOCK_FILE_PATH"] ?? getLockFilePath(agentName);

// CRITICAL-2: Validate CELLO_LOCK_FILE_PATH if set — reject paths outside ~/.cello/ in production.
// Use path.normalize (without realpathSync) so this works on first run before the lock file
// or ~/.cello/ directory exists. The normalized path is checked against the normalized ~/.cello/
// prefix — this catches directory traversal ("../") in the raw path without requiring the file
// to exist. Note: symlink-based path traversal requires the symlink to already exist at the
// exact lock file path; if an attacker can already write arbitrary symlinks to ~/.cello/ they
// have broader access. The normalize check prevents the common env-var injection attack where
// CELLO_LOCK_FILE_PATH=~/../../../etc/passwd is set directly.
// Test/local environments allow flexibility for isolated test fixtures.
if (process.env["CELLO_LOCK_FILE_PATH"]) {
  const isTestOrLocal = process.env["NODE_ENV"] === "test" || (process.env["CELLO_ENV"] ?? "local") === "local";
  if (!isTestOrLocal) {
    const userHome = homedir();
    const celloDir = normalize(join(userHome, ".cello")) + "/";
    const normalizedLockPath = normalize(lockFilePath);
    if (!normalizedLockPath.startsWith(celloDir)) {
      process.stderr.write(`cello-mcp: CELLO_LOCK_FILE_PATH must be within ~/.cello/ directory\n`);
      process.stderr.write(`cello-mcp: Got: ${lockFilePath} (normalized to ${normalizedLockPath})\n`);
      process.exit(1);
    }
  }
}

const releaseLock = await acquireLockFile(lockFilePath, {
  logger: {
    info: (event: string, ctx: Record<string, unknown>) =>
      process.stderr.write(`cello-mcp: [info] ${event} ${JSON.stringify(ctx)}\n`),
    warn: (event: string, ctx: Record<string, unknown>) =>
      process.stderr.write(`cello-mcp: [warn] ${event} ${JSON.stringify(ctx)}\n`),
  },
});

// CRITICAL-1: Register cleanup on exit signals and normal exit.
// The "exit" handler calls releaseLock() and runs on normal exit.
// Signal handlers call process.exit() which triggers the exit handler.
// Exception handlers MUST call releaseLock() before re-throwing because
// Node.js terminates immediately on uncaught exceptions without firing
// the "exit" event. Without this, every cello-mcp crash leaves a stale lock.
//
// NOTE: In-flight backup operations (cello_backup tool) are NOT awaited on SIGTERM/SIGINT.
// This is acceptable risk for M6B scope because:
// 1. Backups are idempotent (checksummed, retried on next run)
// 2. Backup upload failures are logged and return error to the user
// 3. Partial S3 uploads are eventually consistent and can be retried
// 4. Adding graceful shutdown tracking requires wiring state across tool calls (out of scope)
// If graceful shutdown becomes necessary, add a ClientBackup.shutdown() method that:
// - Sets a shuttingDown flag
// - Waits up to 5s for in-flight backup() calls to complete
// - Then allows process.exit(0) to proceed
process.on("exit", () => {
  releaseLock();
});
process.on("SIGTERM", () => {
  process.exit(0);
});
process.on("SIGINT", () => {
  process.exit(0);
});
process.on("uncaughtException", () => {
  releaseLock();
  process.exit(1);
});
process.on("unhandledRejection", () => {
  releaseLock();
  process.exit(1);
});

const keyPath = process.env["CELLO_KEY_FILE"] ?? join(homedir(), ".cello", "key");
const listenAddr = process.env["CELLO_LISTEN_ADDR"] ?? "/ip4/0.0.0.0/tcp/0";
const announceAddrs = process.env["CELLO_ANNOUNCE_ADDRS"]
  ? process.env["CELLO_ANNOUNCE_ADDRS"].split(",").map((a) => a.trim()).filter(Boolean)
  : [];
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
} else if (backupS3Bucket) {
  // Non-local with bucket configured: use S3
  cloudStorageForBackup = new S3CloudStorageProvider({ bucket: backupS3Bucket, region: awsRegion });
} else {
  // Non-local without bucket: no backup configured — ClientBackup will log client.backup.not.configured
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
  error: (event: string, errorOrContext?: Error | Record<string, unknown>, context?: Record<string, unknown>) => {
    if (errorOrContext instanceof Error) {
      process.stderr.write(`cello-mcp: [error] ${event} ${JSON.stringify({ message: errorOrContext.message, stack: errorOrContext.stack, ...context })}\n`);
    } else {
      process.stderr.write(`cello-mcp: [error] ${event} ${JSON.stringify(errorOrContext ?? {})}\n`);
    }
  },
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

// AC-009 (DX-001): Lazy startup.
// Create the libp2p node synchronously (fast — no network), then create the client and MCP server.
// The heavy operations (bootstrap fetch, directory dial, SQLCipher open, loadPersistedState)
// move to a background async task. Tools that need the directory/FROST await readyPromise.

// Create and start single node (fast — just opens a TCP port)
const node = await createNode({
  keyProvider: kp,
  listenAddresses: [listenAddr],
  ...(announceAddrs.length ? { announceAddresses: announceAddrs } : {}),
});
await node.start();

// Late-bound server reference — set after createMcpServer returns.
// The closure captures the box; notifications fired before server is assigned are dropped.
let mcpServer: McpServer | undefined;

// AC-009: readySignal — resolved when background init completes (or fails).
// Tools that require the directory await this with a 10s timeout.
let readyResolve: (value: void) => void = () => {};
let readyReject: (reason?: unknown) => void = () => {};
const readyPromise = new Promise<void>((resolve, reject) => {
  readyResolve = resolve;
  readyReject = reject;
});

// Create client with no thresholdSigner initially — background task populates it.
// directoryEndpoint is also populated in the background task.
const client = createClient(node, kp, {
  thresholdSigner: undefined,
  directoryEndpoint: undefined,
  persistence: undefined, // wired in background task after SQLCipher opens
  onMessageQueued: (senderHex) => {
    if (mcpServer) void pushChannelNotification(mcpServer, senderHex);
  },
});

// Create server with single identity.
// PERSIST-017: checkpointStatusProvider is not available in the cello-mcp binary
// (the client binary has no access to the directory's MmrStore). The provider is
// wired in directory-facing deployments via the server.ts composition root.
// Passing undefined is a safe fallback — the tools return M1 stub responses.
// PERSIST-022: clientBackupInstance passed so cello_backup/cello_restore are registered
// inside createMcpSessionServer (single canonical registration path).
const server = createMcpSessionServer(node, client, kp, {
  clientBackup: clientBackupInstance,
  // AC-007 (DX-001): pass directoryUrl so agent_id lookup works in tool handlers
  directoryUrl,
  // AC-009 (DX-001): pass readyPromise so tools can await background init (up to 10s)
  readyPromise,
  // Wire logger so observability events (e.g. client.directory.agent_lookup.failed) are emitted
  logger: backupLogger,
});
mcpServer = server;

// AC-009 (DX-001): Connect stdio transport NOW — before any network operations.
// This ensures tools/list responds within 2s of process start.
await server.connect(new StdioServerTransport());
await client.registerHandler();

// AC-009 (DX-001): Background init task — runs concurrently with MCP tool calls.
// All network and disk I/O happens here, not on the critical path of server startup.
void (async () => {
  try {
    // Step 1: Open SQLCipher database
    process.stderr.write("cello: opening database...");
    let clientPersistence: ClientStatePersistence | undefined;
    let sqlCipherStore: SQLCipherClientStore | undefined;
    const t0Db = Date.now();
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
        // Wire persistence into client
        (client as unknown as { setPersistence(p: ClientStatePersistence): void }).setPersistence?.(clientPersistence);
        const durationMs = Date.now() - t0Db;
        // AC-001: report schema version and table count when available
        const schemaInfo = (sqlCipherStore as unknown as { getSchemaInfo?: () => { version: number; tableCount: number } }).getSchemaInfo?.();
        if (schemaInfo) {
          process.stderr.write(` ok (V${schemaInfo.version}, ${schemaInfo.tableCount} tables)\n`);
        } else {
          process.stderr.write(` ok (${durationMs}ms)\n`);
        }
        backupLogger.info("client.startup.progress", { step: "opening_database", outcome: "ok", durationMs });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(` failed: ${msg}\n`);
        backupLogger.warn("client.startup.progress", { step: "opening_database", outcome: "failed", reason: msg, durationMs: Date.now() - t0Db });
        // Detect native module load failures
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
          if (platform === "win32") {
            process.stderr.write(`cello-mcp: Windows is not yet supported in the CELLO beta.\n`);
            process.stderr.write(`cello-mcp: Windows support is on the roadmap. Follow https://github.com/Mygentic-AI/cello-client for updates.\n`);
          } else if (platform === "linux") {
            process.stderr.write(`cello-mcp: Missing OpenSSL build dependencies on Linux.\n`);
            process.stderr.write(`cello-mcp: Run: sudo apt-get install build-essential libssl-dev\n`);
            process.stderr.write(`cello-mcp: Then re-run: npx --yes @cello-protocol/connect\n`);
          } else {
            process.stderr.write(`cello-mcp: Xcode Command Line Tools are required on macOS.\n`);
            process.stderr.write(`cello-mcp: Run: xcode-select --install\n`);
            process.stderr.write(`cello-mcp: Then re-run: npx --yes @cello-protocol/connect\n`);
          }
          process.stderr.write(`cello-mcp: Continuing without persistence — data will not survive restarts.\n`);
        }
        // Non-fatal: client continues without persistence
        clientPersistence = undefined;
        sqlCipherStore = undefined;
      }
    } else {
      process.stderr.write(` failed: identity key not available\n`);
      backupLogger.warn("client.startup.progress", { step: "opening_database", outcome: "failed", reason: "identity key not available", durationMs: Date.now() - t0Db });
    }

    // Step 2: Fetch directory address
    let resolvedDirectoryMultiaddr: string | undefined = directoryMultiaddr;
    let directoryEndpoint: { peer_id: string; multiaddrs: string[] } | undefined = undefined;

    if (!resolvedDirectoryMultiaddr) {
      process.stderr.write(`cello: fetching directory address...`);
      const t0Bootstrap = Date.now();
      try {
        const discovered = await fetchBootstrapMultiaddr(directoryUrl);
        if (discovered) {
          resolvedDirectoryMultiaddr = discovered;
          const parts = resolvedDirectoryMultiaddr.split("/");
          const p2pIndex = parts.findIndex((p) => p === "p2p");
          const peerId = p2pIndex !== -1 ? parts[p2pIndex + 1] : null;
          const shortPeerId = peerId ? peerId.slice(0, 20) + "..." : "(unknown)";
          process.stderr.write(` ok (${shortPeerId})\n`);
          backupLogger.info("client.startup.progress", { step: "fetching_directory_address", outcome: "ok", durationMs: Date.now() - t0Bootstrap });
        } else {
          const reason = "bootstrap endpoint unreachable";
          backupLogger.warn("client.bootstrap.fetch.failed", { directoryUrl, reason: "endpoint_returned_null", durationMs: Date.now() - t0Bootstrap });
          process.stderr.write(` failed: ${reason}\n`);
          backupLogger.warn("client.startup.progress", { step: "fetching_directory_address", outcome: "failed", reason, durationMs: Date.now() - t0Bootstrap });
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        backupLogger.warn("client.bootstrap.fetch.failed", { directoryUrl, reason: msg, durationMs: Date.now() - t0Bootstrap });
        process.stderr.write(` failed: ${msg}\n`);
        backupLogger.warn("client.startup.progress", { step: "fetching_directory_address", outcome: "failed", reason: msg, durationMs: Date.now() - t0Bootstrap });
      }
    } else {
      // CELLO_DIRECTORY_MULTIADDR is set — use it directly
      process.stderr.write(`cello: fetching directory address... ok (from CELLO_DIRECTORY_MULTIADDR)\n`);
      backupLogger.info("client.startup.progress", { step: "fetching_directory_address", outcome: "ok", durationMs: 0 });
    }

    if (resolvedDirectoryMultiaddr) {
      const parts = resolvedDirectoryMultiaddr.split("/");
      const p2pIndex = parts.findIndex((p) => p === "p2p");
      const peerId = p2pIndex !== -1 ? parts[p2pIndex + 1] : null;
      if (peerId) {
        directoryEndpoint = { peer_id: peerId, multiaddrs: [resolvedDirectoryMultiaddr] };
      } else {
        // Multiaddr is present but lacks /p2p/<peer-id> — setDirectoryEndpoint will not be called.
        backupLogger.warn("client.startup.multiaddr_parse.failed", { reason: "multiaddr_missing_peer_id", multiaddr: resolvedDirectoryMultiaddr });
        process.stderr.write("cello-mcp: directory multiaddr must include /p2p/<peer-id>\n");
      }
    }

    // AC-003 (DX-001): Set directoryEndpoint on the client BEFORE loadPersistedState() so that
    // loadPersistedState() can populate directoryNodeStubs in the reconstructed FrostThresholdSigner.
    // Only called when directoryEndpoint is parsed successfully (requires /p2p/<peer-id> in the
    // multiaddr). If multiaddr lacks peer ID, loadPersistedState() will reconstruct the
    // FrostThresholdSigner with directoryNodeStubs: undefined — ceremonies will fail until the
    // agent reconnects with a valid multiaddr.
    if (directoryEndpoint) {
      (client as unknown as { setDirectoryEndpoint(e: typeof directoryEndpoint): void }).setDirectoryEndpoint?.(directoryEndpoint);
    }

    // Step 3: Load agent state (moved BEFORE directory connection/bootstrap)
    // Registered agents will have their FrostThresholdSigner reconstructed from DB here.
    // directoryEndpoint is already set, so directoryNodeStubs will be populated.
    process.stderr.write("cello: loading agent state...");
    const t0LoadState = Date.now();
    try {
      await client.loadPersistedState();
      process.stderr.write(" ok\n");
      backupLogger.info("client.startup.progress", { step: "loading_agent_state", outcome: "ok", durationMs: Date.now() - t0LoadState });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(` failed: ${msg}\n`);
      backupLogger.warn("client.startup.progress", { step: "loading_agent_state", outcome: "failed", reason: msg, durationMs: Date.now() - t0LoadState });
      throw err;
    }

    // PERSIST-024 AC-008: Build AgentHashQueue
    const loadedPendingHashes = client.getLoadedPendingHashes();
    const hashQueue = new AgentHashQueue({
      store: new LocalClientStore(),
      agentId,
      logger: backupLogger,
    });
    if (loadedPendingHashes.length > 0) {
      await hashQueue.loadPending(loadedPendingHashes);
      process.stderr.write(`cello-mcp: ${loadedPendingHashes.length} pending hash(es) loaded into AgentHashQueue\n`);
    }
    (client as unknown as { setHashQueue(q: AgentHashQueue): void }).setHashQueue(hashQueue);

    // Check if the agent is already registered (FROST share was loaded from DB).
    // If so, skip bootstrap — the signer is already reconstructed from the DB.
    const regStateAfterLoad = typeof (client as unknown as { getRegistrationState?: () => { agent_id: string } | null }).getRegistrationState === "function"
      ? (client as unknown as { getRegistrationState: () => { agent_id: string } | null }).getRegistrationState()
      : null;

    // Step 4: Connect to directory and bootstrap ONLY if not already registered
    let thresholdSigner: FrostThresholdSigner | undefined;
    let primaryPubkey: Uint8Array | undefined;

    const t0Connect = Date.now();
    if (resolvedDirectoryMultiaddr && directoryEndpoint) {
      process.stderr.write(`cello: connecting to directory...`);
      try {
        await node.dial(directoryEndpoint.multiaddrs[0]!);

        // Announce to the directory immediately after dial so the directory registers
        // this agent in its #streams map. Without this, the directory considers the
        // agent offline even though the libp2p TCP connection succeeded.
        // registerHandler() was called before directoryEndpoint was set, so the
        // proactive announce inside it was skipped — this call makes up for that.
        await (client as unknown as { announceToDirectory(): Promise<void> }).announceToDirectory();

        if (!regStateAfterLoad) {
          // Not yet registered — run bootstrap to initialize FROST key shares.
          // Registered agents already have their signer from loadPersistedState().
          const ownPubkey = await kp.getPublicKey();
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
        }
        process.stderr.write(` ok\n`);
        backupLogger.info("client.startup.progress", { step: "connecting_to_directory", outcome: "ok", durationMs: Date.now() - t0Connect });
      } catch (err: unknown) {
        const msg = err instanceof Error ? `${err.name}: ${err.message}` : JSON.stringify(err);
        process.stderr.write(` failed: ${msg}\n`);
        process.stderr.write(`cello-mcp: continuing without threshold signer\n`);
        backupLogger.warn("client.startup.progress", { step: "connecting_to_directory", outcome: "failed", reason: msg, durationMs: Date.now() - t0Connect });
      }
    } else {
      process.stderr.write(`cello: connecting to directory... failed: no multiaddr configured\n`);
      backupLogger.warn("client.startup.progress", { step: "connecting_to_directory", outcome: "failed", reason: "no multiaddr configured", durationMs: Date.now() - t0Connect });
    }

    // Wire threshold signer into client only when bootstrap ran (unregistered agents).
    // Registered agents already have their signer from loadPersistedState().
    if (thresholdSigner) {
      (client as unknown as { setThresholdSigner(s: FrostThresholdSigner): void }).setThresholdSigner?.(thresholdSigner);
    }
    if (primaryPubkey) {
      client.setPrimaryPubkey(primaryPubkey);
    }

    // Step 5: Emit final ready message (use regStateAfterLoad from loadPersistedState)
    if (regStateAfterLoad) {
      process.stderr.write(`cello: ready (registered as ${regStateAfterLoad.agent_id})\n`);
    } else {
      process.stderr.write(`cello: ready (not registered — call cello_setup_guidance for setup)\n`);
    }
    // durationMs: 0 — "ready" is a completion marker, not a timed operation.
    backupLogger.info("client.startup.progress", { step: "ready", outcome: "ok", durationMs: 0 });

    readyResolve();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`cello-mcp: background init failed: ${msg}\n`);
    readyReject(err);
  }
})();
