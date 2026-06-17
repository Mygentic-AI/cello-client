/**
 * Daemon registration persistence — CELLO-M7-REGISTRATION.
 *
 * The daemon owns each agent's registration material (ML-DSA keypair, FROST key
 * share, registration state) as per-agent files under ~/.cello/agents/<name>/.
 * This mirrors the daemon's existing `key`-file model (see agent-loader.ts) and
 * deliberately does NOT drag the client's SQLCipher ClientStatePersistence into
 * the daemon — that layer is keyed by agent_pubkey in one shared DB, whereas the
 * daemon isolates each agent in its own directory (cleaner for multi-agent).
 *
 * Security posture: the FROST signing share and ML-DSA secret key are written
 * with 0o600 permissions, atomically (write-to-tmp + rename), consistent with the
 * daemon's existing plaintext K_local `key` file. Encryption-at-rest for the
 * daemon is a separate future concern and is intentionally NOT introduced
 * piecemeal here. The signing share (SI-001) and secret key blob (SI-002) must
 * never appear in a log event — only the files hold them.
 */

import { mkdir, readFile, rename, chmod, unlink, open as fsOpen } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join, dirname } from "node:path";
import type { Logger } from "./types.js";

// ─── Loaded record shapes (returned by load* on restart) ─────────────────────

export interface RegistrationStateRecord {
  agentId: string;
  primaryPubkey: string;
  mlDsaPubkey: string;
  registeredAt: number;
  status: string;
}

export interface MlDsaKeypairRecord {
  mlDsaPubkey: string;
  secretKeyBlob: Uint8Array;
  algorithm: string;
}

export interface FrostKeyShareRecord {
  epochId: string;
  primaryPubkey: string;
  identifier: string;
  signingShare: Uint8Array;
  threshold: number;
  participants: number;
  commitmentsCbor: Uint8Array;
  verifyingSharesCbor: Uint8Array;
  dkgMethod: string;
}

/**
 * Narrow persistence seam consumed by the daemon's RegistrationManager. Exactly
 * the three persist operations the registration flow performs, plus the matching
 * load operations needed to rehydrate an already-registered agent on restart.
 */
export interface DaemonRegistrationPersistence {
  persistMlDsaKeypair(opts: { mlDsaPubkey: string; secretKeyBlob: Uint8Array }): Promise<void>;
  persistRegistrationState(opts: {
    agentId: string;
    primaryPubkey: string;
    mlDsaPubkey: string;
    registeredAt: number;
  }): Promise<void>;
  persistFrostKeyShare(opts: {
    epochId: string;
    primaryPubkey: string;
    identifier: string;
    signingShare: Uint8Array;
    threshold: number;
    participants: number;
    commitmentsCbor: Uint8Array;
    verifyingSharesCbor: Uint8Array;
    dkgMethod: "trusted_dealer" | "network_dkg";
  }): Promise<void>;

  loadRegistrationState(): Promise<RegistrationStateRecord | null>;
  loadMlDsaKeypair(): Promise<MlDsaKeypairRecord | null>;
  loadActiveFrostKeyShare(): Promise<FrostKeyShareRecord | null>;
}

// ─── On-disk file names (relative to the agent directory) ────────────────────

const FILE_REGISTRATION_STATE = "registration-state.json";
const FILE_MLDSA_KEYPAIR = "ml-dsa-keypair.json";
const FILE_FROST_SHARE = "frost-share.json";

const SECRET_FILE_MODE = 0o600;

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

/**
 * Required-field accessors. A registration file that exists but is missing or
 * mistypes a field is corrupt — surface it loudly rather than silently coercing
 * to NaN / an empty buffer (which would read as "unregistered" or hand crypto a
 * zero-length key). Atomic writes make this unreachable in normal operation.
 */
function reqStr(obj: Record<string, unknown>, key: string, file: string): string {
  const v = obj[key];
  if (typeof v !== "string") {
    throw new Error(`registration file '${file}' is corrupt: missing or non-string field '${key}'`);
  }
  return v;
}
function reqNum(obj: Record<string, unknown>, key: string, file: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new Error(`registration file '${file}' is corrupt: missing or non-numeric field '${key}'`);
  }
  return v;
}

/**
 * File-backed implementation. One instance is scoped to a single agent's
 * directory (e.g. ~/.cello/agents/alice/). The directory is created on first
 * write; load methods on a fresh agent return null (ENOENT is not an error).
 */
export class FileRegistrationPersistence implements DaemonRegistrationPersistence {
  readonly #agentDir: string;
  readonly #logger: Logger;
  #tmpCounter = 0;

  constructor(opts: { agentDir: string; logger: Logger }) {
    this.#agentDir = opts.agentDir;
    this.#logger = opts.logger;
  }

  // ─── Persist ───────────────────────────────────────────────────────────────

  async persistMlDsaKeypair(opts: { mlDsaPubkey: string; secretKeyBlob: Uint8Array }): Promise<void> {
    // SI-002: secretKeyBlob is written to disk only — never logged.
    await this.#writeJsonAtomic(FILE_MLDSA_KEYPAIR, {
      mlDsaPubkey: opts.mlDsaPubkey,
      secretKeyBlob: hex(opts.secretKeyBlob),
      algorithm: "ML-DSA-44",
    });
    this.#logger.info("registration.mldsa.persisted", { mlDsaPubkey: opts.mlDsaPubkey });
  }

  async persistRegistrationState(opts: {
    agentId: string;
    primaryPubkey: string;
    mlDsaPubkey: string;
    registeredAt: number;
  }): Promise<void> {
    await this.#writeJsonAtomic(FILE_REGISTRATION_STATE, {
      agentId: opts.agentId,
      primaryPubkey: opts.primaryPubkey,
      mlDsaPubkey: opts.mlDsaPubkey,
      registeredAt: opts.registeredAt,
      status: "active",
    });
    this.#logger.info("registration.state.persisted", {
      agentId: opts.agentId,
      primaryPubkey: opts.primaryPubkey,
    });
  }

  async persistFrostKeyShare(opts: {
    epochId: string;
    primaryPubkey: string;
    identifier: string;
    signingShare: Uint8Array;
    threshold: number;
    participants: number;
    commitmentsCbor: Uint8Array;
    verifyingSharesCbor: Uint8Array;
    dkgMethod: "trusted_dealer" | "network_dkg";
  }): Promise<void> {
    // A daemon agent holds exactly one active FROST share; a new DKG replaces it.
    await this.#writeJsonAtomic(FILE_FROST_SHARE, {
      epochId: opts.epochId,
      primaryPubkey: opts.primaryPubkey,
      identifier: opts.identifier,
      signingShare: hex(opts.signingShare), // SI-001: on disk only, never logged
      threshold: opts.threshold,
      participants: opts.participants,
      commitmentsCbor: hex(opts.commitmentsCbor),
      verifyingSharesCbor: hex(opts.verifyingSharesCbor),
      dkgMethod: opts.dkgMethod,
    });
    // SI-001: signingShare MUST NOT appear in this event.
    this.#logger.info("registration.frost.share.persisted", {
      epochId: opts.epochId,
      threshold: opts.threshold,
      participants: opts.participants,
      dkgMethod: opts.dkgMethod,
    });
  }

  // ─── Load (restart rehydration) ──────────────────────────────────────────────

  async loadRegistrationState(): Promise<RegistrationStateRecord | null> {
    const obj = await this.#readJson(FILE_REGISTRATION_STATE);
    if (!obj) return null;
    return {
      agentId: reqStr(obj, "agentId", FILE_REGISTRATION_STATE),
      primaryPubkey: reqStr(obj, "primaryPubkey", FILE_REGISTRATION_STATE),
      mlDsaPubkey: reqStr(obj, "mlDsaPubkey", FILE_REGISTRATION_STATE),
      registeredAt: reqNum(obj, "registeredAt", FILE_REGISTRATION_STATE),
      status: reqStr(obj, "status", FILE_REGISTRATION_STATE),
    };
  }

  async loadMlDsaKeypair(): Promise<MlDsaKeypairRecord | null> {
    const obj = await this.#readJson(FILE_MLDSA_KEYPAIR);
    if (!obj) return null;
    return {
      mlDsaPubkey: reqStr(obj, "mlDsaPubkey", FILE_MLDSA_KEYPAIR),
      secretKeyBlob: unhex(reqStr(obj, "secretKeyBlob", FILE_MLDSA_KEYPAIR)),
      algorithm: reqStr(obj, "algorithm", FILE_MLDSA_KEYPAIR),
    };
  }

  async loadActiveFrostKeyShare(): Promise<FrostKeyShareRecord | null> {
    const obj = await this.#readJson(FILE_FROST_SHARE);
    if (!obj) return null;
    return {
      epochId: reqStr(obj, "epochId", FILE_FROST_SHARE),
      primaryPubkey: reqStr(obj, "primaryPubkey", FILE_FROST_SHARE),
      identifier: reqStr(obj, "identifier", FILE_FROST_SHARE),
      signingShare: unhex(reqStr(obj, "signingShare", FILE_FROST_SHARE)),
      threshold: reqNum(obj, "threshold", FILE_FROST_SHARE),
      participants: reqNum(obj, "participants", FILE_FROST_SHARE),
      commitmentsCbor: unhex(reqStr(obj, "commitmentsCbor", FILE_FROST_SHARE)),
      verifyingSharesCbor: unhex(reqStr(obj, "verifyingSharesCbor", FILE_FROST_SHARE)),
      dkgMethod: reqStr(obj, "dkgMethod", FILE_FROST_SHARE),
    };
  }

  // ─── Internals ───────────────────────────────────────────────────────────────

  async #readJson(name: string): Promise<Record<string, unknown> | null> {
    let raw: Buffer;
    try {
      raw = await readFile(join(this.#agentDir, name));
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
    return JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
  }

  /** Write JSON atomically (tmp + rename) with 0o600 so partial writes never surface. */
  async #writeJsonAtomic(name: string, value: Record<string, unknown>): Promise<void> {
    await mkdir(this.#agentDir, { recursive: true });
    const finalPath = join(this.#agentDir, name);
    // Random suffix (not just pid+counter) so two FileRegistrationPersistence
    // instances sharing an agentDir in one process can never collide on the tmp
    // path and truncate each other's write.
    const tmpPath = join(
      dirname(finalPath),
      `.cello-reg-tmp-${process.pid}-${++this.#tmpCounter}-${randomBytes(6).toString("hex")}-${name}`,
    );
    const body = Buffer.from(JSON.stringify(value), "utf8");
    try {
      const fd = await fsOpen(tmpPath, "w", SECRET_FILE_MODE);
      try {
        await fd.write(body);
        await fd.chmod(SECRET_FILE_MODE);
        // fsync the data before rename so a crash between write and rename can't
        // surface an empty/partial key file on recovery.
        await fd.sync();
      } finally {
        await fd.close();
      }
      await rename(tmpPath, finalPath);
      // rename preserves the tmp file's mode; chmod the final path defensively in
      // case it pre-existed with looser permissions.
      await chmod(finalPath, SECRET_FILE_MODE);
      // Best-effort durability of the rename itself (parent-dir fsync). Not all
      // platforms/filesystems support directory fsync — ignore failures.
      await this.#fsyncDir(this.#agentDir);
    } catch (err) {
      // Never leave plaintext secret material (ML-DSA secret / FROST share) as
      // orphaned tmp litter if the write or rename failed partway.
      await unlink(tmpPath).catch(() => {});
      throw err;
    }
  }

  async #fsyncDir(dir: string): Promise<void> {
    try {
      const dh = await fsOpen(dir, "r");
      try {
        await dh.sync();
      } finally {
        await dh.close();
      }
    } catch {
      // Directory fsync is best-effort; some platforms reject opening a dir for sync.
    }
  }
}
