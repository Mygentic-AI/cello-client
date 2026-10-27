/**
 * M10E 005-SVCCLIENT — the session proof a provider attaches to a service event.
 *
 * The daemon verifies a session assignment (`assignment-verify.ts`) and today keeps only the genesis
 * root and the relay anchor, so a provider has nothing to prove the session with when it later marks
 * a service event. This module keeps the proof: it re-encodes the quorum-signed assignment into the
 * 15-element CBOR array the directory verifies, and stores it keyed on (agent_id, session_id).
 *
 * WIRE CONTRACT: the same array as `trustless-cello/packages/directory/src/session-proof.ts`. The
 * golden bytes in that repo's `attestation-service-event.test.ts` (S13) pin both halves together;
 * K1 asserts the same hex here. The `Encoder` options MUST match the directory's exactly.
 *
 * Crypto: CBOR → RFC 8949 (canonical via cbor-x with records off).
 */
import { Encoder } from "cbor-x";
import type { SessionAssignmentFrost } from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";

export const SESSION_PROOF_DOMAIN = "CELLO-ASPROOF-v1";
const ENC = new Encoder({ tagUint8Array: false, useRecords: false });

export interface SessionProof {
  session_id: Uint8Array;
  pub_a: Uint8Array;
  pub_b: Uint8Array;
  session_timestamp: number;
  initiator_session_peer_id: string | null;
  initiator_session_addrs: string[] | null;
  counterparty_session_peer_id: string | null;
  counterparty_session_addrs: string[] | null;
  transport_mode: "direct" | "relay" | null;
  high_stakes: boolean | null;
  prior_relay_id: string | null;
  relay_id: string | null;
  signer_pubkey: Uint8Array;
  directory_signature: Uint8Array;
}

export function encodeSessionProof(p: SessionProof): Uint8Array {
  return new Uint8Array(ENC.encode([
    SESSION_PROOF_DOMAIN, p.session_id, p.pub_a, p.pub_b, p.session_timestamp,
    p.initiator_session_peer_id, p.initiator_session_addrs, p.counterparty_session_peer_id,
    p.counterparty_session_addrs, p.transport_mode, p.high_stakes, p.prior_relay_id, p.relay_id,
    p.signer_pubkey, p.directory_signature,
  ]));
}

/** Throws on any shape fault: wrong length, wrong domain, wrong type. Mirrors the directory. */
export function decodeSessionProof(raw: Uint8Array): SessionProof {
  const a = ENC.decode(raw) as unknown;
  if (!Array.isArray(a) || a.length !== 15) throw new Error("session proof: must be a 15-element array");
  if (a[0] !== SESSION_PROOF_DOMAIN) throw new Error("session proof: wrong domain");
  const ts = typeof a[4] === "bigint" ? Number(a[4]) : a[4];
  if (typeof ts !== "number" || !Number.isSafeInteger(ts) || ts < 0) throw new Error("session proof: session_timestamp must be a non-negative integer");
  const mode = a[9];
  if (mode !== null && mode !== "direct" && mode !== "relay") throw new Error("session proof: transport_mode");
  if (a[10] !== null && typeof a[10] !== "boolean") throw new Error("session proof: high_stakes");
  const bytes = (v: unknown, len: number, name: string): Uint8Array => {
    if (!(v instanceof Uint8Array) || v.length !== len) throw new Error(`session proof: ${name} must be ${len} bytes`);
    return new Uint8Array(v);
  };
  const strOrNull = (v: unknown, name: string): string | null => {
    if (v === null || typeof v === "string") return v;
    throw new Error(`session proof: ${name} must be a string or null`);
  };
  const strsOrNull = (v: unknown, name: string): string[] | null => {
    if (v === null) return null;
    if (Array.isArray(v) && v.every((s) => typeof s === "string")) return v as string[];
    throw new Error(`session proof: ${name} must be a string array or null`);
  };
  return {
    session_id: bytes(a[1], 16, "session_id"),
    pub_a: bytes(a[2], 32, "pub_a"),
    pub_b: bytes(a[3], 32, "pub_b"),
    session_timestamp: ts,
    initiator_session_peer_id: strOrNull(a[5], "initiator_session_peer_id"),
    initiator_session_addrs: strsOrNull(a[6], "initiator_session_addrs"),
    counterparty_session_peer_id: strOrNull(a[7], "counterparty_session_peer_id"),
    counterparty_session_addrs: strsOrNull(a[8], "counterparty_session_addrs"),
    transport_mode: mode,
    high_stakes: a[10],
    prior_relay_id: strOrNull(a[11], "prior_relay_id"),
    relay_id: strOrNull(a[12], "relay_id"),
    signer_pubkey: bytes(a[13], 32, "signer_pubkey"),
    directory_signature: bytes(a[14], 64, "directory_signature"),
  };
}

/**
 * Re-encode a verified FROST assignment into the directory's proof array. Field-for-field: an absent
 * optional becomes null, so the bytes reconstruct the exact TBS the quorum signed and the directory
 * re-verifies on any node. `pub_a`/`pub_b` are the participants' K_local pubkeys.
 */
export function sessionProofFromAssignment(a: SessionAssignmentFrost): SessionProof {
  return {
    session_id: a.session_id,
    pub_a: a.participant_a.pubkey,
    pub_b: a.participant_b.pubkey,
    session_timestamp: a.session_timestamp,
    initiator_session_peer_id: a.initiator_session_peer_id ?? null,
    initiator_session_addrs: a.initiator_session_addrs ?? null,
    counterparty_session_peer_id: a.counterparty_session_peer_id ?? null,
    counterparty_session_addrs: a.counterparty_session_addrs ?? null,
    transport_mode: a.transport_mode ?? null,
    high_stakes: a.high_stakes ?? null,
    prior_relay_id: a.prior_relay_id ?? null,
    relay_id: a.relay_id ?? null,
    signer_pubkey: a.signer_pubkey,
    directory_signature: a.directory_signature,
  };
}

/** The minimum of the SQLCipher handle this needs — a prepared-statement runner. */
export interface ProofStoreDb {
  prepare(sql: string): { run(...params: unknown[]): unknown };
}

/**
 * Store the proof for (agent_id, session_id) on the assignment-verified path ONLY.
 *
 * Gated on `verified.ok`: a failed verification stores nothing (K2). A write failure is logged at
 * error and swallowed — the session must open even when the proof cannot be kept (K10); only a later
 * mark of that session will be refused `no_session_proof`. `INSERT OR IGNORE` keeps it idempotent.
 */
export function persistSessionProof(
  db: ProofStoreDb,
  agentId: string,
  sessionIdHex: string,
  assignment: SessionAssignmentFrost,
  verified: { ok: boolean },
  now: () => number,
  logger: Logger,
  correlationId: string,
): void {
  if (!verified.ok) return;
  try {
    const proof = encodeSessionProof(sessionProofFromAssignment(assignment));
    db.prepare(
      "INSERT OR IGNORE INTO session_proofs (agent_id, session_id, proof, stored_at) VALUES (?, ?, ?, ?)",
    ).run(agentId, sessionIdHex, Buffer.from(proof), now());
    logger.debug("attestation.session_proof.stored", { session_id: sessionIdHex, correlationId });
  } catch (err: unknown) {
    logger.error("attestation.session_proof.store_failed", {
      session_id: sessionIdHex, reason: err instanceof Error ? err.message : String(err),
    });
  }
}
