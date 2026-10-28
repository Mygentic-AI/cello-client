/**
 * M10E 013-PRIVATE — the client half of a private namespace's reader list.
 *
 * The owner of a PRIVATE namespace names the readers who may receive a delivered copy of its
 * attestations. This builds and signs version N+1 of that list and sends it to the directory, and
 * reads the current one back. The directory holds it (readable only by the owner and the portal) and
 * announces every change to the readers, so a supervisor cannot be dropped silently.
 *
 * COUNTERBALANCE. Nothing here is trusted to assert a reader list into existence: the record is
 * OWNER-SIGNED and the directory re-checks the signature on write AND on replication, so a rewritten
 * client cannot plant a list for anyone else, and the version must be exactly current+1.
 *
 * The record is the directory's canonical CBOR array `[DOMAIN, owner, namespace, readers, version,
 * issued_at]`, replicated here rather than imported from the directory package — nothing publishes
 * mid-stack (M10E §2d-bis), so the two halves are pinned by a golden-bytes contract test, exactly as
 * the session proof is. Readers are strictly ascending and unique, so the record re-hashes
 * identically on every node.
 *
 * Crypto: Ed25519 → RFC 8032, CBOR → RFC 8949, SHA-256 → FIPS 180-4.
 */
import { Encoder } from "cbor-x";
import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import { serialize, sendAndAwait, toU8, type NamespaceDeps } from "./attestation-namespaces.js";

export const READER_LIST_DOMAIN = "CELLO-ARDRS-v1";
const ENC = new Encoder({ tagUint8Array: false, useRecords: false });
const HEX64 = /^[0-9a-f]{64}$/;

export interface ReaderListRecord {
  owner: string;
  namespace: string;
  readers: string[];
  version: number;
  issued_at: number;
}

export function encodeReaderList(r: ReaderListRecord): Uint8Array {
  return new Uint8Array(ENC.encode([READER_LIST_DOMAIN, r.owner, r.namespace, r.readers, r.version, r.issued_at]));
}

export function hashReaderList(r: ReaderListRecord): Uint8Array {
  return new Uint8Array(createHash("sha256").update(encodeReaderList(r)).digest());
}

/** Decode a reader list the directory returned, strictly (the same shape the directory enforces). */
export function decodeReaderList(raw: Uint8Array): ReaderListRecord {
  const a = ENC.decode(raw) as unknown;
  if (!Array.isArray(a) || a.length !== 6 || a[0] !== READER_LIST_DOMAIN) throw new Error("reader list: not a CELLO-ARDRS-v1 array");
  const readers = a[3];
  if (!Array.isArray(readers) || !readers.every((r) => typeof r === "string" && HEX64.test(r))) throw new Error("reader list: readers must be 64-hex");
  const version = typeof a[4] === "bigint" ? Number(a[4]) : a[4];
  const issuedAt = typeof a[5] === "bigint" ? Number(a[5]) : a[5];
  return { owner: a[1] as string, namespace: a[2] as string, readers: readers as string[], version, issued_at: issuedAt };
}

/** Lowercase, dedupe and sort into the canonical strictly-ascending order the record requires. */
export function canonicalReaders(readers: readonly string[]): string[] {
  return Array.from(new Set(readers.map((r) => r.toLowerCase()))).sort();
}

type Refusal = { ok: false; reason: string; guidance: string };

const READERS_GUIDANCE: Record<string, string> = {
  not_private: "Reader lists only apply to a PRIVATE namespace. A public namespace stores its reviews openly, so there is nothing to restrict.",
  not_permitted: "Only the namespace owner may read its reader list. Select the owning agent with cello_use_agent and try again.",
  bad_version: "The reader list changed since this one was built. Run `cello attestations readers list <ns>` to see the current readers, then re-apply your change.",
  not_owner: "This record names an owner that is not the selected agent. Select the owning agent (cello_use_agent) and try again.",
  unregistered: "This agent is not registered with the directory yet. Run `cello status`.",
  unknown_namespace: "There is no such namespace. Create it first with `cello attestations namespace create`.",
  bad_record: "The directory could not read the record. This is a client/version mismatch — upgrade @cello-protocol/connect.",
  bad_signature: "The signature did not verify at the directory. This is a client bug — upgrade @cello-protocol/connect.",
  rate_limited: "Too many reader-list writes too fast. Wait a few seconds and run it again.",
  stale_record: "The record's timestamp is too far from the directory's clock. Check this machine's clock and run it again.",
  store_failed: "The directory accepted the record but could not store it. Try again; re-running is safe.",
  lookup_failed: "The directory could not check your registration. It is a directory-side fault — try again shortly.",
};

function refusalFromError(reason: string): Refusal {
  return { ok: false, reason, guidance: READERS_GUIDANCE[reason] ?? `The directory refused the reader-list operation: ${reason}.` };
}

export interface ReadersView {
  version: number | null;
  readers: string[];
}

/** One inbound reader-list read, inline (no nested `serialize` — the caller already holds the chain). */
async function getCurrent(deps: NamespaceDeps, namespace: string): Promise<{ ok: true; view: ReadersView } | Refusal> {
  const out = await sendAndAwait(deps, { type: "attestation_readers_get", owner_pubkey: deps.ownerPubkeyHex, namespace },
    (r) => r["type"] === "attestation_readers" && r["owner_pubkey"] === deps.ownerPubkeyHex && r["namespace"] === namespace);
  if (out.kind === "send_failed") return { ok: false, reason: out.reason, guidance: out.guidance ?? `The read was not handed to a directory node (${out.reason}).` };
  if (out.kind === "timeout") return { ok: false, reason: "attestation_readers_timeout", guidance: "The directory node did not answer within the timeout. Re-running is safe." };
  const reply = out.reply;
  if (reply["type"] === "attestation_namespace_error") return refusalFromError(typeof reply["reason"] === "string" ? reply["reason"] : "unspecified");
  const version = typeof reply["version"] === "number" ? reply["version"] : null;
  const recordU8 = toU8(reply["record"]);
  let readers: string[] = [];
  if (recordU8) { try { readers = decodeReaderList(recordU8).readers; } catch { readers = []; } }
  return { ok: true, view: { version, readers } };
}

/** List the current readers of a private namespace (owner only). */
export function readersList(deps: NamespaceDeps, namespace: string): Promise<{ ok: true; view: ReadersView } | Refusal> {
  return serialize(() => getCurrent(deps, namespace));
}

/**
 * Add and/or remove readers: fetch the current list, apply the change, and send the signed version
 * N+1. The whole thing rides ONE serialized slot so the version it builds on cannot move under it.
 */
export function readersUpdate(
  deps: NamespaceDeps,
  namespace: string,
  change: { add?: readonly string[]; remove?: readonly string[] },
): Promise<{ ok: true; status: "stored" | "identical"; version: number; readers: string[] } | Refusal> {
  return serialize(async () => {
    const correlationId = randomUUID();
    const current = await getCurrent(deps, namespace);
    if (!current.ok) return current;
    const removeSet = new Set((change.remove ?? []).map((r) => r.toLowerCase()));
    const next = canonicalReaders([...current.view.readers.filter((r) => !removeSet.has(r)), ...(change.add ?? [])]);
    const version = (current.view.version ?? 0) + 1;
    const rec: ReaderListRecord = { owner: deps.ownerPubkeyHex, namespace, readers: next, version, issued_at: Math.floor(deps.now() / 1000) };
    const record = encodeReaderList(rec);
    const signature = await deps.keyProvider.sign(hashReaderList(rec));
    deps.logger.info("attestation.readers.sent", { namespace, version, add: (change.add ?? []).length, remove: (change.remove ?? []).length, correlationId });
    const out = await sendAndAwait(deps, { type: "attestation_readers_set", record, signature },
      (r) => r["type"] === "attestation_readers_result" && r["owner_pubkey"] === deps.ownerPubkeyHex && r["namespace"] === namespace);
    if (out.kind === "send_failed") return { ok: false, reason: out.reason, guidance: out.guidance ?? `The record was not handed to a directory node (${out.reason}). Re-running is safe.` };
    if (out.kind === "timeout") return { ok: false, reason: "attestation_readers_timeout", guidance: "The directory node did not answer within the timeout. Whether the change stored is unknown; re-running is safe." };
    const reply = out.reply;
    if (reply["type"] === "attestation_namespace_error") {
      const reason = typeof reply["reason"] === "string" ? reply["reason"] : "unspecified";
      deps.logger.warn("attestation.readers.replied", { namespace, outcome: reason, correlationId });
      return refusalFromError(reason);
    }
    const status = reply["status"] === "identical" ? "identical" : "stored";
    deps.logger.info("attestation.readers.replied", { namespace, outcome: status, version, correlationId });
    return { ok: true, status, version, readers: next };
  });
}
