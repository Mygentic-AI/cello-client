/**
 * M10E 003-NSCLIENT — the client half of attestation namespaces.
 *
 * The daemon composes, signs and sends a namespace (or a close) to the directory, and reads any
 * owner's index. Three operations: create, close, read.
 *
 * COUNTERBALANCE. The owner's own daemon is the adversary for a write: it is the party that wants to
 * flip a namespace to private after bad reviews, or hide it behind a fresh one. None of that is
 * enforced here — it CANNOT be, because the operator can rewrite this file. The directory (002)
 * re-decodes, re-verifies the owner signature, and refuses any change to a stored namespace, and the
 * index it serves is public and append-only. What this file is responsible for is the OTHER
 * direction: a reader must not have to trust the directory. So `readIndex` verifies every entry's
 * owner signature itself; a forged entry is shown `verified: false`, never dropped and never shown as
 * genuine. A reader seeing fewer namespaces than exist is the hide-an-old-namespace route, so an
 * entry that fails to verify is KEPT, flagged.
 *
 * Crypto: Ed25519 → RFC 8032, CBOR → RFC 8949, SHA-256 → FIPS 180-4.
 */

import { randomUUID } from "node:crypto";
import { verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  attestationTemplateHash,
  decodeAttestationNamespace,
  decodeAttestationNamespaceClose,
  encodeAttestationNamespace,
  encodeAttestationNamespaceClose,
  hashAttestationNamespace,
  hashAttestationNamespaceClose,
  templateIdForHash,
  type AttestationNamespace,
} from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

export interface NamespaceCreateInput {
  namespace: string;
  mode: "public" | "private";
  scored: boolean;
  /** 7..180, default 30. Checked HERE before anything is built or sent. */
  right_ttl_days: number;
  /** NFC-normalized HERE (never inside the 001 codec). The codec then refuses anything outside 1..280 code points as `bad_condition`. */
  condition: string;
}

export interface IndexEntryView {
  namespace: string;
  /** Null only for an entry whose record did not decode. */
  mode: "public" | "private" | null;
  template: "text" | "scored" | null;
  right_ttl_days: number | null;
  condition: string | null;
  created_at: number | null;
  closed_at: number | null;
  /** False whenever the owner signature does not verify, or the record does not decode, or its
   *  owner is not the requested one. The entry is still present — a dropped entry is the hide route. */
  verified: boolean;
}

type Refusal = { ok: false; reason: string; guidance: string };
type WriteOk = { ok: true; status: "stored" | "identical" };

/** Minimum of the signaling manager this needs — the same shapes `signal-submission.ts` uses. */
export interface NamespaceSignaling {
  sendRaw(frame: unknown): Promise<{ ok: boolean; reason?: string; guidance?: string }>;
  registerInboundHandler(handler: (frame: Record<string, unknown>) => void): () => void;
}

export interface NamespaceDeps {
  signaling: NamespaceSignaling;
  keyProvider: Pick<KeyProvider, "sign" | "getPublicKey">;
  /** The selected agent's own pubkey, lowercase 64-hex. The record's `owner_pubkey`; never an input. */
  ownerPubkeyHex: string;
  /** Epoch millis. */
  now: () => number;
  logger: Logger;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const SECONDS_PER_DAY = 86_400;
const TTL_MIN_DAYS = 7;
const TTL_MAX_DAYS = 180;

/**
 * One namespace operation in flight per daemon, serialized through a module-level promise chain.
 *
 * A directory ERROR reply carries no id (it is a bare `{ type, reason }`), so two writes in flight
 * on the one shared signaling stream could not tell whose refusal an error was. Serializing removes
 * the ambiguity structurally: only one operation is ever listening, so an unaddressed error reply is
 * unambiguously this one's. Reads ride the same chain for the same reason.
 */
let opChain: Promise<unknown> = Promise.resolve();
/** Exported so 005's marks ride the SAME chain — a namespace write and a mark never overlap (K7). */
export function serialize<T>(fn: () => Promise<T>): Promise<T> {
  const run = opChain.then(fn, fn);
  opChain = run.then(() => undefined, () => undefined);
  return run;
}

/** One sentence each, naming the next step — never a bare code (procedure §Invariant 4). */
const WRITE_GUIDANCE: Record<string, string> = {
  namespace_immutable: "A namespace never changes. Create a new one under a different name; the old one stays listed.",
  not_owner: "This record names an owner that is not the selected agent. Select the owning agent (cello_use_agent) and try again.",
  unregistered: "This agent is not registered with the directory yet. Run `cello status`.",
  stale_record: "The record's timestamp is too far from the directory's clock. Check this machine's clock and run it again.",
  bad_record: "The directory could not read the record. This is a client/version mismatch — upgrade @cello-protocol/connect.",
  bad_signature: "The signature did not verify at the directory. This is a client bug — upgrade @cello-protocol/connect.",
  rate_limited: "Too many namespace writes too fast. Wait a few seconds and run it again.",
  lookup_failed: "The directory could not check your registration. It is a directory-side fault — try again shortly.",
  store_failed: "The directory accepted the record but could not store it. Try again; re-running is safe.",
  unknown_namespace: "There is no such namespace to close. Create it first, or check the name with `cello attestations index`.",
};

const READ_GUIDANCE: Record<string, string> = {
  rate_limited: "Too many index reads too fast. Wait a few seconds and run it again.",
  lookup_failed: "The directory could not read the index. It is a directory-side fault — try again shortly.",
};

export function toU8(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (v && typeof v === "object" && typeof (v as { length?: unknown }).length === "number") {
    try { return Uint8Array.from(v as ArrayLike<number>); } catch { return null; }
  }
  return null;
}

/**
 * Send one frame and await its reply on the shared stream. `match` picks this operation's reply; a
 * bare error reply (no id) is this operation's because writes/reads are serialized. `not_authenticated`
 * is advisory ONLY — an older directory answers it for any undecodable frame, and it is also what a
 * node sends before auth completes, so it sharpens the TIMEOUT rather than resolving the call.
 */
export async function sendAndAwait(
  deps: { signaling: NamespaceSignaling; timeoutMs?: number },
  frame: Record<string, unknown>,
  match: (reply: Record<string, unknown>) => boolean,
): Promise<{ kind: "reply"; reply: Record<string, unknown> } | { kind: "send_failed"; reason: string; guidance?: string } | { kind: "timeout"; sawNotAuthenticated: boolean }> {
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let sawNotAuthenticated = false;
  let resolveFrame!: (f: Record<string, unknown>) => void;
  const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });
  const unregister = deps.signaling.registerInboundHandler((reply) => {
    const t = reply["type"];
    if (t === "attestation_namespace_error" || match(reply)) resolveFrame(reply);
    else if (t === "not_authenticated") sawNotAuthenticated = true;
  });
  try {
    const sent = await deps.signaling.sendRaw(frame);
    if (!sent.ok) return { kind: "send_failed", reason: sent.reason ?? "send_failed", guidance: sent.guidance };
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<Record<string, unknown>>((r) => { timer = setTimeout(() => r({ type: "__timeout__" }), timeoutMs); });
    const reply = await Promise.race([pending, timeout]);
    clearTimeout(timer);
    if (reply["type"] === "__timeout__") return { kind: "timeout", sawNotAuthenticated };
    return { kind: "reply", reply };
  } finally {
    unregister();
  }
}

/** The timeout reason: an old node that never knew the frame (saw not_authenticated) vs a plain hang. */
function timeoutRefusal(kind: "create" | "close" | "index", sawNotAuthenticated: boolean): Refusal {
  if (sawNotAuthenticated) {
    return {
      ok: false,
      reason: "attestation_namespaces_unsupported_by_node",
      guidance: "The directory node did not recognise the frame — most likely it has not rolled attestation-namespace support yet (nodes deploy independently per region). This is NOT a login failure; retry later.",
    };
  }
  return {
    ok: false,
    reason: "attestation_namespace_timeout",
    guidance: `The directory node did not answer within the timeout. Whether anything was stored is unknown; re-running is safe (the same namespace is stored once).`,
  };
}

async function doWrite(
  deps: NamespaceDeps,
  kind: "create" | "close",
  namespace: string,
  frame: Record<string, unknown>,
): Promise<WriteOk | Refusal> {
  const correlationId = randomUUID();
  deps.logger.info("attestation.namespace.sent", { namespace, kind, correlationId });
  const out = await sendAndAwait(deps, frame, (reply) =>
    reply["type"] === "attestation_namespace_result" && reply["owner_pubkey"] === deps.ownerPubkeyHex && reply["namespace"] === namespace);
  if (out.kind === "send_failed") {
    deps.logger.warn("attestation.namespace.replied", { namespace, outcome: out.reason, correlationId });
    return { ok: false, reason: out.reason, guidance: out.guidance ?? `The record was not handed to a directory node (${out.reason}). Re-running is safe.` };
  }
  if (out.kind === "timeout") {
    const r = timeoutRefusal(kind, out.sawNotAuthenticated);
    deps.logger.warn("attestation.namespace.replied", { namespace, outcome: r.reason, correlationId });
    return r;
  }
  const reply = out.reply;
  if (reply["type"] === "attestation_namespace_error") {
    const reason = typeof reply["reason"] === "string" ? reply["reason"] : "unspecified";
    deps.logger.warn("attestation.namespace.replied", { namespace, outcome: reason, correlationId });
    return { ok: false, reason, guidance: WRITE_GUIDANCE[reason] ?? `The directory refused the record: ${reason}.` };
  }
  const status = reply["status"] === "identical" ? "identical" : "stored";
  deps.logger.info("attestation.namespace.replied", { namespace, outcome: status, correlationId });
  return { ok: true, status };
}

export async function createNamespace(deps: NamespaceDeps, input: NamespaceCreateInput): Promise<WriteOk | Refusal> {
  // TTL is checked BEFORE anything is built or sent (nothing reaches the wire on a bad ttl).
  if (!Number.isInteger(input.right_ttl_days) || input.right_ttl_days < TTL_MIN_DAYS || input.right_ttl_days > TTL_MAX_DAYS) {
    return {
      ok: false,
      reason: "bad_ttl",
      guidance: `A reviewer's window must be ${TTL_MIN_DAYS}..${TTL_MAX_DAYS} days; got ${String(input.right_ttl_days)}. Pass --ttl in that range.`,
    };
  }
  // NORMALIZE HERE, never inside the 001 codec: the codec REFUSES non-NFC rather than repairing it,
  // because silently normalizing would make two different inputs hash to one record.
  const condition = input.condition.normalize("NFC");
  const rec: AttestationNamespace = {
    owner_pubkey: deps.ownerPubkeyHex,
    namespace: input.namespace,
    mode: input.mode,
    template_hash: attestationTemplateHash(input.scored ? "scored" : "text"),
    right_ttl_s: input.right_ttl_days * SECONDS_PER_DAY,
    condition,
    created_at: Math.floor(deps.now() / 1000),
  };
  let record: Uint8Array;
  try {
    record = encodeAttestationNamespace(rec);
  } catch (err: unknown) {
    const reason = err instanceof Error && "code" in err ? String((err as { code: unknown }).code) : "bad_record";
    return { ok: false, reason, guidance: `The namespace could not be built: ${extractErrorMessage(err)}. Fix the input and try again.` };
  }
  const signature = await deps.keyProvider.sign(hashAttestationNamespace(rec));
  return serialize(() => doWrite(deps, "create", input.namespace, { type: "attestation_namespace_put", record, signature }));
}

export async function closeNamespace(deps: NamespaceDeps, namespace: string): Promise<WriteOk | Refusal> {
  const rec = { owner_pubkey: deps.ownerPubkeyHex, namespace, closed_at: Math.floor(deps.now() / 1000) };
  let record: Uint8Array;
  try {
    record = encodeAttestationNamespaceClose(rec);
  } catch (err: unknown) {
    const reason = err instanceof Error && "code" in err ? String((err as { code: unknown }).code) : "bad_record";
    return { ok: false, reason, guidance: `The close could not be built: ${extractErrorMessage(err)}. Check the namespace name.` };
  }
  const signature = await deps.keyProvider.sign(hashAttestationNamespaceClose(rec));
  return serialize(() => doWrite(deps, "close", namespace, { type: "attestation_namespace_close", record, signature }));
}

/** Verify one stored entry against the requested owner key. Fields come ONLY from a decoded record. */
function viewEntry(deps: NamespaceDeps, owner: string, entry: { record: Uint8Array; signature: Uint8Array; close: { record: Uint8Array; signature: Uint8Array } | null }): IndexEntryView {
  const warn = (namespace: string, reason: string): void =>
    deps.logger.warn("attestation.index.unverified_entry", { owner: owner.slice(0, 16), namespace, reason });
  const ownerKey = Buffer.from(owner, "hex");
  let rec: AttestationNamespace;
  try {
    rec = decodeAttestationNamespace(entry.record);
  } catch {
    warn("<undecodable>", "undecodable");
    return { namespace: "<undecodable>", mode: null, template: null, right_ttl_days: null, condition: null, created_at: null, closed_at: null, verified: false };
  }
  let verified = true;
  let reason = "";
  if (rec.owner_pubkey !== owner) { verified = false; reason = "owner_mismatch"; }
  else if (!verify(ownerKey, hashAttestationNamespace(rec), entry.signature)) { verified = false; reason = "bad_signature"; }

  let closed_at: number | null = null;
  if (entry.close) {
    try {
      const closeRec = decodeAttestationNamespaceClose(entry.close.record);
      const closeOk = closeRec.owner_pubkey === owner && closeRec.namespace === rec.namespace
        && verify(ownerKey, hashAttestationNamespaceClose(closeRec), entry.close.signature);
      if (closeOk) closed_at = closeRec.closed_at;
      else if (verified) { verified = false; reason = "bad_close"; }
    } catch {
      if (verified) { verified = false; reason = "bad_close"; }
    }
  }
  if (!verified) warn(rec.namespace, reason);
  return {
    namespace: rec.namespace,
    mode: rec.mode,
    template: templateIdForHash(rec.template_hash),
    right_ttl_days: rec.right_ttl_s / SECONDS_PER_DAY,
    condition: rec.condition,
    created_at: rec.created_at,
    closed_at,
    verified,
  };
}

export async function readIndex(
  deps: NamespaceDeps,
  owner_pubkey: string,
  after?: string,
): Promise<{ ok: true; entries: IndexEntryView[]; next: string | null } | Refusal> {
  const frame: Record<string, unknown> = { type: "attestation_index_get", owner_pubkey, ...(after !== undefined ? { after } : {}) };
  return serialize(async (): Promise<{ ok: true; entries: IndexEntryView[]; next: string | null } | Refusal> => {
    const out = await sendAndAwait(deps, frame, (reply) => reply["type"] === "attestation_index" && reply["owner_pubkey"] === owner_pubkey);
    if (out.kind === "send_failed") {
      return { ok: false, reason: out.reason, guidance: out.guidance ?? `The index request was not handed to a directory node (${out.reason}). Try again shortly.` };
    }
    if (out.kind === "timeout") return timeoutRefusal("index", out.sawNotAuthenticated);
    const reply = out.reply;
    if (reply["type"] === "attestation_namespace_error") {
      const reason = typeof reply["reason"] === "string" ? reply["reason"] : "unspecified";
      return { ok: false, reason, guidance: READ_GUIDANCE[reason] ?? `The directory could not serve the index: ${reason}.` };
    }
    const rawEntries = Array.isArray(reply["entries"]) ? (reply["entries"] as Array<Record<string, unknown>>) : [];
    const entries: IndexEntryView[] = [];
    for (const e of rawEntries) {
      const record = toU8(e["record"]);
      const signature = toU8(e["signature"]);
      if (!record || !signature) {
        deps.logger.warn("attestation.index.unverified_entry", { owner: owner_pubkey.slice(0, 16), namespace: "<undecodable>", reason: "missing_bytes" });
        entries.push({ namespace: "<undecodable>", mode: null, template: null, right_ttl_days: null, condition: null, created_at: null, closed_at: null, verified: false });
        continue;
      }
      const rawClose = e["close"];
      let close: { record: Uint8Array; signature: Uint8Array } | null = null;
      if (rawClose && typeof rawClose === "object") {
        const cr = toU8((rawClose as Record<string, unknown>)["record"]);
        const cs = toU8((rawClose as Record<string, unknown>)["signature"]);
        if (cr && cs) close = { record: cr, signature: cs };
      }
      entries.push(viewEntry(deps, owner_pubkey, { record, signature, close }));
    }
    const next = typeof reply["next"] === "string" ? reply["next"] : null;
    return { ok: true, entries, next };
  });
}
