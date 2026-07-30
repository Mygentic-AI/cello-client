/**
 * The canonical trust-signal envelope (M10 / DOD-CBOR-1): serialize, hash, verify.
 *
 * Four parties independently re-derive this hash — the portal at mint, the directory at submission
 * (INV-CHOKEPOINT's re-hash before store), the directory again at presentation (dumb check 1), and
 * the holder/recipient daemons on receipt and at verification. They must agree byte-for-byte,
 * forever, across three repos and two languages' worth of tooling. A single divergent byte turns a
 * valid signal into a false `hash_mismatch` — unpresentable, and censorship-shaped, because it can
 * differ per node or per client version.
 *
 * THE PREIMAGE IS AN ARRAY, NOT A MAP, AND THAT IS LOAD-BEARING (M10-D15).
 * The shared encoder (`cbor.ts`) is not RFC 8949 §4.2 deterministic for MAPS: map keys follow
 * INSERTION ORDER, and map headers are not minimal-length (a 2-entry map emits `b9 0002`, not `a2`).
 * Arrays, text strings, byte strings, integers and null are all minimal and order-fixed. Encoding
 * the preimage as a fixed-order array therefore makes determinism STRUCTURAL — a property of the
 * shape, not of the encoder's configuration — and costs no encoder change and no migration of the
 * blobs already on disk. Every signed TBS in CELLO is an array for this same reason
 * (`buildAgentRevocationTbs`, `buildPrimaryTransferTbs`, `buildSealTbs`, `buildParkContentTbs`).
 *
 * Consequences, all enforced below:
 *   - FIELD ORDER IS THE WIRE FORMAT. Reordering the array is a breaking hash change, not a
 *     refactor. Retrofitting a canonical form later breaks every hash already minted (spec §5).
 *   - THE FIELD SET IS CLOSED (spec §4). An unknown field is REJECTED, never ignored: silently
 *     dropping it would let two parties who disagree about the field set still agree on the hash,
 *     making the extra field unauthenticated data riding inside a "verified" signal.
 *   - `status` / `class` / `verified_at` ARE NOT IN THE PREIMAGE. They are mutable after minting —
 *     that is the entire point of excluding them. If `status` were hashed, revoking a signal would
 *     change its hash and the directory could never find it again.
 *   - OPTIONAL FIELDS ARE AN EXPLICIT `null` IN A FIXED SLOT, NEVER OMITTED (M10-D17). In an array,
 *     omitting a field shifts every later field and changes the arity, so an absent `expires_at`
 *     becomes confusable with a misaligned `supersedes_hash`.
 *   - NO FLOATING POINT. Timestamps are integer epoch SECONDS. A float would not survive
 *     byte-agreement across languages.
 *   - `payload` IS OPAQUE BYTES, never decoded or re-encoded. A payload parsed and re-serialized
 *     would change bytes under a different encoder version. This is also what INV-ZERO-BUMP rests
 *     on: a type this code has never seen must hash and flow through untouched.
 */

import { hash as sha256 } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain separation, bound as element 0 of the preimage array — the house convention
 *  (`AGENT_REVOCATION_DOMAIN`, `PRIMARY_TRANSFER_DOMAIN`). A trust-signal hash can therefore never
 *  collide with, or be replayed as, any other hashed/signed CELLO structure. */
export const TRUST_SIGNAL_DOMAIN = "CELLO-TSIG-v1";

/** Whose fact this is. Account-subject signals (phone, email, social) are presentable by every agent
 *  under the account; agent-subject signals (track record) belong to one agent. Both are HASHED, so
 *  the scope cannot be changed after minting (M10-D5). */
export type SignalSubjectKind = "account" | "agent";

/** Who attested it. Drives FRAMING at the consuming LLM (INV-FRAMING): `portal` is portal-attested;
 *  `agent` is quoted-untrusted ("Bob says:"). Hashed, so framing cannot be laundered by a relabel. */
export type SignalIssuerKind = "portal" | "agent";

/**
 * The hashed part of a trust signal. This is the WHOLE preimage and nothing else — see spec §4's
 * mandatory-disclosure set. `type` is an OPAQUE STRING here and everywhere in the client and the
 * directory: never an enum, never switched on (INV-ZERO-BUMP).
 */
export interface TrustSignalEnvelope {
  subject_kind: SignalSubjectKind;
  /** The account id or agent id this fact is about. */
  subject: string;
  issuer_kind: SignalIssuerKind;
  /** Hex-encoded Ed25519 public key of the issuer. Verified against the directory's authorized set. */
  issuer_pubkey: string;
  /** OPAQUE type string. Adding a type must require no code change anywhere but the portal. */
  type: string;
  schema_version: number;
  /** OPAQUE payload bytes. Never parsed, never re-encoded, never hoisted into a column. */
  payload: Uint8Array;
  /** Integer epoch SECONDS. */
  issued_at: number;
  /**
   * Co-ownership: the issuer and the subject are the SAME OPERATOR (policy D-29).
   *
   * ON THE ENVELOPE, not in the payload, and that placement is the whole point. A recipient's floor
   * predicate must exclude these from a `min_count` — otherwise ten agents under one operator
   * manufacture standing — and a floor predicate may only read the envelope. It cannot read the
   * payload for two reasons: payload shape is per-TYPE (so reading it makes the predicate need
   * updating for every new signal type, breaking INV-ZEROBUMP), and the payload mixes
   * portal-attested fields with attacker-authored text under indistinguishable CBOR keys.
   *
   * Here it is unambiguous: the preimage is a CLOSED set, so this slot is portal-attested by
   * construction and cannot be forged without breaking the notarized hash.
   */
  same_operator: boolean;
  /** Integer epoch SECONDS, or null for a signal that never expires. */
  expires_at: number | null;
  /** The 32-byte hash this envelope replaces, or null for a first mint. */
  supersedes_hash: Uint8Array | null;
}

/** The preimage field order. THIS ARRAY IS THE WIRE FORMAT — reordering it breaks every hash ever
 *  minted. It also doubles as the closed-set definition used to reject unknown fields. */
const PREIMAGE_FIELDS = [
  "subject_kind",
  "subject",
  "issuer_kind",
  "issuer_pubkey",
  "type",
  "schema_version",
  "payload",
  "issued_at",
  "expires_at",
  "supersedes_hash",
  // M10B / DOD-END-COUNT-1 — APPENDED, never inserted. Field order IS the wire format: putting this
  // anywhere but the end would change the preimage of every existing field position and invalidate
  // every signature already made.
  "same_operator",
] as const;

/** Sanity bound on epoch-SECOND timestamps. A millisecond timestamp (~1.7e12) is the classic
 *  cross-implementation skew: it is a valid integer, so nothing would complain, and it would mint a
 *  signal that expires roughly thirty thousand years from now. Refuse it at the door. */
const MAX_EPOCH_SECONDS = 100_000_000_000; // ~year 5138

/** Above this, a JS `number` is encoded by cbor-x as an IEEE **float64** (major type 7), not as a
 *  uint64 — see `asCborInteger`. Anything hashed must cross this boundary as a BigInt. */
const CBOR_UINT32_MAX = 0xffff_ffff;

/** SHA-256. Named separately from SUPERSEDES_HASH_BYTES even though both are 32 today: they are
 *  independent sizes, and coupling them means a future change to one silently breaks the other. */
const SIGNAL_HASH_BYTES = 32;
const SUPERSEDES_HASH_BYTES = 32;

/**
 * Integers above 2³² MUST cross into CBOR as BigInt, or they are hashed as a FLOAT.
 *
 * Measured with this package's encoder:
 *
 *   encode(1768000000)          -> 1a 69618a00           uint32   (fine)
 *   encode(4920000000)          -> fb 41f25413e0000000   FLOAT64  (WRONG)
 *   encode(BigInt(4920000000))  -> 1b 0000000125413e00   uint64   (what RFC 8949 requires)
 *
 * cbor-x emits any JS `number` above 0xffffffff as major type 7 float64. A conforming CBOR
 * implementation in Rust, Go, or Python emits a uint64 — so the two disagree on the preimage, and
 * therefore on the hash, permanently and unfixably (spec §5: retrofitting the canonical form breaks
 * every hash already minted).
 *
 * This is NOT hypothetical and NOT a 2106 problem: an `expires_at` a hundred years out is
 * 1.768e9 + 3.15e9 = 4.92e9, well past 2³², and reachable by the first long-dated signal the portal
 * mints. `buildSealTbs` (session.ts) and `buildAgentRevocationTbs` (revocation.ts) both carry this
 * coercion. The trust-signal envelope shipped without it and a reviewer caught it.
 */
function asCborInteger(value: number): number | bigint {
  return value > CBOR_UINT32_MAX ? BigInt(value) : value;
}

/** A non-negative integer safe to hash — rejected if it is a float, NaN, Infinity, or negative, and
 *  coerced to BigInt past 2³² so it never encodes as a float64. */
function requireHashableInteger(name: string, value: unknown, max: number, hint: string): number | bigint {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`trust-signal envelope: ${name} must be a finite integer, got ${String(value)}`);
  }
  if (!Number.isInteger(value)) {
    throw new Error(`trust-signal envelope: ${name} must be an integer — no floating point is hashable across implementations, got ${value}`);
  }
  if (value < 0) {
    throw new Error(`trust-signal envelope: ${name} must not be negative, got ${value}`);
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    // Past 2^53 a JS number cannot even represent consecutive integers, so the value the caller
    // meant and the value we hash may already differ. Refuse rather than hash an approximation.
    throw new Error(`trust-signal envelope: ${name} exceeds Number.MAX_SAFE_INTEGER (${value}) — it cannot be hashed exactly`);
  }
  if (value >= max) {
    throw new Error(`trust-signal envelope: ${name} is out of range (${value}) — ${hint}`);
  }
  return asCborInteger(value);
}

const requireEpochSeconds = (name: string, value: unknown): number | bigint =>
  requireHashableInteger(
    name,
    value,
    MAX_EPOCH_SECONDS,
    "this looks like a millisecond timestamp; the contract is epoch SECONDS",
  );

/**
 * Every hashed STRING must be NFC-normalized, and we REFUSE a string that is not — we never
 * normalize it silently.
 *
 * Spec §5's list of cross-language hash-breakers names Unicode normalization explicitly. The same
 * logical string differs on the wire: "é" is `62 c3a9` in NFC and `63 65cc81` in NFD. CBOR does not
 * normalize, and RFC 8949's deterministic profile does not require NFC, so nothing downstream saves
 * us.
 *
 * Refusing rather than normalizing is deliberate: silently normalizing would make two DIFFERENT
 * inputs hash to the SAME signal — a collision we manufactured ourselves, which is strictly worse
 * than refusing the odd one at the door.
 */
function requireNfcString(name: string, value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`trust-signal envelope: ${name} must be a non-empty string, got ${String(value)}`);
  }
  if (value.normalize("NFC") !== value) {
    throw new Error(
      `trust-signal envelope: ${name} must be Unicode NFC-normalized — the same logical string hashes ` +
      `differently in NFD ("é" is c3a9 in NFC, 65cc81 in NFD), so a non-NFC value would produce a ` +
      `signal no other implementation can reproduce. Normalize it before minting.`,
    );
  }
  return value;
}

/**
 * Validate against the CLOSED preimage set and return the fixed-order array to encode.
 *
 * Every rejection here is deliberate and loud. An envelope that cannot be canonicalized must never
 * be hashed "best effort" — a best-effort hash is a hash two parties can disagree about.
 */
function toPreimage(envelope: TrustSignalEnvelope): unknown[] {
  if (envelope === null || typeof envelope !== "object") {
    throw new Error(`trust-signal envelope: expected an object, got ${String(envelope)}`);
  }

  // Closed set, both directions: no unknown fields, no missing fields.
  const known = new Set<string>(PREIMAGE_FIELDS);
  for (const key of Object.keys(envelope)) {
    if (!known.has(key)) {
      throw new Error(
        `trust-signal envelope: unknown envelope field "${key}". The preimage is a CLOSED set (spec §4) — ` +
        `an unhashed field riding inside a verified signal is unauthenticated data. ` +
        `Note status/class/verified_at are deliberately NOT hashed (they are mutable after minting) ` +
        `and do not belong on this object.`,
      );
    }
  }
  for (const field of PREIMAGE_FIELDS) {
    if (!(field in envelope)) {
      throw new Error(`trust-signal envelope: missing mandatory field "${field}" (the preimage is a closed set — spec §4)`);
    }
  }

  const { subject_kind, subject, issuer_kind, issuer_pubkey, type, schema_version, payload, expires_at, supersedes_hash } = envelope;

  if (subject_kind !== "account" && subject_kind !== "agent") {
    throw new Error(`trust-signal envelope: subject_kind must be "account" or "agent", got ${String(subject_kind)}`);
  }
  if (issuer_kind !== "portal" && issuer_kind !== "agent") {
    throw new Error(`trust-signal envelope: issuer_kind must be "portal" or "agent", got ${String(issuer_kind)}`);
  }
  requireNfcString("subject", subject);
  requireNfcString("type", type);
  // issuer_pubkey is hex, and hex has a CASE. "AABB" and "aabb" are the same key and DIFFERENT bytes,
  // so a portal that stores it uppercase and a directory that lowercases it on read would produce
  // two different signal_hashes for one signal — a false hash_mismatch, per-node and per-version.
  // Lowercase-only removes the ambiguity at zero cost. (Length/validity is NOT checked here: this
  // component's job is byte-agreement, and the key's validity is the directory's to judge when it
  // checks it against the authorized-issuer set.)
  requireNfcString("issuer_pubkey", issuer_pubkey);
  if (!/^[0-9a-f]+$/.test(issuer_pubkey) || issuer_pubkey.length % 2 !== 0) {
    throw new Error(
      `trust-signal envelope: issuer_pubkey must be LOWERCASE hex with an even length, got "${issuer_pubkey}". ` +
      `Hex has a case, and "AABB" and "aabb" are the same key but different preimage bytes — which would ` +
      `mint two different hashes for one signal.`,
    );
  }
  const schemaVersion = requireHashableInteger(
    "schema_version",
    schema_version,
    CBOR_UINT32_MAX + 1,
    "a schema version is a small counter, not an identifier",
  );
  // The payload must be RAW BYTES. An object here would be encoded as a CBOR map — the one
  // non-deterministic shape in the encoder — and the hash would silently depend on key insertion
  // order. Callers serialize their own payload and hand us the bytes.
  if (!(payload instanceof Uint8Array)) {
    throw new Error(
      `trust-signal envelope: payload must be raw bytes (Uint8Array), got ${payload === null ? "null" : typeof payload}. ` +
      `An object payload would be map-encoded, and CBOR maps are not deterministic under this encoder — ` +
      `serialize the payload yourself and pass the bytes.`,
    );
  }

  const issuedAt = requireEpochSeconds("issued_at", envelope.issued_at);
  const expiresAt = expires_at === null ? null : requireEpochSeconds("expires_at", expires_at);

  if (supersedes_hash !== null) {
    if (!(supersedes_hash instanceof Uint8Array)) {
      throw new Error(`trust-signal envelope: supersedes_hash must be 32 raw bytes or null, got ${typeof supersedes_hash}`);
    }
    if (supersedes_hash.length !== SUPERSEDES_HASH_BYTES) {
      throw new Error(`trust-signal envelope: supersedes_hash must be exactly ${SUPERSEDES_HASH_BYTES} bytes, got ${supersedes_hash.length}`);
    }
  }

  // FIXED ORDER. Element 0 is the domain tag; the nullable slots keep their position so arity is
  // always 12 and no field can be mistaken for another (M10-D17). `same_operator` is APPENDED —
  // inserting it anywhere earlier would shift every later field's position and invalidate every
  // signature already made over this shape.
  return [
    TRUST_SIGNAL_DOMAIN,
    subject_kind,
    subject,
    issuer_kind,
    issuer_pubkey,
    type,
    schemaVersion,
    payload,
    issuedAt,
    expiresAt,
    supersedes_hash,
    // Always a boolean, never absent: a predicate deciding whether this counts toward a floor must
    // not have to distinguish "not same-operator" from "field missing".
    envelope.same_operator === true,
  ];
}

/** The canonical preimage bytes. Deterministic across every party that runs this code. */
export function encodeTrustSignalEnvelope(envelope: TrustSignalEnvelope): Uint8Array {
  return encodeCbor(toPreimage(envelope));
}

/** The signal's identity: SHA-256 over the canonical preimage. This is the `signal_hash` that the
 *  directory stores, the holder presents, and the recipient re-derives. */
export function hashTrustSignalEnvelope(envelope: TrustSignalEnvelope): Uint8Array {
  return sha256(encodeTrustSignalEnvelope(envelope));
}

/**
 * Does this envelope actually hash to `expected`? Length is checked first, so a truncated hash can
 * never pass by matching a prefix. The comparison is constant-time in the length of the input: a
 * signal hash is public, but the habit is cheap and the alternative invites a timing oracle the day
 * one of these stops being public.
 *
 * ⚠️ THIS RETURNS `false` FOR A WRONG HASH BUT **THROWS** FOR A MALFORMED ENVELOPE, AND THAT
 * ASYMMETRY IS DELIBERATE. A wrong hash is a normal, expected answer ("no, this doesn't match"). A
 * malformed envelope is not an answer at all — it is an envelope that cannot be canonicalized, so
 * there is no hash to compare and any boolean would be a lie.
 *
 * The directory calls this on hostile input. DO NOT wrap it in `try { … } catch { return false }`:
 * that converts "this envelope is unhashable garbage" into "this envelope simply didn't match",
 * which is the silent swallow that hides the attack. Let it throw, and log the cause.
 */
export function verifyTrustSignalHash(envelope: TrustSignalEnvelope, expected: Uint8Array): boolean {
  if (!(expected instanceof Uint8Array) || expected.length !== SIGNAL_HASH_BYTES) return false;
  const actual = hashTrustSignalEnvelope(envelope);
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

/**
 * Decode canonical envelope bytes back into the envelope — the inverse of `encodeTrustSignalEnvelope`,
 * and the ONE decoder every party shares (INV-CANONICAL / M10-D7 — the holder's daemon that RECEIVES a
 * delivered signal must decode with the SAME code the directory and portal encode with, never a vendored
 * copy). The preimage is a fixed-order 12-element ARRAY (M10-D15); element 0 is the domain tag.
 *
 * REFUSES anything that is not EXACTLY canonical: it re-encodes the decoded envelope with
 * `encodeTrustSignalEnvelope` and compares the bytes to the input. If they differ — a number that came
 * back as a float, a byte string mis-read, a non-minimal integer, trailing bytes — it THROWS rather than
 * return a "best-effort" envelope: a best-effort hash is one two parties can disagree about. Reusing the
 * encoder (not a hand-rolled re-encode) guarantees the decoder cannot drift from it, AND runs the encoder's
 * own field validation (epoch-seconds bounds, payload-is-bytes, 32-byte supersedes_hash) — so a
 * canonical-at-the-byte-level-but-semantically-invalid array (e.g. an out-of-range subject_kind) still
 * throws here rather than escaping as a bad envelope.
 *
 * ⚠️ THROWS on any malformed/non-canonical input (never returns a partial). The holder's chokepoint
 * (`deliverWalletSignal`) and the recipient's verify both depend on that: a delivery that does not
 * round-trip is corrupt or tampered and must not be stored. Do NOT wrap in try/catch → default — that is
 * the silent swallow that turns "unhashable garbage" into "a valid-looking empty signal".
 */
export function decodeTrustSignalEnvelope(bytes: Uint8Array): TrustSignalEnvelope {
  const arr = decodeCbor(bytes);
  if (!Array.isArray(arr) || arr.length !== 12) {
    throw new Error(
      `trust-signal envelope must be a 12-element CBOR array (the fixed preimage), got ` +
      `${Array.isArray(arr) ? `${arr.length} elements` : typeof arr}`,
    );
  }
  const [domain, subject_kind, subject, issuer_kind, issuer_pubkey, type, schema_version, payload, issued_at, expires_at, supersedes_hash, same_operator] =
    arr as unknown[];
  if (domain !== TRUST_SIGNAL_DOMAIN) {
    throw new Error(`trust-signal envelope domain tag is '${String(domain)}', expected '${TRUST_SIGNAL_DOMAIN}' — not a trust-signal envelope`);
  }
  // NORMALIZE to a plain, freshly-copied Uint8Array. node's CBOR decoder returns byte strings as a
  // `Buffer` (a Uint8Array subclass) that can ALIAS a pooled ArrayBuffer — returning it as-is would leak a
  // view over shared memory and make the decoded type Buffer, not Uint8Array. `new Uint8Array(v)` copies
  // the bytes into an owned array, so the envelope's byte fields are the same type the encoder expects and
  // never alias a pool.
  const asBytes = (v: unknown, field: string): Uint8Array => {
    if (v instanceof Uint8Array) return new Uint8Array(v);
    throw new Error(`trust-signal envelope: ${field} must be raw bytes, got ${v === null ? "null" : typeof v}`);
  };
  const env: TrustSignalEnvelope = {
    subject_kind: subject_kind as SignalSubjectKind,
    subject: subject as string,
    issuer_kind: issuer_kind as SignalIssuerKind,
    issuer_pubkey: issuer_pubkey as string,
    type: type as string,
    schema_version: Number(schema_version),
    payload: asBytes(payload, "payload"),
    issued_at: Number(issued_at),
    expires_at: expires_at === null || expires_at === undefined ? null : Number(expires_at),
    supersedes_hash: supersedes_hash === null || supersedes_hash === undefined ? null : asBytes(supersedes_hash, "supersedes_hash"),
    // STRICT: anything that is not exactly `true` is false. A truthy non-boolean would let two
    // implementations disagree about whether a signal counts, which is a split-brain on a policy
    // decision rather than a formatting nicety.
    same_operator: same_operator === true,
  };
  // Canonical check: re-encode with the SAME encoder every party runs and compare EXACTLY.
  const reencoded = encodeTrustSignalEnvelope(env);
  if (reencoded.length !== bytes.length) {
    throw new Error("trust-signal envelope bytes are not canonical — re-encoding does not reproduce the input");
  }
  for (let i = 0; i < reencoded.length; i++) {
    if (reencoded[i] !== bytes[i]) {
      throw new Error("trust-signal envelope bytes are not canonical — re-encoding does not reproduce the input");
    }
  }
  return env;
}
