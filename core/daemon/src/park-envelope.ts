/**
 * SEC-1 — the relay-park content envelope, and its authentication.
 *
 * WHY THIS EXISTS. Relay deposit is unauthenticated by design (the blob is E2E-encrypted, so an open
 * deposit cannot LEAK anything) and `sealToRecipient` is an ANONYMOUS public-key seal. Those two
 * facts together mean anyone holding the recipient's PUBLIC key can mint a well-formed sealed entry
 * for their mailbox. Before SEC-1 the recovery path took the sender identity from the SESSION ROW,
 * never from the envelope — so injected content was attributed to the honest counterparty, appended
 * as a Merkle leaf, and then NOTARIZED by the bilateral seal. The party best placed to exploit that
 * is the RELAY ITSELF: the protocol hands it the session_id in plaintext on every deposit and the
 * recipient pubkey is its mailbox key.
 *
 * Confidentiality was mistaken for the whole job. A relay that cannot READ your messages could still
 * WRITE them for you.
 *
 * THE FIX. Every envelope carries a per-message SENDER SIGNATURE over a domain-separated statement
 * bound to (session_id, recipient_pubkey, content_hash) — see `buildParkContentTbs`. It rides INSIDE
 * the seal, so the relay can neither read, strip, nor forge it. Recovery FAILS CLOSED.
 *
 * Note the signature is bound to the sender's own K_local and NOT to the relay's ordering record
 * (Structure1/2). That is deliberate: the ordering record embeds a RELAY-ASSIGNED sequence, so
 * making authenticity depend on it would make the adversary a precondition for trusting content.
 * It also keeps the CELLO-M7-MSG-001 crash backstop working — that path legitimately parks content
 * with no ordering record (the durable awaiting queue does not persist one), and it can still sign.
 *
 * Crypto: Ed25519 (RFC 8032), SHA-256 (FIPS 180-4).
 */
import { timingSafeEqual } from "node:crypto";
import { encode as cborEncode, decode as cborDecode } from "cbor-x";
import { verify, sealToRecipient, type KeyProvider } from "@cello-protocol/crypto";
import { buildParkContentTbs } from "@cello-protocol/protocol-types";

/**
 * Compare an identity key (raw bytes) against a stored hex pubkey — on BYTES, never on the hex
 * strings.
 *
 * Review M1: `sessions.counterparty_pubkey` is persisted VERBATIM from the IPC `target_pubkey`
 * string with no normalization, so an uppercase or mixed-case pubkey is a perfectly functional
 * session (Buffer.from(hex) is case-insensitive, so dialing, sealing and the direct content path all
 * work) — but a `toString("hex") !== stored` comparison would then refuse EVERY parked recovery for
 * that session as `signer_not_counterparty`, i.e. permanent store-and-forward mail loss reported as
 * an attack. Comparing bytes makes the check independent of how the hex was cased on the way in.
 *
 * Length-guarded because timingSafeEqual throws on a length mismatch, and the input is
 * attacker-controlled (a forged envelope can carry a short/long pubkey).
 */
export function pubkeyMatchesHex(pubkey: Uint8Array, storedHex: string | undefined): boolean {
  if (!storedHex) return false;
  let stored: Buffer;
  try {
    stored = Buffer.from(storedHex, "hex");
  } catch {
    return false;
  }
  // Buffer.from ignores trailing garbage rather than throwing, so a length check is the real guard.
  if (stored.length === 0 || stored.length !== pubkey.length) return false;
  return timingSafeEqual(Buffer.from(pubkey), stored);
}

/** Current envelope version. v1 (unsigned) is decodable but NEVER acceptable — see authenticate(). */
export const PARK_ENVELOPE_VERSION = 2;

export interface ParkEnvelope {
  /** 1 = legacy/unsigned (bare content or the pre-SEC-1 shape). 2 = signed. */
  version: number;
  content: Uint8Array;
  /** DOD-MSG-4 ordering record — optional; absent on the crash-backstop path. */
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
  /** SEC-1 — the sender's identity key. Present only on v2. */
  senderPubkey?: Uint8Array;
  /** SEC-1 — Ed25519 over buildParkContentTbs(...). Present only on v2. */
  parkSig?: Uint8Array;
}

export type ParkAuthFailure =
  | "unsigned_envelope"
  | "bad_signature"
  | "signer_not_counterparty"
  | "counterparty_unknown";

export type ParkAuthVerdict = { ok: true } | { ok: false; reason: ParkAuthFailure };

/**
 * SEC-1: encode a SIGNED park envelope. `senderPubkey` and `parkSig` are REQUIRED — the type system
 * is the enforcement point, so no call site can construct an unsigned envelope by omission (the
 * exact drift that made this a downgrade attack: verification existed, but was opt-in).
 */
export function encodeParkEnvelope(args: {
  content: Uint8Array;
  senderPubkey: Uint8Array;
  parkSig: Uint8Array;
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
}): Uint8Array {
  return cborEncode([
    PARK_ENVELOPE_VERSION,
    args.content,
    args.structure1Cbor ?? null,
    args.structure2Cbor ?? null,
    args.senderPubkey,
    args.parkSig,
  ]) as Uint8Array;
}

/**
 * SEC-1 — THE ONLY PRODUCER. Sign the entry as the sending agent, wrap it in a v2 envelope, and seal
 * it to the recipient. Both park sites (the live hook and the crash backstop) call THIS, so the
 * to-be-signed arguments are constructed in exactly one place.
 *
 * Review (hollow-test finding): while the two call sites each built their own signature, a producer
 * that signed the WRONG TBS arguments — e.g. its own pubkey where the recipient's belongs — would
 * emit envelopes no recipient could ever accept, and every consumer-side test would still pass. The
 * bug would only surface as mail that silently never arrives. One producer + a round-trip test
 * against the real consumer removes that whole class: if this function signs the wrong statement,
 * `authenticateParkedEntry` rejects its output and the test goes red.
 */
export async function sealParkEnvelope(args: {
  signer: KeyProvider;
  sessionIdHex: string;
  recipientPubkey: Uint8Array;
  contentHash: Uint8Array;
  content: Uint8Array;
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
}): Promise<Uint8Array> {
  const senderPubkey = await args.signer.getPublicKey();
  const parkSig = await args.signer.sign(
    buildParkContentTbs(args.sessionIdHex, args.recipientPubkey, args.contentHash),
  );
  const envelope = encodeParkEnvelope({
    content: args.content,
    structure1Cbor: args.structure1Cbor,
    structure2Cbor: args.structure2Cbor,
    senderPubkey,
    parkSig,
  });
  // The signature rides INSIDE the seal — the relay (the adversary) never sees it, so it can neither
  // strip nor forge it. INV-3 is untouched: the relay still holds only ciphertext.
  return sealToRecipient(args.recipientPubkey, envelope);
}

/**
 * Decode a park envelope. Legacy shapes (the pre-SEC-1 4-element v1 array, and raw non-CBOR bare
 * content) still DECODE — deliberately, so `authenticate` can reject them with a precise reason
 * rather than the caller seeing an opaque parse failure. Decoding is not accepting.
 */
export function decodeParkEnvelope(plaintext: Uint8Array): ParkEnvelope {
  try {
    const arr = cborDecode(plaintext) as unknown[];
    if (Array.isArray(arr) && arr.length === 6 && arr[0] === PARK_ENVELOPE_VERSION && arr[1] instanceof Uint8Array) {
      return {
        version: PARK_ENVELOPE_VERSION,
        content: arr[1],
        structure1Cbor: arr[2] instanceof Uint8Array ? arr[2] : undefined,
        structure2Cbor: arr[3] instanceof Uint8Array ? arr[3] : undefined,
        senderPubkey: arr[4] instanceof Uint8Array ? arr[4] : undefined,
        parkSig: arr[5] instanceof Uint8Array ? arr[5] : undefined,
      };
    }
    // Pre-SEC-1 v1 envelope: [1, content, s1|null, s2|null]. Decoded so it can be REFUSED by name.
    if (Array.isArray(arr) && arr.length === 4 && arr[0] === 1 && arr[1] instanceof Uint8Array) {
      return {
        version: 1,
        content: arr[1],
        structure1Cbor: arr[2] instanceof Uint8Array ? arr[2] : undefined,
        structure2Cbor: arr[3] instanceof Uint8Array ? arr[3] : undefined,
      };
    }
  } catch {
    /* not an envelope — fall through to raw bare content */
  }
  return { version: 1, content: plaintext };
}

/**
 * SEC-1: the authentication decision for a recovered parked entry. FAIL CLOSED — every path that is
 * not a proven-good signature from THIS session's counterparty returns a failure.
 *
 * `counterpartyPubkeyHex` is the session's counterparty (the only principal allowed to have parked
 * content into this session). Pass undefined when the session/counterparty is unknown: that is
 * `counterparty_unknown` and is a REFUSAL, never a bypass — we cannot prove the signer, so we do not
 * trust the content. (Same fail-closed stance the ordering-record check already takes.)
 */
export function authenticateParkedEntry(args: {
  env: ParkEnvelope;
  sessionIdHex: string;
  recipientPubkey: Uint8Array;
  contentHash: Uint8Array;
  counterpartyPubkeyHex: string | undefined;
}): ParkAuthVerdict {
  const { env, sessionIdHex, recipientPubkey, contentHash, counterpartyPubkeyHex } = args;

  // 1. Unsigned (v1 envelope, or raw bare content) — the shape an attacker sends, and the shape the
  //    pre-SEC-1 daemon ingested without a single check. Refused outright.
  if (env.version !== PARK_ENVELOPE_VERSION || !env.senderPubkey || !env.parkSig) {
    return { ok: false, reason: "unsigned_envelope" };
  }

  // 2. Fail closed when there is no counterparty to bind the signer to.
  if (!counterpartyPubkeyHex) {
    return { ok: false, reason: "counterparty_unknown" };
  }

  // 3. The signature must cover THESE bytes, for THIS session, into THIS mailbox. Verified BEFORE
  //    the signer check so a forged signature is never mistaken for a wrong-principal one.
  const tbs = buildParkContentTbs(sessionIdHex, recipientPubkey, contentHash);
  if (!verify(env.senderPubkey, tbs, env.parkSig)) {
    return { ok: false, reason: "bad_signature" };
  }

  // 4. The signer MUST be this session's counterparty. A cryptographically valid signature by any
  //    other key is still a forgery of THIS conversation. Compared on BYTES (review M1) — the stored
  //    hex is un-normalized, so a string compare would turn a mixed-case pubkey into permanent
  //    mail loss that looks exactly like an attack in the log.
  if (!pubkeyMatchesHex(env.senderPubkey, counterpartyPubkeyHex)) {
    return { ok: false, reason: "signer_not_counterparty" };
  }

  return { ok: true };
}
