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
import { timingSafeEqual, createHash } from "node:crypto";
import { decode as cborDecode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { verify, sealToRecipient, type KeyProvider } from "@cello-protocol/crypto";
import { buildParkContentTbs } from "@cello-protocol/protocol-types";
import { CONTENT_HASH_ALGS, isKnownContentHashAlg } from "./wire-content-hash.js";

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

/**
 * DOD-M15-DELIVERYACK-1 unit 1 — WHAT A PARKED ENTRY IS, SAID WHERE THE RELAY CANNOT READ IT.
 *
 * The relay's mailbox holds opaque ciphertext and has no idea what is inside. An acknowledgement
 * parked there would arrive at the recipient's content-recovery path and be ingested as a MESSAGE —
 * which is why the acknowledgement could not use that path at all, and why an acknowledgement sent
 * while the sender's daemon was down was simply lost.
 *
 * So the discriminator rides INSIDE the seal. Consequences, and all three are the point:
 *  - the relay needs NO change and learns nothing new — it stays a blind custodian (INV-3);
 *  - the relay cannot strip the tag to make an acknowledgement be ingested as content, nor add one
 *    to make a message disappear into the evidence store;
 *  - the envelope's existing SEC-1 gate still runs first, so a parked acknowledgement is
 *    authenticated as coming from this session's counterparty BEFORE anything looks at what it says.
 *
 * ⚠️ THE TAG IS A WIRE VALUE. The string is the contract; renaming the constant is free, changing
 * its value breaks every parked acknowledgement already sitting in a mailbox.
 */
export const PARKED_DELIVERY_ACK_TAG = "cello/park/delivery-ack/v1";

/** Domain separator for the mailbox slot an acknowledgement is filed under. */
const PARKED_DELIVERY_ACK_SLOT_DOMAIN = "CELLO-PARK-DELIVERY-ACK-SLOT-v1";

/**
 * The relay mailbox slot a parked acknowledgement occupies.
 *
 * ⚠️ NOT the hash it acknowledges, and that is a correctness requirement rather than tidiness. The
 * relay files entries by `(recipient_pubkey, content_hash)`. Filing an acknowledgement under the
 * hash it is about would put it in the same slot a parked copy of that very message occupies, so
 * one could evict or be mistaken for the other. A labelled derivation puts it somewhere no
 * message's content hash can land, by accident or by construction.
 *
 * DETERMINISTIC on purpose: re-parking the same acknowledgement lands on the same slot, so the
 * relay's own `INSERT OR IGNORE`-shaped dedup absorbs a repeat instead of growing the mailbox.
 *
 * SHA-256 — FIPS 180-4.
 */
export function parkedDeliveryAckMailboxHash(sessionIdHex: string, contentHash: Uint8Array): Uint8Array {
  return new Uint8Array(
    createHash("sha256")
      .update(Buffer.from(PARKED_DELIVERY_ACK_SLOT_DOMAIN, "utf8"))
      .update(Buffer.from(sessionIdHex, "hex"))
      .update(Buffer.from(contentHash))
      .digest(),
  );
}

/** A parked delivery acknowledgement, as it sits inside the seal. */
export interface ParkedDeliveryAck {
  sessionIdHex: string;
  /** The content hash being acknowledged — the MESSAGE's hash, not the mailbox slot. */
  contentHash: Uint8Array;
  /**
   * The acknowledging agent's Ed25519 signature over the canonical delivery-ack statement.
   *
   * ⚠️ THERE IS NO `signerPubkey` FIELD, AND THERE WAS ONE. It was encoded, decoded and then never
   * read, while its own comment claimed it was "verified against the session's recorded key" — a
   * comment asserting a property no code enforced, which is the exact shape this repo keeps finding.
   * It could not be made useful either: the signature is checked against the key the SESSION
   * recorded, so a self-declared signer adds nothing and a mismatching one adds a second way to say
   * the same no. Removed rather than documented, while nothing is published and no mailbox holds
   * one.
   */
  ackSig: Uint8Array;
}

/**
 * Encode a parked acknowledgement. This becomes the park envelope's `content`, so the envelope's
 * signature covers it and the seal hides it.
 */
export function encodeParkedDeliveryAck(ack: ParkedDeliveryAck): Uint8Array {
  return encodeCbor([
    PARKED_DELIVERY_ACK_TAG,
    ack.sessionIdHex,
    ack.contentHash,
    ack.ackSig,
  ]) as Uint8Array;
}

/**
 * Is this park envelope's content a delivery acknowledgement? `null` means no — which is the answer
 * for every ordinary message, and must stay the answer for every ordinary message.
 *
 * 🚨 STRICT ON PURPOSE, AND IT REFUSES RATHER THAN REPAIRS. A malformed acknowledgement answers
 * `null`, which routes it to the content path where the envelope gate has already vouched for the
 * depositor and ingest will judge it on its own terms. There is no half-accepted acknowledgement:
 * the widths are exact, the tag is in the first slot only, and a hex session id that is not hex is
 * refused. A tolerant decode here would let a crafted message be filed as proof of its own delivery.
 */
export function decodeParkedDeliveryAck(content: Uint8Array): ParkedDeliveryAck | null {
  let arr: unknown;
  try {
    arr = cborDecode(content);
  } catch {
    return null;
  }
  if (!Array.isArray(arr) || arr.length !== 4) return null;
  const [tag, sessionIdHex, contentHash, ackSig] = arr as unknown[];
  if (tag !== PARKED_DELIVERY_ACK_TAG) return null;
  if (typeof sessionIdHex !== "string" || !/^[0-9a-fA-F]+$/.test(sessionIdHex) || sessionIdHex.length % 2 !== 0) return null;
  if (!(contentHash instanceof Uint8Array) || contentHash.length !== 32) return null;
  if (!(ackSig instanceof Uint8Array) || ackSig.length !== 64) return null;
  return { sessionIdHex, contentHash, ackSig };
}

/**
 * THE park envelope version — there is one shape (M9D purge):
 *
 *   [4, content, structure1Cbor|null, structure2Cbor|null, senderPubkey, parkSig,
 *    contentHashAlg, structure1Signature|null, leafKind]
 *
 * The number stays 4 so an envelope from before the purge — which is only ever test mail, the fleet
 * is wiped at the roll — cannot be mistaken for this one. Any other shape decodes as UNREADABLE and
 * is refused as `unsigned_envelope`: it carries nothing this build can authenticate.
 *
 * Why the algorithm is NOT in the signed statement: `parkSig` covers `(session_id, recipient_pubkey,
 * content_hash)` — the HASH, not the name of the function that produced it. An attacker who flips the
 * name cannot make altered content verify, because the recomputed hash must still equal the SIGNED
 * one; a flip can only turn an acceptance into a REFUSAL. `dod-m15-park-envelope-alg.test.ts` pins
 * that, because "only a refusal" is a claim rather than a hope.
 *
 * `structure1Signature` (034-CARRYLEAF review F1) is the sender's signature over `structure1Cbor`.
 * Without it, a withheld message that arrives by mailbox cannot be witnessed by its recipient. It is
 * null only where there is no ordering claim to sign (the direct-retry enqueue, content never
 * framed); park recovery refuses an envelope with neither a relay ordering record nor a signed claim.
 */
export const PARK_ENVELOPE_VERSION = 4;

export interface ParkEnvelope {
  /** `PARK_ENVELOPE_VERSION`, or 0 for anything this build cannot read (refused as unsigned). */
  version: number;
  content: Uint8Array;
  /** DOD-MSG-4 ordering record — optional; absent on the crash-backstop path. */
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
  /** SEC-1 — the sender's identity key. */
  senderPubkey?: Uint8Array;
  /** SEC-1 — Ed25519 over buildParkContentTbs(...). */
  parkSig?: Uint8Array;
  /**
   * 034-CARRYLEAF — the sender's Ed25519 signature over `structure1Cbor`, when there is one.
   *
   * DISTINCT FROM `parkSig`, which signs `(session_id, recipient_pubkey, content_hash)`. This one
   * signs the ordering claim itself, which is the only form the relay will accept when the recipient
   * witnesses a leaf on its author's behalf.
   */
  structure1Signature?: Uint8Array;
  /**
   * The algorithm the sender used for `content_hash`. A non-string decodes as ABSENT, and
   * `resolveContentHashAlg` refuses an absent name — it is never coerced to a default.
   */
  contentHashAlg?: string;
  /**
   * 034-CARRYLEAF — the leaf DOMAIN this content belongs to (0x00 msg, 0x04 doc, …).
   *
   * A leaf kind selects a hash domain, and documents ride this same envelope. Witnessing a recovered
   * leaf under a guessed domain would put a wrong statement in the canonical record, so a recipient
   * that does not see this does not witness at all.
   */
  leafKind?: number;
}

export type ParkAuthFailure =
  | "unsigned_envelope"
  | "bad_signature"
  | "signer_not_counterparty"
  | "counterparty_unknown";

export type ParkAuthVerdict = { ok: true } | { ok: false; reason: ParkAuthFailure };

/**
 * Why this build refused to SEAL an entry — the producer side, distinct from `ParkAuthFailure`,
 * which is why it refused to ACCEPT one.
 */
export const PARK_ENVELOPE_REASONS = {
  /** The entry names a content-hash algorithm this build cannot itself reproduce. */
  ALG_UNREADABLE: "park_envelope_alg_unreadable",
} as const;

/**
 * The relay's park-refusal codes.
 *
 * ⚠️ RE-EXPORTED FROM `@cello-protocol/protocol-types`, NOT declared here. They used to be a private
 * copy that happened to agree with the relay's strings — verified by hand once, which is not a
 * guard. A rename on the relay side would have left this copy silently unmatched, falling through to
 * the generic "the relay link is down" wording: the exact defect this family of work removed,
 * reintroduced by a change nobody would think of as a protocol change.
 */
import { RELAY_PARK_REFUSALS } from "@cello-protocol/protocol-types";
export { RELAY_PARK_REFUSALS };

export type ParkEnvelopeReason = (typeof PARK_ENVELOPE_REASONS)[keyof typeof PARK_ENVELOPE_REASONS];

/**
 * A REFUSAL TO SEAL, carrying a code the caller can branch on — `DOD-M15-SEALWIRE-1` B2b-2
 * constraint 6, inherited from B2a's review.
 *
 * ⚠️ THE PROSE WAS NEVER THE PROBLEM; WHERE IT LANDED WAS. This threw a bare `Error` with a clear
 * paragraph, and `#parkContent`'s catch put `err.message` into `cause` — a field its own callers
 * document as the MACHINE-READABLE half, added (M12-P13) so that nobody would have to substring-match
 * English to decide what to do. A paragraph there is unbranchable, so this fault fell into the
 * generic relay branch and inherited its guidance: *"the relay refused the hand-off, so the message
 * is queued and will be re-sent automatically when the relay link is back."*
 *
 * Both halves of that are false here. The relay was never asked, and every re-park throws in exactly
 * the same place, so the message sits in the queue while its sender waits for a recovery that cannot
 * happen. Splitting the code from the prose is what lets the caller say something true instead.
 */
export class ParkEnvelopeError extends Error {
  readonly reason: ParkEnvelopeReason;
  /** The offending value alone, so a caller can log it without re-parsing the sentence. */
  readonly detail: string;
  constructor(reason: ParkEnvelopeReason, detail: string, message: string) {
    super(message);
    this.name = "ParkEnvelopeError";
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * SEC-1: encode a SIGNED park envelope. `senderPubkey`, `parkSig`, the algorithm and the leaf kind
 * are REQUIRED — the type system is the enforcement point, so no call site can construct an unsigned
 * or unlabelled envelope by omission.
 */
export function encodeParkEnvelope(args: {
  content: Uint8Array;
  senderPubkey: Uint8Array;
  parkSig: Uint8Array;
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
  /** The algorithm behind the signed content hash. */
  contentHashAlg: string;
  /**
   * 034-CARRYLEAF — the sender's signature over `structure1Cbor`. It is what lets the RECIPIENT
   * witness this leaf when the sender did not: the relay accepts a counter-submit only against the
   * author's own signature over their own ordering claim, and `parkSig` signs a different statement.
   * Ignored without `structure1Cbor`: a signature with no claim to check it against is not evidence.
   */
  structure1Signature?: Uint8Array;
  /** The leaf domain, so a recovered leaf is never witnessed under a guessed one. */
  leafKind: number;
}): Uint8Array {
  /**
   * REFUSE TO EMIT A NAME WE CANNOT READ OURSELVES — the producer-side mirror of what
   * `contentHashFor` already does. Without it a caller can seal an envelope every peer refuses —
   * including this build — with no signal at the sender at all: the message parks, is pulled, is
   * refused, is kept, and repeats. A throw here is a developer error at the moment it is made.
   */
  if (!isKnownContentHashAlg(args.contentHashAlg)) {
    throw new ParkEnvelopeError(
      PARK_ENVELOPE_REASONS.ALG_UNREADABLE,
      args.contentHashAlg,
      `PARK ENVELOPE: refusing to seal an entry naming content-hash algorithm "${args.contentHashAlg}", which ` +
      "this build cannot itself reproduce. The recipient would refuse it and keep re-pulling it forever, " +
      "and nothing at the sender would say why.",
    );
  }
  const signedClaim = args.structure1Signature && args.structure1Cbor ? args.structure1Signature : null;
  return encodeCbor([
    PARK_ENVELOPE_VERSION,
    args.content,
    args.structure1Cbor ?? null,
    args.structure2Cbor ?? null,
    args.senderPubkey,
    args.parkSig,
    args.contentHashAlg,
    signedClaim,
    args.leafKind,
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
  /** 034-CARRYLEAF — the sender's signature over `structure1Cbor`, when there is one. */
  structure1Signature?: Uint8Array;
  /** The leaf domain, so a recovered leaf is never witnessed under a guessed one. */
  leafKind: number;
  /** The algorithm behind `contentHash`. */
  contentHashAlg: string;
}): Promise<Uint8Array> {
  const senderPubkey = await args.signer.getPublicKey();
  const parkSig = await args.signer.sign(
    buildParkContentTbs(args.sessionIdHex, args.recipientPubkey, args.contentHash),
  );
  const envelope = encodeParkEnvelope({
    content: args.content,
    structure1Cbor: args.structure1Cbor,
    structure2Cbor: args.structure2Cbor,
    structure1Signature: args.structure1Signature,
    leafKind: args.leafKind,
    senderPubkey,
    parkSig,
    contentHashAlg: args.contentHashAlg,
  });
  // The signature rides INSIDE the seal — the relay (the adversary) never sees it, so it can neither
  // strip nor forge it. INV-3 is untouched: the relay still holds only ciphertext.
  return sealToRecipient(args.recipientPubkey, envelope);
}

/**
 * Decode a park envelope. Anything that is not the one current shape decodes as version 0 — still
 * returned, so `authenticateParkedEntry` refuses it by name rather than the caller seeing an opaque
 * parse failure. Decoding is not accepting.
 */
export function decodeParkEnvelope(plaintext: Uint8Array): ParkEnvelope {
  try {
    const arr = cborDecode(plaintext) as unknown[];
    if (Array.isArray(arr) && arr.length === 9 && arr[0] === PARK_ENVELOPE_VERSION && arr[1] instanceof Uint8Array) {
      return {
        version: PARK_ENVELOPE_VERSION,
        content: arr[1],
        structure1Cbor: arr[2] instanceof Uint8Array ? arr[2] : undefined,
        structure2Cbor: arr[3] instanceof Uint8Array ? arr[3] : undefined,
        senderPubkey: arr[4] instanceof Uint8Array ? arr[4] : undefined,
        parkSig: arr[5] instanceof Uint8Array ? arr[5] : undefined,
        // A non-string stays ABSENT rather than being coerced; `resolveContentHashAlg` refuses it.
        contentHashAlg: typeof arr[6] === "string" ? arr[6] : undefined,
        structure1Signature: arr[7] instanceof Uint8Array ? arr[7] : undefined,
        leafKind: typeof arr[8] === "number" ? arr[8] : undefined,
      };
    }
  } catch {
    /* not CBOR — unreadable */
  }
  return { version: 0, content: plaintext };
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

  // 1. Unreadable or unsigned — the shape an attacker sends. Refused outright.
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


/**
 * The operator-facing guidance for a refused park hand-off — **a pure function, deliberately.**
 *
 * ⚠️ It was an inline ternary inside `sendContent`, which meant the only way to assert any branch of
 * it was to stand up a two-connection fixture and drive a real send. That is why the branch that was
 * WRONG for a throttling relay survived: nothing cheap could reach it. A guidance string is a
 * decision about what a person does next, and it deserves to be testable on its own.
 *
 * `durable` distinguishes "queued and will retry" from "not queued — it is lost", which is the one
 * distinction that changes whether the reader must act right now.
 */
export function parkRefusalGuidance(cause: string | undefined, durable: boolean, retryAfterMs?: number): string {
  if (cause === PARK_ENVELOPE_REASONS.ALG_UNREADABLE) {
    return (
      "This message names a content-hash algorithm your build cannot produce, so it could not be " +
      "sealed for hand-off. The relay is NOT involved and this will not clear on its own — the " +
      "message is safely stored but every retry fails the same way. Upgrade to a build that knows " +
      "the algorithm, or start a new session with this counterparty. Re-sending on this build " +
      "changes nothing."
    );
  }

  /**
   * ⚠️ DIAGNOSIS AND ACTION ARE COMPOSED, NOT WRITTEN TOGETHER — and this shape is the fix for a
   * defect review found in the first version.
   *
   * That version returned a complete paragraph per cause and **never consulted `durable`**, so all
   * three new branches ended "The message is queued and re-sent automatically. Do not re-send it."
   * `durable` is OBSERVED, not assumed: it is false when the durable enqueue was refused as a
   * duplicate, or when the retry hook is unwired. In that case the daemon logs at ERROR that the
   * content is *not* separately retained while the operator was simultaneously told it was queued
   * and instructed not to re-send. **Nothing held the message.** That is precisely the lie this
   * family of work exists to kill, reintroduced one layer up.
   *
   * Splitting them makes the mistake unavailable: the action half is produced in exactly one place
   * and cannot be reached without reading the flag.
   */
  const diagnosis =
    cause === RELAY_PARK_REFUSALS.RATE_LIMITED
      ? `The relay is healthy and deliberately rate-limiting this agent's hand-offs, so it refused this one. NOTHING IS WRONG with the link or the counterparty, and the limit clears on its own${describeRetryWindow(retryAfterMs)}.`
      : cause === RELAY_PARK_REFUSALS.RECIPIENT_FULL
        ? "The relay is holding as much undelivered content for THIS counterparty as it will, so it refused the hand-off. That is about their mailbox, not your connection, and another relay would refuse it too. It clears when they come online and collect it, or when older entries expire."
        : cause === RELAY_PARK_REFUSALS.STORE_FULL
          ? "The relay's parked-content store is full, so it refused the hand-off. The link is fine. If this persists the relay operator needs to know — it means the store is under sustained pressure."
          : null;

  if (diagnosis !== null) {
    return durable
      ? `${diagnosis} The message is queued and re-sent automatically. Do not re-send it: an identical re-send is not separately queued.`
      : `${diagnosis} ⚠️ BUT THIS MESSAGE WAS NOT QUEUED — it is lost. Send it again.`;
  }

  return durable
    ? "Direct delivery failed and the relay refused the hand-off, so the message is queued and will be re-sent automatically when the relay link is back. Do not re-send it: an identical re-send is not separately queued."
    : "Direct delivery failed and the message could NOT be queued for retry — it is lost. Send it again.";
}


/**
 * Render the relay's own retry delay, or say nothing at all.
 *
 * ⚠️ SAYS NOTHING WHEN THE RELAY DID NOT SAY — review MEDIUM-6. The first version of the guidance
 * asserted the limit clears *"in about a minute"*, which is a hardcoded guess about the relay's
 * CONFIGURABLE window: a relay run at ten minutes makes that a wrong promise, and a wrong number is
 * worse than no number because the reader plans around it. When the relay tells us, we quote it;
 * when it does not, the sentence simply ends.
 */
function describeRetryWindow(retryAfterMs: number | undefined): string {
  if (retryAfterMs === undefined || !Number.isFinite(retryAfterMs) || retryAfterMs <= 0) return "";
  const seconds = Math.ceil(retryAfterMs / 1000);
  return seconds < 90 ? ` in about ${String(seconds)} seconds` : ` in about ${String(Math.ceil(seconds / 60))} minutes`;
}
