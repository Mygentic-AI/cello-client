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

/** Current envelope version. v1 (unsigned) is decodable but NEVER acceptable — see authenticate(). */
export const PARK_ENVELOPE_VERSION = 2;

/**
 * v3 — a v2 envelope plus the CONTENT-HASH ALGORITHM (`DOD-M15-SEALWIRE-1` part B2a).
 *
 * ⚠️ EMITTED ONLY WHEN THE ALGORITHM IS NOT THE DEFAULT, and that is the whole compatibility story.
 * Every envelope this build produces today is still v2, because nothing salts — so no current peer
 * sees a version it cannot read.
 *
 * 🚨 AND THE GATE IS A PUBLISHING FACT, NOT A STRUCTURAL ONE — review B2a F6 corrected this. The
 * header used to claim *"a salted envelope can only be addressed to a peer that completed the salt
 * agreement, and a build able to do that necessarily contains this decoder."* **False as stated:**
 * the salt agreement landed several commits before this decoder, so any build cut from that interval
 * has the agreement and not the decoder. On such a peer a v3 envelope matches no decode branch,
 * falls through to the bare-content v1 shape, and `authenticateParkedEntry` refuses it as
 * `unsigned_envelope` — the ATTACKER shape — the entry is never confirm-deleted, and it re-pulls
 * forever. Exactly the failure this unit exists to prevent.
 *
 * What is true, and checkable: **no published build has the salt agreement without this decoder** —
 * nothing in that interval is tagged. Part B2b must therefore gate salting on a real peer-capability
 * signal rather than inferring capability from "they completed the salt agreement".
 *
 * Why the algorithm is NOT in the signed statement: `parkSig` covers `(session_id, recipient_pubkey,
 * content_hash)` — the HASH, not the name of the function that produced it. Adding the name would
 * change `buildParkContentTbs`, a cross-repo type, for no security gain. An attacker who flips the
 * name cannot make altered content verify, because the recomputed hash must still equal the SIGNED
 * one; a flip can only turn an acceptance into a REFUSAL. `dod-m15-park-envelope-alg.test.ts` pins
 * that, because "only a refusal" is a claim rather than a hope.
 */
export const PARK_ENVELOPE_VERSION_ALG = 3;

/**
 * The versions that carry a sender signature and may therefore be authenticated.
 *
 * A SET, not a single constant, and the difference is mail loss. `authenticateParkedEntry` refused
 * anything whose version was not the one `PARK_ENVELOPE_VERSION` names — so bumping that constant to
 * 3 would have turned every v2 envelope sitting in every relay mailbox into `unsigned_envelope`:
 * store-and-forward mail destroyed, and reported as an attack.
 */
const SIGNED_ENVELOPE_VERSIONS = new Set<number>([PARK_ENVELOPE_VERSION, PARK_ENVELOPE_VERSION_ALG]);

export interface ParkEnvelope {
  /** 1 = legacy/unsigned (bare content or the pre-SEC-1 shape). 2 = signed. */
  version: number;
  content: Uint8Array;
  /** DOD-MSG-4 ordering record — optional; absent on the crash-backstop path. */
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
  /** SEC-1 — the sender's identity key. Present only on v2. */
  senderPubkey?: Uint8Array;
  /** SEC-1 — Ed25519 over buildParkContentTbs(...). Present on v2 and v3. */
  parkSig?: Uint8Array;
  /**
   * The algorithm the sender used for `content_hash`. Present only on v3.
   *
   * ABSENT rather than defaulted to `"sha256"`, deliberately: `resolveContentHashAlg` reads absent as
   * "a peer that predates the field", and that is the only value meaning legacy. Filling in the
   * literal here would work today while erasing the distinction between "they said sha256" and "they
   * said nothing" — the same collapse B1's empty-string case exists to prevent.
   */
  contentHashAlg?: string;
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
 * The relay's own refusal reasons that the CLIENT must branch on, as codes rather than prose.
 *
 * ⚠️ `RATE_LIMITED` exists because the operator-facing sentence for a refused park was written for a
 * relay OUTAGE — *"will be re-sent automatically when the relay link is back"* — and
 * `DOD-M15-RELAYABUSE-1` made a second, opposite cause reachable: a perfectly healthy relay
 * deliberately throttling this peer. The link is not down and there is no link-restored event
 * coming, so that sentence promises a trigger that will never fire. **A wrong diagnosis is worse
 * than none: it tells the operator where NOT to look.**
 */
export const RELAY_PARK_REFUSALS = {
  /** The relay is throttling this depositor. Self-clears; the relay says when via `retry_after_ms`. */
  RATE_LIMITED: "rate_limited",
  /** The relay's parked-content store is at a bound. Self-clears as entries expire or are collected. */
  STORE_FULL: "content_store_full",
  /** This RECIPIENT's mailbox is at its own bound — another relay will not help. */
  RECIPIENT_FULL: "content_store_recipient_full",
} as const;

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
  /** Omit, or pass the default, to emit a v2 envelope every current peer can read. */
  contentHashAlg?: string;
}): Uint8Array {
  const base = [
    args.content,
    args.structure1Cbor ?? null,
    args.structure2Cbor ?? null,
    args.senderPubkey,
    args.parkSig,
  ];
  /**
   * The DEFAULT algorithm stays on v2 even when named explicitly. A caller that starts passing the
   * algorithm through would otherwise push every envelope to a version older peers cannot read,
   * without anyone having decided to.
   *
   * ABSENT is `undefined`/`null` ONLY, never "falsy" — review B2a F4. `!args.contentHashAlg` also
   * caught the EMPTY STRING, which is the collapse `resolveContentHashAlg` documents as forbidden
   * and which this file's own `contentHashAlg` doc cites B1 for. A caller whose variable is `""`
   * would have emitted a v2 envelope labelled sha256-by-absence, and the recipient would report a
   * tamper on a message nobody touched.
   */
  const alg = args.contentHashAlg;
  if (alg === undefined || alg === null || alg === CONTENT_HASH_ALGS.SHA256) {
    return encodeCbor([PARK_ENVELOPE_VERSION, ...base]) as Uint8Array;
  }
  /**
   * REFUSE TO EMIT A NAME WE CANNOT READ OURSELVES — the producer-side mirror of what
   * `contentHashFor` already does, and it costs nothing to have.
   *
   * Without it a caller can seal an envelope every peer refuses — including this build — with no
   * signal at the sender at all: the message parks, is pulled, is refused, is kept, and repeats.
   * A throw here is a developer error at the moment it is made, rather than a silent mail loop.
   */
  if (!isKnownContentHashAlg(alg)) {
    throw new ParkEnvelopeError(
      PARK_ENVELOPE_REASONS.ALG_UNREADABLE,
      alg,
      `PARK ENVELOPE: refusing to seal an entry naming content-hash algorithm "${alg}", which this ` +
      "build cannot itself reproduce. The recipient would refuse it and keep re-pulling it forever, " +
      "and nothing at the sender would say why.",
    );
  }
  return encodeCbor([PARK_ENVELOPE_VERSION_ALG, ...base, alg]) as Uint8Array;
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
  /** The algorithm behind `contentHash`. Omit for the default; see `PARK_ENVELOPE_VERSION_ALG`. */
  contentHashAlg?: string;
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
    contentHashAlg: args.contentHashAlg,
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
    // v3 first: a v2 envelope plus the content-hash algorithm as a 7th element.
    if (Array.isArray(arr) && arr.length === 7 && arr[0] === PARK_ENVELOPE_VERSION_ALG && arr[1] instanceof Uint8Array) {
      return {
        version: PARK_ENVELOPE_VERSION_ALG,
        content: arr[1],
        structure1Cbor: arr[2] instanceof Uint8Array ? arr[2] : undefined,
        structure2Cbor: arr[3] instanceof Uint8Array ? arr[3] : undefined,
        senderPubkey: arr[4] instanceof Uint8Array ? arr[4] : undefined,
        parkSig: arr[5] instanceof Uint8Array ? arr[5] : undefined,
        // A non-string here stays ABSENT rather than being coerced. `resolveContentHashAlg` refuses
        // a name it cannot read; it must never be handed a `"42"` that looks like one.
        contentHashAlg: typeof arr[6] === "string" ? arr[6] : undefined,
      };
    }
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
  if (!SIGNED_ENVELOPE_VERSIONS.has(env.version) || !env.senderPubkey || !env.parkSig) {
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
export function parkRefusalGuidance(cause: string | undefined, durable: boolean): string {
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
      ? "The relay is healthy and deliberately rate-limiting this agent's hand-offs, so it refused this one. NOTHING IS WRONG with the link or the counterparty, and the limit clears on its own."
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
