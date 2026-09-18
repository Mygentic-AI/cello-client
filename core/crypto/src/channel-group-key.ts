/**
 * M16 019-MEMBERSHIP Part A — a channel's group key, and the fetch key derived from it.
 *
 * ─── Why there are two keys and not one ───────────────────────────────────────────────────────
 *
 * The GROUP KEY encrypts post bodies, so a relay holds ciphertext it cannot read. That alone does
 * not keep a non-member out: they could still fetch every post and hold the ciphertext, which leaks
 * the channel's size, cadence and timing even when it leaks no words.
 *
 * The FETCH KEY is DERIVED from the group key, and it is what the relay checks before serving the
 * queue at all. Deriving rather than generating is the point: every member can compute the private
 * half from the group key they already hold, and the publisher hands the relay only the public half.
 * Nothing extra has to be distributed, and — the part that matters — **rotating the group key
 * rotates the fetch key too**. That is why ejection is a re-key: the ejected member cannot read new
 * posts and cannot even ask for them.
 *
 * ─── Construction ────────────────────────────────────────────────────────────────────────────
 *
 *   encryptBody(gk, channel, seq, plaintext):
 *     1. nonce  = random 12 bytes                                    # NIST SP 800-38D §8.2.2
 *     2. aad    = CBOR ["cello-broadcast-body-v1", channel, seq, generation]
 *     3. ct||tag = AES-256-GCM(gk.key, nonce, plaintext, aad)         # NIST SP 800-38D
 *     4. body   = generation(4, BE) || nonce(12) || ct || tag(16)
 *
 *   deriveFetchKey(gk, channel):
 *     seed = HKDF-SHA256(ikm=gk.key, salt=channel,                    # RFC 5869
 *                        info="cello-channel-fetch-key-v1" || generation, 32)
 *
 * ⚠️ **ONE AEAD.** AES-256-GCM, the same primitive `content-seal.ts` and `session-content-seal.ts`
 * use. A second cipher here would be a second thing to reason about and a second dependency, for a
 * property neither would give.
 *
 * ⚠️ **THE ASSOCIATED DATA IS LOAD-BEARING, NOT DECORATION.** It binds the channel, the position and
 * the generation to the ciphertext. Without it a relay could serve post 7's body at position 3, or
 * one channel's bodies as another's, and every signature would still check out — the signature
 * covers the post, and the post is what a hostile relay replays whole.
 *
 * ⚠️ **A RANDOM NONCE, NEVER A COUNTER.** A counter needs state shared by every daemon that
 * publishes under this key, and there is no such state. Under a key that encrypts a channel's posts,
 * a 96-bit random nonce has a birthday bound around 2^32 messages, which is not the limiting factor.
 *
 * ⚠️ **NOTHING HERE EVER LOGS.** `generation` may be logged by callers; key bytes may not, ever.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { InMemoryKeyProvider, generateKeypair } from "./ed25519.js";
import { sealToRecipient, openSealed } from "./content-seal.js";
import type { KeyProvider, PublicKey, Signature } from "./types.js";

const KEY_BYTES = 32;
const PUBKEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const GENERATION_BYTES = 4;
/** generation + nonce + tag. A body shorter than this cannot be framed at all. */
const BODY_OVERHEAD = GENERATION_BYTES + NONCE_BYTES + TAG_BYTES;

const BODY_AAD_DOMAIN = "cello-broadcast-body-v1";
const BUNDLE_DOMAIN = "cello-channel-key-bundle-v1";
const FETCH_KEY_INFO = "cello-channel-fetch-key-v1";

/**
 * ⚠️ **NOT CBOR, AND THE ORDER SAYS CBOR — a deviation, recorded and raised.**
 *
 * Two things rule it out here. `cbor-x` lives in `protocol-types`, which DEPENDS ON this package, so
 * importing it back is a cycle; and `no-multiple-cbor-encoders.test.ts` forbids a second encoder
 * instance precisely because two of them once wrote byte strings two different ways into the same
 * columns. Adding one here is the thing that guard exists to stop.
 *
 * Nothing is lost. The associated data is CONSTRUCTED and never parsed — both sides build it from
 * the same fields — so all it must be is unambiguous, which fixed widths and a domain prefix give.
 * The key bundle IS parsed, and it is a fixed layout for the same reason: no length fields to
 * disagree about, no decoder to hand attacker-chosen bytes to.
 */
function frame(domain: string, parts: Uint8Array[]): Uint8Array {
  return new Uint8Array(Buffer.concat([Buffer.from(domain, "utf-8"), ...parts.map((p) => Buffer.from(p))]));
}

function u32(value: number): Uint8Array {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value, 0);
  return new Uint8Array(b);
}

export interface GroupKey {
  generation: number;
  /** 32 bytes. Never logged, never leaves the SQLCipher database in the clear. */
  key: Uint8Array;
}

export type BodyDecryptFailure = "unknown_generation" | "auth_failed" | "malformed";

export type BodyDecryptResult =
  | { ok: true; plaintext: Uint8Array; generation: number }
  | { ok: false; reason: BodyDecryptFailure };

export type GroupKeyUnwrapResult =
  | { ok: true; gk: GroupKey }
  | { ok: false; reason: "not_for_me" | "malformed" | "wrong_channel" };

/** An Ed25519 keypair derived from a group key, for authenticating fetches to the relay. */
export interface FetchKey {
  publicKey: PublicKey;
  /** The 32-byte seed, so a publisher can reconstruct the same pair. Never logged. */
  privateKey: Uint8Array;
  sign: (data: Uint8Array) => Promise<Signature>;
}

/** A fresh group key at the given generation. CSPRNG — never derived from anything guessable. */
export function generateGroupKey(generation: number): GroupKey {
  return { generation, key: new Uint8Array(randomBytes(KEY_BYTES)) };
}

/**
 * domain || channel(32) || seq(4) || generation(4). Every field is fixed width, so no two distinct
 * (channel, seq, generation) triples can produce the same bytes — which is the only property
 * associated data needs.
 */
function bodyAad(channelPubkey: Uint8Array, seq: number, generation: number): Uint8Array {
  return frame(BODY_AAD_DOMAIN, [channelPubkey, u32(seq), u32(generation)]);
}

/** Encrypt one post body. The channel, position and generation are bound in as associated data. */
export function encryptBody(gk: GroupKey, channelPubkey: Uint8Array, seq: number, plaintext: Uint8Array): Uint8Array {
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(gk.key), Buffer.from(nonce));
  cipher.setAAD(Buffer.from(bodyAad(channelPubkey, seq, gk.generation)));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();

  const out = Buffer.alloc(GENERATION_BYTES);
  out.writeUInt32BE(gk.generation, 0);
  return new Uint8Array(Buffer.concat([out, Buffer.from(nonce), ct, tag]));
}

/**
 * Decrypt one post body against every generation this subscriber holds. **NEVER THROWS.**
 *
 * ⚠️ `unknown_generation` IS ITS OWN ANSWER and must stay separate from `auth_failed`. A member who
 * missed a re-key is in a recoverable state — ask for the new key — while a body that fails to
 * authenticate under a key we DO hold is a forgery or a relay corrupting content. Folding them
 * together would have a member who simply missed a message treat the channel as hostile.
 */
export function decryptBody(
  keys: readonly GroupKey[], channelPubkey: Uint8Array, seq: number, body: Uint8Array,
): BodyDecryptResult {
  if (body.length < BODY_OVERHEAD) return { ok: false, reason: "malformed" };

  const generation = Buffer.from(body.subarray(0, GENERATION_BYTES)).readUInt32BE(0);
  const gk = keys.find((k) => k.generation === generation);
  if (!gk) return { ok: false, reason: "unknown_generation" };

  try {
    const nonce = body.subarray(GENERATION_BYTES, GENERATION_BYTES + NONCE_BYTES);
    const rest = body.subarray(GENERATION_BYTES + NONCE_BYTES);
    const ct = rest.subarray(0, rest.length - TAG_BYTES);
    const tag = rest.subarray(rest.length - TAG_BYTES);

    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(gk.key), Buffer.from(nonce));
    decipher.setAAD(Buffer.from(bodyAad(channelPubkey, seq, generation)));
    decipher.setAuthTag(Buffer.from(tag));
    const pt = Buffer.concat([decipher.update(Buffer.from(ct)), decipher.final()]);
    return { ok: true, plaintext: new Uint8Array(pt), generation };
  } catch {
    // The tag did not check out: wrong key at this generation, or the channel/seq the body was
    // encrypted for is not the one it is being served at.
    return { ok: false, reason: "auth_failed" };
  }
}

/**
 * Wrap a group key for ONE member, addressed to their identity key.
 *
 * ⚠️ PER MEMBER, deliberately. A re-key hands each remaining member their own bundle, and the whole
 * mechanism of ejection is that one member is simply not given one — which only means anything if
 * somebody else's bundle is useless to them.
 *
 * The channel is inside the sealed plaintext, so a bundle cannot be replayed into another channel's
 * join to hand a member a key for a channel they were never admitted to.
 */
export function wrapGroupKeyFor(
  gk: GroupKey, channelPubkey: Uint8Array, memberPubkey: Uint8Array, _senderKeys: KeyProvider,
): Promise<Uint8Array> {
  // domain || channel(32) || generation(4) || key(32) — fixed layout, read back by offset.
  const payload = frame(BUNDLE_DOMAIN, [channelPubkey, u32(gk.generation), gk.key]);
  return Promise.resolve(sealToRecipient(memberPubkey, payload));
}

/** Open a bundle addressed to this member. Returns a reason, never throws. */
export async function unwrapGroupKey(
  bundle: Uint8Array, channelPubkey: Uint8Array, myKeys: KeyProvider,
): Promise<GroupKeyUnwrapResult> {
  // `openContentSeal` is the KeyProvider's own opener — the seed never leaves it. A provider that
  // cannot open (threshold, signing-only) is not a member and says so rather than crashing.
  if (!myKeys.openContentSeal) return Promise.resolve({ ok: false, reason: "not_for_me" });

  let opened: Uint8Array | null;
  try {
    opened = await myKeys.openContentSeal(bundle);
  } catch {
    return { ok: false, reason: "not_for_me" };
  }
  if (!opened) return { ok: false, reason: "not_for_me" };

  // Fixed layout, read by offset: domain || channel(32) || generation(4) || key(32).
  const domainBytes = Buffer.from(BUNDLE_DOMAIN, "utf-8");
  const expected = domainBytes.length + PUBKEY_BYTES + GENERATION_BYTES + KEY_BYTES;
  if (opened.length !== expected) return { ok: false, reason: "malformed" };
  const buf = Buffer.from(opened);
  if (!buf.subarray(0, domainBytes.length).equals(domainBytes)) return { ok: false, reason: "malformed" };

  let at = domainBytes.length;
  const channel = buf.subarray(at, at + PUBKEY_BYTES); at += PUBKEY_BYTES;
  const generation = buf.readUInt32BE(at); at += GENERATION_BYTES;
  const key = buf.subarray(at, at + KEY_BYTES);

  // The channel named INSIDE the seal must be the one we are joining. Checked here rather than by
  // the caller so there is no join path that can forget it.
  if (!channel.equals(Buffer.from(channelPubkey))) return { ok: false, reason: "wrong_channel" };
  return { ok: true, gk: { generation, key: new Uint8Array(key) } };
}

/**
 * Derive the channel's fetch keypair for this generation.
 *
 * ⚠️ DETERMINISTIC, and it has to be: the publisher gives the relay the PUBLIC half, and every
 * member derives the same PRIVATE half from the group key they already hold. A random pair would
 * leave members unable to sign what the relay is checking.
 *
 * The channel is the HKDF salt and the generation is in the info string, so a fetch key is useless
 * on another channel and a re-key produces a different one — which is what ends an ejected member's
 * access at the relay rather than merely at the ciphertext.
 */
export function deriveFetchKey(gk: GroupKey, channelPubkey: Uint8Array): Promise<FetchKey> {
  const info = new TextEncoder().encode(`${FETCH_KEY_INFO}:${String(gk.generation)}`);
  const seed = hkdf(sha256, gk.key, channelPubkey, info, KEY_BYTES);
  const provider = new InMemoryKeyProvider(new Uint8Array(seed));
  return provider.getPublicKey().then((publicKey) => ({
    publicKey,
    privateKey: new Uint8Array(seed),
    sign: (data: Uint8Array) => provider.sign(data),
  }));
}

/** Re-exported so a caller needing a throwaway identity does not reach past this module. */
export { generateKeypair, openSealed };
