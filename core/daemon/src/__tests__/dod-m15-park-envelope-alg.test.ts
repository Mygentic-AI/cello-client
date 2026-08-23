/**
 * THE PARK ENVELOPE CARRIES THE CONTENT-HASH ALGORITHM — `DOD-M15-SEALWIRE-1` bullet 6, part B2a.
 *
 * ─── Why this must land BEFORE anything salts ──────────────────────────────────────────────────
 *
 * A message takes one of two routes: the direct peer-to-peer stream, or the relay park when direct
 * delivery fails. Part B1 taught the DIRECT route to carry a `content_hash_alg` and verify under it.
 * The park route carries no such field, so both of its verifiers assume `sha256`.
 *
 * That is provably correct today — nothing salts — and becomes a defect the instant part B2b turns
 * salting on. It is worth stating the cost precisely, because it is not just a refused message:
 * `content-park.ts`'s annex check refuses the entry, **does not annex it, and KEEPS the relay copy**,
 * so the next drain pulls it again, refuses again, and keeps it again. A tamper report and a re-pull
 * loop, for a message whose only sin was taking the long way round.
 *
 * ─── RECEIVER FIRST AGAIN, but this time it is self-gating ─────────────────────────────────────
 *
 * The decoder learns v3. The encoder emits v3 **only when the algorithm is not the default**, so
 * every envelope this build actually produces is still v2 and decodes on any current peer. The gate
 * is structural rather than a promise: a salted envelope can only be addressed to a peer that
 * completed the salt agreement, and a build that can do that necessarily has this decoder.
 *
 * ─── Why the algorithm is NOT inside the signature, which is a deliberate call ──────────────────
 *
 * `parkSig` covers `(session_id, recipient_pubkey, content_hash)` — the HASH, not the name of the
 * function that produced it. Adding the name to that statement would change `buildParkContentTbs`,
 * a cross-repo type, for no security gain: flipping the name cannot make altered content verify,
 * because the computed hash must still equal the SIGNED one. A flipped name can only produce a
 * refusal — and the tests below pin exactly that, because "only a refusal" is a claim, not a hope.
 */

import { describe, it, expect } from "vitest";
import {
  encodeParkEnvelope,
  decodeParkEnvelope,
  authenticateParkedEntry,
  sealParkEnvelope,
  PARK_ENVELOPE_VERSION,
  PARK_ENVELOPE_VERSION_ALG,
} from "../park-envelope.js";
import { CONTENT_HASH_ALGS, contentHashFor, wireContentHash } from "../wire-content-hash.js";
import {
  generateKeypair, deriveSessionSalt, saltedContentHash, SALT_CONTRIBUTION_BYTES,
} from "@cello-protocol/crypto";

/**
 * Open a sealed park blob as the recipient does in production: through the KeyProvider's own
 * `openContentSeal`, not a test-local re-implementation of the seal. A helper that decrypted some
 * other way would let a producer/consumer mismatch pass unseen, which is the exact class this
 * file's round-trip test exists to catch.
 */
async function openAsRecipient(recipient: ReturnType<typeof generateKeypair>, sealed: Uint8Array): Promise<Uint8Array> {
  const opened = await recipient.openContentSeal!(sealed);
  if (!opened) throw new Error("the recipient could not open its own sealed envelope");
  return opened;
}

const CONTENT = new TextEncoder().encode("the offer is 4200");
const SESSION = "ab".repeat(16);
const SALT = deriveSessionSalt(
  new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x11),
  new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x22),
);

describe("the envelope version is chosen by the algorithm, not bumped for everyone", () => {
  it("★ an UNSALTED envelope is still v2 — every current peer must keep decoding what we send", () => {
    /**
     * The compatibility assertion, and the one that would break all store-and-forward mail at once
     * if it regressed. `authenticateParkedEntry` refuses anything whose version it does not know as
     * `unsigned_envelope`, so emitting v3 unconditionally would make every parked message from this
     * build unrecoverable by every peer that has not upgraded.
     */
    const env = encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
    });
    expect(decodeParkEnvelope(env).version).toBe(PARK_ENVELOPE_VERSION);
    expect(PARK_ENVELOPE_VERSION).toBe(2);
  });

  it("★ explicitly naming sha256 STILL emits v2 — the default must not silently bump the version", () => {
    // The subtle break: a caller that starts passing the algorithm explicitly would otherwise push
    // every envelope to v3 without anyone deciding to.
    const env = encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      contentHashAlg: CONTENT_HASH_ALGS.SHA256,
    });
    expect(decodeParkEnvelope(env).version).toBe(PARK_ENVELOPE_VERSION);
  });

  it("★ a SALTED envelope is v3 and carries the name", () => {
    const env = encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      contentHashAlg: CONTENT_HASH_ALGS.HMAC_SALT_V1,
    });
    const decoded = decodeParkEnvelope(env);
    expect(decoded.version).toBe(PARK_ENVELOPE_VERSION_ALG);
    expect(decoded.contentHashAlg).toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
  });

  it("★ the EMPTY STRING is refused, not folded into 'absent' — review B2a F4", () => {
    /**
     * `!args.contentHashAlg` was true for `undefined`, `null` AND `""`. `resolveContentHashAlg`
     * documents that conflation as forbidden — an empty string is a peer that sent a name we cannot
     * read, not a peer that sent no name — and this file's own `contentHashAlg` doc cites B1 for it.
     * The decoder honoured the rule; the encoder re-introduced it on the producer side.
     *
     * A caller whose algorithm variable is `""` would have emitted a v2 envelope labelled
     * sha256-by-absence, and the recipient would report a TAMPER on a message nobody touched.
     *
     * ⚠️ This test exists because the mutant survived. My own mutation loop reported it CAUGHT, and
     * re-running it alone showed 36 tests green — a false negative in the harness, which is the same
     * class of error as a conditional assertion: the check ran and its answer was not what I read.
     */
    expect(() => encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      contentHashAlg: "",
    })).toThrow(/cannot itself reproduce/);
  });

  it("★ a name this build cannot read is refused at the PRODUCER, not left to the recipient", () => {
    // Without this the sender seals an envelope every peer refuses — including itself — and nothing
    // at the sending end says so: the message parks, is pulled, is refused, is kept, and repeats.
    expect(() => encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      contentHashAlg: "hmac-sha512-salt-v9",
    })).toThrow(/cannot itself reproduce/);
  });

  it("★ a v2 envelope decodes with NO algorithm — absent, not defaulted to a string", () => {
    /**
     * `undefined` is what `resolveContentHashAlg` reads as "a peer that predates the field", which is
     * the only value that means legacy. Defaulting to the literal `"sha256"` here would work today
     * and quietly erase the distinction between "they said sha256" and "they said nothing" — the
     * same collapse B1's empty-string case exists to prevent.
     */
    const env = encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
    });
    expect(decodeParkEnvelope(env).contentHashAlg).toBeUndefined();
  });
});

describe("a v3 envelope authenticates exactly as a v2 one does", () => {
  it("★ BOTH signed versions are accepted — bumping the constant must not orphan v2", () => {
    /**
     * The trap this test exists for: `authenticateParkedEntry` refused anything whose version was
     * not the single `PARK_ENVELOPE_VERSION` constant. Bump that constant to 3 and every v2 envelope
     * in every relay mailbox becomes `unsigned_envelope` — mail loss, reported as an attack.
     */
    for (const version of [PARK_ENVELOPE_VERSION, PARK_ENVELOPE_VERSION_ALG]) {
      const verdict = authenticateParkedEntry({
        env: {
          version, content: CONTENT,
          senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
        },
        sessionIdHex: SESSION,
        recipientPubkey: new Uint8Array(32).fill(3),
        contentHash: wireContentHash(CONTENT),
        counterpartyPubkeyHex: "01".repeat(32),
      });
      // Both get PAST the version gate — they fail later, on the signature, which is the point.
      expect(verdict.ok === false && verdict.reason, `v${version} must not be refused as unsigned`)
        .not.toBe("unsigned_envelope");
    }
  });

  it("★ an UNKNOWN version is still refused as unsigned — the set is closed", () => {
    const verdict = authenticateParkedEntry({
      env: {
        version: 99, content: CONTENT,
        senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      },
      sessionIdHex: SESSION,
      recipientPubkey: new Uint8Array(32).fill(3),
      contentHash: wireContentHash(CONTENT),
      counterpartyPubkeyHex: "01".repeat(32),
    });
    expect(verdict.ok === false && verdict.reason).toBe("unsigned_envelope");
  });
});

describe("the producer round-trips through the real consumer", () => {
  it("★ a SALTED envelope seals, unseals, decodes as v3, and authenticates", async () => {
    /**
     * The whole path in one test, against the real `sealParkEnvelope` — the pattern this file's
     * predecessor established after a producer signing the wrong statement was found to be invisible
     * to every consumer-side test.
     */
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const recipientPub = await recipient.getPublicKey();
    const contentHash = contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt: SALT });

    const sealed = await sealParkEnvelope({
      signer: sender, recipientPubkey: recipientPub, sessionIdHex: SESSION,
      content: CONTENT, contentHash, contentHashAlg: CONTENT_HASH_ALGS.HMAC_SALT_V1,
    });
    const env = decodeParkEnvelope(await openAsRecipient(recipient, sealed));

    expect(env.version).toBe(PARK_ENVELOPE_VERSION_ALG);
    expect(env.contentHashAlg).toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
    const verdict = authenticateParkedEntry({
      env, sessionIdHex: SESSION, recipientPubkey: recipientPub, contentHash,
      counterpartyPubkeyHex: Buffer.from(await sender.getPublicKey()).toString("hex"),
    });
    expect(verdict.ok, `expected authentication to pass, got ${JSON.stringify(verdict)}`).toBe(true);
  });

  it("★ the recovered content verifies under the NAMED algorithm and not under the other one", () => {
    /**
     * The assertion that makes the field load-bearing rather than decorative. Without it, a consumer
     * that read the name and then hashed with `sha256` anyway would pass every test above.
     */
    const salted = contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt: SALT });
    expect(Buffer.from(salted).toString("hex")).toBe(Buffer.from(saltedContentHash(SALT, CONTENT)).toString("hex"));
    expect(Buffer.from(salted).toString("hex")).not.toBe(Buffer.from(wireContentHash(CONTENT)).toString("hex"));
  });
});

describe("a flipped algorithm name can only cause a REFUSAL, never an acceptance", () => {
  it("★ the claim behind leaving the name out of the signature, pinned rather than asserted", async () => {
    /**
     * `parkSig` covers the content HASH, not the name of the function that produced it. That is a
     * deliberate call — adding the name would change a cross-repo to-be-signed statement — and it
     * rests on one property: an attacker who flips the name cannot make altered content verify,
     * because the computed hash must still equal the SIGNED one.
     *
     * B1's lesson was that an unsigned field steering verification is dangerous when it changes what
     * happens on FAILURE. Here it changes nothing but which failure: both flips below produce a
     * hash that does not match, and the signature over the real hash is untouched.
     */
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const recipientPub = await recipient.getPublicKey();
    const trueHash = contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt: SALT });

    const sealed = await sealParkEnvelope({
      signer: sender, recipientPubkey: recipientPub, sessionIdHex: SESSION,
      content: CONTENT, contentHash: trueHash, contentHashAlg: CONTENT_HASH_ALGS.HMAC_SALT_V1,
    });
    const env = decodeParkEnvelope(await openAsRecipient(recipient, sealed));

    // Flip the name as an attacker would, then recompute the way a consumer must.
    const asIfUnsalted = contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.SHA256, salt: null });
    expect(
      Buffer.from(asIfUnsalted).toString("hex"),
      "verifying under the flipped name must not reproduce the signed hash",
    ).not.toBe(Buffer.from(trueHash).toString("hex"));

    // And the signature still binds the REAL hash, so the flip cannot launder altered content.
    expect(authenticateParkedEntry({
      env, sessionIdHex: SESSION, recipientPubkey: recipientPub, contentHash: trueHash,
      counterpartyPubkeyHex: Buffer.from(await sender.getPublicKey()).toString("hex"),
    }).ok).toBe(true);
    expect(authenticateParkedEntry({
      env, sessionIdHex: SESSION, recipientPubkey: recipientPub, contentHash: asIfUnsalted,
      counterpartyPubkeyHex: Buffer.from(await sender.getPublicKey()).toString("hex"),
    }).ok, "a different hash must not authenticate against the same signature").toBe(false);
  });
});
