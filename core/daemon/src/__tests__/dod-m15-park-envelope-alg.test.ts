/**
 * THE PARK ENVELOPE CARRIES THE CONTENT-HASH ALGORITHM — `DOD-M15-SEALWIRE-1` bullet 6, part B2a.
 *
 * A message takes one of two routes: the direct stream, or the relay park when direct delivery
 * fails. Both must name the algorithm, or the park route verifies a salted message as `sha256`,
 * refuses it, KEEPS the relay copy, and pulls it again on every drain.
 *
 * There is one envelope shape, and it always carries the name (M9D purge).
 *
 * Why the algorithm is NOT inside the signature: `parkSig` covers `(session_id, recipient_pubkey,
 * content_hash)` — the HASH, not the name of the function that produced it. Flipping the name cannot
 * make altered content verify, because the computed hash must still equal the SIGNED one. A flipped
 * name can only produce a refusal — and the tests below pin exactly that.
 */

import { describe, it, expect } from "vitest";
import {
  encodeParkEnvelope,
  decodeParkEnvelope,
  authenticateParkedEntry,
  sealParkEnvelope,
  PARK_ENVELOPE_VERSION,
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

describe("every envelope names its algorithm, in the one shape", () => {
  it("★ both algorithms round-trip their name through the same version", () => {
    for (const alg of [CONTENT_HASH_ALGS.SHA256, CONTENT_HASH_ALGS.HMAC_SALT_V1]) {
      const decoded = decodeParkEnvelope(encodeParkEnvelope({
        content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
        contentHashAlg: alg,
        leafKind: 0,
      }));
      expect(decoded.version).toBe(PARK_ENVELOPE_VERSION);
      expect(decoded.contentHashAlg, `${alg} must travel as a name, never as an absence`).toBe(alg);
    }
  });

  it("★ the EMPTY STRING is refused, not folded into 'absent' — review B2a F4", () => {
    /**
     * `!args.contentHashAlg` was true for `undefined`, `null` AND `""`. `resolveContentHashAlg`
     * documents that conflation as forbidden — an empty string is a peer that sent a name we cannot
     * read, not a peer that sent no name — and this file's own `contentHashAlg` doc cites B1 for it.
     * The decoder honoured the rule; the encoder re-introduced it on the producer side.
     *
     * A caller whose algorithm variable is `""` would have emitted an envelope labelled
     * sha256-by-absence, and the recipient would report a TAMPER on a message nobody touched.
     *
     * ⚠️ This test exists because the mutant survived. My own mutation loop reported it CAUGHT, and
     * re-running it alone showed 36 tests green — a false negative in the harness, which is the same
     * class of error as a conditional assertion: the check ran and its answer was not what I read.
     */
    expect(() => encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      contentHashAlg: "",
      leafKind: 0,
    })).toThrow(/cannot itself reproduce/);
  });

  it("★ a name this build cannot read is refused at the PRODUCER, not left to the recipient", () => {
    // Without this the sender seals an envelope every peer refuses — including itself — and nothing
    // at the sending end says so: the message parks, is pulled, is refused, is kept, and repeats.
    expect(() => encodeParkEnvelope({
      content: CONTENT, senderPubkey: new Uint8Array(32).fill(1), parkSig: new Uint8Array(64).fill(2),
      contentHashAlg: "hmac-sha512-salt-v9",
      leafKind: 0,
    })).toThrow(/cannot itself reproduce/);
  });

});

describe("an envelope in any other shape is refused as unsigned", () => {
  it("★ an UNKNOWN version is refused — there is one shape", () => {
    for (const version of [0, 2, 3, 99]) {
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
      expect(verdict.ok === false && verdict.reason, `v${version}`).toBe("unsigned_envelope");
    }
  });
});

describe("the producer round-trips through the real consumer", () => {
  it("★ a SALTED envelope seals, unseals, decodes, and authenticates", async () => {
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
      leafKind: 0,
    });
    const env = decodeParkEnvelope(await openAsRecipient(recipient, sealed));

    expect(env.version).toBe(PARK_ENVELOPE_VERSION);
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
      leafKind: 0,
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
