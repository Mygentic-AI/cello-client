/**
 * THE content hash every session content frame carries on the wire.
 *
 * `sha256(0x00 || content)`. The `0x00` is a domain-separation prefix, and it is NOT the leaf kind:
 * the receiver recomputes with `0x00` for every frame regardless of what the content turns out to
 * be (`session-node-manager.ts` cross-check), and the leaf KIND — `msg`, `doc`, `ctrl` — is decided
 * afterwards, when the leaf is appended. Confusing the two is the mistake this module exists to
 * stop, because it produces a hash that is individually plausible and rejected by every peer.
 *
 * ── WHY IT IS A MODULE ────────────────────────────────────────────────────────────────────────
 *
 * The expression was written out at five call sites. The two DOCUMENT senders — added last — wrote
 * `sha256(content)` without the prefix, and the failure is the least debuggable shape there is:
 * the send succeeds, `parked: false`, the sender's log says the frame left, and the receiver
 * discards it at the authenticity check with `content_hash_mismatch` before the document layer is
 * ever consulted. The receiving side logs nothing about documents at all, so the evidence points at
 * classification, at the router, at the gateway — everywhere except the sender's hash.
 *
 * No unit test could see it: both sides of every in-process test compute the hash with the same
 * function, so they agree with each other whether or not either agrees with the wire. It took two
 * real daemons.
 */

import { createHash } from "node:crypto";
import { saltedContentHash } from "@cello-protocol/crypto";

/**
 * ─── THE ALGORITHM TRAVELS WITH THE HASH — `DOD-M15-SEALWIRE-1` part B1 ───────────────────────
 *
 * A salted content hash and an unsalted one are both 32 bytes in the same wire field. Nothing in
 * the bytes distinguishes them, so a receiver handed one and told nothing has no way to know which
 * it is holding — and gets `content_hash_mismatch` on every frame, which is the exact
 * silent-discard failure this module's header says cost two real daemons.
 *
 * Hence a NAME on the wire, and three cases that must stay apart (Decisions Carried #15):
 *
 *   ABSENT            → `sha256`. A peer that predates the field. We know what it computed.
 *   NAMED and KNOWN   → verify under that name.
 *   NAMED and UNKNOWN → **refuse.** Not a legacy peer — an unreadable one. There is no correct hash
 *                       to compare against, and falling back to `sha256` would compare two
 *                       unrelated values and report a TAMPER for a version skew.
 *
 * ⚠️ RECEIVER FIRST. Part B1 teaches the receiver to read the name; **no sender salts yet.** Every
 * peer must be able to understand a salted frame before any peer can send one. Reversed, the first
 * upgraded sender breaks every conversation it has with a peer that has not upgraded.
 */
export const CONTENT_HASH_ALGS = {
  /** `sha256(0x00 ‖ content)` — what every build before the salt computes, and the absent-field default. */
  SHA256: "sha256",
  /** `hmac-sha256(salt, 0x00 ‖ content)` — Decision #9. HMAC, never `sha256(salt ‖ content)`. */
  HMAC_SALT_V1: "hmac-sha256-salt-v1",
} as const;

export type ContentHashAlg = (typeof CONTENT_HASH_ALGS)[keyof typeof CONTENT_HASH_ALGS];

const KNOWN_ALGS = new Set<string>(Object.values(CONTENT_HASH_ALGS));

/** Whether this daemon can reproduce a hash under the given name. */
export function isKnownContentHashAlg(alg: string): alg is ContentHashAlg {
  return KNOWN_ALGS.has(alg);
}

/**
 * What a frame says it used, or a refusal naming the value.
 *
 * ABSENT is deliberately `undefined`/`null` ONLY — not "falsy". An empty string is a peer that sent
 * a name we cannot read, not a peer that sent no name, and folding the two together would verify a
 * malformed frame as legacy instead of telling its sender the frame is unreadable.
 */
export function resolveContentHashAlg(
  raw: string | null | undefined,
): { ok: true; alg: ContentHashAlg } | { ok: false; value: string } {
  if (raw === undefined || raw === null) return { ok: true, alg: CONTENT_HASH_ALGS.SHA256 };
  if (typeof raw !== "string" || !isKnownContentHashAlg(raw)) {
    return { ok: false, value: typeof raw === "string" ? raw : `(${typeof raw})` };
  }
  return { ok: true, alg: raw };
}

/**
 * The content hash under a named algorithm.
 *
 * THROWS rather than substituting, in both failure cases, and that is the point of the function. A
 * 32-byte value returned for an unknown algorithm — or an unsalted one returned because the salt was
 * missing — flows straight into the cross-check and surfaces as `content_hash_mismatch`: a TAMPER
 * REPORT for what is really a version skew or a missing salt. The caller must handle those as what
 * they are.
 */
export function contentHashFor(
  content: Uint8Array,
  opts: { alg: string; salt: Uint8Array | null },
): Uint8Array {
  if (opts.alg === CONTENT_HASH_ALGS.SHA256) return wireContentHash(content);
  if (opts.alg === CONTENT_HASH_ALGS.HMAC_SALT_V1) {
    if (!opts.salt) {
      throw new Error(
        `CONTENT HASH: ${CONTENT_HASH_ALGS.HMAC_SALT_V1} was requested with no session salt. Refusing rather ` +
        "than computing the unsalted form — that would put bytes on the wire under a label they do not match, " +
        "and the peer would report a tamper on a message nobody touched.",
      );
    }
    return saltedContentHash(opts.salt, content);
  }
  throw new Error(
    `CONTENT HASH: unknown algorithm "${opts.alg}". This daemon cannot reproduce it, so there is no value to ` +
    "compare against. Refusing rather than falling back to sha256, which would compare two unrelated hashes " +
    "and report a tamper for what is a version difference.",
  );
}

/**
 * Domain-separation prefix. Fixed at `0x00` for ALL content frames — see the header on why this is
 * not the leaf kind.
 */
const CONTENT_HASH_DOMAIN = new Uint8Array([0x00]);

/** The hash a sender puts on the wire and the receiver recomputes to authenticate it. */
export function wireContentHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(CONTENT_HASH_DOMAIN).update(content).digest());
}

/** The same value, hex — what the Merkle leaf records. */
export function wireContentHashHex(content: Uint8Array): string {
  return Buffer.from(wireContentHash(content)).toString("hex");
}
