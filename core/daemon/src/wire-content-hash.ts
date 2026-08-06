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
