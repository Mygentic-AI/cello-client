/**
 * What a channel's publisher and subscribers SIGN when they ask a relay to do something (M16).
 *
 * These are the to-be-signed byte strings for the channel frames that carry a signature of their
 * own, rather than riding inside a signed post: prune, reader counts, the fetch key, and a
 * non-public fetch.
 *
 * ⚠️ **THIS IS THE ONE DEFINITION, AND BOTH SIDES IMPORT IT.** Order 017 defined these inside the
 * relay package, where the client could not reach them; a client that re-derived the construction
 * from the relay's source would be one edit away from signing a preimage the relay no longer builds,
 * and the symptom of that drift is `signature_invalid` on every prune with nothing to say why.
 *
 * ⚠️ **THE CONSTRUCTION IS FIXED.** Domain string, then the channel's public key, then each numeric
 * part as its DECIMAL TEXT, then the time in milliseconds as decimal text — all SHA-256. Numbers are
 * text rather than fixed-width integers so the preimage is unambiguous to read in a log; changing
 * any of it invalidates every signature in flight, so it is versioned in the domain string instead.
 */
import { createHash } from "node:crypto";

export const CHANNEL_FETCH_AUTH_DOMAIN = "CELLO-CHANNEL-FETCH-AUTH-v1";
export const CHANNEL_PRUNE_DOMAIN = "CELLO-CHANNEL-PRUNE-v1";
export const CHANNEL_READER_COUNTS_DOMAIN = "CELLO-CHANNEL-READER-COUNTS-v1";
export const CHANNEL_FETCH_KEY_DOMAIN = "CELLO-CHANNEL-FETCH-KEY-v1";

function domainTbs(domain: string, channelPubkey: Uint8Array, parts: number[], timeMs: number): Uint8Array {
  const h = createHash("sha256").update(domain, "utf8").update(Buffer.from(channelPubkey));
  for (const n of parts) h.update(Buffer.from(String(n), "utf8"));
  h.update(Buffer.from(String(timeMs), "utf8"));
  return new Uint8Array(h.digest());
}

/** What a subscriber signs with the channel's fetch key to read a non-public channel. */
export function buildChannelFetchAuthTbs(channelPubkey: Uint8Array, sinceSeq: number, timeMs: number): Uint8Array {
  return domainTbs(CHANNEL_FETCH_AUTH_DOMAIN, channelPubkey, [sinceSeq], timeMs);
}

/** What the publisher signs with the CHANNEL key to prune its own queue. */
export function buildChannelPruneTbs(channelPubkey: Uint8Array, throughSeq: number, timeMs: number): Uint8Array {
  return domainTbs(CHANNEL_PRUNE_DOMAIN, channelPubkey, [throughSeq], timeMs);
}

/** What the publisher signs with the CHANNEL key to read its own reader counts. */
export function buildChannelReaderCountsTbs(
  channelPubkey: Uint8Array, fromSeq: number, toSeq: number, timeMs: number,
): Uint8Array {
  return domainTbs(CHANNEL_READER_COUNTS_DOMAIN, channelPubkey, [fromSeq, toSeq], timeMs);
}

/**
 * What the publisher signs with the CHANNEL key to set or rotate the fetch key.
 *
 * ⚠️ It exists because the post's signature does NOT cover the fetch key: the key rides on the
 * deposit frame, outside the signed post. Without a signature of its own, anyone who could read one
 * post could replay its exact bytes within the clock window, attach their own key, and take the
 * channel over — every real subscriber gets `not_a_member` and the attacker signs the fetches.
 */
export function buildChannelFetchKeyTbs(channelPubkey: Uint8Array, fetchPubkey: Uint8Array, timeMs: number): Uint8Array {
  const h = createHash("sha256")
    .update(CHANNEL_FETCH_KEY_DOMAIN, "utf8")
    .update(Buffer.from(channelPubkey))
    .update(Buffer.from(fetchPubkey))
    .update(Buffer.from(String(timeMs), "utf8"));
  return new Uint8Array(h.digest());
}
