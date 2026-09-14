/**
 * Where a resumed session's acknowledgement starts — from the durable record, not from nothing.
 *
 * The relay client keeps "the last position I saw from you" in memory. A session interrupted after
 * messages (Ctrl-C, a restart) came back at position 0, so every close claimed "I have seen nothing
 * from you". The relay refuses that as stale, because the other side's messages are filed after 0,
 * and the re-sign waits for a new message that never comes: the session could never seal (live,
 * 2026-09-14).
 *
 * Two durable sources, because the live path advances from two places:
 *   - the seal leaf store: every leaf the other side authored that reached this side via the relay,
 *     with the Structure 1 they signed;
 *   - the transcript: every message placed from the direct path, which never writes the store.
 * The highest of the two is where the live path would have been. Both hashes are the leaf's content
 * hash, which is what the relay's content check compares against.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { SessionSealLeafStore } from "./session-seal-leaf-store.js";
import type { Logger } from "./types.js";

export function lastSeenFromRecord(
  store: SessionSealLeafStore,
  logger: Logger,
  ownPubkey: Uint8Array,
  sessionIdHex: string,
): { seq: number; hash: Uint8Array } | undefined {
  const own = Buffer.from(ownPubkey);
  let best = store.receivedFrontier(own.toString("hex"), sessionIdHex);
  for (const leaf of store.getCarry(own.toString("hex"), sessionIdHex)) {
    const s1 = decodeStructure1(leaf.structure1Cbor);
    if (!s1.ok) {
      logger.warn("session.relay.last_seen.resume_leaf_unreadable", {
        sessionId: sessionIdHex, sequenceNumber: leaf.sequenceNumber, reason: s1.reason,
        impact: "this stored leaf is skipped when resuming, so a close may claim an earlier position and be refused as stale",
      });
      continue;
    }
    if (Buffer.from(s1.fields.senderPubkey).equals(own)) continue;
    if (!best || leaf.sequenceNumber > best.seq) best = { seq: leaf.sequenceNumber, hash: s1.fields.contentHash };
  }
  return best;
}
