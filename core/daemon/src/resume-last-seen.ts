/**
 * Where a resumed session's acknowledgement starts — from the durable record, not from nothing.
 *
 * The relay client keeps "the last position I saw from you" in memory. A session interrupted after
 * messages (Ctrl-C, a restart) came back at position 0, so every close claimed "I have seen nothing
 * from you". The relay refuses that as stale, because the other side's messages are filed after 0,
 * and the re-sign waits for a new message that never comes: the session could never seal (live,
 * 2026-09-14).
 *
 * The seal leaf store holds every leaf the other side authored, at its position, with the
 * Structure 1 they signed. The highest one is exactly where the live path would have advanced to,
 * and its content hash is read from their signed bytes, so the relay's content check accepts it.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { SessionSealLeafStore } from "./session-seal-leaf-store.js";

export function lastSeenFromRecord(
  store: SessionSealLeafStore,
  ownPubkey: Uint8Array,
  sessionIdHex: string,
): { seq: number; hash: Uint8Array } | undefined {
  const own = Buffer.from(ownPubkey);
  let best: { seq: number; hash: Uint8Array } | undefined;
  for (const leaf of store.getCarry(own.toString("hex"), sessionIdHex)) {
    const s1 = decodeStructure1(leaf.structure1Cbor);
    if (!s1.ok || Buffer.from(s1.fields.senderPubkey).equals(own)) continue;
    if (!best || leaf.sequenceNumber > best.seq) best = { seq: leaf.sequenceNumber, hash: s1.fields.contentHash };
  }
  return best;
}
