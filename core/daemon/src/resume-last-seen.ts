/**
 * Where a resumed session's acknowledgement starts — from the durable record, not from nothing.
 *
 * The relay client keeps "the last position I saw from you" in memory. A session interrupted after
 * messages (Ctrl-C, a restart) came back at position 0, so every close claimed "I have seen nothing
 * from you". The relay refuses that as stale, because the other side's messages are filed after 0,
 * and the re-sign waits for a new message that never comes: the session could never seal (live,
 * 2026-09-14).
 *
 * Two durable sources, both holding RELAY positions — never a position guessed from the local leaf
 * index, which can drift one ahead of the relay:
 *   - `session_last_ack`: what the live path acknowledged, written at the moment it did, for every
 *     route a message can arrive by (relay, direct, recovered park, screened-out);
 *   - the seal leaf store: every leaf the other side authored that the relay delivered, with the
 *     Structure 1 they signed.
 * The higher of the two is where the live path would have been.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { SessionSealLeafStore } from "./session-seal-leaf-store.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Record an acknowledgement the live path just made. Forward-only: an earlier position is ignored. */
export function recordLastAck(
  db: DaemonDatabase,
  a: { agentId: string; sessionId: string; seq: number; hash: Uint8Array },
): void {
  db.prepare(
    `INSERT INTO session_last_ack (agent_id, session_id, relay_seq, hash_hex) VALUES (?, ?, ?, ?)
     ON CONFLICT (agent_id, session_id) DO UPDATE SET relay_seq = excluded.relay_seq, hash_hex = excluded.hash_hex
     WHERE excluded.relay_seq > session_last_ack.relay_seq`,
  ).run(a.agentId, a.sessionId, a.seq, Buffer.from(a.hash).toString("hex"));
}

export function lastSeenFromRecord(
  store: SessionSealLeafStore,
  logger: Logger,
  ownPubkey: Uint8Array,
  sessionIdHex: string,
): { seq: number; hash: Uint8Array } | undefined {
  const own = Buffer.from(ownPubkey);
  let best = store.recordedAcknowledgement(own.toString("hex"), sessionIdHex);
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
