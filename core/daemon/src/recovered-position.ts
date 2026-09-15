/**
 * Remember where a mailbox-recovered message sits, so the seal answer can place it.
 *
 * Live 2026-09-15: a laptop slept while the counterparty sent two messages. The relay wrote both
 * `leaf_deliver` frames onto the dead connection — it logged them delivered and queued nothing — so
 * the only copy that reached this side came from the mailbox. Its position was verified against the
 * sender's signature and then held only in memory, so the seal answer listed both messages
 * unnumbered and told the operator their copy did not match a seal that was correct.
 *
 * ⚠️ NOT A SEAL LEAF. The position comes from the sender's Structure 2, which the relay did not sign
 * on this route, so writing it into `session_seal_leaves` would let a sender claim a position that
 * then blocks the real `leaf_deliver` (INSERT OR IGNORE) and rides into the seal carry. It goes in its
 * own table, which no seal path reads. The sealed root is what proves the claim: the answer counts
 * these positions only toward a root check, and a wrong one shows as a mismatch.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

export function storeRecoveredPosition(args: {
  db: DaemonDatabase | null;
  logger: Logger;
  agentId: string | null;
  sessionId: string;
  /** 0-based canonical position from the verified record; stored as the relay's 1-based one. */
  canonicalSeq: number;
  contentHash: Uint8Array;
  /** The author, from the Structure 1 whose signature the verification already checked. */
  structure1Cbor: Uint8Array;
}): void {
  const relaySeq = args.canonicalSeq + 1;
  if (!args.db || !args.agentId) {
    args.logger.error("content.recover.position.not_stored", {
      sessionId: args.sessionId, relaySeq, cause: !args.db ? "no_database" : "unknown_agent",
      impact: "this recovered message is in the transcript, but the seal answer will list it unnumbered",
    });
    return;
  }
  const hashHex = Buffer.from(args.contentHash).toString("hex");
  const s1 = decodeStructure1(args.structure1Cbor);
  if (!s1.ok) {
    args.logger.error("content.recover.position.not_stored", {
      sessionId: args.sessionId, relaySeq, cause: "structure1_undecodable",
      impact: "this recovered message is in the transcript, but the seal answer will list it unnumbered",
    });
    return;
  }
  const senderHex = Buffer.from(s1.fields.senderPubkey).toString("hex");
  try {
    const existing = args.db
      .prepare("SELECT hash_hex FROM session_recovered_positions WHERE agent_id = ? AND session_id = ? AND relay_seq = ?")
      .get(args.agentId, args.sessionId, relaySeq) as { hash_hex: string } | undefined;
    if (existing && existing.hash_hex !== hashHex) {
      args.logger.warn("content.recover.position.conflict", {
        sessionId: args.sessionId, relaySeq, kept: existing.hash_hex, refused: hashHex,
        impact: "two recovered messages claim the same position; the first is kept and the seal root will show which was right",
      });
      return;
    }
    args.db
      .prepare("INSERT OR IGNORE INTO session_recovered_positions (agent_id, session_id, relay_seq, hash_hex, sender_hex) VALUES (?, ?, ?, ?, ?)")
      .run(args.agentId, args.sessionId, relaySeq, hashHex, senderHex);
  } catch (err: unknown) {
    args.logger.error("content.recover.position.store_failed", {
      sessionId: args.sessionId, relaySeq, error: extractErrorMessage(err),
      impact: "this recovered message is in the transcript, but the seal answer will list it unnumbered",
    });
  }
}
