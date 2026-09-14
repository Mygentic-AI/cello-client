/**
 * Is the other side replying to an old message?
 *
 * Every message signs the last position its author had seen. Reading the other side's latest
 * replies against this side's newest message tells the operator, during the conversation, that they
 * are answering something older. One crossed reply is ordinary back-and-forth; two in a row is the
 * signal. Reads the seal leaf store, which holds both sides' signed Structure 1.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";

const LEAF_KIND_MSG = 0;
const LAG_THRESHOLD = 2;

export interface ReplyLag {
  /** How many of their latest replies in a row were written before they saw your message. */
  replies: number;
  /** The last position those replies say they had seen. */
  their_last_seen_seq: number;
  /** Your newest message they had not seen. */
  your_unseen_seq: number;
}

export function replyLag(db: DaemonDatabase, agentPubkeyHex: string, sessionIdHex: string): ReplyLag | undefined {
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_seal_leaves'").get() === undefined) return undefined;
  const rows = db
    .prepare(
      `SELECT sequence_number AS seq, structure1_cbor AS s1 FROM session_seal_leaves
        WHERE agent_pubkey = ? AND session_id = ? AND leaf_kind = ? ORDER BY sequence_number ASC`,
    )
    .all(agentPubkeyHex, sessionIdHex, LEAF_KIND_MSG) as Array<{ seq: number; s1: Uint8Array }>;
  const mine: number[] = [];
  const theirs: Array<{ seq: number; lastSeen: number }> = [];
  for (const r of rows) {
    const d = decodeStructure1(r.s1 instanceof Uint8Array ? r.s1 : new Uint8Array(r.s1));
    if (!d.ok) continue;
    if (Buffer.from(d.fields.senderPubkey).toString("hex") === agentPubkeyHex) mine.push(r.seq);
    else theirs.push({ seq: r.seq, lastSeen: d.fields.lastSeenSeq });
  }
  if (mine.length === 0 || theirs.length < LAG_THRESHOLD) return undefined;
  let replies = 0;
  let unseen = 0;
  for (let i = theirs.length - 1; i >= 0; i--) {
    const t = theirs[i]!;
    const newestMineBefore = mine.filter((m) => m < t.seq).at(-1);
    if (newestMineBefore === undefined || t.lastSeen >= newestMineBefore) break;
    replies += 1;
    unseen = Math.max(unseen, newestMineBefore);
  }
  if (replies < LAG_THRESHOLD) return undefined;
  return { replies, their_last_seen_seq: theirs[theirs.length - 1]!.lastSeen, your_unseen_seq: unseen };
}
