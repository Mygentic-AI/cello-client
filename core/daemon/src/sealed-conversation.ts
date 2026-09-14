/**
 * The seal answer's conversation — every leaf the seal covers, in the relay's numbering.
 *
 * The relay countersigns every leaf in a session, both sides' messages and both closes, and this
 * daemon keeps that countersignature for each one. So the relay's receipts are the spine: one row
 * per numbered position. The transcript supplies the text, and the two acknowledgement tables
 * supply the delivery signature for each message, whichever side sent it.
 *
 * Matching a receipt to a message is done IN ORDER, never by hash alone: both sides can send
 * identical bytes ("ok"), and a hash lookup would hand one side's message to the other.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { SessionTree } from "./session-tree.js";

/** Relay leaf kind byte for a control (close) leaf. */
const LEAF_KIND_CTRL = 2;

export interface SealedLeaf {
  /** The relay's sequence number (from 1). Null only for a message the relay never numbered. */
  seq: number | null;
  kind: "message" | "close";
  from: string | null;
  from_pubkey: string | null;
  /** Messages only. */
  text?: string;
  content_hash: string;
  /** When the relay numbered it (ISO 8601), the one independent time in the record. */
  at: string | null;
  /** The relay's signature over this position. */
  relay_ack: string | null;
  /** Messages only: the recipient's signature that their machine received it. */
  delivery_ack?: string | null;
}

export interface SealedConversation {
  leaves: SealedLeaf[];
  closed_by: string[];
  root_matches_my_transcript: boolean;
}

export function readSealedConversation(
  db: DaemonDatabase,
  logger: Logger,
  a: {
    agentId: string;
    agentPubkey: string;
    sessionId: string;
    sealedRoot: string;
    /** Transcript text by local sequence (already redacted for quarantined messages). */
    texts: ReadonlyMap<number, string>;
    nameFor: (pubkeyHex: string) => string;
  },
): SealedConversation {
  const messages = db
    .prepare(
      `SELECT l.leaf_index AS idx, l.leaf_hash_hex AS hash, t.direction AS direction
         FROM session_tree_leaves l
         JOIN transcript t
           ON t.agent_id = l.agent_id AND t.session_id = l.session_id AND t.sequence = l.leaf_index
        WHERE l.agent_id = ? AND l.session_id = ?
        ORDER BY l.leaf_index ASC`,
    )
    .all(a.agentId, a.sessionId) as Array<{ idx: number; hash: string; direction: string }>;

  const relayTablePresent =
    db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'relay_ack_receipts'").get() !== undefined;
  const receipts = relayTablePresent
    ? (db
        .prepare(
          `SELECT sequence_number AS seq, hash_hex AS hash, relay_timestamp AS ts, signature_hex AS sig,
                  structure1_cbor AS s1, leaf_kind AS kind
             FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ?
            ORDER BY sequence_number ASC`,
        )
        .all(a.agentPubkey, a.sessionId) as Array<{ seq: number; hash: string; ts: number; sig: string; s1: Uint8Array | null; kind: number | null }>)
    : [];

  const acksReceived = ackMap(db, "delivery_acks", a.agentId, a.sessionId);
  const acksGiven = ackMap(db, "delivery_acks_given", a.agentId, a.sessionId);

  const authorOf = (s1: Uint8Array | null): string | null => {
    if (!s1) return null;
    const d = decodeStructure1(s1 instanceof Uint8Array ? s1 : new Uint8Array(s1));
    return d.ok ? Buffer.from(d.fields.senderPubkey).toString("hex") : null;
  };
  const messageLeaf = (
    m: { idx: number; hash: string; direction: string },
    seq: number | null, at: number | null, relaySig: string | null, s1Author: string | null,
  ): SealedLeaf => {
    const received = m.direction !== "sent";
    const pubkey = s1Author ?? (received ? null : a.agentPubkey);
    return {
      seq,
      kind: "message",
      from: pubkey ? a.nameFor(pubkey) : null,
      from_pubkey: pubkey,
      text: a.texts.get(m.idx) ?? "",
      content_hash: m.hash,
      at: at === null ? null : new Date(at).toISOString(),
      relay_ack: relaySig,
      delivery_ack: (received ? acksGiven : acksReceived).get(m.hash) ?? null,
    };
  };

  const leaves: SealedLeaf[] = [];
  const unnumbered: SealedLeaf[] = [];
  let next = 0;
  for (const r of receipts) {
    const author = authorOf(r.s1);
    let matched = -1;
    if (r.kind !== LEAF_KIND_CTRL) {
      for (let i = next; i < messages.length; i++) {
        if (messages[i]!.hash === r.hash) { matched = i; break; }
      }
    }
    if (matched >= 0) {
      // Any message passed over here was never numbered by the relay.
      for (let i = next; i < matched; i++) unnumbered.push(messageLeaf(messages[i]!, null, null, null, null));
      leaves.push(messageLeaf(messages[matched]!, r.seq, r.ts, r.sig, author));
      next = matched + 1;
    } else {
      leaves.push({
        seq: r.seq,
        kind: "close",
        from: author ? a.nameFor(author) : null,
        from_pubkey: author,
        content_hash: r.hash,
        at: new Date(r.ts).toISOString(),
        relay_ack: r.sig,
      });
    }
  }
  for (let i = next; i < messages.length; i++) unnumbered.push(messageLeaf(messages[i]!, null, null, null, null));

  const tree = SessionTree.empty();
  for (const r of receipts) tree.appendLeafHash("msg", r.hash);
  const contiguous = receipts.every((r, i) => r.seq === i + 1);
  const rootMatches = unnumbered.length === 0 && contiguous && tree.rootHex() === a.sealedRoot;
  if (!rootMatches) {
    logger.warn("session.sealed_conversation.root_mismatch", {
      sessionId: a.sessionId,
      unnumberedMessages: unnumbered.length,
      contiguous,
      impact: "the seal answer reports that the sealed root does not match this side's record of the conversation",
    });
  }

  return {
    leaves: [...leaves, ...unnumbered],
    closed_by: leaves.filter((l) => l.kind === "close").map((l) => l.from ?? "unknown"),
    root_matches_my_transcript: rootMatches,
  };
}

function ackMap(db: DaemonDatabase, table: "delivery_acks" | "delivery_acks_given", agentId: string, sessionId: string): Map<string, string> {
  const present = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table) !== undefined;
  const out = new Map<string, string>();
  if (!present) return out;
  for (const r of db
    .prepare(`SELECT content_hash_hex AS hash, signature AS sig FROM ${table} WHERE agent_id = ? AND session_id = ?`)
    .all(agentId, sessionId) as Array<{ hash: string; sig: Uint8Array }>) {
    out.set(r.hash, Buffer.from(r.sig).toString("hex"));
  }
  return out;
}
