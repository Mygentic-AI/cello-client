/**
 * The seal answer's conversation — every leaf the seal covers, in the relay's numbering.
 *
 * Three stores, each supplying what only it holds:
 *   - `relay_ack_receipts`: the relay's countersignature for every numbered position, both sides'
 *     leaves and both closes. This is the spine: one row per position.
 *   - `session_seal_leaves`: the signed Structure 1 and leaf kind at each position — the AUTHOR.
 *     Receipts never carry these, so the author must come from here.
 *   - the transcript and the two acknowledgement tables: text, and the delivery signature for each
 *     message, whichever side sent it.
 *
 * Matching a position to a message is done IN ORDER, never by hash alone: both sides can send
 * identical bytes ("ok"), and a hash lookup would hand one side's message to the other.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { SessionTree } from "./session-tree.js";

/** Relay leaf kind bytes other than a message (session-relay-client.ts), named for an operator. */
const NON_MESSAGE_KINDS: Record<number, SealedLeaf["kind"]> = { 2: "close", 4: "document", 5: "refusal" };

export interface SealedLeaf {
  /** The relay's sequence number (from 1). Null only for a message the relay never numbered. */
  seq: number | null;
  /** `unknown` only when this side holds no signed record of the leaf's kind. */
  kind: "message" | "close" | "document" | "refusal" | "unknown";
  from: string | null;
  from_pubkey: string | null;
  /** Messages only. Null when this side holds no text for it. */
  text?: string | null;
  content_hash: string;
  /** When the relay numbered it (ISO 8601), the one independent time in the record. */
  at: string | null;
  /** The relay's signature over this position. */
  relay_ack: string | null;
  /** Messages only: the recipient's signature that their machine received it. */
  delivery_ack?: string | null;
}

export type RootMismatchReason = "unnumbered_messages" | "sequence_gap" | "no_relay_record" | "root_differs";

export interface SealedConversation {
  leaves: SealedLeaf[];
  closed_by: string[];
  root_matches_my_transcript: boolean;
  root_mismatch_reason?: RootMismatchReason;
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

  // The two relay stores are created by their own classes the first time a session goes through a
  // relay, not by the session schema, so on a daemon that has never used one they do not exist yet.
  // That is the same fact as holding no relay record, not a degraded read.
  const receipts = tableExists(db, "relay_ack_receipts")
    ? (db
        .prepare(
          `SELECT sequence_number AS seq, hash_hex AS hash, relay_timestamp AS ts, signature_hex AS sig
             FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ?
            ORDER BY sequence_number ASC`,
        )
        .all(a.agentPubkey, a.sessionId) as Array<{ seq: number; hash: string; ts: number; sig: string }>)
    : [];
  const signed = new Map<number, { author: string | null; kind: number }>();
  if (tableExists(db, "session_seal_leaves")) {
    for (const r of db
      .prepare(
        `SELECT sequence_number AS seq, leaf_kind AS kind, structure1_cbor AS s1
           FROM session_seal_leaves WHERE agent_pubkey = ? AND session_id = ?`,
      )
      .all(a.agentPubkey, a.sessionId) as Array<{ seq: number; kind: number; s1: Uint8Array }>) {
      // The author is read from the bytes they signed, not from the stored sender column.
      const d = decodeStructure1(r.s1 instanceof Uint8Array ? r.s1 : new Uint8Array(r.s1));
      signed.set(r.seq, { author: d.ok ? Buffer.from(d.fields.senderPubkey).toString("hex") : null, kind: r.kind });
    }
  }

  const acksReceived = ackMap(db, "delivery_acks", a.agentId, a.sessionId);
  const acksGiven = ackMap(db, "delivery_acks_given", a.agentId, a.sessionId);

  const messageLeaf = (
    m: { idx: number; hash: string; direction: string },
    r: { seq: number; ts: number; sig: string } | null,
  ): SealedLeaf => {
    const received = m.direction !== "sent";
    const pubkey = (r ? signed.get(r.seq)?.author : null) ?? (received ? null : a.agentPubkey);
    return {
      seq: r?.seq ?? null,
      kind: "message",
      from: pubkey ? a.nameFor(pubkey) : null,
      from_pubkey: pubkey,
      text: a.texts.get(m.idx) ?? null,
      content_hash: m.hash,
      at: r ? new Date(r.ts).toISOString() : null,
      relay_ack: r?.sig ?? null,
      delivery_ack: (received ? acksGiven : acksReceived).get(m.hash) ?? null,
    };
  };

  const leaves: SealedLeaf[] = [];
  const unnumbered: SealedLeaf[] = [];
  let next = 0;
  for (const r of receipts) {
    const s = signed.get(r.seq);
    let matched = -1;
    if (s === undefined || NON_MESSAGE_KINDS[s.kind] === undefined) {
      for (let i = next; i < messages.length; i++) {
        if (messages[i]!.hash === r.hash) { matched = i; break; }
      }
    }
    if (matched >= 0) {
      // Any message passed over here was never numbered by the relay.
      for (let i = next; i < matched; i++) unnumbered.push(messageLeaf(messages[i]!, null));
      leaves.push(messageLeaf(messages[matched]!, r));
      next = matched + 1;
    } else {
      const author = s?.author ?? null;
      leaves.push({
        seq: r.seq,
        kind: s ? (NON_MESSAGE_KINDS[s.kind] ?? "unknown") : "unknown",
        from: author ? a.nameFor(author) : null,
        from_pubkey: author,
        content_hash: r.hash,
        at: new Date(r.ts).toISOString(),
        relay_ack: r.sig,
      });
    }
  }
  for (let i = next; i < messages.length; i++) unnumbered.push(messageLeaf(messages[i]!, null));

  const tree = SessionTree.empty();
  for (const r of receipts) tree.appendLeafHash("msg", r.hash);
  const computedRoot = tree.rootHex();
  const reason: RootMismatchReason | undefined =
    receipts.length === 0 ? "no_relay_record"
    : unnumbered.length > 0 ? "unnumbered_messages"
    : !receipts.every((r, i) => r.seq === i + 1) ? "sequence_gap"
    : computedRoot !== a.sealedRoot ? "root_differs"
    : undefined;
  if (reason) {
    logger.warn("session.sealed_conversation.root_mismatch", {
      sessionId: a.sessionId,
      reason,
      receiptCount: receipts.length,
      unnumberedMessages: unnumbered.length,
      computedRoot,
      sealedRoot: a.sealedRoot,
      impact: "the seal answer reports that the sealed root does not match this side's record of the conversation",
    });
  }

  return {
    leaves: [...leaves, ...unnumbered],
    closed_by: leaves.filter((l) => l.kind === "close").map((l) => l.from ?? "unknown"),
    root_matches_my_transcript: reason === undefined,
    ...(reason ? { root_mismatch_reason: reason } : {}),
  };
}

function tableExists(db: DaemonDatabase, name: string): boolean {
  return db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined;
}

/** Both acknowledgement tables are created by the session schema, so a missing one throws. */
function ackMap(db: DaemonDatabase, table: "delivery_acks" | "delivery_acks_given", agentId: string, sessionId: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const r of db
    .prepare(`SELECT content_hash_hex AS hash, signature AS sig FROM ${table} WHERE agent_id = ? AND session_id = ?`)
    .all(agentId, sessionId) as Array<{ hash: string; sig: Uint8Array }>) {
    out.set(r.hash, Buffer.from(r.sig).toString("hex"));
  }
  return out;
}
