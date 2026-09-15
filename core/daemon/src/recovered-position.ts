/**
 * Keep a mailbox-recovered message's verified position as the counterparty's seal leaf.
 *
 * Live 2026-09-15: a laptop slept while the counterparty sent two messages. The relay wrote both
 * `leaf_deliver` frames onto the dead connection — it logged them delivered and queued nothing — so
 * the only copy that reached this side came from the mailbox. Its ordering record was verified and
 * then held only in memory. With no seal-leaf row, the seal answer could not place either message
 * and told the operator their copy did not match a seal that was correct.
 *
 * Stored exactly as a `leaf_deliver` for a counterparty leaf is stored: the signed Structure 1, the
 * relay's Structure 2, the position, and NO relay acknowledgement — the mailbox copy carries none.
 * Called only for a record `recordFrameOrdering` has already verified; the store is INSERT OR
 * IGNORE, so a later `leaf_deliver` for the same position changes nothing.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { SessionSealLeafStore } from "./session-seal-leaf-store.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

export function storeRecoveredSealLeaf(args: {
  store: SessionSealLeafStore;
  logger: Logger;
  agentPubkeyHex: string;
  sessionId: string;
  /** 0-based canonical position from the verified record; the store keys the relay's 1-based one. */
  canonicalSeq: number;
  leafKind: number;
  structure1Cbor: Uint8Array;
  structure2Cbor: Uint8Array;
}): void {
  const s1 = decodeStructure1(args.structure1Cbor);
  if (!s1.ok) return; // unreachable after verification, which decoded the same bytes
  try {
    args.store.store(args.agentPubkeyHex, args.sessionId, {
      sequenceNumber: args.canonicalSeq + 1,
      leafKind: args.leafKind,
      senderPubkeyHex: Buffer.from(s1.fields.senderPubkey).toString("hex"),
      structure2Cbor: args.structure2Cbor,
      structure1Cbor: args.structure1Cbor,
    }, Date.now());
  } catch (err: unknown) {
    args.logger.error("content.recover.seal_leaf.store_failed", {
      sessionId: args.sessionId,
      sequenceNumber: args.canonicalSeq + 1,
      error: extractErrorMessage(err),
      impact: "this recovered message is in the transcript, but the seal answer will list it unnumbered",
    });
  }
}
