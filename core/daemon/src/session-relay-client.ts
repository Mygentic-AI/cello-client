/**
 * Daemon-side relay witness client (PER AGENT).
 *
 * In CELLO the relay is the ordering/witness authority (Structure 2): it never sees
 * plaintext (content is peer↔peer), only the SIGNED content-hash leaves. It assigns
 * the canonical `sequence_number` and forwards each witnessed leaf to the counterparty
 * (`leaf_deliver`). A `cello_send` whose hash the relay never witnessed has no canonical
 * sequence and is not a complete CELLO message — so the session submits the message leaf
 * hash here, in parallel with the direct content delivery.
 *
 * ONE stream per AGENT, not per session. The relay authenticates a stream by the agent's
 * K_local pubkey and keys its delivery/queue maps by that pubkey (relay-node
 * #handleRelayStream / #processHashSubmit), so a second stream for the same pubkey would
 * OVERWRITE the first's delivery stream and steal its queued `leaf_deliver`s. The protocol
 * is designed for one relay connection per agent identity multiplexing all that agent's
 * sessions — every wire frame carries `session_id`. So this client is shared across an
 * agent's sessions: submits are globally FIFO-serialized on the stream (a `hash_submit_ack`
 * carries NO session_id, so at most one submit may be outstanding at a time and acks match
 * the queue head in order), while inbound `leaf_deliver` (which DOES carry `session_id`) is
 * routed to the owning session's handler.
 *
 * The stream is (re)dialed from whatever live session node is current at submit time, so it
 * survives individual session teardown (the relay treats a same-pubkey reconnect as a
 * reconnect, re-auths, and re-drains).
 *
 * The server contract this must match: `packages/relay/src/relay-node.ts`.
 *
 * Crypto: Ed25519 RFC 8032. Relay auth domain: "CELLO-RELAY-AUTH-v1".
 */
import { createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import { evaluateRelayAck, type RelayReceiptStore } from "./relay-receipt-store.js";
import type { SessionSealLeafStore } from "./session-seal-leaf-store.js";


export const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
export const RELAY_AUTH_DOMAIN = "CELLO-RELAY-AUTH-v1";
/** Structure 1 leaf kind: 0x00 = message, 0x02 = control (matches the relay). */
export const LEAF_KIND_MSG = 0x00;
/** Control leaf (SEAL etc.) — two distinct-sender ctrl leaves trigger directory notarization. */
export const LEAF_KIND_CTRL = 0x02;
/** Document-operation leaf (DOD-DOC-LEAF-1): a CRDT update riding the session tree. */
export const LEAF_KIND_DOC = 0x04;
/** Rejection leaf (DOD-DOC-LEAF-1): references the rejected update envelope's hash. */
export const LEAF_KIND_REJECT = 0x05;

const RELAY_AUTH_TIMEOUT_MS = 5_000;
const HASH_SUBMIT_TIMEOUT_MS = 10_000;

/**
 * The Ed25519-signed payload that proves K_local ownership to the relay:
 * SHA-256("CELLO-RELAY-AUTH-v1" || nonce || pubkey). The relay verifies the
 * signature against exactly this hash (relay-node #handleRelayStream).
 */
export function buildRelayAuthPayload(nonce: Uint8Array, pubkey: Uint8Array): Uint8Array {
  const domain = Buffer.from(RELAY_AUTH_DOMAIN, "utf8");
  const authMsg = Buffer.concat([domain, nonce, pubkey]);
  return new Uint8Array(createHash("sha256").update(authMsg).digest());
}

/**
 * Canonical Structure 1 CBOR the sender signs and the relay re-verifies byte-for-byte:
 * [1, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, timestamp].
 * The relay decodes this (decodeStructure1) AND verifies Ed25519 over these EXACT bytes,
 * so the encoded bytes — not a re-encoding — are what gets signed and sent.
 */
export function encodeStructure1(
  contentHash: Uint8Array,
  senderPubkey: Uint8Array,
  sessionId: Uint8Array,
  lastSeenSeq: number,
  timestamp: number,
): Uint8Array {
  return encodeCbor([1, contentHash, senderPubkey, sessionId, lastSeenSeq, timestamp]) as Uint8Array;
}

export interface LeafDeliverFrame {
  sequence_number: number;
  leaf_kind: number;
  structure1_cbor: Uint8Array;
  structure2_cbor: Uint8Array;
  /**
   * True when the relay echoed back OUR OWN submitted leaf (sender_pubkey ===
   * our K_local), false when it is a genuine COUNTERPARTY leaf. The auto-acknowledge gate uses
   * this to never auto-co-sign in response to its own SEAL ctrl leaf (which would loop). An
   * explicit field — the consumer must not have to re-decode structure1_cbor to learn it.
   */
  authored_by_us: boolean;
}

/** Result of a single relay hash submission. */
export type SubmitResult =
  | {
      ok: true;
      sequence_number: number;
      // The signed ordering record for THIS leaf, so the sender can stamp it into the content frame.
      // structure1_cbor is the sender-signed bytes (built locally); structure2_cbor is the relay's
      // committed record (from hash_submit_ack). Both undefined against an OLD relay that does not
      // return structure2_cbor.
      structure1_cbor?: Uint8Array;
      structure2_cbor?: Uint8Array;
    }
  | { ok: false; reason: string };
type AckResolver = (r: SubmitResult) => void;

export interface AgentRelayClientOpts {
  relayPeerId: string;
  relayAddrs: string[];
  /** The agent's K_local signing key (relay auth + leaf signatures). */
  keyProvider: KeyProvider;
  /** The agent's K_local public key (32 bytes) — relay routes delivery by this. */
  senderPubkey: Uint8Array;
  logger: Logger;
  /**
   * Durable store for the relay's signed ordering-record receipts. When present, each
   * verified `hash_submit_ack` is recorded immutably (the client's evidence of the relay's sequence
   * attestation, carried to the directory at seal time). Optional — when absent, ACKs are not recorded.
   */
  receiptStore?: RelayReceiptStore;
  /**
   * The per-session leaf log a unilateral seal carries to the directory. When
   * present, every leaf this client sees — its OWN submits (with the relay receipt) and the COUNTERPARTY's
   * delivered leaves (no receipt) — is recorded so a later unilateral seal presents the full chain for the
   * directory's OFFLINE tree rebuild. Optional — when absent, no leaf log is kept.
   */
  sealLeafStore?: SessionSealLeafStore;
}

/**
 * The directory-signed relay assignment a client presents to its chosen relay (a
 * `client_record_assignment` frame). The relay
 * reconstructs the relay TBS from these fields and verifies `assignmentSignature` (the directory's
 * per-node relayDirSig) against any consortium directory pubkey. Field order/presence MUST match the
 * directory producer (directory-node.ts) and the relay verifier (relay-node.ts recordAssignment).
 */
export interface RelayAssignmentCarry {
  participantA: Uint8Array;            // 32-byte initiator pubkey
  participantB: Uint8Array;            // 32-byte counterparty pubkey
  sessionTimestamp: number;            // Unix ms
  initiatorSessionPeerId?: string;     // present for relay-mode sessions (covered by the sig when both present)
  counterpartySessionPeerId?: string;
  assignmentSignature: Uint8Array;     // 64-byte per-node directory sig over the relay TBS (relay_directory_signature)
}

/**
 * Extract a real message from a thrown value. libp2p / cross-package errors are not
 * always `instanceof Error` in this realm (multi-version split), so fall back to a
 * `message` property or JSON — never the useless "[object Object]".
 */
export function extractErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err && typeof err === "object" && typeof (err as { message?: unknown }).message === "string") {
    return (err as { message: string }).message;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (v && typeof (v as { subarray?: unknown }).subarray === "function") {
    return (v as { subarray(): Uint8Array }).subarray();
  }
  if (v && typeof (v as { slice?: unknown }).slice === "function") {
    return (v as { slice(): Uint8Array }).slice();
  }
  return new Uint8Array();
}

async function nextWithTimeout(
  iter: AsyncIterator<Uint8Array>,
  ms: number,
): Promise<{ value: Uint8Array | undefined; done: boolean }> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<{ value: undefined; done: true }>((resolve) => {
    timer = setTimeout(() => resolve({ value: undefined, done: true }), ms);
  });
  try {
    const result = (await Promise.race([iter.next(), timeout])) as IteratorResult<Uint8Array>;
    return { value: result.value, done: !!result.done };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Per-AGENT relay witness client. Shared across all of an agent's sessions; one
 * authenticated stream at a time (the relay keys by agent pubkey). Submits are FIFO and
 * single-in-flight on the stream; `leaf_deliver` is routed by session_id.
 */
export class AgentRelayClient {
  readonly #relayPeerId: string;
  readonly #relayAddrs: string[];
  readonly #keyProvider: KeyProvider;
  readonly #senderPubkey: Uint8Array;
  readonly #logger: Logger;
  readonly #receiptStore: RelayReceiptStore | undefined;
  readonly #sealLeafStore: SessionSealLeafStore | undefined;

  #stream: Stream | null = null;
  #connecting: Promise<boolean> | null = null;
  #closed = false;
  /**
   * PER-SESSION highest relay-assigned sequence (session_id hex → seq). The relay's
   * `seq_counter` is per session, and it rejects `last_seen_seq > seq_counter`, so each
   * session's submit MUST carry that session's own high-water mark — NOT an agent-global
   * one (which would make a newer session's first submit look ahead and get rejected).
   */
  readonly #lastSeen = new Map<string, number>();
  /** The one outstanding submit's resolver (global FIFO — ack carries no session_id). */
  #pendingAck: AckResolver | null = null;
  // The sender-signed structure1_cbor of the in-flight submit, paired with its ack so the
  // SubmitResult can carry it (the ack itself only returns the relay's structure2_cbor).
  #pendingStructure1: Uint8Array | null = null;
  // The in-flight submit's leaf kind (0x00 msg / 0x02 ctrl), paired with its ack so
  // #captureReceipt can persist it alongside the Structure2/Structure1 carry bytes for the unilateral seal.
  #pendingLeafKind: number | null = null;
  /** The session_id hex of the in-flight submit, so its ack updates the right #lastSeen. */
  #pendingAckSessionHex: string | null = null;
  /**
   * Resolver for the in-flight `client_record_assignment` ack. The ack carries
   * no session_id (like hash_submit_ack), so at most one record is in flight; records are serialized on
   * the same `#submitChain` as submits, guaranteeing no overlap.
   */
  #pendingRecord: ((result: "ok" | "rejected" | "closed") => void) | null = null;
  /** Serializes submits so only one is in flight at a time across all sessions. */
  #submitChain: Promise<unknown> = Promise.resolve();
  /** session_id hex → { the live node to (re)dial from, inbound leaf handler, Option-B assignment to present }. */
  readonly #sessions = new Map<string, {
    node: CelloNode;
    onLeafDeliver: (frame: LeafDeliverFrame) => void;
    /** The directory-signed relay assignment to present (absent for direct/legacy sessions). */
    assignment?: RelayAssignmentCarry;
    /** True once the relay has acked this session's client_record_assignment. */
    recorded: boolean;
    /**
     * The relay cleanly REJECTED this assignment (assignment_invalid — e.g. not signed by any
     * consortium directory). Terminal: stop re-presenting
     * it, so a misconfigured relay can't trigger a reconnect/re-present storm across sibling sessions.
     */
    recordRejected: boolean;
    /**
     * The record TIMED OUT rather than failing fast. A distinct sub-state because it means the
     * relay is unhealthy, not that the session is "not ready yet" — and the retry loop below is
     * for the not-ready-yet case. Retrying a timeout burns HASH_SUBMIT_TIMEOUT_MS per attempt on
     * the agent's SHARED submit chain, so a degraded relay would hold every session's sends.
     */
    recordTimedOut: boolean;
  }>();

  constructor(opts: AgentRelayClientOpts) {
    this.#relayPeerId = opts.relayPeerId;
    this.#relayAddrs = opts.relayAddrs;
    this.#keyProvider = opts.keyProvider;
    this.#senderPubkey = opts.senderPubkey;
    this.#logger = opts.logger;
    this.#receiptStore = opts.receiptStore;
    this.#sealLeafStore = opts.sealLeafStore;
  }

  /** The agent's K_local public key as hex — the responder identity for auto-acknowledge. */
  get senderPubkeyHex(): string {
    return Buffer.from(this.#senderPubkey).toString("hex");
  }

  /**
   * Register a session's inbound leaf handler + a live node to (re)dial the relay from
   * (idempotent). Storing the node per session lets a pure-receiver session re-establish
   * the shared stream if the node that originally dialed is torn down.
   */
  registerSession(
    sessionIdHex: string,
    node: CelloNode,
    onLeafDeliver?: (frame: LeafDeliverFrame) => void,
    assignment?: RelayAssignmentCarry,
  ): void {
    const existing = this.#sessions.get(sessionIdHex);
    this.#sessions.set(sessionIdHex, {
      node,
      onLeafDeliver: onLeafDeliver ?? (() => {}),
      // Carry the assignment forward across re-registration; never lose a recorded flag on re-register.
      assignment: assignment ?? existing?.assignment,
      recorded: existing?.recorded ?? false,
      recordRejected: existing?.recordRejected ?? false,
      recordTimedOut: existing?.recordTimedOut ?? false,
    });
    // Eagerly present the assignment so the relay records the session (binds peer IDs, creates the
    // session entry) BEFORE the first hash_submit or the counterparty's leaves arrive — the relay
    // rejects frames for a session it has not recorded. Best-effort + serialized on the submit chain
    // (the ack carries no session_id, so no overlap).
    if (assignment) {
      this.#submitChain = this.#submitChain
        .then(() => this.#doRecord(node, sessionIdHex))
        .then(() => undefined, () => undefined);
    }
  }

  /**
   * Present the directory-signed assignment to the relay. Idempotent
   * (no-op once `recorded`, or when the session has no assignment — direct/persisted/legacy sessions).
   * The relay reconstructs the TBS and verifies the per-node directory signature against any consortium
   * key. On success the session is recorded; the send/ack is single-in-flight (mirrors #doSubmit).
   */
  async #doRecord(node: CelloNode, sessionIdHex: string): Promise<boolean> {
    if (this.#closed) return false;
    const sess = this.#sessions.get(sessionIdHex);
    if (!sess || !sess.assignment) return true;
    if (sess.recorded) return true;
    // Terminal rejection: a relay that cleanly rejected this assignment will reject it
    // again — stop re-presenting so a misconfigured/forged case can't storm the shared stream.
    if (sess.recordRejected) return false;
    if (!(await this.#ensureConnected(node))) return false;
    const stream = this.#stream;
    if (!stream) return false;
    const a = sess.assignment;
    const frame = encodeCbor({
      type: "client_record_assignment",
      session_id: new Uint8Array(Buffer.from(sessionIdHex, "hex")),
      participant_a: a.participantA,
      participant_b: a.participantB,
      session_timestamp: a.sessionTimestamp,
      initiator_session_peer_id: a.initiatorSessionPeerId,
      counterparty_session_peer_id: a.counterpartySessionPeerId,
      assignment_signature: a.assignmentSignature,
    }) as Uint8Array;
    let resolveRec!: (result: "ok" | "rejected" | "closed") => void;
    const ackPromise = new Promise<"ok" | "rejected" | "closed">((r) => { resolveRec = r; });
    this.#pendingRecord = resolveRec;
    try {
      stream.send(lp.encode.single(frame));
    } catch (err: unknown) {
      if (this.#pendingRecord === resolveRec) this.#pendingRecord = null;
      this.#logger.warn("session.relay.record.send.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return false;
    }
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<"timeout">((r) => { timer = setTimeout(() => r("timeout"), HASH_SUBMIT_TIMEOUT_MS); });
    try {
      const result = await Promise.race([ackPromise, timeout]);
      if (result === "ok") {
        sess.recorded = true;
        sess.recordTimedOut = false;
        this.#logger.info("session.relay.assignment.recorded", { relayPeerId: this.#relayPeerId, sessionShort: sessionIdHex.slice(0, 16) });
        return true;
      }
      if (result === "timeout") {
        // ONLY here reset the stream: a late ack on this superseded stream would settle a LATER submit's
        // resolver (FIFO desync). recorded stays false ⇒ a transient timeout is retried on reconnect.
        this.#resetStream();
        sess.recordTimedOut = true;
        this.#logger.warn("session.relay.assignment.record.timeout", { relayPeerId: this.#relayPeerId, sessionShort: sessionIdHex.slice(0, 16) });
        return false;
      }
      if (result === "rejected") {
        // The relay cleanly rejected (assignment_invalid) — the ack already arrived, the stream is HEALTHY.
        // Do NOT reset (that would tear down sibling sessions' in-flight submits). Mark terminal so we stop
        // re-presenting. The session has no relay witness; sends still complete via the direct path
        // (sovereign-node redundancy) and a hash_submit will fail loud (session_not_found) — diagnosable.
        sess.recordRejected = true;
        this.#logger.warn("session.relay.assignment.record.rejected", { relayPeerId: this.#relayPeerId, sessionShort: sessionIdHex.slice(0, 16) });
        return false;
      }
      // "closed": the stream dropped while the record was in flight (settled by the reader/close path).
      // Transient — no reset needed (already gone); recorded stays false ⇒ retried on reconnect.
      return false;
    } finally {
      clearTimeout(timer);
      if (this.#pendingRecord === resolveRec) this.#pendingRecord = null;
    }
  }

  /** Remove a session; caller closes the client when no sessions remain. */
  unregisterSession(sessionIdHex: string): void {
    this.#sessions.delete(sessionIdHex);
    this.#lastSeen.delete(sessionIdHex);
  }

  hasSessions(): boolean {
    return this.#sessions.size > 0;
  }

  /** Settle the one outstanding submit (if any) exactly once. */
  #settlePending(r: SubmitResult): void {
    const resolve: AckResolver | null = this.#pendingAck;
    this.#pendingAck = null;
    this.#pendingAckSessionHex = null;
    this.#pendingStructure1 = null;
    this.#pendingLeafKind = null;
    if (resolve) resolve(r);
  }

  /**
   * Tear down the current stream (drops it so the next submit re-dials). Used on a submit
   * timeout: because `hash_submit_ack` carries no session_id, ack↔submit matching is purely
   * FIFO, so a LATE ack from a timed-out submit would settle the NEXT submit's resolver and
   * shift every subsequent ack by one. Resetting the stream prevents that desync (the relay
   * re-auths + re-drains on the reconnect).
   */
  #resetStream(): void {
    const stream = this.#stream;
    this.#stream = null;
    if (stream) {
      try { void stream.close(); } catch { /* best-effort */ }
    }
  }

  #bumpLastSeen(sessionIdHex: string, seq: number): void {
    if (seq < 0) return;
    const prev = this.#lastSeen.get(sessionIdHex) ?? 0;
    if (seq > prev) this.#lastSeen.set(sessionIdHex, seq);
  }

  /** True if this Structure-1 leaf was authored by US (sender_pubkey === our K_local). */
  #isOwnLeaf(structure1Cbor: Uint8Array): boolean {
    try {
      const arr = decode(structure1Cbor) as unknown[];
      // Structure 1 = [1, content_hash, sender_pubkey, session_id, last_seen_seq, ts].
      const senderPubkey = toU8(arr[2]);
      return Buffer.from(senderPubkey).equals(Buffer.from(this.#senderPubkey));
    } catch {
      // Undecodable → treat as NOT ours (conservative: don't suppress a real counterparty leaf).
      return false;
    }
  }

  /**
   * Verify a relay `hash_submit_ack`'s signed ordering record and durably store the receipt.
   * The relay signs TBS = SHA-256(content_hash || seq_BE4 || ts_BE8) with its ack-signing key, whose hex is
   * `relay_id`. We verify SELF-CONSISTENCY (the signature binds the sequence ⇒ a FORGED sequence fails) and
   * record the immutable receipt. The authoritative registered-relay check is the directory's at seal
   * (OPTIONB-SEAL). No-op when there is no receipt store, no pending leaf, or the ACK is unsigned.
   */
  #captureReceipt(frame: Record<string, unknown>, structure1Cbor: Uint8Array | undefined, seq: number): boolean {
    if (seq < 0 || !structure1Cbor) return false;
    let contentHash: Uint8Array;
    let sessionId: Uint8Array;
    try {
      // Structure 1 = [1, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, ts].
      const arr = decode(structure1Cbor) as unknown[];
      contentHash = toU8(arr[1]);
      sessionId = toU8(arr[3]);
    } catch {
      // Our OWN just-signed bytes — near-impossible to fail; surface it rather than drop silently.
      this.#logger.warn("relay.receipt.undecodable_leaf", { seq });
      return false;
    }
    const ev = evaluateRelayAck({
      contentHash,
      sessionIdHex: Buffer.from(sessionId).toString("hex"),
      agentPubkeyHex: this.senderPubkeyHex,
      relayId: typeof frame["relay_id"] === "string" ? frame["relay_id"] : undefined,
      relaySignature: frame["relay_signature"] instanceof Uint8Array ? (frame["relay_signature"] as Uint8Array) : undefined,
      timestamp: typeof frame["timestamp"] === "number" ? frame["timestamp"] : undefined,
      sequenceNumber: seq,
    });
    switch (ev.kind) {
      case "unsigned":
        // A relay that SHOULD sign but didn't → no durable witness for this message. Unsigned ACKs are
        // tolerated, but make it diagnosable instead of invisible.
        this.#logger.debug("relay.receipt.unsigned", { seq, hashShort: Buffer.from(contentHash).toString("hex").slice(0, 16) });
        return false;
      case "bad_relay_id":
        this.#logger.warn("relay.receipt.bad_relay_id", { seq });
        return false;
      case "invalid_signature":
        // FORGED / corrupt ACK — the signature does not bind (hash, seq, ts). REJECT the submit so the send
        // does NOT settle ok on an unverified sequence (a forged ordering record must not drive ordering),
        // and store nothing. The send still completes via the direct
        // content path — the relay witness simply degrades to absent for this leaf.
        this.#logger.warn("relay.receipt.signature_invalid", { seq });
        return true;
      case "store": {
        if (!this.#receiptStore) return false;
        try {
          const wrote = this.#receiptStore.store(ev.receipt, Date.now());
          if (wrote) {
            this.#logger.info("relay.receipt.stored", { seq, hashShort: ev.receipt.hashHex.slice(0, 16), relayShort: ev.receipt.relayId.slice(0, 16) });
          }
          // Record this OWN leaf in the seal-leaf log WITH its relay receipt (the
          // relay's signature pins content_hash→seq — the teeth that stop a supplier reordering its own
          // leaves). structure2_cbor rides the ack we just verified; structure1Cbor + the leaf kind are this
          // submit's paired in-flight values. Best-effort + separate from the receipt write.
          const structure2Cbor = frame["structure2_cbor"] instanceof Uint8Array ? (frame["structure2_cbor"] as Uint8Array) : undefined;
          if (this.#sealLeafStore && structure2Cbor && structure1Cbor && this.#pendingLeafKind !== null) {
            this.#sealLeafStore.store(this.senderPubkeyHex, ev.receipt.sessionIdHex, {
              sequenceNumber: seq,
              leafKind: this.#pendingLeafKind,
              senderPubkeyHex: this.senderPubkeyHex,
              structure2Cbor,
              structure1Cbor,
              relayId: ev.receipt.relayId,
              relayTimestamp: ev.receipt.timestamp,
              relaySignatureHex: ev.receipt.signatureHex,
            }, Date.now());
          }
        } catch (err) {
          // A durable-evidence write failure must be LOUD — the relay will not re-emit this ack, so a
          // swallowed write permanently loses a verified receipt.
          this.#logger.error("relay.receipt.store_failed", { seq, error: err instanceof Error ? err.message : String(err) });
        }
        return false;
      }
    }
  }

  #dispatch(frame: Record<string, unknown>): void {
    const type = frame["type"];
    if (type === "hash_submit_ack") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      // DO NOT advance #lastSeen here: the ack is for OUR OWN leaf. last_seen_seq must track
      // the highest COUNTERPARTY sequence we've observed — the directory's causal check rejects a leaf
      // whose last_seen_seq exceeds the max sequence of OTHER-sender leaves before it. Advancing on our
      // own ack would inflate it and trip causal_chain_violated on a subsequent submit (e.g. the SEAL
      // leaf after a sent message).
      // Pair the relay's committed structure2_cbor with our in-flight structure1_cbor so
      // the SubmitResult carries the full signed ordering record for the self-ordering content frame.
      // Captured BEFORE #settlePending clears #pendingStructure1.
      const s2 = frame["structure2_cbor"];
      const structure2Cbor = s2 instanceof Uint8Array ? s2 : undefined;
      const structure1Cbor = this.#pendingStructure1 ?? undefined;
      // Verify the relay's signed ordering record and durably store the receipt BEFORE
      // settling (which clears #pendingStructure1, the source of the content hash + session id). A
      // signed-but-INVALID ACK rejects the submit so the send does not settle ok on an unverified sequence.
      const rejectSubmit = this.#captureReceipt(frame, structure1Cbor, seq);
      this.#settlePending(
        rejectSubmit
          ? { ok: false, reason: "relay_ack_signature_invalid" }
          : seq >= 0
            ? { ok: true, sequence_number: seq, structure1_cbor: structure1Cbor, structure2_cbor: structure2Cbor }
            : { ok: false, reason: "relay_ack_malformed" },
      );
    } else if (type === "hash_submit_error") {
      const reason = typeof frame["reason"] === "string" ? frame["reason"] : "relay_rejected";
      this.#settlePending({ ok: false, reason });
    } else if (type === "assignment_ok") {
      // The relay verified + recorded our client-presented assignment.
      const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("ok");
    } else if (type === "assignment_invalid") {
      // The relay rejected the assignment (e.g. directory_signature_invalid — not signed by any
      // consortium directory). Fail LOUD: the session has no relay witness until this is resolved.
      this.#logger.warn("session.relay.assignment.invalid", { relayPeerId: this.#relayPeerId, reason: typeof frame["reason"] === "string" ? frame["reason"] : "unknown" });
      const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("rejected");
    } else if (type === "leaf_deliver") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      const sidHex = Buffer.from(toU8(frame["session_id"])).toString("hex");
      const s1 = toU8(frame["structure1_cbor"]);
      // Advance last_seen_seq ONLY for a COUNTERPARTY leaf. The relay also echoes our OWN
      // leaf back as a leaf_deliver — that must NOT advance it (same reason as the ack above).
      const authoredByUs = this.#isOwnLeaf(s1);
      if (seq >= 0 && !authoredByUs) this.#bumpLastSeen(sidHex, seq);
      // Record the COUNTERPARTY's delivered leaf in the seal-leaf log (no relay
      // receipt — the relay does not ack-sign a delivery to the recipient). It is pinned at seal by the
      // absent party's sender_signature (unforgeable) + sequence contiguity against our receipt-pinned own
      // leaves. Our OWN echoed leaf is skipped here (it is recorded WITH its receipt on the ack path).
      if (this.#sealLeafStore && seq >= 0 && !authoredByUs) {
        const s2 = frame["structure2_cbor"];
        const structure2Cbor = s2 instanceof Uint8Array ? s2 : undefined;
        let senderHex: string | undefined;
        try { senderHex = Buffer.from(toU8((decode(s1) as unknown[])[2])).toString("hex"); } catch { senderHex = undefined; }
        if (structure2Cbor && s1.length > 0 && senderHex) {
          try {
            this.#sealLeafStore.store(this.senderPubkeyHex, sidHex, {
              sequenceNumber: seq,
              leafKind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
              senderPubkeyHex: senderHex,
              structure2Cbor,
              structure1Cbor: s1,
            }, Date.now());
          } catch (err) {
            this.#logger.error("relay.seal_leaf.counterparty.store_failed", { seq, session: sidHex, error: err instanceof Error ? err.message : String(err) });
          }
        } else {
          this.#logger.warn("relay.seal_leaf.counterparty.capture_skipped", { seq, session: sidHex, hasS2: !!structure2Cbor, hasS1: s1.length > 0, hasSender: !!senderHex });
        }
      }
      const session = this.#sessions.get(sidHex);
      if (session && seq >= 0) {
        session.onLeafDeliver({
          sequence_number: seq,
          leaf_kind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
          structure1_cbor: s1,
          structure2_cbor: toU8(frame["structure2_cbor"]),
          // Tell the consumer whether this is our own echoed leaf (so the
          // auto-acknowledge gate never co-signs in response to its own SEAL ctrl leaf).
          authored_by_us: authoredByUs,
        });
      }
    }
    // session_interrupted / content_park_notify are out of scope here — session interruption
    // is handled by the session node manager's dedicated relay-stream watcher.
  }

  /**
   * Proactively establish the authenticated stream from `node`. The RECEIVER must connect
   * before the counterparty submits, so the relay has its stream to deliver `leaf_deliver`
   * to (otherwise the relay queues until the recipient connects). Best-effort.
   */
  async connect(node: CelloNode): Promise<boolean> {
    return this.#ensureConnected(node);
  }

  /** Ensure an authenticated stream exists, (re)dialing from `node` if needed. */
  async #ensureConnected(node: CelloNode): Promise<boolean> {
    if (this.#closed) return false;
    if (this.#stream) return true;
    if (this.#connecting) return this.#connecting;
    this.#connecting = this.#connect(node).finally(() => { this.#connecting = null; });
    return this.#connecting;
  }

  async #connect(node: CelloNode): Promise<boolean> {
    // Best-effort dial: newStream auto-dials a known peer, but the relay's addrs may not
    // be in the peerstore yet, so dial each addr first. One success is enough.
    let dialed = false;
    let lastDialError = "";
    for (const addr of this.#relayAddrs) {
      try {
        await node.dial(addr);
        dialed = true;
        break;
      } catch (err: unknown) {
        lastDialError = extractErrorMessage(err);
      }
    }
    if (!dialed && this.#relayAddrs.length > 0) {
      this.#logger.warn("session.relay.dial.failed", {
        relayPeerId: this.#relayPeerId,
        relayAddrs: this.#relayAddrs,
        error: lastDialError,
      });
      return false;
    }

    let stream: Stream;
    try {
      stream = await node.newStream(this.#relayPeerId, RELAY_PROTOCOL_ID);
    } catch (err: unknown) {
      this.#logger.warn("session.relay.stream.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return false;
    }

    // ONE shared lp.decode iterator for the whole stream lifetime — splitting it signals
    // EOF to the relay's single-iterator reader and breaks subsequent reads.
    const iter = (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
      Symbol.asyncIterator
    ]() as AsyncIterator<Uint8Array>;

    if (!(await this.#authenticate(stream, iter))) return false;

    this.#stream = stream;
    this.#logger.info("session.relay.connected", { relayPeerId: this.#relayPeerId });
    this.#startReader(stream, iter);
    return true;
  }

  async #authenticate(stream: Stream, iter: AsyncIterator<Uint8Array>): Promise<boolean> {
    const challengeRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (challengeRes.done || challengeRes.value === undefined) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "no_challenge" });
      return false;
    }
    let challenge: Record<string, unknown>;
    try {
      challenge = decode(toU8(challengeRes.value)) as Record<string, unknown>;
    } catch {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "challenge_decode" });
      return false;
    }
    if (challenge["type"] !== "relay_auth_challenge") {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "not_challenge" });
      return false;
    }
    const nonce = toU8(challenge["nonce"]);
    if (nonce.length !== 32) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "bad_nonce" });
      return false;
    }
    const authSig = await this.#keyProvider.sign(buildRelayAuthPayload(nonce, this.#senderPubkey));
    try {
      stream.send(lp.encode.single(encodeCbor({ type: "relay_auth_response", pubkey: this.#senderPubkey, signature: authSig }) as Uint8Array));
    } catch (err: unknown) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "response_send", error: extractErrorMessage(err) });
      return false;
    }
    const ackRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (ackRes.done || ackRes.value === undefined) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "no_auth_ok" });
      return false;
    }
    let ackFrame: Record<string, unknown>;
    try {
      ackFrame = decode(toU8(ackRes.value)) as Record<string, unknown>;
    } catch {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "auth_ok_decode" });
      return false;
    }
    if (ackFrame["type"] !== "relay_auth_ok") {
      this.#logger.warn("session.relay.auth.failed", {
        relayPeerId: this.#relayPeerId,
        reason: ackFrame["type"] === "relay_auth_failed" ? "auth_rejected" : "unexpected_frame",
      });
      return false;
    }
    return true;
  }

  #startReader(stream: Stream, iter: AsyncIterator<Uint8Array>): void {
    void (async () => {
      try {
        while (!this.#closed && this.#stream === stream) {
          const res = await iter.next();
          if (res.done || res.value === undefined) break;
          // The await above can suspend across a #resetStream() (timeout) that supersedes this
          // stream. Re-check identity before dispatching so a late frame from a stale stream
          // (e.g. a buffered ack for a timed-out submit) can't bump/settle the wrong session.
          if (this.#stream !== stream) break;
          let frame: Record<string, unknown>;
          try {
            frame = decode(toU8(res.value)) as Record<string, unknown>;
          } catch {
            continue;
          }
          this.#dispatch(frame);
        }
      } catch (err: unknown) {
        this.#logger.debug?.("session.relay.reader.ended", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      } finally {
        // Stream gone — clear it so the next submit re-dials, and fail any in-flight submit.
        if (this.#stream === stream) this.#stream = null;
        this.#settlePending({ ok: false, reason: "relay_stream_closed" });
        // Settle an in-flight record too, so #doRecord doesn't
        // wait the full timeout on a dropped stream. "closed" is transient (not a directory rejection) ⇒
        // recorded stays false and it is retried after reconnect.
        { const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("closed"); }
        // A pure-receiver session issues no submit, so it would never trigger a re-dial
        // after the node that owned the stream is torn down. If sessions remain, proactively
        // re-establish from any still-live registered session node so queued leaf_delivers
        // are drained (the relay queues by pubkey and re-delivers on reconnect).
        if (!this.#closed && this.#sessions.size > 0) {
          void this.#reconnectFromAnySession();
        }
      }
    })();
  }

  /** Re-establish the shared stream from any registered session's node (first that dials). */
  async #reconnectFromAnySession(): Promise<void> {
    if (this.#closed || this.#stream) return;
    for (const { node } of this.#sessions.values()) {
      if (await this.#ensureConnected(node)) return;
    }
  }

  /**
   * Submit a session's MESSAGE-leaf (0x00) hash to the relay. Connects/re-connects from
   * `node` if needed. Globally FIFO across the agent's sessions (the ack has no session_id).
   */
  async submitMessageHash(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array): Promise<SubmitResult> {
    return this.submitLeaf(node, sessionId, contentHash, LEAF_KIND_MSG);
  }

  /**
   * Submit a leaf hash of a given kind (0x00 message / 0x02 control) to the relay. The SEAL
   * ctrl leaf rides this path: two distinct-sender ctrl leaves in the relay's
   * log trigger the directory's FROST notarization (relay `#maybeProcessSeal`).
   */
  async submitLeaf(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number): Promise<SubmitResult> {
    // Chain on the prior submit so only one is outstanding at a time (FIFO). The ack
    // carries no session_id, so concurrent submits on one stream would be ambiguous.
    const run = this.#submitChain.then(() => this.#doSubmit(node, sessionId, contentHash, leafKind));
    // Keep the chain alive regardless of this submit's outcome.
    this.#submitChain = run.then(() => undefined, () => undefined);
    return run;
  }

  /**
   * DOD-FIRSTMSG-WITNESS-1: `session_not_found` is TRANSIENT, not terminal.
   *
   * The relay answers it when it does not hold the session YET — the assignment record is still
   * landing, or the counterparty recorded it and our own record raced ahead of the submit. Proven
   * from the live log: in all 23 first-message failures the `assignment.recorded` event lands
   * 5 ms – 2.1 s AFTER the rejected submit. The relay is reachable and answering; it is simply
   * not ready.
   *
   * Before this, the rejection was returned to `sendContent`, which logged
   * `session.relay.hash.submit.failed` and appended the leaf UNWITNESSED anyway. Nothing retried,
   * so the relay's counter never counted that message and the local record stayed exactly one
   * ahead for the life of the session. Because the bilateral certificate is rebuilt EXCLUSIVELY
   * from relay-witnessed leaves, the sealed receipt omitted the conversation's opening message —
   * and was issued regardless.
   *
   * Retrying re-presents the assignment first (idempotent — the relay answers `assignment_ok` on
   * `session_already_exists`), which is also what supplies the wait: re-recording is a full
   * round trip, so the retry cannot busy-spin against a relay that is still catching up.
   *
   * This does NOT collapse the two states the fix must tell apart:
   *   - `session_not_found` — a reachable relay that does not hold the session yet → retry here.
   *   - `relay_unavailable` / stream failures — a genuine outage → returned untouched, so
   *     `sendContent` still degrades to an unwitnessed append and the inbox stays readable.
   * Any other rejection (`session_sealed`, `not_a_participant`, signature failures) is terminal
   * and returned as-is — retrying those would be pointless traffic masking a real state.
   */
  static readonly #SESSION_NOT_FOUND_ATTEMPTS = 3;

  async #doSubmit(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number): Promise<SubmitResult> {
    const sessionIdHex = Buffer.from(sessionId).toString("hex");
    // Snapshotted BEFORE the first attempt, and it is the whole safety of this loop.
    //
    // The first-message race is BY DEFINITION a session we have not recorded yet. A session we DID
    // record and that the relay now reports missing is a DIFFERENT state: the relay destroys a
    // session on seal (relay-node.ts `confirmSeal`) and on idle sweep, and its store keeps NO
    // tombstone — `recordSession` re-creates any absent key fresh (`seq_counter: 0`, empty
    // leaf_log, status "active"). So `getSession` answers `session_not_found`, NOT `session_sealed`.
    // Re-presenting our still-valid directory-signed assignment there would silently RESURRECT a
    // sealed session on the relay: a ghost with an empty log, an idle timer and a delivery path,
    // created by a client submit retry. Two ctrl leaves on it would drive a second notarization
    // over a 1-leaf log for an already-certified session.
    //
    // The 2 post-seal failures in this defect's own evidence table are exactly that shape — they
    // reported `session_not_found`, indistinguishable at the wire from the race — which is why
    // this must be discriminated on OUR state, not on the relay's reason string.
    const recordedBefore = this.#sessions.get(sessionIdHex)?.recorded === true;

    let result = await this.#doSubmitOnce(node, sessionId, contentHash, leafKind);
    for (
      let attempt = 1;
      attempt < AgentRelayClient.#SESSION_NOT_FOUND_ATTEMPTS
        && !recordedBefore
        && !result.ok
        && (result.reason === "session_not_found" || result.reason === "session_not_recorded")
        && !this.#closed;
      attempt++
    ) {
      // Force the assignment to be re-presented: we never recorded this session, so the relay
      // genuinely does not hold it yet. A session with no assignment to present (direct/legacy)
      // re-submits without a record — still bounded, and it surfaces the same named failure
      // rather than hanging.
      const sess = this.#sessions.get(sessionIdHex);
      if (sess) sess.recorded = false;
      this.#logger.info("session.relay.submit.retry", {
        relayPeerId: this.#relayPeerId,
        sessionShort: sessionIdHex.slice(0, 16),
        attempt,
        reason: result.reason,
      });
      result = await this.#doSubmitOnce(node, sessionId, contentHash, leafKind);
    }

    // The relay lost a session we had successfully recorded — sealed, idle-swept, or restarted.
    // Report THAT, rather than letting the caller read a bare `session_not_found` that reads like
    // the first-message race. Never re-present here: recreating it is the resurrection above.
    if (recordedBefore && !result.ok && result.reason === "session_not_found") {
      this.#logger.warn("session.relay.session.gone", {
        relayPeerId: this.#relayPeerId,
        sessionShort: sessionIdHex.slice(0, 16),
        guidance: "the relay no longer holds a session it had recorded (sealed, idle-swept, or restarted) — not re-presented, because that would recreate it with an empty leaf log",
      });
      return { ok: false, reason: "relay_session_gone" };
    }
    return result;
  }

  async #doSubmitOnce(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number): Promise<SubmitResult> {
    if (this.#closed) return { ok: false, reason: "relay_client_closed" };
    if (!(await this.#ensureConnected(node))) return { ok: false, reason: "relay_unavailable" };

    const sessionIdHex = Buffer.from(sessionId).toString("hex");
    // The relay records the session from the CLIENT-presented assignment. It MUST be recorded BEFORE
    // the first hash_submit — the relay rejects a submit for an unknown session. Idempotent + no-op when
    // there is no assignment to present (direct/persisted sessions). Runs inline on the submit chain (no re-chaining
    // — #doSubmit is already a chain link), and may reset the stream on failure, so capture #stream after.
    const recorded = await this.#doRecord(node, sessionIdHex);
    const sess = this.#sessions.get(sessionIdHex);
    if (!recorded && sess?.assignment) {
      // DOD-FIRSTMSG-WITNESS-1 AC3: do NOT send a hash_submit for a session we know the relay does
      // not hold. Previously this return value was discarded and the doomed frame went out anyway —
      // the line this defect's producer→consumer trace names as THE gap. Two sub-states, kept apart:
      //   - recordRejected  → TERMINAL (the relay refused the assignment as unverifiable). Retrying
      //                       cannot help and would storm the shared stream.
      //   - anything else   → the record is in flight or transiently failed. Retryable.
      // A session with NO assignment to present (direct/legacy) is not covered here: #doRecord
      // returns true for it, so it still submits exactly as before.
      if (sess.recordRejected) return { ok: false, reason: "relay_assignment_rejected" };
      // A TIMEOUT IS NOT "NOT READY YET". The retry below exists for a relay that has not finished
      // registering the session — it answers in milliseconds. A record that timed out means the relay
      // is not answering at all, and retrying spends HASH_SUBMIT_TIMEOUT_MS again per attempt on the
      // chain SHARED by every session this agent holds on this relay. Classifying it as unreachable
      // proceeds unwitnessed immediately, which is what AC2 asks for on an outage — the send is not
      // lost, and one sick relay cannot hold an operator's other conversations for half a minute.
      if (sess.recordTimedOut) return { ok: false, reason: "relay_unavailable" };
      return { ok: false, reason: "session_not_recorded" };
    }
    const stream = this.#stream;
    if (!stream) return { ok: false, reason: "relay_unavailable" };

    // This session's OWN high-water mark (NOT an agent-global one) — the relay's seq_counter
    // is per session and rejects last_seen_seq > seq_counter.
    const lastSeenForSession = this.#lastSeen.get(sessionIdHex) ?? 0;
    const structure1 = encodeStructure1(contentHash, this.#senderPubkey, sessionId, lastSeenForSession, Date.now());
    const signature = await this.#keyProvider.sign(structure1);
    const frame = encodeCbor({
      type: "hash_submit",
      session_id: sessionId,
      leaf_kind: leafKind,
      structure1_cbor: structure1,
      sender_signature: signature,
    }) as Uint8Array;

    // Set the resolver synchronously (no await between the in-flight check and the set):
    // the submit chain guarantees no other submit runs concurrently, so #pendingAck is null.
    let resolveAck!: AckResolver;
    const ackPromise = new Promise<SubmitResult>((r) => { resolveAck = r; });
    this.#pendingAck = resolveAck;
    this.#pendingAckSessionHex = sessionIdHex;
    // Remember this submit's sender-signed structure1_cbor so its ack can return the full
    // ordering record (the ack itself carries only the relay's structure2_cbor).
    this.#pendingStructure1 = structure1;
    this.#pendingLeafKind = leafKind;
    try {
      stream.send(lp.encode.single(frame));
    } catch (err: unknown) {
      if (this.#pendingAck === resolveAck) { this.#pendingAck = null; this.#pendingAckSessionHex = null; this.#pendingStructure1 = null; this.#pendingLeafKind = null; }
      this.#logger.warn("session.relay.submit.send.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return { ok: false, reason: "relay_submit_send_failed" };
    }
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<SubmitResult>((r) => {
      timer = setTimeout(() => r({ ok: false, reason: "relay_submit_timeout" }), HASH_SUBMIT_TIMEOUT_MS);
    });
    try {
      const result = await Promise.race([ackPromise, timeout]);
      // On timeout, reset the stream so a late ack can't settle a LATER submit (FIFO desync).
      if (!result.ok && result.reason === "relay_submit_timeout") this.#resetStream();
      return result;
    } finally {
      clearTimeout(timer);
      if (this.#pendingAck === resolveAck) { this.#pendingAck = null; this.#pendingAckSessionHex = null; this.#pendingStructure1 = null; this.#pendingLeafKind = null; }
    }
  }

  /** The highest relay-assigned sequence observed for a given session (ack or deliver). */
  lastSeenSeq(sessionIdHex: string): number {
    return this.#lastSeen.get(sessionIdHex) ?? 0;
  }

  close(): void {
    this.#closed = true;
    this.#settlePending({ ok: false, reason: "relay_client_closed" });
    // Settle any in-flight record so #doRecord resolves promptly.
    { const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("closed"); }
    const stream = this.#stream;
    this.#stream = null;
    if (stream) {
      try { void stream.close(); } catch { /* best-effort */ }
    }
  }
}
