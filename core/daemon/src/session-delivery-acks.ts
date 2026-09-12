/**
 * DOD-M15-DELIVERYACK-1 — the delivery acknowledgement, both directions.
 *
 * Split out of `session-content-ingest.ts` rather than added to it. The acknowledgement is now a
 * signed artifact with its own five rules and its own evidence store, which is a subject of its
 * own — and the ingest file sits on a `max-lines` ratchet whose whole purpose is that a feature
 * lands as a module instead of as growth in a file nobody can read.
 *
 * ⚠️ NOTHING HERE TOUCHES THE TAMPER-EVIDENT RECORD. An acknowledgement takes no chain leaf, is
 * never itself acknowledged, and its absence proves nothing. The evidence it produces is read by
 * the sealed-receipt surface and by nothing else.
 */

import * as lp from "it-length-prefixed";
import type { Stream } from "@libp2p/interface";
import { signDeliveryAck, verifyDeliveryAck } from "@cello-protocol/crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { SessionContentPipelineContext } from "./session-content-context.js";
import { CELLO_CONTENT_PROTOCOL_ID } from "@cello-protocol/transport";
import { extractErrorMessage } from "./error-message.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/**
 * DOD-M15-DELIVERYACK-1 rule 2 — is this a hash we sent in this session and are still awaiting an
 * acknowledgement for?
 *
 * The bind check, and the thing that bounds the whole path: `awaitingAck` is populated only by our
 * OWN sends and each entry is consumed on the first accepted acknowledgement, so the number a
 * session can ever record is the number of messages this side sent in it. A counterparty cannot
 * make this side allocate anything by sending acknowledgements.
 */
function isAwaitingAck(
  ctx: SessionContentPipelineContext,
  agentName: string,
  sessionId: string,
  contentHash: Uint8Array,
): boolean {
  const bySession = ctx.awaitingAck.get(ctx.sessionKey(agentName, sessionId));
  return bySession?.has(Buffer.from(contentHash).toString("hex")) === true;
}

/**
 * Send a SIGNED `persisted` delivery ACK back to the sender over the same
 * /cello/content/1.0.0 protocol (AC-001).
 *
 * ⚠️ IT USED TO BE UNSIGNED, and the comment here used to justify that: "authentication is the
 * Noise session channel, so the ACK carries no signature". That is true of the HOP and it dies
 * with the connection — it left the sender holding nothing it could show a third party, which is
 * what `DOD-M15-DELIVERYACK-1` exists to fix. Rewritten rather than deleted, because the old
 * sentence is exactly why an auditor would conclude the frame is unsigned by design.
 *
 * What is signed says only *this machine received these bytes in this session*. Signed on INGEST,
 * so it asserts nothing about attention and nothing about agreement.
 *
 * Still best-effort in the SEND: a failed ACK send is logged and the sender recovers via its
 * TTF/recovery path rather than a thrown error here.
 */
export async function sendDeliveryAck(
  ctx: SessionContentPipelineContext,
  agentName: string,
  sessionId: string,
  contentHash: Uint8Array,
  correlationId?: string,
): Promise<void> {
  const entry = ctx.activeNodes.get(ctx.sessionKey(agentName, sessionId));
  if (!entry) {
    // NOT a silent return. No ACK is exactly this milestone's symptom — the sender's TTF expires
    // and the message parks — so the one case where we knowingly decline to send one has to say
    // so, or it is indistinguishable from the defect.
    ctx.logger.debug("content.delivery.ack.skipped", {
      agentName,
      sessionId,
      contentHash: Buffer.from(contentHash).toString("hex"),
      reason: "session_node_gone",
      correlationId,
    });
    return;
  }
  /**
   * SIGN BEFORE THE STREAM IS OPENED — an unsignable acknowledgement must not be sent at all.
   *
   * A frame with no signature is discarded at the far end on the same path as a wrong one, so
   * sending one would burn a stream slot to produce a refusal. Declining is LOUD rather than
   * silent, for the reason the `session_node_gone` branch above is: no acknowledgement is this
   * unit's own symptom, so every case where we knowingly do not send one has to say so.
   */
  const signer = ctx.keyProvider(agentName);
  if (!signer) {
    ctx.logger.error("content.delivery.ack.unsignable", {
      agentName,
      sessionId,
      contentHash: Buffer.from(contentHash).toString("hex"),
      reason: "no_identity_key",
      impact:
        "this machine holds no identity key for the agent, so it cannot sign for the message it " +
        "just received. The message IS ingested and readable here; what is missing is the proof " +
        "the sender keeps, so from their side this message will look unacknowledged",
      guidance:
        "This is a LOCAL fault, not anything your counterparty did. Check that the agent's " +
        "identity key is present on this machine (cello_status), then restart the agent.",
      correlationId,
    });
    return;
  }
  let ackSig: Uint8Array;
  try {
    ackSig = await signDeliveryAck(signer, Buffer.from(sessionId, "hex"), contentHash);
  } catch (err: unknown) {
    ctx.logger.error("content.delivery.ack.unsignable", {
      agentName, sessionId,
      contentHash: Buffer.from(contentHash).toString("hex"),
      reason: "signing_failed",
      error: extractErrorMessage(err),
      impact:
        "the message is ingested and readable here, but no acknowledgement could be signed for " +
        "it, so the sender will see it as unacknowledged",
      guidance:
        "This is a LOCAL fault. Check the agent's identity key on this machine (cello_status) " +
        "and restart the agent; nothing your counterparty did causes this.",
      correlationId,
    });
    return;
  }
  // Held outside the try so the catch can retire a stream that was opened and then failed to
  // write. Without it every failure leaks the OUTBOUND half of the stream the receiver-side
  // `finally` retires — same defect, other end, other cap. See the note on #handleContentStream.
  // Assigned IMMEDIATELY after newStream: anything between the two is a window where a throw
  // leaks the stream because the catch cannot see it.
  let ackStream: Stream | undefined;
  try {
    const stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
    ackStream = stream;
    // Injected ACK-write failure — thrown from inside the try so it lands in exactly the catch a
    // real reset lands in, and the whole downstream path (impair → abort → log) runs unmodified.
    if (ctx.ackFaultRemaining > 0) {
      ctx.ackFaultRemaining -= 1;
      ctx.logger.warn("content.delivery.ack.fault.injected", { sessionId });
      throw new Error("connection_lost: injected delivery-ack fault");
    }
    const frame = encodeCbor({
      type: "content_delivery_ack",
      session_id: sessionId,
      content_hash: contentHash,
      level: "persisted",
      // DOD-M15-DELIVERYACK-1: what the sender can still show someone after the connection is gone.
      ack_sig: ackSig,
      correlation_id: correlationId,
    }) as Uint8Array;
    stream.send(lp.encode.single(frame));
    // NOT SWALLOWED, for the same reason the direct-send path stopped swallowing it: `close()`
    // waits for the write buffer to drain, so a reset mid-flush throws HERE and that is exactly
    // the case where the bytes never left. A swallowed close made two things happen at once —
    // this log claimed the ACK went out while the sender's TTF fired and parked, and the abort in
    // the catch below (the thing that frees the stream slot) became unreachable.
    await stream.close();
    // AFTER the close, because that is when it is true. The receiver-side counterpart to the
    // sender's content.delivery.acked: B has acknowledged this content `persisted`, so the sender
    // stops retrying/parking. Emitted for BOTH a normally delivered message AND a terminal-screen
    // block (the block is a definitive receipt — the leaf is recorded, so the sender must stop) —
    // and deliberately NOT for a transient hold.
    ctx.logger.info("content.delivery.ack.sent", {
      sessionId,
      contentHash: Buffer.from(contentHash).toString("hex"),
      correlationId,
    });
    // An agent that mostly LISTENS sends content rarely and ACKs constantly. Clearing only on the
    // content path would leave exactly those sessions reporting a broken conversation forever
    // after one bad ACK — the one-way door, on the other send path.
    ctx.liveness.clearSessionImpairment(agentName, sessionId, "delivery_ack", correlationId);
  } catch (err: unknown) {
    ctx.logger.warn("content.delivery.ack.send.failed", {
      sessionId,
      contentHash: Buffer.from(contentHash).toString("hex"),
      error: extractErrorMessage(err),
      // "Cannot write to a stream that is closed" names where the write died, never why. The
      // why is almost always the per-protocol stream cap, and these two numbers are what turn
      // that from a log-measurement session into a grep.
      ...ctx.streamCensus(entry.node, entry.counterpartySessionPeerId),
      correlationId,
    });
    // The ACK travels the same direct path as our own content, so a failure here is the same
    // evidence: writes to this counterparty are not landing.
    ctx.liveness.markSessionImpaired(agentName, sessionId, { cause: "delivery_ack", error: extractErrorMessage(err), correlationId });
    if (ackStream !== undefined) {
      try { ackStream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
    }
  }
}



/**
 * DOD-M15-DELIVERYACK-1 — AN INBOUND ACKNOWLEDGEMENT IS ATTACKER-CONTROLLED INPUT.
 *
 * The client is open source and runs on the counterparty's machine, so they can send whatever
 * they like here. Five properties, and all five are load-bearing:
 *
 * 1. **Verified against the session's RECORDED counterparty key**, never a key in the frame. The
 *    recorded key comes from what the operator asked for (initiator) or the directory-attested
 *    offer (responder) — `entry.counterpartyPubkey`. Checking a signature against a key carried
 *    inside its own frame proves only that somebody owns a keypair.
 *    ⚠️ Deliberately NARROWER than "either participant". The clause says an ack verifying under
 *    neither participant key is discarded; ours additionally discards one signed by US, which is
 *    the self-referential case — our own signature on our own message, stored in our own
 *    database, constrains nobody.
 * 2. **Bound** — it must name a hash this side actually sent in this session and is still
 *    awaiting. The session is already pinned by the shared frame gate above.
 * 3. **Inert** — it records evidence and resolves the sender's own fallback timer. It advances no
 *    sequence, touches no tree, takes no leaf, closes nothing, seals nothing.
 * 4. **Idempotent and bounded** — the awaiting entry is consumed on the first accepted ack, so a
 *    duplicate finds nothing and does nothing, and the number of acks that can ever be recorded
 *    for a session is the number of messages this side sent in it. There is no counter an
 *    attacker can inflate because there is no per-ack allocation at all.
 * 5. **Malformed fails exactly as missing does.** Both take this one discard path: the timer stays
 *    armed, no `content.delivery.acked` fires, nothing is recorded, and the message parks on TTF
 *    expiry exactly as it would have with no acknowledgement at all.
 *
 * 🚨 AND A DISCARD IS NOT A SECURITY EVENT. It does not freeze the session and must never feed a
 * trust signal. A missing acknowledgement is usually innocent — the relay parked the content, the
 * far daemon died between ordering and pull, a bounded queue dropped its oldest frame, a screener
 * refused it. Reading absence as evasion is the defect, not the fix.
 */
export function onDeliveryAck(
  ctx: SessionContentPipelineContext,
  resolveAwaitingAck: (agentName: string, sessionId: string, contentHash: Uint8Array) => void,
  agentName: string,
  sessionId: string,
  contentHash: Uint8Array,
  rawSig: unknown,
  correlationId?: string,
): void {
  const hashHex = Buffer.from(contentHash).toString("hex");
  // RULE 2 — bound. Cheapest check, and it is what bounds everything below: an ack naming a hash
  // we never sent (or already recorded) allocates nothing and is gone here.
  if (!isAwaitingAck(ctx, agentName, sessionId, contentHash)) {
    ctx.logger.debug("content.delivery.ack.discarded", {
      agentName, sessionId, contentHash: hashHex, correlationId,
      reason: "not_awaiting",
      impact:
        "an acknowledgement arrived for a message this side is not awaiting one for — it was " +
        "never sent in this session, or it was already acknowledged, or its fallback window had " +
        "already expired and the message parked. Discarded; nothing is concluded from it",
    });
    return;
  }
  const entry = ctx.activeNodes.get(ctx.sessionKey(agentName, sessionId));
  // RULE 1 — the key we check against is the session's own record, and the frame supplies none of it.
  const counterparty = entry?.counterpartyPubkey;
  const verdict = verifyDeliveryAck({
    participantIdentityPublics:
      counterparty && /^[0-9a-fA-F]{64}$/.test(counterparty)
        ? [new Uint8Array(Buffer.from(counterparty, "hex"))]
        : [],
    sessionId: new Uint8Array(Buffer.from(sessionId, "hex")),
    contentHash,
    // RULE 5 — a non-Uint8Array arrives at the verifier as ABSENT, so a present-but-wrong-typed
    // field takes the missing path rather than a tolerance branch of its own.
    signature: rawSig instanceof Uint8Array ? rawSig : undefined,
  });
  if (!verdict.ok) {
    /**
     * WHO HEARS THIS, and why the answer is only the log — asked because a refusal with no named
     * surface is this milestone's most repeated defect and the exception has to be argued.
     *
     * There is no caller to answer: this arrives on an inbound stream, unrequested. And the AGENT
     * must not be told, because telling it is the harm. "Your counterparty sent a bad
     * acknowledgement" reads as an accusation, and the one thing this unit must never do is let an
     * absent or unusable acknowledgement be read as evasion. The behavioural consequence the agent
     * DOES see is already correct and already surfaced: the message stays awaiting and parks on the
     * usual fallback, exactly as if nothing had arrived — which is the truth. The log keeps the
     * forensic record for the operator who goes looking.
     *
     * ONCE PER MESSAGE, LOUDLY; after that quietly — the flag rides on the awaiting entry, so it
     * is freed with it and an entry exists only for a message THIS side sent. See
     * `AwaitingAckEntry.ackRefusalLogged` for why the budget is not something the other side can
     * spend.
     */
    const awaiting = ctx.awaitingAck.get(ctx.sessionKey(agentName, sessionId))?.get(hashHex);
    const firstForThisMessage = awaiting?.ackRefusalLogged !== true;
    if (awaiting) awaiting.ackRefusalLogged = true;
    ctx.logger[firstForThisMessage ? "warn" : "debug"]("content.delivery.ack.discarded", {
      agentName, sessionId, contentHash: hashHex, correlationId,
      reason: verdict.reason,
      detail: verdict.detail,
      impact:
        "this message is treated exactly as if no acknowledgement had arrived: it stays awaiting " +
        "and will park on the usual fallback. Nothing about the counterparty is concluded",
    });
    return;
  }
  // RULE 3 — evidence, and nothing else. Recorded BEFORE the timer is resolved so a write failure
  // cannot leave the sender believing it holds a proof it does not.
  // `rawSig` is a Uint8Array whenever the verdict is ok — the verifier refuses `undefined`.
  ctx.records.recordDeliveryAck(
    agentName,
    sessionId,
    hashHex,
    Buffer.from(verdict.signerPublic).toString("hex"),
    rawSig as Uint8Array,
    correlationId,
  );
  resolveAwaitingAck(agentName, sessionId, contentHash);
}

/**
 * DOD-M15-DELIVERYACK-1 — keep the counterparty's signature that their machine received a message.
 *
 * Called ONLY after `verifyDeliveryAck` succeeded against the session's recorded counterparty key.
 * `INSERT OR IGNORE` is the idempotence: the first acknowledgement recorded for a (session, hash)
 * stands and a replay changes nothing.
 *
 * A write failure is LOUD and it is not fatal. The message was delivered; what is lost is this
 * side's ability to prove it later, and the operator is the only one who can act on that.
 */
export function storeDeliveryAck(
  db: DaemonDatabase,
  logger: Logger,
  a: {
    agentId: string;
    agentName: string;
    sessionId: string;
    contentHashHex: string;
    signerPubkeyHex: string;
    signature: Uint8Array;
    correlationId?: string;
  },
): void {
  const { agentId, agentName, sessionId, contentHashHex, signerPubkeyHex, signature, correlationId } = a;
  try {
    db
      .prepare(
        `INSERT OR IGNORE INTO delivery_acks
           (agent_id, session_id, content_hash_hex, signer_pubkey, signature, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        agentId,
        sessionId,
        contentHashHex,
        signerPubkeyHex,
        Buffer.from(signature),
        Date.now(),
      );
    logger.info("content.delivery.ack.recorded", {
      agentName, sessionId, contentHash: contentHashHex, signerPubkey: signerPubkeyHex, correlationId,
    });
  } catch (err: unknown) {
    logger.error("content.delivery.ack.record.failed", {
      agentName, sessionId, contentHash: contentHashHex, correlationId,
      reason: extractErrorMessage(err),
      impact:
        "the counterparty's signed acknowledgement for this message could not be stored, so the " +
        "sealed receipt will report this message as not acknowledged even though it was. The " +
        "message itself was delivered and nothing about the conversation is affected",
      guidance:
        "This is a LOCAL storage fault. If it repeats, check free disk space and that the " +
        "agent's database is writable; the acknowledgement cannot be re-requested afterwards.",
    });
  }
}

/**
 * DOD-M15-DELIVERYACK-1 — the three facts, per message this side SENT, each standing alone.
 *
 * ⚠️ READ THE ASYMMETRY BEFORE USING THIS. Each fact is present or absent on its own and a
 * missing one is reported as missing and NOTHING MORE. There is deliberately no combined status,
 * no derived verdict, and no count — a message can be delivered, read and acted on with no
 * acknowledgement recorded here, because the acknowledgement can be lost exactly as the message
 * can. Anything that renders absence as fault is a defect, not a display choice.
 *
 *   ordered      — the RELAY assigned it a position. Read from `relay_ack_receipts`, which holds
 *                  the relay's own countersignature, scoped to THIS agent's pubkey so a loopback
 *                  session's two ends never read each other's.
 *   delivered    — the RELAY handed the bytes over. **This side holds no such evidence for any
 *                  message today, on either path**: the relay answers the RECIPIENT on pickup and
 *                  never tells the depositor. It is reported absent with that reason named rather
 *                  than fabricated from "our own send succeeded", which would be this machine
 *                  asserting a relay fact about itself. `069-ORDERPROOF` plus a pickup notice to
 *                  the depositor is what fills it.
 *   acknowledged — the RECIPIENT's own signature, from `delivery_acks`.
 */
export function readDeliveryFacts(
  db: DaemonDatabase,
  agentId: string,
  sessionId: string,
): Array<{
  seq: number | null;
  content_hash: string;
  ordered: { asserted_by: "relay"; relay_id: string; relay_timestamp: number; signature: string } | null;
  delivered: null;
  acknowledged: { asserted_by: "recipient"; signer_pubkey: string; signature: string; recorded_at: number } | null;
}> {
  const agentPubkey = (
    db.prepare("SELECT k_local_pubkey FROM agents WHERE agent_id = ?").get(agentId) as
      | { k_local_pubkey: string }
      | undefined
  )?.k_local_pubkey ?? "";
  /**
   * ⚠️ THE ROW KEY IS THE CONTENT HASH, NOT THE SEQUENCE, AND IT HAD TO BE.
   *
   * The first version drove this list from `transcript WHERE direction = 'sent'` and joined out
   * to the leaf for its hash. That reports nothing at all for a message whose leaf never landed —
   * which is exactly the message a reader most needs to see, because a send that never got a
   * position is one of the blameless ways a message goes missing. Keying on the hash means every
   * message this side has ANY evidence about appears, and each of the three facts is then
   * independently present or absent on it. `seq` joins in when this side holds a leaf and is null
   * when it does not; a null there is the ordinary shape, not a fault.
   */
  const seqByHash = new Map<string, number>();
  for (const l of db
    .prepare(
      `SELECT l.leaf_index AS seq, l.leaf_hash_hex AS hash_hex
         FROM session_tree_leaves l
         JOIN transcript t
           ON t.agent_id = l.agent_id AND t.session_id = l.session_id AND t.sequence = l.leaf_index
        WHERE l.agent_id = ? AND l.session_id = ? AND t.direction = 'sent'`,
    )
    .all(agentId, sessionId) as Array<{ seq: number; hash_hex: string }>) {
    seqByHash.set(l.hash_hex, l.seq);
  }

  const receipts = new Map<string, { relay_id: string; relay_timestamp: number; signature_hex: string }>();
  /**
   * `relay_ack_receipts` is created by `RelayReceiptStore`'s constructor, not by the session
   * schema, so on a daemon that has never opened a relay-witnessed session the table is simply
   * absent. That is not a degraded read and nothing is substituted for it: no table means no
   * relay ever countersigned a position here, which is the same fact as an empty table. The
   * existence check is explicit rather than a swallowed `catch`, so a genuine SQL fault still
   * throws instead of arriving as "nothing was ordered".
   */
  const relayTablePresent =
    db
      .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'relay_ack_receipts'")
      .get() !== undefined;
  if (relayTablePresent) {
    for (const r of db
      .prepare(
        `SELECT hash_hex, relay_id, relay_timestamp, signature_hex
           FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ?`,
      )
      .all(agentPubkey, sessionId) as Array<{ hash_hex: string; relay_id: string; relay_timestamp: number; signature_hex: string }>) {
      receipts.set(r.hash_hex, r);
    }
  }
  const acks = new Map<string, { signer_pubkey: string; signature: Uint8Array; recorded_at: number }>();
  for (const a of db
    .prepare(
      `SELECT content_hash_hex, signer_pubkey, signature, recorded_at
         FROM delivery_acks WHERE agent_id = ? AND session_id = ?`,
    )
    .all(agentId, sessionId) as Array<{ content_hash_hex: string; signer_pubkey: string; signature: Uint8Array; recorded_at: number }>) {
    acks.set(a.content_hash_hex, a);
  }

  const hashes = [...new Set([...seqByHash.keys(), ...receipts.keys(), ...acks.keys()])];
  hashes.sort((x, y) => (seqByHash.get(x) ?? Number.MAX_SAFE_INTEGER) - (seqByHash.get(y) ?? Number.MAX_SAFE_INTEGER));
  return hashes.map((hash) => {
    const receipt = receipts.get(hash);
    const ack = acks.get(hash);
    return {
      seq: seqByHash.get(hash) ?? null,
      content_hash: hash,
      ordered: receipt
        ? {
            asserted_by: "relay" as const,
            relay_id: receipt.relay_id,
            relay_timestamp: receipt.relay_timestamp,
            signature: receipt.signature_hex,
          }
        : null,
      delivered: null,
      acknowledged: ack
        ? {
            asserted_by: "recipient" as const,
            signer_pubkey: ack.signer_pubkey,
            signature: Buffer.from(ack.signature).toString("hex"),
            recorded_at: ack.recorded_at,
          }
        : null,
    };
  });
}
