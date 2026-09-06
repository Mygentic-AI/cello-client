/**
 * CELLO Daemon — TAKING A MESSAGE IN
 *
 * The inbound half of the content path, split out of `session-node-manager.ts` with its outbound
 * counterpart in `session-content-send.ts`. Everything between a frame arriving on the wire and a
 * row appearing in the transcript: the stream that carries it, the ordering record that places it,
 * the hash, the salt, the authorship proof, the screening gateway, the dedupe, the size bound, and
 * the ten distinct reasons a message can be refused.
 *
 * **Moved verbatim, comments included.** The comments here are the record of why each guard
 * exists, several of them recording a defect that was reintroduced once already. They are the
 * asset; they moved with the code they describe and none was summarised.
 *
 * `ingestReceivedContent` alone is ~1,000 lines and forty top-level statements, and it is not
 * decomposed here: every guard reads locals the guards above it declared, so lifting a phase out
 * needs either a state object or a signature nobody can read. Moving it intact preserves behaviour
 * exactly, which is the point of this pass; taking it apart is a separate piece of work.
 */
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor, decodeStructure1 } from "@cello-protocol/protocol-types";
import { openSessionContent } from "@cello-protocol/crypto";
import { CELLO_CONTENT_PROTOCOL_ID, type CelloNode } from "@cello-protocol/transport";
import { GATEWAY_UNAVAILABLE, GOVERNANCE_TIMEOUT, type SecurityGatewayClient } from "@cello-protocol/gateway";
import type { Stream } from "@libp2p/interface";
import { contentHashFor, resolveContentHashAlg } from "./wire-content-hash.js";
import { SALT_ADOPTION_LABEL_MAX } from "./session-salt-agreement.js";
import { CONTENT_ENCRYPTION_INBOUND_GUIDANCE, SESSION_CONTENT_ENCRYPTION_V1 } from "./content-encryption-status.js";
import { REFUSAL_KINDS } from "./refusal-reasons.js";
import { triageOrphanedContent } from "./orphan-triage.js";
import { extractErrorMessage } from "./error-message.js";
import { retentionSentence } from "./quarantine-framing.js";
import { LEAF_KIND_CTRL } from "./session-relay-client.js";
import { ACK_HASH_REASONS, AUTHORSHIP_SELF_CHAIN_MISMATCH, AUTHORSHIP_SESSION_MISMATCH, CONTENT_MAX_INBOUND_STREAMS, CONTENT_STREAM_LINGER_MS, RECEIVED_BUFFER_CAP, REFUSAL_MAY_STILL_ARRIVE, REFUSAL_NO_OTHER_ROUTE, type AckHashReason, type ReceivedContentEntry } from "./session-node-types.js";
import type { SessionContentPipelineContext } from "./session-content-context.js";
import type { SessionContentSender } from "./session-content-send.js";

export class SessionContentIngest {
  readonly #ctx: SessionContentPipelineContext;
  /**
   * The outbound half — reached for exactly ONE thing, and the reason is worth stating.
   *
   * The counterparty's delivery acknowledgement arrives on the SAME stream this class is already
   * reading, so the receiver is the only code positioned to notice it; what it settles, though, is
   * a message WE sent, whose timer and parked copy belong to the sender. Rather than give both
   * halves a claim on that state, the frame is handed across this one edge.
   */
  readonly #send: SessionContentSender;

  constructor(ctx: SessionContentPipelineContext, send: SessionContentSender) {
    this.#ctx = ctx;
    this.#send = send;
  }

  /**
   * DOD-M12B-REVIVE-RELAY-1 — the relay witness leaf handler, shared by establishment and revival.
   *
   * Extracted because a REVIVED session must register the same handler. It was inline in
   * `#connectSessionRelay`, so revival — which never called that at all — had no live inbound path:
   * every message fell back to the five-minute mailbox poll, which is why a reconnected session took
   * three minutes to deliver what a fresh one delivers in seconds, and why doorbells stopped firing.
   *
   * A revived session that behaves differently from a fresh one is the defect. This is one of the
   * two halves of making them the same.
   */
  relayLeafHandler(agentName: string, sessionId: string, correlationId: string) {
    return (frame: {
      sequence_number: number;
      leaf_kind: number;
      authored_by_us: boolean;
      structure1_cbor: Uint8Array;
    }): void => {
        // The counterparty's witnessed leaf arrived with its canonical sequence. The
        // plaintext is delivered separately over the direct content stream; this is the
        // ordering/witness signal. Full canonical-sequence reconciliation against the
        // local tree is MSG-001-3b (J-CONTENT).
        this.#ctx.logger.info("session.relay.leaf.delivered", {
          sessionId,
          sequenceNumber: frame.sequence_number,
          leafKind: frame.leaf_kind,
          correlationId,
        });
        // DOD-MSG-4 (strict in-order): record the relay-witnessed canonical sequence for the
        // counterparty's MSG leaves. The relay is the ordering authority; structure1_cbor =
        // [version, content_hash(32), sender_pubkey, session_id, last_seen_seq, ts] (+ last_seen_hash
        // at index 6 on a v2 claim — 020-ACKHASH; content_hash stays at 1). The relay sequence
        // is 1-based and global per session; the daemon tree is 0-based — normalize with -1. Only
        // COUNTERPARTY leaves (the ones B will ingest); our own echoed leaf already lands via the
        // send path. The gate (ingestReceivedContent) reads this map to hold out-of-order arrivals.
        if (!frame.authored_by_us && frame.leaf_kind !== LEAF_KIND_CTRL) {
          const s1 = decodeStructure1(frame.structure1_cbor);
          if (s1.ok) {
            if (frame.sequence_number > 0) {
              this.recordWitnessedSequence(
                agentName,
                sessionId,
                Buffer.from(s1.fields.contentHash).toString("hex"),
                frame.sequence_number - 1,
              );
            }
          } else {
            // `structure1Reason`, not `error` — review F6. This is a named refusal code, and putting
            // it in a field called `error` reads as an exception message to anyone scanning logs.
            // The old `try` here also wrapped `recordWitnessedSequence`, so a throw from THAT was
            // reported as a decode failure; the decode no longer throws, and the split is deliberate.
            this.#ctx.logger.warn("session.relay.leaf.witness.decode.failed", {
              sessionId,
              structure1Reason: s1.reason,
              correlationId,
            });
          }
        }
        // M7-UPGRADE-002: auto-acknowledge close. When the COUNTERPARTY's SEAL ctrl leaf (0x02)
        // arrives and B has verified the content, B's OWN node auto-co-signs the responder SEAL
        // leaf — no agent prompt — so the bilateral seal completes promptly instead of degrading
        // to unilateral on a slow/busy/crashed agent. Never auto-ack our OWN echoed ctrl leaf.
        if (frame.leaf_kind === LEAF_KIND_CTRL && !frame.authored_by_us) {
          this.#ctx.maybeAutoAcknowledgeSeal(agentName, sessionId, correlationId);
        }
    };
  }

  /**
   * DOD-M12B-ABANDON-NOTIFY-1 — drive the REAL inbound content handler with one framed message and
   * a claimed peer identity.
   *
   * The handler is registered on a live libp2p node, so without this the only way to reach its
   * branches is a full two-node transport fixture — which is why the session-abandoned branch and
   * its peer pinning had no coverage at all. This feeds the same function the protocol handler
   * calls, including the authentication check, rather than a copy of its logic.
   */
  async handleContentFrameForTest(agentName: string, sessionId: string, framedBytes: Uint8Array, remotePeerId?: string): Promise<void> {
    const source = {
      async *[Symbol.asyncIterator]() { yield framedBytes; },
      close: async (): Promise<void> => {},
      abort: (): void => {},
      status: "closed",
    } as unknown as Stream;
    await this.#handleContentStream(agentName, sessionId, source, remotePeerId);
  }


  async ingestReceivedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
    /**
     * DOD-FRONTIER-STRAND-1 AC1: the relay-assigned canonical position for THIS message, taken from
     * the verified ordering record by the caller. Passed EXPLICITLY rather than recovered from
     * `#witnessedSeq`, because that map is keyed by content hash — so two byte-identical messages
     * collapse in it before dedup is ever consulted, which is the whole defect. Absent when the
     * session has no relay witness (relay-degraded): see the announced fallback below.
     */
    canonicalSeqIn?: number,
    /**
     * DOD-M15-SEALWIRE-1 part B1 — the algorithm the SENDER named on the frame, verbatim.
     *
     * `undefined` means the frame carried no name, which is a peer that predates the field and is
     * the one case we may safely assume `sha256` for. It is threaded through rather than read off
     * the session, because whether a hash is salted is a fact about the FRAME and its sender, never
     * about what this side happens to hold.
     */
    contentHashAlgIn?: string | null,
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: the VERIFIED authorship proof for this message, when the caller
     * has one. The caller is the only place that has it — `#verifyAuthorshipClaim` verifies the
     * signature the frame carries beside the sender's own signed bytes, against the key inside those
     * bytes, and matches the signer to this session's counterparty. That result reaches here or
     * nowhere.
     *
     * ⚠️ IT USED TO NAME `#recordFrameOrdering`, and that was accurate until
     * `DOD-M15-AUTHORSHIP-ABSENT-1`: the signature arrived only inside the RELAY's Structure 2, so
     * checking authorship needed a relay record. It does not now, and the old name sends a reader to
     * a method that answers a different question. Rewritten, not deleted — that dependence is the
     * defect the unit removed.
     *
     * Optional, because the PARK route ingests without it: recovered mail proves its sender by the
     * mailbox envelope instead. The row records which it was, so absence is never silent.
     */
    verifiedAuthorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
    /**
     * 024-ORPHANTRIAGE — the key whose signature VERIFIED on a frame we could not tie to a session.
     *
     * Read by the orphan branch below and NOWHERE ELSE. It exists because the daemon establishes,
     * cryptographically, that the sender holds a private key — and then discarded that the instant
     * the session lookup came back empty, leaving the operator advised to go and make contact with
     * whoever sent a message for a conversation that does not exist.
     *
     * Absent on the park-recovery caller, which cannot reach the orphan branch at all:
     * `authenticateParkedEntry` refuses `counterparty_unknown` from the same missing record first.
     */
    verifiedSignerUnmatched?: Uint8Array,
  ): Promise<{ ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number; screenedOut?: boolean } | { ok: false; reason: string }> {
    // The transcript is frozen ONLY once it is COMMITTED + signed — 'sealed' or
    // 'seal_interrupted_pending' (the bilateral seal commitment) — because a later FROST
    // notarization attests that exact root; a late leaf would diverge from it.
    //
    // MSG-001-3b recovery: a merely 'interrupted' session is NOT yet committed. The
    // counterparty's last message(s) may have been parked while this party was offline, so its
    // local transcript is INCOMPLETE (not frozen-final). Recovering that parked content COMPLETES
    // the local view to match the counterparty BEFORE the bilateral seal — it is not a resumption
    // (no new activity, no re-accept) and its root was never committed. So allow 'active' AND
    // 'interrupted'; reject only the two committed states.
    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    // DOD-UNREAD-1 D4a: NEVER record content you cannot attribute. With no sessions row there is
    // no counterparty — the transcript has no counterparty column, so a row written here is
    // unattributable forever, counted unread by getUnreadSummary, and unreadable by cello_receive
    // (the phantom-session residue). The old "(No DB row = test-only path, allowed.)" fallback
    // papered that in with senderPubkey="unknown". Refuse loudly instead; the content stays
    // un-acked, so a live sender redelivers once the session actually exists. After D3
    // (DOD-INBOUND-GUARD-1) this path is unreachable from the wire — a fail-loud assertion.
    /**
     * DOD-M15-REFUSEDEVIDENCE-1 — HOISTED from below the hash cross-check, so that every refusal
     * above that point can retain the bytes under it. Same expression, earlier.
     *
     * It is the SENDER'S CLAIM at this point — nothing has checked it yet, and on a
     * `content_hash_mismatch` it provably does not describe these bytes. The quarantine read
     * recomputes its own hash over what was retained rather than reprinting this one.
     */
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    if (!record) {
      /**
       * RETAINED FIRST, because the triage below now tells the operator whether there is an artifact
       * to report — and that claim has to be made after the write, never before it (023 review F3).
       *
       * This is the case retention matters most for. A message for a session this daemon has no
       * record of is the least explicable thing that can arrive, so it is the thing an operator has
       * the least other way to show anyone. There is no `sessions` row and no counterparty, so no
       * tier — `#quarantineRefusedContent` bounds it at UNKNOWN and files it at a negative position,
       * outside the chain it never joined.
       */
      const keptOrphan = this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, "session_orphaned", content, contentHashHex, { correlationId });
      /**
       * 024-ORPHANTRIAGE — TWO ACTIONS EXIST AND THE EVIDENCE DECIDES WHICH.
       *
       * The advice here used to be *"ask the counterparty to start a NEW session."* When the message
       * is a stranger probing a peer id, obeying that advice is the probe succeeding: it confirms
       * somebody is home and that this agent answers, from a message that was refused.
       *
       * All three signals are read from things the sender does not control — their signature is
       * checked against the key inside their own signed bytes, "known" comes from OUR address book,
       * and "ongoing" comes from OUR transcript rows rather than the sequence number they chose.
       */
      const evidence = this.#ctx.refusals.orphanEvidence(agentName, sessionId, verifiedSignerUnmatched);
      const triage = triageOrphanedContent(evidence, retentionSentence(sessionId, keptOrphan));
      /**
       * BOTH SURFACES, per Invariant 2. The log is the durable forensic record and carries the
       * signals structurally — this is where an investigation days later reads what was known and
       * when. The notice below is the control: it is what the agent actually reads and acts on.
       */
      this.#ctx.logger.warn("session.content.orphaned", {
        agentName, sessionId, correlationId,
        signerPubkey: evidence.signerPubkeyHex ?? "(no verifiable signature)",
        signatureVerified: evidence.signerPubkeyHex !== null,
        // Review F6: `"not_checked"` where nothing was measured, never a `false` that reads as a
        // reading. An investigator filtering this event is the only person who will ever ask.
        knownContact: evidence.knownContact,
        ongoingConversation: evidence.ongoingConversation,
        action: triage.action,
        // 023: whether the evidence the triage points at actually exists.
        retained: keptOrphan !== null,
        impact: triage.impact,
      });
      // DOD-M15-NO-SILENT-REFUSAL-1. The notice is written even though there is no session row —
      // the store is keyed (agent_id, session_id) and holds no foreign key to `sessions` precisely
      // so this case can be recorded. A refusal for a session that does not exist here is the one
      // the operator has the least other way to learn about.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "session_orphaned", {
        kind: REFUSAL_KINDS.REFUSED,
        impact: triage.impact,
        guidance: triage.guidance,
      });
      return { ok: false, reason: "session_orphaned" };
    }
    // DOD-TERMINAL-WAKE-1 (review F1): `abandoned` belongs here too. It is terminal and, unlike
    // `interrupted`, can NEVER complete — there is nothing left to append to and no seal to join.
    // Without it, late content for a force-abandoned session was accepted: a leaf was written, the
    // `cello_message` doorbell rang, the away-response and Telegram doorbell fired, and
    // `cello_receive` handed it over as live work. That is the same "agent obeys a directive out of
    // a conversation that has ended" harm as the sealed case, reached with no restart at all.
    //
    // `currentStatus` carries the real status onward: the content-park disposition and the operator
    // must be able to tell an abandoned session from a sealed one, and `session_committed` alone is
    // the exit point, not the cause.
    if (
      record.status === "sealed" ||
      record.status === "seal_interrupted_pending" ||
      record.status === "abandoned"
    ) {
      this.#ctx.logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "session_committed",
        currentStatus: record.status,
        correlationId,
      });
      // DOD-M15-REFUSEDEVIDENCE-1 — RETAINED. A post-seal straggler on the DIRECT path kept nothing
      // before this: `sealed_session_annex` covers the park-drain and held-drift routes, not this
      // exit. Something arriving into a signed, closed conversation is exactly the kind of thing an
      // operator later wants to produce.
      this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, "session_committed", content, contentHashHex, {
        senderPubkeyHex: record.counterparty_pubkey ?? null, correlationId,
      });
      /**
       * DOD-M15-REFUSALTERMINAL-1 — the retention call above is also what STOPS THE WORK: it runs
       * the terminal funnel, and `session_committed` is the one reason in it.
       *
       * Without that, the relay's next redelivery of the witness leaf armed another park fetch,
       * which drained, verified, arrived here, and was refused again — measured at ~2 per second
       * for 62 hours on one message. `#markContentResolved` could not be reused: this content did
       * not land, and saying that it did is a lie a future reader would act on.
       */
      // DOD-M15-NO-SILENT-REFUSAL-1. `currentStatus` on the log line carries the REAL status —
      // sealed, seal_interrupted_pending or abandoned — and the notice must not flatten those into
      // one claim, so it names the record as frozen rather than asserting which way it ended.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "session_committed", {
        kind: REFUSAL_KINDS.REFUSED,
        impact:
          `This conversation is closed (it ended as "${record.status}"), so the message could not be delivered and neither can anything else they send to it. A closed conversation is signed and cannot be added to — that is what closing it means. Nothing is wrong on your side.`,
        guidance:
          "There is nothing to repair here. If they still have something to say, ask them to start a NEW conversation — a closed one cannot be reopened, and it is worth telling them, because they may not realise it ended. Read what was said before it closed with cello_transcript.",
      });
      return { ok: false, reason: "session_committed" };
    }

    /**
     * DOD-M15-SEALWIRE-1 part B1 — VERIFY UNDER THE ALGORITHM THE SENDER NAMED.
     *
     * Three outcomes and they must stay apart, because two of them are version differences and only
     * the third is evidence of tampering. Collapsing them is how a routine skew becomes a security
     * incident in the operator's log, and how a real tamper gets dismissed as a skew.
     */
    /**
     * ⚠️ `content_hash_alg` IS NOT COVERED BY ANY SIGNATURE — review F1, and it shapes both branches
     * below.
     *
     * The sender's signature is over `structure1_cbor`, which binds `content_hash`. It does NOT bind
     * the frame envelope, so this field is an unauthenticated CLAIM by whoever sent the frame. That
     * is fine for choosing how to verify — a wrong choice simply fails — but it means neither branch
     * may state, as fact, anything it learned only from this field.
     *
     * It also means both branches MUST mark the session unverifiable. Before B1 every frame that
     * failed the cross-check reached `#contentDesynced`, which gates auto-co-signing and unilateral
     * ratification. Returning early here would have let a sender bypass the tamper detector by
     * appending one unsigned string: sign hash H, send different bytes, add an unreadable algorithm
     * name, and the receiver refuses politely, records nothing, and auto-co-signs at seal time.
     */
    const algResolved = resolveContentHashAlg(contentHashAlgIn);
    if (!algResolved.ok) {
      // A NAME WE CANNOT READ. Not a legacy peer — an unreadable one. There is no value to compare
      // against, so `content_hash_mismatch` here would be an exit-point label standing in for
      // "their build is newer than ours" (Invariant 2). Refused by its own name instead.
      this.#ctx.markContentUnverifiable(agentName, sessionId, "unverifiable");
      this.#ctx.refusals.noteUnreadableAlgFrame(agentName, sessionId, contentHash, algResolved.value);
      this.#ctx.logger.error("session.content.cross_check.failed", {
        sessionId, correlationId,
        reason: "content_hash_alg_unknown",
        declaredAlg: algResolved.value,
        // States only what is KNOWN. The old wording said "nothing was altered and nobody did
        // anything wrong" and "Do not treat this as a security event" — both inferred from the
        // unsigned field, i.e. from the attacker in the case that matters.
        impact: "this message could not be verified, so it was NOT ingested and NOT shown. The algorithm name is a claim by the sender and is not covered by any signature, so it does not establish what they actually did. This session will not auto-co-sign at close.",
        guidance: "Almost always their CELLO build is newer than this one: ask which version they are running, and upgrade. If they are on the SAME version as you, that explanation does not hold and the frame was malformed or crafted — do not close the session by auto-acknowledgement.",
      });
      // DOD-M15-REFUSEDEVIDENCE-1 — RETAINED. The algorithm name is an unsigned claim by whoever
      // sent the frame, so this branch is reachable by crafting as well as by version skew, and the
      // crafted case is one to be able to show someone.
      this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, "content_hash_alg_unknown", content, contentHashHex, {
        senderPubkeyHex: record.counterparty_pubkey ?? null, correlationId,
      });
      // DOD-M15-REFUSED-INBOUND-SILENT-1: the SAME strings the log just carried, to the operator.
      // This reason is a version skew, so it affects every message from that counterparty — without
      // this the conversation goes permanently quiet and they conclude the peer stopped replying.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "content_hash_alg_unknown", {
        kind: REFUSAL_KINDS.REFUSED,
        impact: "this message could not be verified, so it was NOT ingested and NOT shown. The algorithm name is a claim by the sender and is not covered by any signature, so it does not establish what they actually did. This session will not auto-co-sign at close.",
        guidance: "Almost always their CELLO build is newer than this one: ask which version they are running, and upgrade. If they are on the SAME version as you, that explanation does not hold and the frame was malformed or crafted — do not close the session by auto-acknowledgement.",
      });
      return { ok: false, reason: "content_hash_alg_unknown" };
    }
    let computed: Uint8Array;
    try {
      computed = contentHashFor(content, {
        alg: algResolved.alg,
        // The salt is OURS — the sender's frame never carries one, and could not be trusted if it
        // did. A salted frame we hold no salt for throws below and is refused by name.
        salt: this.#ctx.salts.getSessionSalt(agentName, sessionId),
      });
    } catch (err: unknown) {
      // Reached when the peer named the salted algorithm and this side holds no salt for the
      // session — the agreement never completed, or its record is gone. Distinct from a mismatch
      // for the same reason as above: nothing was tampered with, we simply cannot check it.
      this.#ctx.markContentUnverifiable(agentName, sessionId, "unverifiable");
      this.#ctx.logger.error("session.content.cross_check.failed", {
        sessionId, correlationId,
        reason: "content_hash_salt_unavailable",
        declaredAlg: algResolved.alg,
        detail: extractErrorMessage(err),
        // "Nothing was altered" was the same mistake as the branch above: it is not knowable from
        // here. What IS knowable is that we could not check.
        impact: "this message could not be verified — the sender says it is salted and this side holds no salt for the session — so it was NOT ingested and NOT shown. This session will not auto-co-sign at close.",
        // Review F6: `#getSessionSalt` returns null for THREE conditions and only one of them wants
        // a close. A read failure and a corrupt row both leave us holding no salt, which is exactly
        // what makes the agreement re-offer a contribution and repair itself on the next connect.
        //
        // The adoption refusal is the FOURTH, added with the Decision #8 guard, and it is the only
        // one that does not repair: this side declined the salt permanently for this session, so
        // waiting for a reconnect is exactly the wrong advice. Leaving it out of this list would
        // have sent an operator to look for a read failure that is not there and never will be.
        // DOD-M15-SALTSPLIT-1 review MEDIUM-3: `session.salt.discarded` is the FIFTH cause, and it
        // was added by the discard without appearing in this tree. Without it an operator whose salt
        // was deliberately dropped is sent to look for three events that will not be there and then
        // told a fifth thing that is false — the agreement DID complete here, and was then undone on
        // purpose.
        guidance: "Look for session.salt.discarded first: if it is there, this side dropped its salt because the counterparty said it could never hold one, the agreement did complete and was deliberately undone, and a new session is the repair. Otherwise look for session.salt.adoption.refused: if it is there, this side declined the salt because the session had already hashed messages, that is permanent for this session, and reconnecting will NOT fix it — close the session and start a new one. Otherwise look for session.salt.read.failed or session.salt.persist.failed. If either is present the agreement re-runs on the next reconnect and this repairs itself — wait for that before doing anything. If none of the four is present, the agreement never completed with this counterparty: close the session and start a new one. In every case the transcript up to here is intact.",
      });
      // DOD-M15-REFUSEDEVIDENCE-1 — RETAINED. We could not check it, which is precisely why the
      // bytes have to survive: the question of what they actually were stays open, and a hash we
      // could not verify answers none of it.
      this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, "content_hash_salt_unavailable", content, contentHashHex, {
        senderPubkeyHex: record.counterparty_pubkey ?? null, correlationId,
      });
      // DOD-M15-REFUSED-INBOUND-SILENT-1 — and this branch needed it MORE than the two that had it.
      //
      // It was refused, logged with a full impact and guidance, not ingested, not shown — and the
      // operator was told nothing. Twenty lines below the branches that were wired, in the same
      // function, with the same shape.
      //
      // One of its four causes is permanent, and the guidance above says so in its own words: an
      // adoption refusal means this side declined the salt for the life of the session and
      // reconnecting will NOT fix it. So the failure this line exists to close — the conversation
      // goes quiet, the explanation sits in a log nobody opens — was still live on the one branch
      // that never repairs itself.
      //
      // The guidance is passed by reference to the log's own text rather than duplicated: a second
      // copy is a second thing to keep true, and the log's version is the one that gets maintained.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "content_hash_salt_unavailable", {
        kind: REFUSAL_KINDS.REFUSED,
        impact:
          "this message could not be verified — the sender says it is salted and this side holds no salt for the session — so it was NOT ingested and NOT shown. This session will not auto-co-sign at close.",
        guidance:
          "If session.salt.discarded is present, this side dropped its salt on purpose because the counterparty said it could never hold one — a new session is the repair. If this side refused the salt because the session had already hashed messages, that is PERMANENT for this session and reconnecting will not fix it — close the session and start a new one. Otherwise the salt agreement re-runs on the next reconnect and this repairs itself. Check session.salt.discarded and session.salt.adoption.refused in the log to tell which. The transcript up to here is intact either way.",
      });
      return { ok: false, reason: "content_hash_salt_unavailable" };
    }
    if (Buffer.from(computed).toString("hex") !== contentHashHex) {
      this.#ctx.logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "content_hash_mismatch",
        // WHICH algorithm the comparison ran under. Without it, a mismatch is unfalsifiable from the
        // log: an operator cannot tell "the bytes were altered" from "we checked it the wrong way".
        declaredAlg: algResolved.alg,
        correlationId,
      });
      // M7-UPGRADE-002 (SI-002): a tamper makes this session's content unverifiable — the
      // auto-acknowledge gate must never auto-co-sign it. The session stays alive (DOD-MSG-7),
      // but the responder seal now requires the agent's explicit decision, not an auto-ack.
      this.#ctx.markContentUnverifiable(agentName, sessionId, "tampered");
      /**
       * DOD-M15-REFUSEDEVIDENCE-1 — RETAINED, and this is the highest-value row in the table.
       *
       * A tampered frame is the one case where the message and the sender's commitment PROVABLY
       * disagree, and the proof only exists while both halves do. Before this, the bytes went on the
       * floor and all that survived was a hash of something nobody still had.
       *
       * `verifiedAuthorship` is stored when the caller verified a signature over the sender's own
       * bytes. That is what makes the row evidence rather than a note: the signature is checked
       * against the key inside the sender's signed bytes, not against anything this side chose.
       */
      this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, "content_hash_mismatch", content, contentHashHex, {
        senderPubkeyHex: this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId))?.counterpartyPubkey ?? record.counterparty_pubkey ?? null,
        ...(verifiedAuthorship ? { authorship: verifiedAuthorship } : {}),
        correlationId,
      });
      // DOD-M15-REFUSED-INBOUND-SILENT-1. Deliberately does NOT include the content or the hashes:
      // it failed verification, and showing it is the injection path this cross-check closes.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "content_hash_mismatch", {
        kind: REFUSAL_KINDS.REFUSED,
        impact:
          "a message arrived whose bytes do not match the hash the sender committed to, so it was NOT ingested and NOT shown. This session will not auto-co-sign at close.",
        guidance:
          "Either the message was altered in transit or the sender's record is wrong. Ask the counterparty to resend. Do not close this session by auto-acknowledgement — seal it only by an explicit decision.",
      });
      return { ok: false, reason: "content_hash_mismatch" };
    }

    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    const senderPubkey = entry?.counterpartyPubkey ?? record.counterparty_pubkey;
    if (!senderPubkey) {
      // DOD-UNREAD-1 D4a (AC4, supersedes the MSGWAKE-1 F1 paper-in): the schema requires
      // counterparty_pubkey NOT NULL, so this is unreachable unless a row was hand-crafted empty.
      // Either way, "unknown" is never written to a transcript row — refuse instead.
      this.#ctx.logger.warn("session.content.sender_unresolved", { sessionId, agentName, correlationId });
      // DOD-M15-REFUSEDEVIDENCE-1 — RETAINED, with NO sender key, because there is none and that
      // absence is the evidence. The guidance below says to report this; this is the artifact there
      // is to report. Bounded at the UNKNOWN tier — there is no contact to look a tier up on, which
      // is the same fact that made it unattributable.
      const keptUnresolved = this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, "sender_unresolved", content, contentHashHex, { correlationId });
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "sender_unresolved", {
        kind: REFUSAL_KINDS.REFUSED,
        impact:
          "A message arrived that this daemon could not attribute to anyone, so it was not delivered. This conversation's record does not say who the other party is, which a conversation opened normally always does. TREAT THIS AS HOSTILE: a message that cannot be tied to a sender is far more likely to be a probe or an attack than a fault.",
        /**
         * ⚠️ NO "WHEN IN DOUBT" HERE — Andre, 2026-09-03: *"This message has no sender, the chances
         * that it is hostile are very high. When in doubt? No. Just report it."*
         *
         * That hedge belongs on the ambiguous branch in `024-ORPHANTRIAGE`, where a verified
         * signature from a known contact leaves a real judgement to make. There is no judgement
         * here. Softening it would teach the operator to weigh a case that does not need weighing.
         *
         * ⚠️ IT NAMES NO REPORTING DESTINATION, and that is still true — but HALF of the reason has
         * gone, so the sentence is rewritten rather than left to read as though nothing changed.
         *
         * It used to rest on two facts: `CELLO_Reporting` does not exist (`DOD-M15-ORPHANTRIAGE-1`,
         * still open) and **the message itself is not retained**. The second is no longer true —
         * `DOD-M15-REFUSEDEVIDENCE-1` retains it, and the guidance below now says so and names where
         * it is. Telling an operator to report something while keeping nothing to report was the
         * gap; naming a destination nobody can reach would be Invariant 4's failure. So: the
         * artifact is named now, the destination when 024 lands.
         *
         * ⚠️ THE ROTATION ADVICE IS MEASURED, NOT ASSUMED. `#startReceiverNode` mints the standing
         * receiver's transport key with `randomBytes(32)` and never persists it, so a logout/login
         * genuinely yields a NEW peer id and fresh directory connections. **And the bound is stated
         * in the same breath:** session nodes DO persist their seed (`DOD-M12B-SESSION-SEED-1`, so a
         * revived conversation keeps its address), so this rotates the front door and not the doors
         * already open. Telling an operator to rotate without that bound would have them believe
         * they had closed something they had not.
         */
        guidance:
          // "That is the artifact to show someone" is NOT appended: it would be false on the branch
          // where nothing was retained, which is the branch this sentence exists to be honest about.
          "Report this. " + retentionSentence(sessionId, keptUnresolved) +
          "Do not try to reply — there is no one to reply to, and answering an unattributable message is what a probe is looking for. " +
          "Then rotate your address: run cello logout followed by cello login. Your standing receiver's network identity is generated fresh each time it starts and is never stored, so this gives you a new one and rebuilds your connections to the directory — anyone holding the old address is left talking to something that no longer answers. " +
          "It does NOT change the addresses of conversations you already have open: those identities are kept on purpose so an interrupted conversation can resume. " +
          "This conversation cannot be repaired: close it with cello_close_session, and open a new one yourself if you were expecting someone. See session.content.sender_unresolved in the daemon log.",
      });
      return { ok: false, reason: "sender_unresolved" };
    }

    // DOD-MSG-5: a content_hash satisfies AT MOST ONE Merkle leaf, exactly once. If this hash is
    // already a leaf in the tree — it arrived BOTH directly and via the relay-park backstop, or it
    // is a replay — do NOT append a second leaf and do NOT double-count it. The recipient already
    // holds this message at its assigned sequence. (In the normal single-delivery case this find is
    // -1, so the live/recover append paths are unchanged.)
    // ─── DOD-FRONTIER-STRAND-1 AC1: the discriminator is the POSITION, not the content ───
    //
    // The old rule ("a content_hash satisfies AT MOST ONE Merkle leaf") is false whenever two
    // genuinely distinct messages match byte-for-byte — and two instances of the same model,
    // answering the same message with similar context, collide far more readily than humans do.
    // That is what stranded session dbb93dfc... for a week: an away responder fired twice with
    // identical text, the sender appended both, the receiver dropped the second as a "redelivery",
    // and the two frontiers disagreed forever. No receipt was ever possible.
    //
    // The relay already assigns every submission a unique position: a REDELIVERY carries the same
    // position, a genuinely new identical message carries a NEW one. So a duplicate is the same
    // hash AT THE SAME POSITION -- never the same hash anywhere.
    const tree = this.#ctx.getSessionTree(agentName, sessionId);
    let existingIdx: number;
    if (canonicalSeqIn !== undefined && canonicalSeqIn >= 0 && tree.hashAt(canonicalSeqIn) === contentHashHex) {
      // The relay position holds exactly this content: a redelivery.
      existingIdx = canonicalSeqIn;
    } else if (canonicalSeqIn !== undefined && canonicalSeqIn >= 0 && canonicalSeqIn >= tree.size()) {
      // The position is at or beyond the frontier, so it cannot be a leaf we already hold. A
      // genuinely new message — including one byte-identical to an earlier leaf, which is the whole
      // point of AC1.
      existingIdx = -1;
    } else if (canonicalSeqIn !== undefined && canonicalSeqIn >= 0) {
      // ─── POSITION DRIFT (review F2, a regression this fix introduced and this branch repairs) ───
      //
      // `canonicalSeqIn < tree.size()` yet that slot holds different content, so **leaf index is no
      // longer the relay position** and the position cannot be used as an index into the tree. That
      // is §7a's drift: a first message whose relay submit failed is appended locally and never
      // counted by the relay, leaving the local record permanently one ahead.
      //
      // Using the position as an index here made a TRUE REDELIVERY append a second leaf — measured:
      // tree size 3 where the pre-fix code correctly gave 2. That is the "too permissive" direction,
      // and it inflates this side's tree against the counterparty's: the strand, from the other end.
      //
      // So under drift, fall back to the content-hash rule. It is weaker — it still cannot tell two
      // identical messages apart — but it is CORRECT about redelivery, which is the failure actually
      // reachable here, and it is exactly the pre-existing behavior, so this is not a regression in
      // either direction. Loudly announced, because the ambiguity is real and the drift is the thing
      // that should be fixed (DOD-FIRSTMSG-WITNESS-1 closes the producer).
      existingIdx = tree.indexOfHash(contentHashHex);
      // Announce only when the fallback actually DECIDED something (it found a duplicate). When it
      // finds nothing the message simply appends, `session.content.sequence_behind_tree` already
      // reports the drift itself, and a second warn on every message of a drifted session would
      // bury the case that matters. A signal that fires on the normal case is not a signal.
      if (existingIdx >= 0) this.#ctx.logger.warn("session.content.dedup.position_drifted", {
        sessionId,
        agentName,
        contentHashHex,
        canonicalSeq: canonicalSeqIn,
        treeSize: tree.size(),
        dedupedAt: existingIdx,
        reason: "leaf_index_is_not_relay_position_fell_back_to_content_hash",
        correlationId,
      });
    } else {
      // RELAY-DEGRADED: no witness, so no discriminator exists and the content-hash rule is all
      // there is. Keeping it preserves today's protection against real redelivery and today's blind
      // spot for identical messages -- the strand can still form on this path. Section 5a permits
      // proceeding rather than refusing (losing content is worse than mis-ordering it), but only
      // ANNOUNCED: a silent fallback is exactly how this went a week unnoticed. Fires only when the
      // hash actually matches, so it marks a real decision rather than every unwitnessed message.
      existingIdx = tree.indexOfHash(contentHashHex);
      // Gated exactly as its sibling `session.content.unwitnessed` is (see :3933): a session with NO
      // RELAY ATTACHED has no witness BY DESIGN, so warning there would fire on every message of a
      // normal no-relay session and bury the case that means something. A signal that fires on the
      // normal case is not a signal. The reason distinguishes the two shapes rather than asserting
      // the relay is absent — the position can also be missing because this particular frame carried
      // no ordering record while the relay is perfectly healthy.
      if (existingIdx >= 0 && this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId))?.relayClient) {
        this.#ctx.logger.warn("session.content.dedup.unwitnessed", {
          sessionId,
          agentName,
          contentHashHex,
          sequenceNumber: existingIdx,
          reason: "no_ordering_record_deduped_on_content_hash",
          correlationId,
        });
      }
    }
    if (existingIdx >= 0) {
      this.#ctx.logger.info("session.content.deduplicated", {
        sessionId,
        contentHashHex,
        sequenceNumber: existingIdx,
        witnessed: canonicalSeqIn !== undefined,
        correlationId,
      });
      // appendedCount 0 — a dedup appends NO new leaf, so a recover that re-pulls an already-ingested
      // entry (e.g. after auto-recover already drained it) must not count it as a fresh recovery.
      return { ok: true, leafIndex: existingIdx, sequenceNumber: existingIdx, appendedCount: 0 };
    }

    // M8C-ABUSE-1 (reviewer HIGH fix, D18): per-session total-size cap (anti-drip-feed) —
    // "whitelisted senders bounded only by disk" (DoD), so a known contact is exempt entirely.
    // MUST run BEFORE the hold-branch below — the original placement (after it) let a
    // non-contact sender drip-feed unbounded bytes by making every message arrive "out of order"
    // relative to the relay witness (held content skipped the cap entirely, then #releaseHeld
    // appended it later with no re-check). Accounts for bytes already committed AND bytes
    // currently sitting in the hold buffer (multiple held chunks could otherwise each individually
    // pass the check while cumulatively exceeding it once released). Runs BEFORE the M9 screening
    // seam below (cheap + synchronous — fail fast on volume before spending gateway compute on
    // content headed for rejection anyway); both gates are independent and either rejects on its
    // own criteria, so ordering between them does not change correctness.
    {
      // DOD-TIER-2 AC2: the per-session byte cap is the sender's TIER cap (DEFAULT_TIER_BOUNDS),
      // applied to EVERY sender — no tier is unbounded (INV-TIER-BOUND), so a contact is no longer
      // "exempt entirely". A stranger (no row → UNKNOWN) keeps the 25 MB cap; KNOWN+ get more.
      const senderTier = this.#ctx.records.getTier(agentName, senderPubkey);
      const cap = this.#ctx.records.resolveTierBound(agentName, senderTier, "max_bytes");
      const priorTotal = this.#ctx.queries.getReceivedBytesTotal(agentName, sessionId);
      const heldTotal = this.#ctx.held.getHeldBytesTotal(agentName, sessionId);
      if (priorTotal + heldTotal + content.length > cap) {
        this.#ctx.logger.warn("session.content.abuse_bound.session_size_exceeded", {
          sessionId,
          agentName,
          senderPubkey,
          priorTotal,
          heldTotal,
          incoming: content.length,
          cap,
          tier: senderTier,
          correlationId,
        });
        this.#ctx.notices.noteSizeCapRefusal(agentName, sessionId, cap, senderTier);
        return { ok: false, reason: "session_size_limit_exceeded" };
      }
    }

    // M9-CORE-001: the inbound screening seam (INV-5). Screen here — after the content is proven
    // authentic (hash cross-check) and confirmed not a duplicate, before it is either held for
    // ordering or appended to the agent-facing buffer. This is the SINGLE inbound funnel: direct
    // arrivals, recovered/parked content (daemon recover → here), and held-then-released content
    // (held below, screened now, released already-screened) all pass this point. A non-allow
    // verdict means the content is NOT delivered to the agent: it is not held, not buffered, and
    // no leaf is appended — the message stays un-acked so the sender's TTF/park/retry redelivers
    // it once the gateway is reachable again (DB-001 fail-closed: hold, never expose ungated).
    // DOD-DOC-SCREEN-CLASSIFY-1: a DOCUMENT frame skips the gateway's content screen HERE, and is
    // screened later on text instead of bytes. Every content step is inert or worse for one at this
    // point — the sanitizer's rewrites are deliberately discarded by the funnel below (rewriting a
    // signed envelope destroys it), and language/injection judge a UTF-8 decode of binary. Size stays
    // bounded twice (MAX_DOCUMENT_FRAME_BYTES at classify, the gate's own cap).
    //
    // WHAT IS TRADED, stated plainly: the screen skipped here is fail-CLOSED (a gateway that is down
    // returns a transient block, and the frame is held un-acked for redelivery). Its replacement —
    // the gate's in-process rules, then the semantic screen at `document-inbound.ts` step 7a-bis —
    // is fail-OPEN on that same condition, because holding document convergence hostage to an
    // optional layer breaks a layer that degrades by design. That degradation is LOGGED BY NAME
    // there (`document.inbound.screen.unavailable`); it is not silent, and it is not free.
    //
    // Logged by name so the skip is visible rather than assumed.
    const isDocFrame = this.#ctx.isDocumentFrame?.(content) === true;
    if (isDocFrame) {
      this.#ctx.logger.info("session.content.screen.skipped_document_frame", {
        sessionId,
        agentName,
        correlationId,
      });
    }
    const inboundVerdict: Awaited<ReturnType<SecurityGatewayClient["screenInbound"]>> = isDocFrame
      ? { disposition: "allow", content }
      : await this.#ctx.securityGateway.screenInbound(content, {
          direction: "inbound",
          agentName,
          sessionId,
          correlationId,
        });
    // M9 terminal-vs-transient split. A TERMINAL block (inboundVerdict.terminal) is a detector
    // rejecting the CONTENT itself — a confident non-allowlisted language (IN-003), a high-score
    // injection (IN-002), or an oversized payload (IN-001). The identical bytes would be rejected
    // identically on redelivery, so holding them un-acked would loop the sender forever. Instead a
    // terminal block is `screenedOut`: it records a leaf binding the ORIGINAL content hash and is
    // acknowledged (the sender stops), but is NEVER buffered for the agent (cello_receive never sees
    // it). The leaf is REQUIRED, not cosmetic: the sender appended this leaf at its CANONICAL position
    // on send, so a terminal block must take the SAME strict-in-order path as a delivered message —
    // record the leaf at its canonical index, not in arrival order — or the two parties' hash chains
    // diverge by POSITION and the bilateral seal cross-check mismatches (code-review HIGH-1). The only
    // difference from a normal message is that it leafs WITHOUT buffering. A TRANSIENT block (a
    // fail-closed gateway_unavailable / governance_timeout) records nothing and is not acked.
    const terminalBlock = inboundVerdict.disposition === "block" && inboundVerdict.terminal === true;
    if (inboundVerdict.disposition !== "allow" && inboundVerdict.disposition !== "redact" && !terminalBlock) {
      // TRANSIENT block / warn HOLD (do not deliver, do not leaf, do not ack). The message stays
      // un-acked so the sender's TTF/park/retry redelivers and re-screens it once the gateway recovers.
      // (If we committed a leaf, dedup would later swallow the redelivery and the agent would never
      // receive it.)
      if (inboundVerdict.reason === GOVERNANCE_TIMEOUT) {
        this.#ctx.logger.error("security.gateway.timeout", {
          sessionId,
          reason: inboundVerdict.reason,
          correlationId,
        });
      } else if (inboundVerdict.reason === GATEWAY_UNAVAILABLE) {
        this.#ctx.logger.error("security.gateway.unavailable", {
          direction: "inbound",
          reason: inboundVerdict.reason,
          correlationId,
        });
      } else {
        this.#ctx.logger.warn("security.gateway.inbound.blocked", {
          sessionId,
          disposition: inboundVerdict.disposition,
          reason: inboundVerdict.reason,
          correlationId,
        });
      }
      /**
       * DOD-M15-REFUSEDEVIDENCE-1 — **A TRANSIENT BLOCK RETAINS NOTHING, and nothing is lost by
       * that.** Nothing was recorded and, decisively, nothing was ACKNOWLEDGED: the message is still
       * with the sender, whose daemon redelivers it. When the gateway recovers the same bytes are
       * screened, and if they are blocked they are retained then, under the detector's own reason.
       *
       * Retaining here would file a copy of a message that is coming back — a duplicate, not
       * evidence — and it would do so for content nothing has yet judged, once per redelivery
       * attempt, for as long as the gateway stays down.
       */
      // DOD-M15-NO-SILENT-REFUSAL-1 — a TRANSIENT block, and saying which it is, is the whole
      // value of the notice. Nothing was recorded and nothing was acked, so the sender's daemon
      // redelivers on its own. An operator who reads the silence as delivery, or who asks the
      // counterparty to resend, is acting on the opposite of what happened.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, inboundVerdict.reason ?? "inbound_screen_blocked", {
        kind: REFUSAL_KINDS.DEFERRED,
        impact:
          "the screener could not reach a verdict on an inbound message, so it was NOT ingested and NOT shown. Nothing was recorded and nothing was acknowledged — the message is still with the sender and their daemon will redeliver it once screening works again. Do not read this silence as delivery.",
        guidance:
          "TRANSIENT — do not ask the counterparty to resend, and do not close the session. Get the local screening gateway healthy and the backlog comes through on its own: look for security.gateway.timeout, security.gateway.unavailable and security.gateway.inbound.blocked in the daemon log — the third is what an internal screen_error logs, and naming only the first two sends you looking for lines that will not be there. While it stays down, every message from every counterparty takes this path.",
      });
      return { ok: false, reason: inboundVerdict.reason ?? "inbound_screen_blocked" };
    }
    // Assigned only on the terminal-block branch and invoked beside each retention attempt below.
    let noteTerminalBlock: ((stored: number | null) => void) | undefined;
    if (terminalBlock) {
      this.#ctx.logger.warn("security.gateway.inbound.terminal_block", {
        sessionId,
        disposition: inboundVerdict.disposition,
        reason: inboundVerdict.reason,
        correlationId,
      });
      /**
       * DOD-M15-REFUSEDEVIDENCE-1 — retention for a terminal block happens where its LEAF happens,
       * not here. Two sites below (the hold branch and the in-order append), each writing the
       * quarantine row at the same index as the leaf it accompanies.
       *
       * Not here, deliberately: this point is upstream of the post-screen dedup re-check and the
       * size-cap re-check, either of which can still refuse. Retaining above them would file
       * evidence for a message this call then reports as capped — and the cap path is the one that
       * is ruled NOT to retain.
       */
      /**
       * DOD-M15-NO-SILENT-REFUSAL-1 — **the moment the product catches the attack it exists to
       * catch, and until now the operator was told nothing about it.**
       *
       * This path is not an error path, which is exactly why it had no notice: the block leafs the
       * original content hash at its canonical position and acknowledges the sender, so nothing
       * fails and nothing loops. The message is simply never handed to the agent. From the
       * operator's chair a message they were expecting never arrives and the record shows a leaf
       * with nothing in it.
       *
       * The notice NEVER carries the blocked content — a screener that can be talked into surfacing
       * what it blocked is not a screener.
       *
       * ⚠️ **THE GUIDANCE USED TO SAY "DO NOT ASK FOR THE ORIGINAL TEXT", AND THAT IS NOW WRONG.**
       * Rewritten rather than deleted, per the claim-comment rule, because the reasoning is what
       * changed and not just the sentence. It rested on the content being unavailable; under
       * `DOD-M15-REFUSEDEVIDENCE-1` it is retained and there is a route that returns it FRAMED. And
       * the friction was never protection: Andre, 2026-09-03 — *"eventually the LLM is going to go
       * searching for it, because human beings are going to direct their LLMs to find it, and it's
       * going to come back and say 'Hey, I found it here, the message says…' — which is far
       * worse."* Withholding the route removes the WARNING from the read, not the read.
       *
       * What survives unchanged: do not turn screening off. That is still the one action that makes
       * things worse, and it is the one the guidance still refuses.
       */
      /**
       * ⚠️ THE DETECTOR'S OWN REASON SURVIVES — `inbound_screen_blocked` is only the fallback.
       *
       * Invariant 3: a downstream handler must not replace an upstream descriptive error with a
       * generic one. The verdict already says WHICH detector fired — `inbound_language_blocked` and
       * an injection block are different problems with different remedies, and one of them has an
       * operator command that fixes it. Flattening both to `inbound_screen_blocked` would also
       * deduplicate them together, so the second kind would be silent for the life of the session.
       *
       * The gateway's own `guidance` is appended when it has one, for the same reason: it is the
       * half that names the actual command.
       */
      // `?? "inbound_screen_blocked"` is a floor, not a live branch: every verdict producer in the
      // tree sets `reason`, so today it never fires. It stays because `reason` is optional on the
      // type, and a notice keyed on `undefined` would collapse every future detector into one row.
      /**
       * ⚠️ **DEFERRED UNTIL THE RETENTION HAS ACTUALLY RUN — review F3.** The notice used to be
       * written here, above both append sites, and claimed the message was kept before anything had
       * tried to keep it. It is now a closure invoked beside each `#quarantineRefusedContent` call,
       * carrying that call's own answer.
       *
       * Two paths between here and there deliberately write NO notice now, and both are the better
       * answer: a post-screen dedup means this exact message was already noticed the first time, and
       * a size-cap refusal writes `#noteSizeCapRefusal` instead — which is what actually happened,
       * where before the operator got both stories at once.
       */
      noteTerminalBlock = (stored: number | null): void => {
        this.#ctx.notices.noteContentRefusal(agentName, sessionId, inboundVerdict.reason ?? "inbound_screen_blocked", {
          kind: REFUSAL_KINDS.BLOCKED,
          impact:
            "the screener blocked an inbound message: its content matched a detector this agent runs on everything that arrives. It was NOT shown to the agent. It IS recorded in the hash chain at its position and the sender was acknowledged, so they will not resend it and they were not told it was blocked.",
          guidance:
            "This is the protection doing its job, and nothing is required of you. If you were expecting something from this counterparty around now, tell them it was blocked and ask them to say it differently. " +
            retentionSentence(sessionId, stored) +
            (stored === null ? "" : "There is no reason to read it unless you need to show someone, or judge whether this was an attack. ") +
            "Do NOT turn screening off to read it: that is the one action here that makes things worse. security.gateway.inbound.terminal_block in the daemon log names which detector fired." +
            (inboundVerdict.guidance !== undefined ? ` The detector says: ${inboundVerdict.guidance}` : ""),
        });
      };
    }

    // M9-IN-001: a `redact` verdict (inbound sanitization) DELIVERS the sanitized text to the agent,
    // while the Merkle leaf still binds the ORIGINAL content hash below — the transcript records what
    // the peer actually sent; the agent sees the sanitized form. `allow` leaves the content unchanged.
    // A terminal block carries the original bytes here only so its leaf binds the right hash; it is
    // never delivered (the screenedOut flag below routes it to a leaf-without-buffer).
    const deliverContent = inboundVerdict.disposition === "redact" && inboundVerdict.content !== undefined
      ? inboundVerdict.content
      : content;

    // screenInbound above is the ONLY suspension point in this method, and it splits the dedup check
    // (indexOfHash, above) from the leaf append (below). Across that await, two concurrent ingests of
    // the SAME content hash — e.g. a direct retry and a park-recovery racing on reconnect — can BOTH
    // pass the first dedup check before either appends, producing two leaves for one hash
    // (DOD-MSG-5 break → leafIndex≠canonicalSeq → root divergence). So re-check dedup on resume.
    // Everything from here to the append is synchronous (atomic under Node's single thread): the
    // first to resume appends, and the second sees its leaf and dedups.
    //
    // Adding any further await between here and the append reopens the window.
    // DOD-FRONTIER-STRAND-1 AC1: this re-check must use the SAME discriminator as the first one.
    // Left keyed on the content hash it silently re-created the whole defect one branch later --
    // the pre-screen check would correctly let a second identical-but-distinct message through, and
    // then this one would drop it anyway. The race it exists to close is unaffected: two concurrent
    // ingests of a true redelivery share a position, so the second still sees the first's leaf.
    const treeAfterScreen = this.#ctx.getSessionTree(agentName, sessionId);
    const dedupAfterScreen = canonicalSeqIn !== undefined && canonicalSeqIn >= 0
      ? (treeAfterScreen.hashAt(canonicalSeqIn) === contentHashHex ? canonicalSeqIn : -1)
      : treeAfterScreen.indexOfHash(contentHashHex);
    if (dedupAfterScreen >= 0) {
      this.#ctx.logger.info("session.content.deduplicated", {
        sessionId,
        contentHashHex,
        sequenceNumber: dedupAfterScreen,
        witnessed: canonicalSeqIn !== undefined,
        phase: "post_screen",
        correlationId,
      });
      return { ok: true, leafIndex: dedupAfterScreen, sequenceNumber: dedupAfterScreen, appendedCount: 0, ...(terminalBlock ? { screenedOut: true } : {}) };
    }

    // M8C-ABUSE-1 (cello-unit-reviewer HIGH fix, post-M9INT-1 merge): re-check the size cap here,
    // in the SAME synchronous window as the dedup re-check above. The original check (before the
    // screenInbound await) used totals that can go stale: two concurrent ingests for the same
    // non-contact session — e.g. a live direct arrival racing a recoverParkedFromRelay pull —
    // could each independently pass the pre-await check using the SAME stale totals, then both
    // append/hold, jointly exceeding the cap. Symmetric to the dedup fix: everything from here to
    // the append/hold branch is synchronous, so whichever call resumes first appends/holds before
    // the second's re-check runs, and the second's freshly-recomputed totals correctly include the
    // first's contribution.
    {
      // DOD-TIER-2 AC2 (re-check): the SAME tier cap as the primary gate above, recomputed in this
      // synchronous window (the totals can go stale across the screenInbound await). Applied to EVERY
      // sender — a contact is no longer exempt (INV-TIER-BOUND). Must mirror the primary gate exactly
      // so a sender can never pass one and fail the other.
      const senderTier = this.#ctx.records.getTier(agentName, senderPubkey);
      const cap = this.#ctx.records.resolveTierBound(agentName, senderTier, "max_bytes");
      const priorTotal = this.#ctx.queries.getReceivedBytesTotal(agentName, sessionId);
      const heldTotal = this.#ctx.held.getHeldBytesTotal(agentName, sessionId);
      if (priorTotal + heldTotal + content.length > cap) {
        this.#ctx.logger.warn("session.content.abuse_bound.session_size_exceeded", {
          sessionId,
          agentName,
          senderPubkey,
          priorTotal,
          heldTotal,
          incoming: content.length,
          cap,
          tier: senderTier,
          correlationId,
          recheck: true,
        });
        this.#ctx.notices.noteSizeCapRefusal(agentName, sessionId, cap, senderTier);
        return { ok: false, reason: "session_size_limit_exceeded" };
      }
    }

    // DOD-MSG-4 (strict in-order gate): the RELAY is the ordering authority. If B holds the
    // canonical sequence for this hash (witnessed via leaf_deliver) and it is AHEAD of the next
    // expected leaf, HOLD the content rather than append it out of order. The missing in-between
    // sequence(s) are recovered from the relay mailbox; #releaseHeld then drains the held entries
    // in canonical order. This keeps the daemon-owned leaf index === the canonical sequence by
    // construction, so two parties' roots match even when direct delivery and park-recovery
    // interleave. With NO witness for this hash (relay-degraded) B falls back to arrival-order
    // append — the pre-MSG-4 behavior (no ordering signal available).
    const key = this.#ctx.sessionKey(agentName, sessionId);
    // Prefer the position the CALLER verified for this specific message over the hash-keyed map.
    // The map cannot distinguish two identical messages (AC1) -- it holds one entry per hash, so the
    // second firing overwrites the first's position. The explicit value is per-message and correct;
    // the map remains the fallback for paths that have no ordering record.
    const canonicalSeq = canonicalSeqIn !== undefined && canonicalSeqIn >= 0
      ? canonicalSeqIn
      : this.#ctx.witnessedSeq.get(key)?.get(contentHashHex);
    const nextExpected = this.#ctx.getSessionTree(agentName, sessionId).size();
    if (canonicalSeq !== undefined && canonicalSeq > nextExpected) {
      this.#ctx.held.ensureHeldRestored(agentName, sessionId);
      let held = this.#ctx.heldContent.get(key);
      if (!held) { held = new Map(); this.#ctx.heldContent.set(key, held); }
      // A terminal block out of canonical order is held WITHOUT delivery (screenedOut): #releaseHeld
      // leafs it at its canonical index when the gap fills, but never buffers it for the agent. This
      // keeps leafIndex === canonicalSeq for screened-out content too (code-review HIGH-1).
      // THE PEER'S RAW BYTES RIDE ALONG. Classification (document frame vs conversation) reads
      // byte 0, and `deliverContent` is the SCREENED copy — for a CBOR frame that is no longer a
      // map header, so a held document frame was released into the CONVERSATION path: transcript,
      // doorbell, and `cello_receive` handing an agent raw CBOR as though a person typed it.
      // The in-order path has always passed these bytes; only the held path dropped them.
      held.set(canonicalSeq, { content: deliverContent, originalContent: content, contentHashHex, correlationId, ...(terminalBlock ? { screenedOut: true } : {}) });
      // DOD-M12B-STRAND-1: and to disk, before we answer. The in-memory Map is the working copy;
      // this row is the one that survives the teardown that used to destroy it.
      this.#ctx.queries.persistHeldContent(agentName, sessionId, canonicalSeq, deliverContent, content, contentHashHex, terminalBlock === true, correlationId);
      // DOD-M15-REFUSEDEVIDENCE-1 (site 1 of 2 for a terminal block): a block held behind an
      // ordering gap. `#releaseHeld` appends its leaf later WITHOUT re-entering this method, so
      // retaining at release is not available — it is retained here, at the position the leaf will
      // take. `held_content` is not a substitute: that row is deleted the moment the gap fills.
      if (terminalBlock) {
        const keptHeld = this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, inboundVerdict.reason ?? "inbound_screen_blocked", content, contentHashHex, {
          senderPubkeyHex: senderPubkey, canonicalSeq,
          ...(verifiedAuthorship ? { authorship: verifiedAuthorship } : {}),
          correlationId,
        });
        noteTerminalBlock?.(keptHeld);
      }
      this.#ctx.logger.info("session.content.held", {
        sessionId,
        canonicalSeq,
        nextExpected,
        gap: canonicalSeq - nextExpected,
        screenedOut: terminalBlock,
        correlationId,
      });
      // Held content is NOT yet a durable leaf, so it is deliberately NOT acknowledged `persisted`
      // (the caller checks `held`). The sender's TTF→park backstop and the recover/dedup path
      // guarantee eventual delivery; B never claims persisted for content it only holds in memory.
      return { ok: true, leafIndex: canonicalSeq, sequenceNumber: canonicalSeq, held: true, ...(terminalBlock ? { screenedOut: true } : {}) };
    }
    if (canonicalSeq !== undefined && canonicalSeq < nextExpected) {
      // Contradiction (review finding #2): the witness says this hash belongs BEHIND the current
      // tree, yet the dedup scan above found no existing leaf for it — so it is neither a duplicate
      // nor in canonical order. This is only reachable via the accepted content-before-witness /
      // relay-degraded interleaving (the next sub-increment's pending-witness buffer closes it). Log
      // it loudly (the leaf-index===sequence invariant is at risk) and append rather than DROP the
      // message — losing content is worse than a transient mis-order the seal cross-check will catch.
      this.#ctx.logger.warn("session.content.sequence_behind_tree", {
        sessionId,
        canonicalSeq,
        nextExpected,
        correlationId,
      });
    }

    // In-order append. A terminal block leafs the ORIGINAL content hash WITHOUT buffering it for the
    // agent (screenedOut); a delivered message buffers + leafs via #appendVerifiedContent.
    const leafIndex = terminalBlock
      ? this.#ctx.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, correlationId).leafIndex
      : this.appendVerifiedContent(agentName, sessionId, deliverContent, contentHashHex, senderPubkey, correlationId, content, verifiedAuthorship).leafIndex;

    /**
     * DOD-M15-REFUSEDEVIDENCE-1 (site 2 of 2) — **the moment the product catches the attack it
     * exists to catch, and until now it kept only the hash.**
     *
     * The terminal-block branch above takes `appendSessionLeaf`, not `#appendVerifiedContent`, so
     * the row carrying the plaintext, the sender's key and the sender's signature was never written.
     * A hash proves a message you still hold has not changed; it proves nothing about one you threw
     * away — and this is precisely the message an operator would most want to produce.
     *
     * At `leafIndex`, so the leaf and the evidence describe one event and DoD 7's leaf placement is
     * untouched. The ORIGINAL bytes, never the sanitized `deliverContent`: evidence is what they
     * sent, not what a filter made of it.
     */
    if (terminalBlock) {
      const keptBlocked = this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, inboundVerdict.reason ?? "inbound_screen_blocked", content, contentHashHex, {
        senderPubkeyHex: senderPubkey, canonicalSeq: leafIndex,
        ...(verifiedAuthorship ? { authorship: verifiedAuthorship } : {}),
        correlationId,
      });
      noteTerminalBlock?.(keptBlocked);
      /**
       * ⚠️ **DROP THE WITNESS — A BLOCKED MESSAGE MADE THE SESSION PERMANENTLY UNSEALABLE.**
       *
       * THE THIRD INSTANCE of the shape already fixed for document frames at `:10593`, found by the
       * first journey that ever sealed a session after a screener block.
       *
       * `sealReadiness` derives `missingLeaves` from `#witnessedSeq.size` — every position the
       * ordering authority committed that this tree has not appended. The entry is dropped where the
       * leaf is credited, and that drop lives inside `#appendVerifiedContent`. A terminal block does
       * not go through it: the branch above takes `appendSessionLeaf` directly, so the leaf WAS
       * committed and the witness was never retired.
       *
       * **From the operator's chair:** their screener catches one hostile message, and from that
       * moment `cello_close_session` answers `session_incomplete` forever — *"waiting on an earlier
       * message from the counterparty that has not arrived"* — about a message that arrived, was
       * judged, and is sitting in the chain. The only exit is a force-abandon, which forfeits the
       * notarized receipt. Measured live: `treeSize 3, highWaterSeq 2, missingLeaves 1`.
       *
       * Not introduced by `DOD-M15-REFUSEDEVIDENCE-1` — it is older than this unit and simply had no
       * test that both blocked a message and then sealed. It is fixed here because this unit's own
       * DoD requires that session to seal.
       */
      this.#ctx.witnessedSeq.get(key)?.delete(contentHashHex);
    }

    // DOD-COATTEND-1 (review F2): the plaintext failed to reach the transcript, and since Tier 1 the
    // transcript IS the delivery path — so this message can never be handed to any session. Report
    // the ingest as failed. Reporting `ok: true` here is what let a local SQLCipher failure surface,
    // 30 seconds later and one subsystem away, as "no content arrived — keep waiting": the operator
    // is sent to debug a counterparty who did nothing wrong.
    //
    // The leaf STAYS. It is genuinely committed to the hash chain, and unwinding a committed leaf to
    // tidy up a reporting problem would corrupt the frontier the counterparty already co-signs
    // against. The hole is now crossable by delivery (F1), so it costs a gap, not a stall.
    if (!terminalBlock && this.getUndeliverableSeqs(agentName, sessionId).includes(leafIndex)) {
      /**
       * DOD-M15-REFUSEDEVIDENCE-1 — **THIS PATH CANNOT RETAIN, because the storage layer is what
       * just failed.** The write that would keep the evidence is the same `INSERT` into the same
       * table that has already thrown for this message. Attempting it produces a second error line
       * and no evidence. Named here rather than left to be rediscovered as a missing case.
       */
      // DOD-M15-NO-SILENT-REFUSAL-1. `#appendVerifiedContent` already noted `content_undeliverable`
      // at the point the write failed; this is the INGEST's own refusal, and it is a different fact
      // — the sender is told the ingest failed, so it will redeliver, and every redelivery of the
      // same hash now dedups against a leaf whose plaintext is not there. Two reasons, because a
      // reader fixing the disk fault needs to know both that the text is gone and that the sender
      // is retrying into a hole.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "transcript_write_failed", {
        kind: REFUSAL_KINDS.LOST,
        impact:
          "A message reached this agent, was verified, and was committed to the conversation's record — and then its text could not be written to local storage, so it can never be delivered. There is a permanent gap in your copy of this conversation. This is a fault on THIS machine; the counterparty did nothing wrong and cannot fix it.",
        /**
         * ⚠️ THE READER IS USUALLY ALREADY IN A CODING AGENT, so the guidance says GO AND LOOK
         * rather than listing symptoms. Andre, 2026-09-03: *"The message should mention to try and
         * figure out why you cannot store it — it is likely a local machine problem. But if you
         * truly cannot figure this out using a coding agent, then we advise reaching out to
         * CELLO_Support."*
         *
         * That ordering matters: this is a machine fault with an ordinary cause, and an operator
         * sent straight to support for a full disk has been wasted. Support is the exit, not the
         * first step.
         */
        guidance:
          "Find out why the write failed — this is almost always something ordinary on this machine. " +
          "If you are reading this through a coding agent, have it check: free disk space, the permissions on ~/.cello, whether the database file is readable and writable, and transcript.message.record.failed in the daemon log, which carries the underlying error. " +
          "Waiting cannot recover the message. Once the fault is fixed, ask them to resend — the text is gone and only its hash remains. " +
          "If you genuinely cannot work out the cause, reach out to CELLO_Support.",
      });
      return { ok: false, reason: "transcript_write_failed" };
    }

    // NO relay witness for this hash. We appended it anyway — refusing would make the relay a hard
    // precondition for reading mail, so a relay outage would render the inbox unreadable, and the
    // direct path and park backstop exist precisely to survive that. But this append is a WEAKER
    // guarantee and must not masquerade as the stronger one: with a witness, the received content is
    // checked against a hash the sender committed to a third party; without one, the only available
    // hash rode in the same frame as the content, so the check is the sender's claim against the
    // sender's own claim. Say so. A sender who simply never submits to the relay is otherwise
    // indistinguishable from one the relay merely has not witnessed YET.
    // The relay witness is an INDEPENDENT attestation: a (content_hash → sequence) binding derived
    // from the sender's own signed leaf. Holding one, we check received content against a hash the
    // sender committed to a THIRD PARTY. Holding none, the only hash available rode in the same frame
    // as the content — the sender's claim checked against the sender's claim.
    //
    // Unwitnessed content is still ingested. Refusing it would make the relay a precondition for
    // READING mail, so a relay outage would render the inbox unreadable — the redundancy the direct
    // path and the park backstop exist to provide.
    //
    // Warn ONLY when a witness was EXPECTED. A session with no relay attached has no witness BY
    // DESIGN, and warning on every message there would bury the one case that means something —
    // a relay IS attached, so the sender's leaf should have been submitted and witnessed, and it
    // was not. A signal that fires on the normal case is not a signal.
    if (canonicalSeq === undefined && this.#ctx.activeNodes.get(key)?.relayClient) {
      this.#ctx.logger.warn("session.content.unwitnessed", {
        agentName,
        sessionId,
        leafIndex,
        contentHash: contentHashHex,
        correlationId,
        guidance: "a relay is attached to this session but no witness bound this content hash — it was ingested with no independent commitment from the sender",
      });
    }
    // A just-appended leaf may unblock held out-of-order arrivals whose turn is now next.
    // appendedCount = this leaf + any held leaves released by it, so a caller (recover) can tally the
    // leaves ACTUALLY written, not just the directly-ingested one (review #3).
    const released = this.#ctx.held.releaseHeld(agentName, sessionId, senderPubkey);
    return { ok: true, leafIndex, sequenceNumber: leafIndex, appendedCount: 1 + released, ...(terminalBlock ? { screenedOut: true } : {}) };
  }

  /**
   * DOD-MSG-4: record the relay-witnessed canonical sequence for a content hash. The relay is the
   * ordering authority (Structure 2): it assigns each message a sequence from its hash and delivers
   * B the (content_hash -> sequence) binding via leaf_deliver. The strict-in-order gate orders the
   * transcript by THIS — never a sender-stamped field. Also advances the per-session high-water mark
   * (the largest witnessed sequence) reserved for the future catch-up-before-live increment. Idempotent.
   */
  recordWitnessedSequence(agentName: string, sessionId: string, contentHashHex: string, sequenceNumber: number): void {
    if (sequenceNumber < 0) return;
    const key = this.#ctx.sessionKey(agentName, sessionId);
    // DOD-M12B-SEAL-STUCK-1: this process has now seen this session's ordering state, so an empty
    // witness map for it means "no gap" rather than "never looked".
    this.#ctx.orderingObserved.add(key);
    let map = this.#ctx.witnessedSeq.get(key);
    if (!map) { map = new Map(); this.#ctx.witnessedSeq.set(key, map); }
    map.set(contentHashHex, sequenceNumber);
    const hw = this.#ctx.highWaterSeq.get(key) ?? -1;
    if (sequenceNumber > hw) this.#ctx.highWaterSeq.set(key, sequenceNumber);

    /**
     * DOD-M12B-LEAF-TRIGGERS-FETCH-1 — A LEAF WE CANNOT READ IS A FETCH ORDER.
     *
     * MEASURED LIVE 2026-08-18: the relay delivered this leaf one second after the counterparty
     * sent. We had the hash and the sequence, the bytes were parked at that same relay, and the
     * plaintext arrived 102 seconds later on a background sweep. Nothing connected the two facts —
     * this method recorded the sequence and stopped.
     *
     * The witness leaf and the plaintext are separate deliveries: the leaf comes over the relay, the
     * bytes over the direct content stream. After an interruption the two session nodes have no
     * direct connection, so the bytes go to the park instead and only a timer ever finds them.
     *
     * The grace window is what keeps this off the hot path. On a healthy session the direct content
     * lands within milliseconds of its leaf, so fetching immediately would mean a relay round trip
     * for every message in every session. We give the direct path its two seconds first.
     */
    this.#scheduleLeafFetchIfUnresolved(agentName, sessionId, contentHashHex);
  }

  /**
   * Cancel a pending leaf fetch for one piece of content. The TIMERS stay the manager's — it has
   * three users and only one of them moved — so `#markContentTerminallyRefused`, now in
   * `inbound-refusals.ts`, asks for the cancellation instead of reaching into the map.
   */
  cancelLeafFetch(key: string, contentHashHex: string): void {
    const timerKey = `${key}::${contentHashHex}`;
    const t = this.#ctx.leafFetchTimers.get(timerKey);
    if (t !== undefined) {
      clearTimeout(t);
      this.#ctx.leafFetchTimers.delete(timerKey);
    }
  }

  /** DOD-M12B-LEAF-TRIGGERS-FETCH-1: this content is here — no fetch is owed for it, and any
   *  pending one is cancelled. Called wherever content actually lands. */
  markContentResolved(agentName: string, sessionId: string, contentHashHex: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let set = this.#ctx.resolvedContent.get(key);
    if (!set) { set = new Set(); this.#ctx.resolvedContent.set(key, set); }
    set.add(contentHashHex);
    const timerKey = `${key}::${contentHashHex}`;
    const t = this.#ctx.leafFetchTimers.get(timerKey);
    if (t !== undefined) {
      clearTimeout(t);
      this.#ctx.leafFetchTimers.delete(timerKey);
    }
  }

  #scheduleLeafFetchIfUnresolved(agentName: string, sessionId: string, contentHashHex: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#ctx.resolvedContent.get(key)?.has(contentHashHex)) return;
    // DOD-M15-REFUSALTERMINAL-1: a refusal nothing can get past is the end of the work, not a
    // reason to come back in two seconds.
    if (this.#ctx.refusals.isTerminallyRefused(agentName, sessionId, contentHashHex)) return;
    const timerKey = `${key}::${contentHashHex}`;
    // ONE fetch per content hash. The relay redelivers, and a redelivery carries the same sequence —
    // scheduling per redelivery turns a slow relay into a storm against itself.
    if (this.#ctx.leafFetchTimers.has(timerKey)) return;
    const timer = setTimeout(() => {
      this.#ctx.leafFetchTimers.delete(timerKey);
      if (this.#ctx.resolvedContent.get(key)?.has(contentHashHex)) return; // the direct path won
      if (this.#ctx.shuttingDown) return;
      this.#ctx.logger.info("session.content.leaf_unresolved.fetch", {
        agentName,
        sessionId,
        contentHash: contentHashHex,
        graceMs: this.#ctx.leafFetchGraceMs,
        impact: "the relay told us this message exists and its plaintext never arrived directly — "
          + "fetching it now instead of waiting for the periodic sweep",
      });
      this.#ctx.park.fireParkedDrain(agentName, "witnessed_leaf_unresolved");
    }, this.#ctx.leafFetchGraceMs);
    timer.unref?.();
    this.#ctx.leafFetchTimers.set(timerKey, timer);
  }

  /**
   * DOD-MSG-4: the relay's high-water canonical sequence for this session (largest witnessed leaf),
   * or -1 if none. The relay is the ordering authority, so this is the outside view of how far the
   * session has actually progressed — which is why it is the right input to a catch-up-before-live
   * gate. Consumed by `sealReadiness` (M12-P14) for REPORTING only: the missing-leaf decision is made
   * from `#witnessedSeq`, because this counts the relay's sequence space (which includes ctrl leaves)
   * and the tree does not. Maintained by `recordWitnessedSequence`.
   */
  /**
   * DOD-COATTEND-1 (review F2): leaf sequences whose plaintext failed to reach the transcript and
   * are therefore undeliverable. Empty is the overwhelmingly normal case.
   */
  getUndeliverableSeqs(agentName: string, sessionId: string): readonly number[] {
    return [...(this.#ctx.undeliverableSeqs.get(this.#ctx.sessionKey(agentName, sessionId)) ?? [])];
  }

  /** DOD-MSG-4 / DAEMON-004: append a verified message leaf and buffer it for cello_receive. */
  appendVerifiedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHashHex: string,
    senderPubkey: string,
    correlationId?: string,
    /**
     * The bytes as the PEER SENT THEM, before inbound sanitization — for the document classifier
     * only. Defaults to `content` for callers that never screened (the held-release path).
     *
     * A `redact` verdict rewrites `content` for the agent's benefit, and that is right for
     * conversation: the operator sees the sanitized form while the leaf still binds the original.
     * It is WRONG for a document frame, and not marginally. Rewriting bytes inside a signed CBOR
     * envelope does not sanitize it — it destroys it. The frame stops decoding, stops being
     * recognised as document traffic at all, and falls through to the conversation path, where it
     * is recorded as something a person said and handed to the agent by `cello_receive`.
     *
     * Measured live: roughly half of proposals vanished this way. Intermittent because a proposal
     * carries a random 16-byte nonce, so whether its bytes trip a sanitizer rule varies per run —
     * which is why it read as flakiness rather than as a rule firing.
     *
     * Documents are NOT unscreened as a result. They are screened by `DocumentGate`, which is built
     * for them and REFUSES rather than mutates (§16.7) — because mutating one party's replica of a
     * CRDT is not a false positive, it is permanent divergence that both sides converge on and
     * neither can see.
     */
    originalContent?: Uint8Array,
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: threaded from `ingestReceivedContent`, which is the only place
     * that has it — `#verifyAuthorshipClaim` verified this signature (carried on the frame beside
     * the bytes it signs) against the pubkey inside those bytes, and matched the signer to this
     * session's counterparty. It reaches the transcript row from here or not at all.
     *
     * ⚠️ IT USED TO NAME `#recordFrameOrdering`, true until `DOD-M15-AUTHORSHIP-ABSENT-1` moved the
     * check off the relay's record and onto the frame's own signature. Rewritten rather than
     * deleted: the old name is the evidence of what authorship used to depend on.
     *
     * Undefined on the held-release and soft-fallback paths; the row records that as
     * `local_session_state` rather than leaving it indistinguishable from a proven one.
     */
    verifiedAuthorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
  ): { leafIndex: number } {
    // M14 / DOD-DOC-INBOUND-2 — DOCUMENT FRAMES DIVERGE HERE, and the three-way split is the whole
    // contract:
    //
    //   LEAF   yes, and as `doc` (0x04) rather than `msg` (0x00). The seal covers document traffic
    //          — that is what makes the exchange provable — but it is not conversation, and the
    //          leaf kind is what a verifier renders it by.
    //   TRANSCRIPT no. Recording CRDT bytes as a received message puts them in the operator's
    //          conversation history, where `cello_receive` hands them to an agent as something a
    //          person said.
    //   DOORBELL no (§11.3). A collaborator typing produces a stream of updates; a doorbell each
    //          time would interrupt the operator's agent continuously for something with no
    //          deadline.
    //
    // The hook is injected and absent by default, so a daemon without the document layer behaves
    // exactly as before — this cannot change the conversation path by being unwired.
    const routed = this.#ctx.onDocumentFrame?.(
      agentName,
      sessionId,
      // THE PEER'S BYTES, not the sanitized ones. See `originalContent` above.
      originalContent ?? content,
      senderPubkey,
      correlationId,
    );
    if (routed?.consumed === true) {
      const { leafIndex } = this.#ctx.appendSessionLeaf(agentName, sessionId, "doc", contentHashHex, correlationId);
      // DROP THE WITNESS, exactly as the conversation branch does once its leaf is appended. The
      // witness has done its ordering job either way — the leaf IS committed here.
      //
      // This branch returns early and so never reached that cleanup, and every inbound document
      // frame left a permanent entry behind. Harmless until `sealReadiness` started deriving
      // `missingLeaves` from the size of that map (M12-P14): from then on a session that carried
      // ANY document traffic could never seal, because the ordering authority was recorded as
      // having committed leaves this tree had — but had not been credited with. The refusal is
      // `session_incomplete`, whose only escape is a force-abandon with no notarized receipt.
      //
      // Two correct changes, each fine alone, that break where they meet. Caught by running the
      // live enforcers straight after merging main rather than trusting a green unit suite.
      this.#ctx.witnessedSeq.get(this.#ctx.sessionKey(agentName, sessionId))?.delete(contentHashHex);
      /**
       * ⚠️ THIS LINE USED TO LOG `ok: routed.ok` AND `reason: routed.reason`, AND NEITHER CAN EVER
       * BE PRESENT HERE. Removed rather than left, because their absence was read as evidence.
       *
       * The producer is `DocumentFrameRouter.routeSync`, and it has four returns — `unshaped`,
       * `undecodable`, `owner_unresolved`, and the normal path — **none of which sets either
       * field.** It cannot: the normal path is `void this.#enqueue(...)`, fire-and-forget, so at the
       * instant this line is written the frame has been CLASSIFIED and QUEUED and nothing has yet
       * decided whether it will be accepted. The verdict is genuinely not knowable here.
       *
       * **What that cost:** `j-stale-session` reported `framesReceived=3 inbound=0`, and the
       * investigation recorded that `ok` and `reason` were "ABSENT from every line in the run — so
       * the router returned neither, which is itself the next thread to pull: a routing result that
       * reports no outcome cannot say whether it accepted or dropped the frame." That thread leads
       * nowhere. The router did not fail to report an outcome; **it has no outcome to report at this
       * point in the flow**, and a JSON logger omits an `undefined` field, so a structural absence
       * looked exactly like a fault. A field that can never be populated is worse than no field.
       *
       * **Where the verdict actually lands**, named here so the next reader does not have to find it
       * the hard way: a refusal is `document.frame.refused` (warn, carrying `kind` + `reason`,
       * emitted from `#enqueue`'s continuation under the same `correlationId`). Acceptance is
       * silent on this event. So "was this frame ingested?" is answered by joining on
       * `correlationId`, never by reading this line alone.
       */
      this.#ctx.logger.info("session.document.received", {
        sessionId,
        senderPubkey,
        contentHashHex,
        sequenceNumber: leafIndex,
        kind: routed.kind,
        // The verdict is asynchronous. Stated positively so absence is not mistaken for silence.
        dispatch: "queued",
        verdictEvent: "document.frame.refused",
        correlationId,
      });
      return { leafIndex };
    }

    const { leafIndex } = this.#ctx.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, correlationId);
    // DOD-LOG-1: persist the readable RECEIVED plaintext to the durable transcript, keyed by the
    // canonical leaf sequence so it joins the committed hash chain (survives restart; INV-3 — the
    // relay/directory never see this plaintext, only the hash).
    const durable = this.#ctx.records.recordTranscriptMessage(
      agentName, sessionId, leafIndex, "received", content, correlationId,
      // DOD-M15-SEALWIRE-1 bullet 5: present only when the ordering record verified AND the signer
      // matched this session's counterparty. Undefined on the soft fallback, which the row records
      // as `local_session_state` rather than leaving indistinguishable.
      verifiedAuthorship,
    );
    const recvKey = this.#ctx.sessionKey(agentName, sessionId);
    if (!durable) {
      // The leaf is committed and the plaintext is not. Delivery reads the transcript, so this
      // message is now unreachable by every session — record it so the receive path can SAY that
      // rather than time out wearing the quiet-counterparty answer (review F2).
      let lost = this.#ctx.undeliverableSeqs.get(recvKey);
      if (!lost) { lost = new Set(); this.#ctx.undeliverableSeqs.set(recvKey, lost); }
      lost.add(leafIndex);
      // DOD-M15-NO-SILENT-REFUSAL-1: noted HERE, where the write actually fails, and not on the
      // cello_receive exit that reports it. `#undeliverableSeqs` is in memory, so the receive exit
      // stops being able to say this after a restart while the transcript hole stays permanent —
      // and the exit only runs if somebody is attending, which is the case this whole line is for.
      this.#ctx.notices.noteContentRefusal(agentName, sessionId, "content_undeliverable", {
        kind: REFUSAL_KINDS.LOST,
        impact:
          `a message arrived and was committed to the hash chain at sequence ${leafIndex}, and then its text could not be written to the local transcript. Delivery reads the transcript, so that message can never be handed to any session — it is a permanent hole in this side's copy of the conversation.`,
        guidance:
          "This is a fault on THIS machine; the counterparty did nothing wrong. Find out why the write failed — it is almost always something ordinary. " +
          "If you are reading this through a coding agent, have it check free disk space, the permissions on ~/.cello, and transcript.message.record.failed in the daemon log, which carries the underlying error. " +
          "Waiting cannot recover it. Once the fault is fixed, ask them to resend. If you genuinely cannot work out the cause, reach out to CELLO_Support.",
      });
    }
    // Review finding #6: the witness for this hash has done its ordering job once the leaf is
    // appended — drop it so #witnessedSeq stays proportional to held/pending content, not the whole
    // transcript. A later replay of the same hash is still caught by the dedup leaf-scan, which is
    // independent of the witness map.
    this.#ctx.witnessedSeq.get(recvKey)?.delete(contentHashHex);
    // DOD-M12B-LEAF-TRIGGERS-FETCH-1: the bytes are here, so cancel any fetch the witness leaf
    // scheduled. On a healthy session this is the branch that runs — the direct path beats the
    // grace window and the relay is never asked, which is what keeps a fetch off the hot path of
    // every message.
    this.markContentResolved(agentName, sessionId, contentHashHex);
    let buf = this.#ctx.receivedContent.get(recvKey);
    if (!buf) { buf = []; this.#ctx.receivedContent.set(recvKey, buf); }
    buf.push({ contentHex: Buffer.from(content).toString("hex"), senderPubkey, sequenceNumber: leafIndex });
    // DOD-COATTEND-1: BOUNDED, because delivery no longer drains this. Its remaining job is
    // `peekLatestReceivedContentHex` (M8C-AWAY-1 reads the TAIL to spot a [[WRAP]]), so only the
    // recent tail is load-bearing — but an unbounded array holding every message of every live
    // session, in memory, for the life of the daemon, is a leak the old destructive read hid.
    if (buf.length > RECEIVED_BUFFER_CAP) buf.splice(0, buf.length - RECEIVED_BUFFER_CAP);
    this.#ctx.logger.info("session.content.received", {
      sessionId,
      senderPubkey,
      contentHashHex,
      sequenceNumber: leafIndex,
      correlationId,
    });
    // M8C-MSGWAKE-1: content is now buffered and drainable — fire the doorbell AFTER the push so a
    // woken cello_receive finds the message. Content-free (agent/session/senderPubkey only). Never
    // let a listener error escape the content path.
    try {
      this.#ctx.onContentArrived?.(agentName, sessionId, senderPubkey);
    } catch (err: unknown) {
      this.#ctx.logger.warn("notification.cello_message.dispatch.failed", {
        sessionId, agentName, reason: err instanceof Error ? err.message : String(err),
      });
    }
    return { leafIndex };
  }



  /** DAEMON-004: pop the oldest verified received content for cello_receive. */
  takeReceivedContent(agentName: string, sessionId: string): ReceivedContentEntry | null {
    const buf = this.#ctx.receivedContent.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!buf || buf.length === 0) return null;
    return buf.shift() ?? null;
  }



  /**
   * Send an unsigned `persisted` delivery ACK back to the sender over the same
   * /cello/content/1.0.0 protocol (AC-001). Best-effort: authentication is the Noise
   * session channel, so the ACK carries no signature; a failed ACK send is logged and
   * the sender recovers via its TTF/recovery path rather than a thrown error here.
   */
  async #sendDeliveryAck(agentName: string, sessionId: string, contentHash: Uint8Array, correlationId?: string): Promise<void> {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) {
      // NOT a silent return. No ACK is exactly this milestone's symptom — the sender's TTF expires
      // and the message parks — so the one case where we knowingly decline to send one has to say
      // so, or it is indistinguishable from the defect.
      this.#ctx.logger.debug("content.delivery.ack.skipped", {
        agentName,
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        reason: "session_node_gone",
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
      if (this.#ctx.ackFaultRemaining > 0) {
        this.#ctx.ackFaultRemaining -= 1;
        this.#ctx.logger.warn("content.delivery.ack.fault.injected", { sessionId });
        throw new Error("connection_lost: injected delivery-ack fault");
      }
      const frame = encodeCbor({
        type: "content_delivery_ack",
        session_id: sessionId,
        content_hash: contentHash,
        level: "persisted",
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
      this.#ctx.logger.info("content.delivery.ack.sent", {
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        correlationId,
      });
      // An agent that mostly LISTENS sends content rarely and ACKs constantly. Clearing only on the
      // content path would leave exactly those sessions reporting a broken conversation forever
      // after one bad ACK — the one-way door, on the other send path.
      this.#ctx.liveness.clearSessionImpairment(agentName, sessionId, "delivery_ack", correlationId);
    } catch (err: unknown) {
      this.#ctx.logger.warn("content.delivery.ack.send.failed", {
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        error: err instanceof Error ? err.message : String(err),
        // "Cannot write to a stream that is closed" names where the write died, never why. The
        // why is almost always the per-protocol stream cap, and these two numbers are what turn
        // that from a log-measurement session into a grep.
        ...this.#ctx.streamCensus(entry.node, entry.counterpartySessionPeerId),
        correlationId,
      });
      // The ACK travels the same direct path as our own content, so a failure here is the same
      // evidence: writes to this counterparty are not landing.
      this.#ctx.liveness.markSessionImpaired(agentName, sessionId, { cause: "delivery_ack", error: err instanceof Error ? err.message : String(err), correlationId });
      if (ackStream !== undefined) {
        try { ackStream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
    }
  }



  /**
   * DAEMON-004: register the /cello/content/1.0.0 handler on a session node so
   * inbound content_frames are decoded, cross-checked, and ingested.
   */
  // Awaited by createSessionNode / acceptSession so the /cello/content/1.0.0 handler
  // is provably registered before the caller returns (and thus before any peer sends
  // content). libp2p registers the protocol synchronously today, but awaiting removes
  // the fragile dependency on that internal timing (review L4).
  async registerContentHandler(agentName: string, sessionId: string, node: CelloNode, _counterpartyPubkey: string): Promise<void> {
    try {
      await node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream, remotePeerId) => {
        // `.catch` is not decoration: the handler builds its length-prefixed decoder before its own
        // try, and a throw there would otherwise become an unhandled rejection that takes the
        // daemon down for one malformed inbound stream.
        void this.#handleContentStream(agentName, sessionId, stream, remotePeerId).catch((err: unknown) => {
          this.#ctx.logger.warn("session.content.stream.handler.failed", {
            sessionId,
            error: err instanceof Error ? err.message : String(err),
          });
        });
      }, { maxInboundStreams: CONTENT_MAX_INBOUND_STREAMS });
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.handler.register.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Hand the relay a leaf this agent RECEIVED whose author never submitted it — 034-CARRYLEAF.
   *
   * **The attack this closes:** somebody sends you something, declines to have it witnessed, and
   * seals one message short. The relay's account really does end before their last message, so your
   * receipt does too — every leaf validly signed, nothing false, the last thing said simply absent.
   *
   * **Why this is admissible and not a forgery:** the bytes are theirs, the signature over them is
   * theirs, and `#verifyAuthorshipClaim` verified it against this session's counterparty before a
   * word of it was ingested. The relay verifies it again against the directory-signed assignment.
   * Nothing here is asserted by us except that we received it.
   *
   * ⚠️ BEST-EFFORT, AND ITS FAILURE IS NOT SILENT. If the relay cannot be reached, the message is
   * still delivered and read — refusing it would make the relay a precondition for reading mail,
   * which is the thing every unit on this path has been careful not to do. What is lost is only the
   * guarantee that it can enter a receipt, and that surfaces where the operator can act on it: the
   * seal's own pre-flight refuses a gapped chain by name (`seal_carry_noncontiguous`) with guidance,
   * so the consequence reaches them at the moment it matters rather than as a log line here.
   */
  witnessReceivedLeaf(
    agentName: string,
    sessionId: string,
    contentHash: Uint8Array,
    structure1Cbor: Uint8Array,
    senderSignature: Uint8Array,
    /** The domain the AUTHOR assigned this leaf, read off their frame — never guessed (review F5). */
    leafKind: number,
    correlationId?: string,
  ): void {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry?.relayClient || !entry.relaySessionIdBytes) {
      this.#ctx.logger.warn("session.content.witness_received.unavailable", {
        agentName, sessionId, correlationId,
        impact:
          "a message arrived that its sender never had witnessed, and this side has no relay client " +
          "for the session, so it could not be witnessed here either. It is delivered and readable; " +
          "it cannot enter a notarized receipt until some party witnesses it.",
      });
      return;
    }
    void entry.relayClient
      .witnessReceivedLeaf(entry.node, entry.relaySessionIdBytes, contentHash, leafKind, {
        structure1Cbor,
        senderSignature,
      })
      .then((res) => {
        if (res.ok) {
          this.#ctx.logger.info("session.content.witness_received", {
            agentName, sessionId, correlationId, relaySequence: res.sequence_number,
            impact:
              "this side witnessed a message its SENDER did not. The leaf now holds a canonical " +
              "position, so it can appear in a receipt whatever the sender does next.",
          });
          // It has a position now, so it can be acknowledged like any other received message.
          this.noteAcknowledgeable(agentName, sessionId, res.sequence_number - 1, contentHash);
          return;
        }
        /**
         * `counter_submit_duplicate` is NOT a failure and must not be logged as one: it means this
         * relay already holds the leaf, which is the outcome we wanted. It fires on the ordinary
         * race where the sender's own submit lands while ours is in flight.
         */
        if (res.reason === "counter_submit_duplicate") {
          this.#ctx.logger.info("session.content.witness_received.already_held", {
            agentName, sessionId, correlationId,
            impact: "the relay already held this leaf — its sender witnessed it after all, or in parallel with us.",
          });
          return;
        }
        this.#ctx.logger.error("session.content.witness_received.failed", {
          agentName, sessionId, correlationId, reason: res.reason,
          ...(res.detail === undefined ? {} : { detail: res.detail }),
          impact:
            "a message arrived that its sender never had witnessed, and this side could not witness " +
            "it either. It is delivered and readable. What is at risk is the RECEIPT: if this " +
            "message is still unwitnessed when the conversation is sealed, the seal will refuse a " +
            "gapped chain by name rather than quietly leaving it out.",
        });
      })
      .catch((err: unknown) => {
        this.#ctx.logger.error("session.content.witness_received.threw", {
          agentName, sessionId, correlationId, error: extractErrorMessage(err),
        });
      });
  }

  /**
   * Record that a message ARRIVED and was accepted at a known canonical position — 033-ACKEMIT
   * review F1.
   *
   * The one writer for both copies of the acknowledgement, so the claim this daemon signs says what
   * it actually received rather than what the relay got round to delivering back to it.
   *
   * Monotonic, and it must be: a re-delivery or a recovered park of an EARLIER message must not walk
   * the acknowledgement backwards, and must not swap the hash under an unchanged position.
   */
  noteAcknowledgeable(agentName: string, sessionId: string, canonicalSeq: number, contentHash: Uint8Array): void {
    // Relay sequences are 1-based; a canonical leaf index is 0-based. The claim carries the relay's
    // number, because the relay is what checks it.
    const relaySeq = canonicalSeq + 1;
    if (relaySeq < 1) return;
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const prev = this.#ctx.lastAck.get(key);
    if (prev && relaySeq <= prev.seq) return;
    this.#ctx.lastAck.set(key, { seq: relaySeq, hash: Uint8Array.from(contentHash) });
    const entry = this.#ctx.activeNodes.get(key);
    const sessionIdHex = entry?.relaySessionIdBytes
      ? Buffer.from(entry.relaySessionIdBytes).toString("hex")
      : sessionId;
    entry?.relayClient?.noteReceivedLeaf(sessionIdHex, relaySeq, contentHash);
  }



  #refuseInboundContent(
    agentName: string,
    sessionId: string,
    reason: string,
    contentHash: Uint8Array,
    detail: { impact: string; guidance: string } & Record<string, unknown>,
    correlationId?: string,
  ): void {
    // The sentence about the other route is chosen HERE, from what this machine can actually do —
    // never written into a caller's literal, where it would be a promise nobody re-checked.
    const guidance = `${detail.guidance} ${this.#ctx.mailboxRouteAvailable(agentName) ? REFUSAL_MAY_STILL_ARRIVE : REFUSAL_NO_OTHER_ROUTE}`;
    this.#ctx.logger.error("session.content.refused", { agentName, sessionId, correlationId, reason, ...detail, guidance });
    this.#ctx.notices.noteContentRefusal(agentName, sessionId, reason, {
      kind: REFUSAL_KINDS.REFUSED, impact: detail.impact, guidance,
    });
    /**
     * Review F4 — A PROMISE MADE HERE IS CLOSED IN `recoverParkedEntry`, not left standing.
     *
     * The guidance above tells the operator the message may arrive by the mailbox. Both sibling
     * refusals on this path already arm a memo so the recovery can say the refusal did not hold;
     * this one armed nothing, so a delivered message would have left a permanent alarm sitting in
     * `cello_check_notifications` saying it had been turned away.
     *
     * Armed AFTER the notice is filed, so the memo can never claim a refusal that did not happen.
     */
    this.#ctx.refusals.noteRefusedOnDirectPath(agentName, sessionId, contentHash);
  }

  async #handleContentStream(agentName: string, sessionId: string, stream: Stream, remotePeerId?: string): Promise<void> {
    // CLOSING THIS STREAM IS WHAT KEEPS THE SESSION ALIVE PAST ITS 33RD MESSAGE.
    //
    // Every content frame and every delivery ACK opens a fresh /cello/content/1.0.0 stream on the
    // one muxed connection the session holds, and libp2p caps INBOUND streams per protocol per
    // connection. It enforces that cap AFTER multistream-select has answered, so an over-cap stream
    // negotiates fine and is reset an instant later, and the SENDER's next `stream.send(...)`
    // throws "Cannot write to a stream that is closed" — an error that names the exit point and not
    // one thing about the cause.
    //
    // A stream leaves the muxer's set only on its `close` event, and closing our write end triggers
    // that only once the peer has closed its end too. So a handler that reads its frame and returns
    // leaves the stream half-open for the life of the connection and the count only ever rises.
    // Measured on a live daemon: 115 failures over 3.5 hours, with EXACTLY 32 successful streams
    // before the first one on both affected sessions (M12B Entry 10).
    //
    // The decoder is built INSIDE the try so a malformed stream cannot throw past the close below.
    let iter: AsyncIterator<Uint8Array> | undefined;
    try {
      iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
      const result = await iter.next();
      if (result.done || result.value === undefined) return;
      const bytes = result.value instanceof Uint8Array ? result.value
        : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
        : (result.value as { slice(): Uint8Array }).slice();
      const frame = decode(bytes) as Record<string, unknown>;
      const correlationId = typeof frame["correlation_id"] === "string" ? frame["correlation_id"] : undefined;
      const frameType = typeof frame["type"] === "string" ? frame["type"] : "(absent)";

      /**
       * DOD-M15-FRAME-1 — ONE GATE, BEFORE THE DISPATCH, FOR EVERY FRAME ON THIS PROTOCOL.
       *
       * A stranger could dial an agent's standing receiver (it admitted everyone until DOD-M15-ASSIGN-1), hold
       * the connection open through promotion — libp2p's gater runs only at connection
       * establishment, so narrowing it does not evict anyone already attached — and then speak the
       * content protocol the moment it activated. The frame was ingested, leafed, transcribed, and
       * attributed to the legitimate counterparty, because attribution is read from local session
       * state rather than from anything the frame proved.
       *
       * DELIBERATELY SHARED RATHER THAN COPIED INTO EACH BRANCH. `session_abandoned_notice` already
       * had both checks, correct and complete, twenty lines below — and the other two frame types
       * did not. Copying the pattern a third and fourth time would fix today's three and leave the
       * fifth frame type, added later by someone who did not read this comment, unguarded again.
       * Placing it above the dispatch makes the guard the DEFAULT: a new frame type is protected by
       * construction and has to opt OUT visibly rather than opt in silently.
       *
       * Verified safe for all three current types by enumeration, not assumption — `content_frame`
       * (:5169), `session_abandoned_notice` (:6663) and `content_delivery_ack` (:7439) are the only
       * senders on `CELLO_CONTENT_PROTOCOL_ID`, and all three put `session_id` in the frame.
       *
       * MISSING, MALFORMED AND MISMATCHED TAKE ONE PATH. An attacker evading a mismatch check does
       * not send a wrong value — it sends no value, and a guard that only fires on a present-and-
       * wrong field is a guard that is trivially skipped. That is exactly what the old
       * `content_frame` check did: `typeof x === "string" && x !== sessionId`.
       */
      const expectedPeer = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId))?.counterpartySessionPeerId;
      if (!remotePeerId || !expectedPeer || remotePeerId !== expectedPeer) {
        // Loud in the LOG — there is no caller to answer on an inbound stream, so this is the whole
        // surface. Neutral wording: this is an observation, not a verdict about intent. The same
        // signal comes from a real impersonation attempt and from our own fallback paths
        // mishandling a reconnect, and nothing here can tell them apart.
        this.#ctx.logger.warn("session.content.peer_mismatch", {
          agentName, sessionId, frameType,
          remotePeerId: remotePeerId ?? "(absent)", expected: expectedPeer ?? "(unknown)",
          impact: "a frame arrived on this session's content protocol from a peer that is not its counterparty; it was refused — not ingested, not attributed, not recorded — and the peer was disconnected",
        });
        /**
         * PEER-ENDING, NOT SESSION-ENDING — and the difference is a deliberate deviation from the
         * DoD clause (review F2).
         *
         * The clause says the refusal is session-ending. Applied HERE that would be a worse hole
         * than the one it closes: a pre-positioned stranger could kill any session on the machine
         * with a single frame, trading an injection hole for a denial-of-service hole. The
         * session-ending response belongs where the evidence is about the SESSION's counterparty —
         * `#freezeOnIdentityFailure`, reached when a party that IS the peer we dialled signs with a
         * key that is not theirs.
         *
         * Here the evidence is about the PEER: they are not party to this session at all. So the
         * connection goes and the session is untouched. Without this the stranger stayed attached
         * for the life of the session and the gate re-refused each frame forever — and the eviction
         * sweep's own fallback ("the frame gate still refuses anything this peer sends") only closes
         * the loop if the frame gate does something about the connection.
         *
         * Fire-and-forget: a hang-up that fails must not turn a successful refusal into a thrown
         * handler, and the refusal above has already done the load-bearing work.
         */
        if (remotePeerId) {
          const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
          void entry?.node.hangUp(remotePeerId).catch((err: unknown) => {
            this.#ctx.logger.debug("session.content.peer_mismatch.hangup_failed", {
              sessionId, peerId: remotePeerId, error: extractErrorMessage(err),
            });
          });
        }
        return;
      }
      const claimedSessionId = frame["session_id"];
      if (typeof claimedSessionId !== "string" || claimedSessionId !== sessionId) {
        this.#ctx.logger.warn("session.content.session_mismatch", {
          agentName, sessionId, frameType,
          claimedSessionId: typeof claimedSessionId === "string" ? claimedSessionId : "(absent)",
          impact: "the frame does not name the session whose stream it arrived on; it was refused rather than routed, because the authenticated stream is the better authority for where content belongs",
        });
        return;
      }

      // CELLO-M7-MSG-001 (AC-001/AC-002): a `persisted` delivery ACK arriving on the
      // same /cello/content/1.0.0 protocol resolves the sender's awaiting-ACK timer.
      // The protocol acts on `persisted` ONLY — any other level leaves the timer armed.
      if (frame["type"] === "content_delivery_ack") {
        const ackHash = frame["content_hash"];
        const level = frame["level"];
        if (ackHash instanceof Uint8Array && level === "persisted") {
          this.#send.resolveAwaitingAck(agentName, sessionId, ackHash);
        }
        return;
      }

      // DOD-M12B-ABANDON-NOTIFY-1: the counterparty force-abandoned. Handled here, on the same
      // authenticated stream the delivery acknowledgement rides, and AFTER the session-id check
      // below cannot be skipped — the frame names its session and the handler is bound to one.
      if (frame["type"] === "session_abandoned_notice") {
        // DOD-M15-FRAME-1: the peer and session checks that used to live here now run above, for
        // EVERY frame type, unchanged in substance — this branch was where they were written first
        // and correctly, and it is the reference the shared gate was lifted from. Its comment is
        // preserved there, including the reason the transport being authenticated is not enough.
        // Left as a bare dispatch on purpose: a second copy of a guard is a second thing to keep in
        // step, and the one that drifts is the one nobody is reading.
        void this.#ctx.retireOnCounterpartyAbandon(agentName, sessionId, correlationId);
        return;
      }

      /**
       * DOD-M15-SEALWIRE-1 bullet 6 (part A) — the salt agreement.
       *
       * Placed BELOW the shared peer/session gate deliberately, which is the whole reason that gate
       * was lifted above the dispatch: a new frame type is protected by construction rather than
       * having to remember to opt in. A stranger's salt frame is refused before it reaches here, so
       * nothing about this session's salt can be steered by a peer that is not its counterparty.
       *
       * The fields are read defensively into the frame shape rather than cast: an inbound value is
       * whatever a peer chose to encode, and `onPeerSaltFrame` refuses both-fields and neither-field
       * by name — so a non-Uint8Array in either slot must arrive at that function as ABSENT, not as
       * a present-but-wrong value it would then try to use.
       */
      /**
       * 007-CRYPTO — the peer's SIGNED ephemeral.
       *
       * Fields are read defensively rather than cast, exactly like the salt frame below: an inbound
       * value is whatever a peer chose to encode, and `verifySessionEphemeral` refuses a missing or
       * wrong-width one BY NAME — so a non-`Uint8Array` must arrive there as ABSENT rather than as a
       * present-but-wrong value it would try to use.
       */
      if (frame["type"] === "session_key_agreement") {
        const ephemeralPublic = frame["ephemeral_public"];
        const signature = frame["ephemeral_sig"];
        await this.#ctx.ephemerals.handleEphemeralFrame(agentName, sessionId, {
          ...(ephemeralPublic instanceof Uint8Array ? { ephemeralPublic } : {}),
          ...(signature instanceof Uint8Array ? { signature } : {}),
        }, correlationId);
        return;
      }
      if (frame["type"] === "session_salt_agreement") {
        const contribution = frame["contribution"];
        const fingerprint = frame["fingerprint"];
        const adoptionClosed = frame["adoption_closed"];
        await this.#ctx.salts.handleSaltFrame(agentName, sessionId, {
          ...(contribution instanceof Uint8Array ? { contribution } : {}),
          ...(fingerprint instanceof Uint8Array ? { fingerprint } : {}),
          // A non-string stays ABSENT rather than being coerced, exactly like the other two: the
          // decision function refuses a shape it cannot read, and must never be handed a `"42"`.
          //
          // TRUNCATED AT THE BOUNDARY — 006-CRYPTO finding 6. Every label CELLO sends is under
          // twenty characters, and this one is chosen entirely by the peer. Cutting it here means
          // no unbounded peer string is stored, logged or rendered anywhere downstream; the
          // rendering that keeps it out of our own sentences is `renderPeerAdoptionLabel`.
          ...(typeof adoptionClosed === "string" && adoptionClosed.length > 0
            ? { adoptionClosed: adoptionClosed.slice(0, SALT_ADOPTION_LABEL_MAX) }
            : {}),
        }, correlationId);
        return;
      }

      if (frame["type"] !== "content_frame") {
        // LOGGED, not silently dropped. This handler is bound to one session, and a frame it does
        // not understand arriving on that stream is either a peer speaking a newer protocol or a
        // bug on our side — both worth a line, and neither distinguishable from "nothing arrived"
        // when the return is silent.
        this.#ctx.logger.warn("session.content.frame_unknown_type", {
          sessionId,
          type: typeof frame["type"] === "string" ? String(frame["type"]) : "(absent)",
        });
        return;
      }
      // DOD-M15-FRAME-1: the session-id check moved to the shared gate above, and its `&&` became
      // `||` on the way. It read `typeof x === "string" && x !== sessionId` — firing only when the
      // field was PRESENT and wrong, so omitting it passed. Its own sibling twenty lines up already
      // refused absence, with a comment saying treating a missing field as agreement is how a guard
      // stops guarding. Same file, same switch, opposite conclusion.
      // Review F4: hand the DECODED frame to a test observer before anything consumes it. Absent in
      // production — the field is null unless a test installs one.
      this.#ctx.inboundFrameObserver?.(frame as Record<string, unknown>);
      const contentBytes = frame["content_bytes"];
      const contentHash = frame["content_hash"];
      if (!(contentBytes instanceof Uint8Array) || !(contentHash instanceof Uint8Array)) {
        // Same reasoning as the unknown type above: a malformed frame that vanishes without a trace
        // is indistinguishable, from the operator's side, from a counterparty who never sent
        // anything.
        this.#ctx.logger.warn("session.content.frame_malformed", {
          sessionId,
          hasContent: contentBytes instanceof Uint8Array,
          hasHash: contentHash instanceof Uint8Array,
        });
        return;
      }
      /**
       * 🚨 DECRYPT BEFORE ANYTHING ELSE READS THE BODY — `DOD-M15-EPHEMERAL-AUTH-1`.
       *
       * `content_hash` is over the PLAINTEXT, so the hash check, the transcript, the seal and the
       * salted hash all keep meaning exactly what they mean today — but only if the body is put back
       * before any of them run.
       *
       * ⚠️ ABSENT IS NOT A PASS. A frame with no `content_encryption` is refused rather than read as
       * plaintext. There is no unencrypted sender to be compatible with, and treating a missing
       * marker as "this one is in the clear" is precisely the downgrade an attacker asks for: strip
       * one field and the receiver reads the body raw. Missing and unknown take the same path as a
       * failed decrypt, for the reason that runs through this whole unit — a check lenient about an
       * absent proof is a check that gets skipped.
       */
      const declaredEncryption = frame["content_encryption"];
      const encState = this.#ctx.ephemerals.contentEncryptionState(agentName, sessionId);
      let plaintextBody: Uint8Array;
      if (declaredEncryption !== SESSION_CONTENT_ENCRYPTION_V1) {
        this.#refuseInboundContent(agentName, sessionId, "content_encryption_absent_or_unknown", contentHash, {
          declared: typeof declaredEncryption === "string" ? declaredEncryption : "(absent)",
          impact: "the frame did not say it was encrypted under this session's key, so it was refused unread — nothing was shown and this copy was not kept.",
          guidance:
            "STOPPED ON PURPOSE. A message arrived that was not encrypted under this session's key. " +
            "This build never sends one, so either something between you rewrote the frame, or your " +
            "counterparty is running something that is not CELLO. Confirm with them OUT OF BAND " +
            "before opening another session.",
        }, correlationId);
        return;
      }
      if (encState.key === null) {
        this.#refuseInboundContent(agentName, sessionId, "no_session_key", contentHash, {
          detail: encState.reason,
          impact: "an encrypted message arrived and this side has no agreed key to open it, so it was refused unread rather than shown as garbage.",
          // Review F6: the RECEIVE-side wording. The send-side table explains what became of a
          // message this operator sent, which is the wrong direction entirely for a message they
          // cannot open.
          guidance: CONTENT_ENCRYPTION_INBOUND_GUIDANCE[encState.reason],
        }, correlationId);
        return;
      }
      const opened = openSessionContent(encState.key, contentBytes);
      if (opened === null) {
        // GCM's tag is the only thing separating "not for us" from "modified in flight", and this
        // side must not branch on which — that would be branching on attacker-controlled input.
        this.#refuseInboundContent(agentName, sessionId, "decrypt_failed", contentHash, {
          impact: "the message did not decrypt under this session's agreed key — it was modified in flight, or it was encrypted under a different key. Refused unread.",
          guidance:
            "STOPPED ON PURPOSE. Nothing was shown and this copy was not kept. A message that fails " +
            "this check has either been altered on its way to you or was not encrypted for this " +
            "session. Confirm with your counterparty OUT OF BAND, then start a new session.",
        }, correlationId);
        return;
      }
      plaintextBody = opened;
      // DOD-MSG-4 (self-ordering content frame): if the frame carries the relay's signed ordering
      // record, verify the sender signature and record the canonical sequence FROM THE FRAME, BEFORE
      // ingest — so the strict-in-order gate has the position without waiting on the separate
      // leaf_deliver witness (removes the content-before-witness race).
      //
      // DOD-M15-FRAME-1 — POSITION MAY BE SOFT; IDENTITY MAY NOT. The old comment here read "A
      // bad/absent record is non-fatal: the content still ingests", and it was accurate: a
      // signature that failed to verify, and a signature by a key that is NOT this session's
      // counterparty, both returned null and the content was ingested and attributed anyway. An
      // ABSENT record stays soft — that is the documented relay-degraded path and refusing it would
      // make the relay a precondition for reading mail. A record that is PRESENT and REFUTED is a
      // different fact, and it is now refused.
      const s1Cbor = frame["structure1_cbor"];
      const s2Cbor = frame["structure2_cbor"];
      /**
       * `DOD-M15-AUTHORSHIP-ABSENT-1` — the sender's own signature, carried BESIDE the bytes it
       * signs, exactly as `hash_submit` has always carried it. This field is why identity no longer
       * depends on the relay: it arrives whether or not a relay witnessed the message.
       */
      const senderSig = frame["sender_signature"];
      let framedSeq: number | null = null;
      /**
       * DOD-M15-SEALWIRE-1 bullet 5. Set ONLY when the ordering record verified — the signature
       * checked against the pubkey inside the sender's own signed bytes AND the signer matched this
       * session's counterparty. It is deliberately NOT set on the two soft paths below (no record
       * supplied; decode failed), because on those the author is attested by local session state
       * and the transcript row must say so rather than imply a proof it does not have.
       */
      let verifiedAuthorship: { senderPubkey: Uint8Array; senderSig: Uint8Array } | undefined;
      /**
       * 024-ORPHANTRIAGE: the signer when the signature verified but there was no counterparty to
       * match it against. Its ONLY consumer is the orphan branch inside ingest — everywhere else a
       * session record exists, so this stays `undefined` and nothing reads it.
       */
      let verifiedSignerUnmatched: Uint8Array | undefined;
      /**
       * ─── NO PASSPORT, NO ENTRY — `DOD-M15-AUTHORSHIP-ABSENT-1` ───────────────────────────────
       *
       * ⚠️ **THIS COMMENT USED TO SAY THE OPPOSITE, AND THE SENTENCE IT REPLACES IS THE DEFECT.**
       * It read: *"it means the per-message signer check is **opt-in for the sender** — a party that
       * passed the peer gate and wants to avoid the comparison simply omits the proof."* That was an
       * accurate description of the code, which is why it is rewritten here rather than deleted: it
       * is the sentence a reader with a coding agent finds, and it must now describe what the code
       * does. A frame that supplies nothing checkable is REFUSED. Omitting the proof buys the sender
       * nothing except a message that does not arrive.
       *
       * The old reasoning was sound as far as it went — the signature was only ever DELIVERED inside
       * the relay's Structure 2, so refusing on its absence would have made the relay a precondition
       * for reading mail. It stopped one field short: the signature travels beside the bytes it
       * signs now, on every content frame, so identity no longer needs the relay and position still
       * does not require identity.
       *
       * ⚠️ REFUSED, NOT FROZEN. A frozen session is only cleared by opening a new one, and the
       * overwhelmingly likely cause of an absent proof is a counterparty on an older build. The
       * freeze is for a proof that FAILED (below, and in `#recordFrameOrdering`) — a positive fact
       * about their key.
       */
      if (!(s1Cbor instanceof Uint8Array) || !(senderSig instanceof Uint8Array)) {
        this.#ctx.refusals.refuseUnprovenAuthorship(agentName, sessionId, "authorship_proof_absent", contentHash, {
          // WHICH half is missing. A sender on an older build supplies neither; a stripped frame is
          // likelier to be missing one, and an investigator should not have to guess which.
          hasStructure1: s1Cbor instanceof Uint8Array,
          hasSenderSignature: senderSig instanceof Uint8Array,
        }, correlationId);
        return;
      }
      const authorship = this.#ctx.authorship.verifyAuthorshipClaim(agentName, sessionId, s1Cbor, senderSig, contentHash);
      if (authorship.verdict === "refuted") {
        /**
         * THE FORENSIC LINE, BEFORE THE FREEZE. `session.content.identity.frozen` records that a
         * session was stopped; this records WHICH check stopped it and on WHICH proof — the frame's
         * own signature, not the relay's copy of it. The two used to be the same event because there
         * was only one place a signer was checked; there are two now, and an investigation that
         * cannot tell them apart is looking at the wrong half of the wire.
         */
        this.#ctx.logger.warn("session.content.authorship.refuted", {
          agentName, sessionId, correlationId, reason: authorship.reason,
          impact: "a message arrived with a proof of authorship that FAILED — it does not verify, or it is signed by a key that is not this session's counterparty. Nothing was ingested and the session is being frozen.",
        });
        await this.#ctx.freezeOnIdentityFailure(agentName, sessionId, authorship.reason, correlationId);
        return;
      }
      if (authorship.verdict === "unusable") {
        // A replayed claim gets its own name on BOTH surfaces, not just in the log context: it is
        // the one `unusable` cause that may be adversarial, and it is the one the operator can act
        // on. The others are a peer whose build or bytes we could not read.
        /**
         * 033-ACKEMIT — AND THE THREE ACKNOWLEDGEMENT CAUSES GET THEIR OWN SURFACE REASON, for the
         * same argument that gave the replay one: `authorship_proof_unusable` tells the operator the
         * proof was "unreadable, or signed over different content", and for these it is neither.
         * The proof is perfect; what it CLAIMS TO HAVE SEEN is wrong. Filing them under the generic
         * name would send someone to audit a decoder, and would spend the operator's attention
         * asking their counterparty about a version number that is not the question.
         */
        this.#ctx.refusals.refuseUnprovenAuthorship(
          agentName, sessionId,
          authorship.reason === AUTHORSHIP_SESSION_MISMATCH
            ? "authorship_wrong_conversation"
            /**
             * `DOD-M15-SELFCHAIN-1` — its own name on the surface the operator reads, not only in a
             * log field. See the sentences in `#refuseUnprovenAuthorship`.
             */
            : authorship.reason === AUTHORSHIP_SELF_CHAIN_MISMATCH
              ? AUTHORSHIP_SELF_CHAIN_MISMATCH
            : ACK_HASH_REASONS.has(authorship.reason)
              /**
               * ⚠️ THE SPECIFIC CAUSE, NOT THE CLASS — review F5, and the diff's own comment on
               * `ACK_HASH_REASONS` had already said why: "the operator's next move differs for
               * each." It then collapsed all three into ONE surface reason carrying ONE sentence,
               * so the three names survived only in a log field nobody reads. For an absent
               * acknowledgement the shared impact was flatly false — there is no part that "does
               * not match", because there is no part — and for the other two the shared guidance
               * sent the reader to ask about a build version that cannot be the cause.
               */
              ? (authorship.reason as AckHashReason)
              : "authorship_proof_unusable",
          contentHash, { detail: authorship.reason }, correlationId,
        );
        /**
         * ─── AND THE SESSION FREEZES — `DOD-M15-SELFCHAIN-1`, the escalation clause ──────────────
         *
         * ⚠️ ONLY THIS ONE OF THE `unusable` CAUSES FREEZES, and the split is the whole rule.
         *
         * The acknowledgement causes say the sender is wrong about what WE said, which a record
         * that has drifted produces honestly, and refusing the message is proportionate. This one
         * says they are wrong about what THEY said — the one thing a party cannot be honestly
         * mistaken about for long — so continuing writes a disputed order into the receipt. There
         * is nothing to gain from message N+1 on a conversation whose order is already in question.
         *
         * The freeze is what makes the refusal an ESCALATION rather than a dropped frame: it is
         * visible in the session's own state, not only in a notice the operator has to go and read.
         */
        if (authorship.reason === AUTHORSHIP_SELF_CHAIN_MISMATCH) {
          await this.#ctx.freezeOnIdentityFailure(agentName, sessionId, authorship.reason, correlationId);
        }
        return;
      }
      if (authorship.verdict === "verified") {
        verifiedAuthorship = { senderPubkey: authorship.senderPubkey, senderSig: authorship.senderSig };
      } else {
        verifiedSignerUnmatched = authorship.senderPubkey;
      }
      if (s2Cbor instanceof Uint8Array) {
        const ordering = this.#ctx.refusals.recordFrameOrdering(agentName, sessionId, s1Cbor, s2Cbor, contentHash, correlationId);
        if (ordering.fatal) {
          await this.#ctx.freezeOnIdentityFailure(agentName, sessionId, ordering.fatal.reason, correlationId);
          return;
        }
        framedSeq = ordering.seq;
      } else {
        /**
         * POSITION IS THE ONLY THING THAT CAN BE ABSENT NOW, and this event is about position.
         *
         * It fires on the relay-degraded path, where the sender had no witnessed record to stamp
         * on. The message is ingested — its author is proven, above, by the frame's own signature —
         * and only its place in the canonical sequence falls back to the witness stream. Refusing
         * here would make the relay a precondition for reading mail, which is the thing this unit
         * was careful NOT to do.
         */
        this.#ctx.logger.info("session.content.ordering.absent", {
          agentName, sessionId, correlationId,
          impact: "this frame carried no relay ordering record, so its POSITION in the canonical sequence is not known from the frame and falls back to the witness stream. Its AUTHOR was verified from the frame's own signature.",
        });
      }
      // AC-001: carry the sender's correlationId from the frame into the receive
      // path so both sides log the same flow id (never re-minted on receipt).
      /**
       * DOD-M15-SEALWIRE-1 part B1 — the algorithm the sender named, taken from the FRAME.
       *
       * Read as `unknown` and passed through verbatim, deliberately: `resolveContentHashAlg` is the
       * one place that decides what a value means, and it distinguishes ABSENT (a peer predating
       * the field — verify as `sha256`) from a non-string or an unreadable name (refuse by name).
       * Coercing here would collapse that distinction and turn a version skew into a tamper report.
       */
      const declaredAlg = frame["content_hash_alg"];
      const ingest = await this.ingestReceivedContent(
        // THE DECRYPTED body — everything downstream (the hash cross-check, the leaf, the transcript,
        // the delivery buffer) works on plaintext, exactly as it did before this layer existed.
        agentName, sessionId, plaintextBody, contentHash, correlationId, framedSeq ?? undefined,
        declaredAlg === undefined ? undefined : (declaredAlg as string | null),
        verifiedAuthorship,
        verifiedSignerUnmatched,
      );
      // AC-001: after the content is durably ingested AND its hash cross-check
      // succeeds, emit an unsigned `persisted` delivery ACK back to the sender. A
      // rejected ingest (tamper / not-active) produces NO ACK, so the sender's TTF
      // path can park / recover.
      // DOD-MSG-4: a HELD (out-of-order) frame is NOT yet a durable leaf, so it is NOT
      // acknowledged `persisted` — the sender's TTF→park backstop then guarantees the
      // missing-earlier message is fetchable, and dedup absorbs the redundant copy.
      if (ingest.ok && !ingest.held) {
        /**
         * ─── THE SELF CHAIN IS PURELY CONTENT, SO IT ADVANCES HERE — `DOD-M15-SELFCHAIN-1` ───────
         *
         * ⚠️ NOT INSIDE `#noteAcknowledgeable`, and that placement was the bug. The acknowledgement
         * is a (POSITION, content) pair and needs the relay's number, so on a session the relay
         * never witnessed it is never written at all. The self link needs no position — it is one
         * party's hash chain over their own messages — so tying it to the acknowledgement meant the
         * receiver's record never moved on an unwitnessed session, and the counterparty's SECOND
         * message was refused as a broken chain for the rest of the conversation.
         *
         * That is the path this unit exists for: a conversation that ran while the relay was down is
         * precisely the one whose order gets disputed later.
         */
        this.#ctx.authorship.noteReceivedFromCounterparty(agentName, sessionId, contentHash);
        /**
         * 033-ACKEMIT review F1 — ACKNOWLEDGE WHAT ARRIVED, HERE, not when the relay gets round to
         * delivering its copy back to us.
         *
         * Placed after a successful, non-held ingest deliberately: a HELD frame is not yet a durable
         * leaf and is not acknowledged `persisted` either, so claiming to have seen it would put a
         * position in our signed claim that our own record does not yet hold.
         *
         * `framedSeq` is the relay's canonical position taken from the sender's own signed ordering
         * record and verified before it got here. When it is absent the message arrived with no
         * ordering record — the withheld-submit case — and there is no position to acknowledge,
         * whatever we hold of the content. That limit is structural to a (position, content) pair
         * and it is what the carried-leaf follow-on closes.
         */
        if (framedSeq !== null) {
          this.noteAcknowledgeable(agentName, sessionId, framedSeq, contentHash);
        } else {
          /**
           * ─── WITNESS WHAT THEY DID NOT — 034-CARRYLEAF, and this is the line that closes
           * `DOD-M15-WITHHOLD-SEAL-1` ────────────────────────────────────────────────────────────
           *
           * No ordering record means the sender never asked the relay to witness this message. Two
           * things look identical from here: their relay was briefly unreachable, or they are
           * withholding it on purpose so it cannot appear in the receipt. **We do not need to tell
           * those apart, and that is the point** — the same action repairs both, and it costs the
           * honest case nothing.
           *
           * We hold their signature over their own bytes. So we hand it to the relay ourselves.
           */
          /**
           * ─── THE KIND COMES OFF THE FRAME, AND A FRAME WITHOUT ONE IS REFUSED ─────────────────
           *
           * A leaf kind selects a HASH DOMAIN — documents and rejection envelopes ride this same
           * frame — so witnessing under a guessed domain would put a wrong statement in the
           * canonical record.
           *
           * ⚠️ **THIS USED TO DECLINE TO WITNESS AND DELIVER THE MESSAGE ANYWAY, "because a peer
           * too old to send the field should be left alone". THAT SENTENCE WAS INHERITED, NOT
           * DERIVED, AND IT LEFT THE WHOLE ATTACK OPEN.** CELLO is alpha with no users; there is no
           * older peer to protect. What the leniency actually bought was an opt-out: emit the shape
           * a 2026-09-04 build emitted, and your message is delivered AND cannot be witnessed —
           * which is precisely the withholding this line exists to stop, reachable by anyone
           * willing to modify their client.
           *
           * So it is refused. Missing, malformed and mismatched take one path (§5), and a peer that
           * cannot say which domain its own leaf belongs to has supplied an unusable proof.
           */
          const framedKind = frame["leaf_kind"];
          if (typeof framedKind !== "number") {
            this.#ctx.refusals.refuseUnprovenAuthorship(agentName, sessionId, "authorship_proof_unusable", contentHash, {
              detail: "leaf_kind_absent",
            }, correlationId);
            return;
          }
          void this.witnessReceivedLeaf(agentName, sessionId, contentHash, s1Cbor, senderSig, framedKind, correlationId);
        }
        void this.#sendDeliveryAck(agentName, sessionId, contentHash, correlationId);
      }
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.content.stream.read.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      // `close()` waits only for OUR write buffer, which is empty here, so this cannot stall the
      // handler; it runs on every exit above, and there are several early returns.
      try {
        await stream.close();
      } catch (err: unknown) {
        // NOT SILENT. A close that fails here is the signature of the cap biting from the other
        // side, and it was the absence of exactly this line that turned the original diagnosis
        // into a 6,451-record log measurement.
        this.#ctx.logger.warn("session.content.stream.close.failed", {
          sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
        try { stream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
        return;
      }
      // OUR CLOSE ALONE DOES NOT FREE THE SLOT — the peer has to close its end too, and a peer
      // owns its own daemon. Without this, someone who opens content streams and never closes them
      // pins every inbound slot we have and puts us straight back into the defect above, with the
      // same unreadable error. `abort` resets unilaterally, so it works regardless of the peer;
      // the delay is what keeps it from landing while a well-behaved sender is still inside its
      // own `close()`. Unref'd so it can never hold the process open at shutdown, and tracked so
      // teardown can drop it.
      if (stream.status === "open" || stream.status === "closing") {
        const linger = setTimeout(() => {
          this.#ctx.lingeringStreams.delete(linger);
          if (stream.status !== "open" && stream.status !== "closing") return;
          this.#ctx.logger.debug("session.content.stream.linger.reset", { sessionId });
          try { stream.abort(new Error("inbound content stream not closed by peer")); } catch { /* already gone */ }
        }, CONTENT_STREAM_LINGER_MS);
        linger.unref?.();
        this.#ctx.lingeringStreams.add(linger);
      }
    }
  }
}

