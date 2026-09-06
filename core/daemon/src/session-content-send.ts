/**
 * CELLO Daemon — SENDING A MESSAGE
 *
 * The outbound half of the content path, split out of `session-node-manager.ts` with its inbound
 * counterpart in `session-content-ingest.ts`. What happens between an operator calling
 * `cello_send` and the bytes leaving this machine: hashing and labelling the content, having the
 * relay witness its position, signing our own authorship of it, encrypting it, placing our leaf,
 * opening the stream, and arming the timer that parks the message when no acknowledgement returns.
 *
 * **Moved verbatim, comments included.**
 *
 * The two halves are separated because they share almost nothing: outbound reaches nothing on the
 * inbound side at all, and inbound reaches exactly ONE thing here — `resolveAwaitingAck`, when the
 * counterparty's delivery acknowledgement arrives on the stream the receiver is already reading.
 * That single edge is why this class is constructed first and handed to the other one.
 */
import * as lp from "it-length-prefixed";
import { encodeCbor, decodeStructure1, encodeStructure1 } from "@cello-protocol/protocol-types";
import { verify, sealSessionContent } from "@cello-protocol/crypto";
import { CELLO_CONTENT_PROTOCOL_ID, type CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { WritableSessionTreeLeafKind } from "./session-tree.js";
import { CONTENT_ENCRYPTION_GUIDANCE, SESSION_CONTENT_ENCRYPTION_V1 } from "./content-encryption-status.js";
import { REFUSAL_KINDS, relayAckHashRefusalNotice } from "./refusal-reasons.js";
import { parkRefusalGuidance } from "./park-envelope.js";
import { terminalRelayRefusal } from "./session-terminal-refusal.js";
import { AgentRelayClient, isTerminalRelayRefusal } from "./session-relay-client.js";
import { REDIAL_COOLDOWN_MS, type ActiveSessionEntry, type SentAuthorship } from "./session-node-types.js";
import type { SessionContentPipelineContext } from "./session-content-context.js";

export class SessionContentSender {
  readonly #ctx: SessionContentPipelineContext;

  constructor(ctx: SessionContentPipelineContext) {
    this.#ctx = ctx;
  }

  /**
   * Send content over the session node's direct P2P content stream.
   * On a dead/missing stream this returns a NAMED, diagnosable failure — never a silent success
   * (which desyncs the two sides). Do not swallow a send error here.
   *
   * SCOPE / findings #3 + #4 — what this send path does and does NOT do today:
   *   - #4: it delivers the content over the direct /cello/content/1.0.0 P2P
   *     stream only. It does NOT also submit a K_local-SIGNED content_hash leaf to
   *     the RELAY on /cello/relay/1.0.0 (EARS behavior #1). That relay hash-submit
   *     is MSG-001's scope; AC-001's "relay log shows a hash_submit" evidence is
   *     produced once MSG-001 lands.
   *   - #3: because there is no relay yet, the sequence number cello_send returns
   *     is the LOCAL leaf index, not a relay-assigned canonical global sequence.
   *     Each daemon appends leaves in its own LOCAL observation order, so two
   *     daemons' roots agree only under perfectly ping-ponged traffic. Canonical
   *     cross-process ordering (and thus AC-002 root agreement under concurrent
   *     bidirectional traffic) requires the relay-assigned sequence from MSG-001.
   */
  async sendContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    /**
     * Required alongside the two below — every production caller already passes one, and an optional
     * parameter in front of a required one is what TypeScript refuses. Making it explicit costs
     * nothing and removes the last place a positional argument can silently shift.
     */
    correlationId: string | undefined,
    /**
     * The DOMAIN this content belongs to, as the relay and the directory will see it. Defaults to
     * MESSAGE so `cello_send` is unchanged; the document path passes 0x04/0x05. Not cosmetic — the
     * directory computes `final_message` and `answered` from the witnessed kind, and both of its
     * document exclusions were dead while every document leaf arrived here as a message.
     *
     * ⚠️ ALSO REQUIRED NOW, and for the same reason as `contentHashAlg` below — this parameter is the
     * precedent, not a bystander. It defaulted to MESSAGE, the document adapter in `daemon.ts`
     * silently dropped it, and the wire was wrong for a whole release: *"0.0.145 shipped the fix
     * everywhere except here."* A default that matches the common case makes the omission invisible
     * at every call site and at typecheck. Every caller states its kind now.
     */
    leafKind: number,
    /**
     * `DOD-M15-SEALWIRE-1` part B2b — the algorithm `contentHash` was produced under, taken from
     * `contentHashForSession` by the caller that computed the hash.
     *
     * Passed rather than re-derived HERE, deliberately: re-deriving would ask "how would this
     * session hash something now?", and the answer can differ from how THIS message was actually
     * hashed. A hash and its label must travel together or the peer refuses a message nobody touched.
     *
     * ⚠️ REQUIRED, NOT DEFAULTED — review B2b-1 F4, and the default is what made four mutants
     * unfalsifiable. It was `= CONTENT_HASH_ALGS.SHA256`, which equals the only value in play today,
     * so DROPPING THE ARGUMENT AT ANY OF THE FIVE HOPS produced byte-identical output and the whole
     * 2,800-test daemon suite stayed green. Measured at all four send sites individually.
     *
     * A default that equals the current value makes every threading edit invisible until the value
     * changes — and the day it changes, the dropped argument mislabels the message and every peer
     * refuses it as a tamper. Required makes a dropped argument a TYPECHECK failure instead of a
     * test question nobody can answer.
     */
    contentHashAlg: string,
  ): Promise<
    // DOD-M12B-INDEX-1: `sequenceNumber` is the position the relay assigned this message, carried
    // out so the caller can place its leaf THERE rather than at whatever the tail happens to be.
    // Absent when no ordering authority answered — the documented relay-degraded case.
    // DOD-M15-SEALWIRE-1 bullet 5, SENT half: `authorship` is OUR OWN signature over the Structure-1
    // bytes we put on the wire, carried out so the caller can store it on the sent transcript row.
    //
    // ⚠️ IT IS RETURNED, NOT STASHED, for the same reason `sequenceNumber` is: the value belongs to
    // THIS send, and a side map keyed by session would hand a caller the wrong send's signature the
    // moment two are in flight. It is also paired with the exact `structure1_cbor` it signs —
    // a signature next to the wrong signed bytes is worse than no signature, because it looks
    // checkable and fails.
    //
    // Absent whenever the relay did not witness this leaf: an unwitnessed send has no Structure 1 on
    // the wire, so there is nothing signed to store. The row then records `self_authored` with no
    // proof, which is exactly what happened, rather than implying one.
    | { ok: true; delivered: true; sequenceNumber?: number; authorship?: SentAuthorship }
    | { ok: true; delivered: false; parked: true; sequenceNumber?: number; authorship?: SentAuthorship }
    /**
     * ⚠️ `authorship` RIDES THE FAILURE PATH TOO — review pass 2, and it is the same reasoning that
     * already put `sequenceNumber` here.
     *
     * A DURABLY QUEUED message was witnessed and SIGNED before delivery was attempted; only the
     * direct hand-off failed. Omitting the proof here meant every relay-degraded-but-alive send —
     * the common case — wrote a transcript row indistinguishable from one the relay never saw, while
     * the signature for it sat in scope and was discarded. The position survives a failed delivery
     * for exactly this reason; so does the proof.
     */
    | { ok: false; reason: string; error: string; durable: boolean; cause?: string; guidance?: string; sequenceNumber?: number; authorship?: SentAuthorship }
  > {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) {
      // M12-P13: no node, so nothing was witnessed and nothing was queued — the caller must NOT
      // commit a leaf for this. `durable` is a required field precisely so a new failure branch
      // cannot be added without answering the question every caller now asks.
      return { ok: false, reason: "session_node_unavailable", error: "no active session node for this session", durable: false };
    }
    // R1 (MSG-001-3b): witness the message-leaf HASH to the relay FIRST, INDEPENDENT of
    // direct delivery. The relay is the ordering authority (Structure 2): it assigns the
    // canonical sequence from the hash whether or not the counterparty is reachable for direct
    // content. So an OFFLINE recipient still gets a sequence, and the parked content is later
    // recovered AT that sequence (DOD-MSG-4 recovery-not-desync). The relay only ever sees the
    // hash (INV-3). Best-effort: a relay miss degrades to local-only sequencing.
    //
    // This MUST run BEFORE the direct send, not after it: an offline recipient never completes a
    // direct send, and sequencing after it would leave their content with no sequence at all.
    //
    // DOD-MSG-4 (self-ordering content frame): the relay's committed ordering record for this leaf,
    // captured from the hash submit so it can be stamped into the content frame (and the parked
    // entry). Undefined if the relay is unreachable / an old relay — the receiver then falls back to
    // the leaf_deliver witness stream / arrival order.
    let orderingS1: Uint8Array | undefined;
    let orderingS2: Uint8Array | undefined;
    /**
     * `DOD-M15-AUTHORSHIP-ABSENT-1`: the sender's signature over `orderingS1`, when the relay
     * witnessed this leaf. Undefined when it did not — and the frame builder below then signs a
     * Structure 1 of its own rather than shipping a frame with nothing to check.
     */
    let orderingSig: Uint8Array | undefined;
    /**
     * DOD-M15-SEALWIRE-1 bullet 5, SENT half. Our own Ed25519 signature over `orderingS1`.
     *
     * The submit path already computes this — `keyProvider.sign(structure1)` — and puts it on the
     * wire as `sender_signature`. It was simply never handed back, which is the whole of the defect:
     * a RECEIVED row could prove its author to a third party and a SENT row could not, so half the
     * transcript was provable and half was assertion.
     */
    let sentAuthorship: SentAuthorship | undefined;
    // DOD-M12B-INDEX-1: the relay's answer to "where does this message go", carried to the caller.
    let assignedSeq: number | undefined;
    // DOD-MP-SESSION-RETIRE-1 — the relay's answer SURVIVES to the caller even when the direct send
    // then succeeds. `relay_session_gone` is deliberately not terminal (it also fires for perfectly
    // live sessions whenever the relay restarts, because the relay stores sessions in memory), so
    // this path warns and carries on — and the send returns `ok: true, delivered: true` for a leaf
    // that was never witnessed. The content arrives; the RECORD stops growing, silently.
    //
    // Reporting it does not change success or failure for any existing caller. It lets the document
    // worker, which has no human in the loop, notice that a session's record is dead and route
    // around it. Without this the suspicion counter could never see the one reason it exists for,
    // and the successful direct send actively CLEARED it.
    let relayRefusal: string | undefined;
    if (entry.relayClient && entry.relaySessionIdBytes) {
      try {
        const witnessed = await entry.relayClient.submitMessageHash(entry.node, entry.relaySessionIdBytes, contentHash, leafKind);
        if (witnessed.ok) {
          orderingS1 = witnessed.structure1_cbor;
          orderingS2 = witnessed.structure2_cbor;
          // `DOD-M15-AUTHORSHIP-ABSENT-1`: the signature that goes ON THE FRAME beside `orderingS1`.
          // Captured here, next to the bytes it signs, because a signature assigned anywhere else
          // could end up beside a different Structure 1 — a proof next to the wrong signed bytes is
          // worse than no proof, since it looks checkable and fails.
          orderingSig = witnessed.sender_signature;
          /**
           * PAIRED WITH THE BYTES IT SIGNS, in one place, so the two can never be assigned apart.
           *
           * ⚠️ THE PUBKEY COMES FROM INSIDE `structure1_cbor`, NOT FROM AN AGENT LOOKUP — the same
           * source the RECEIVED half uses. A verifier checks the signature against the key in the
           * signed bytes; storing any other key would produce a row that looks checkable and fails,
           * and a lookup could drift from what was actually signed (a rotated identity, the wrong
           * agent resolved by name). Taking it from the signed bytes makes that class impossible.
           */
          if (witnessed.structure1_cbor && witnessed.sender_signature) {
            /**
             * ⚠️ THE DROP IS SOFT, BUT IT MUST NOT BE SILENT — review pass 1, F2.
             *
             * My comment here claimed the resulting row is "distinguishable from one that carries a
             * signature". True, and it misses the comparison that matters: **it is byte-identical to
             * an UNWITNESSED send** — `self_authored`, both proof columns NULL. So the record cannot
             * tell "the relay never witnessed this" from "we witnessed it, held the proof, and
             * dropped it decoding our own bytes."
             *
             * And the asymmetry with the received half is the argument. The received half is soft
             * about a missing ORDERING record (`#recordFrameOrdering`) because the COUNTERPARTY
             * supplied those bytes — an absence we cannot resolve. It is not soft about a missing
             * authorship proof any more; `DOD-M15-AUTHORSHIP-ABSENT-1` refuses that outright.
             * Here **we produced them**, in `session-relay-client.ts`, moments earlier. A failure
             * means our own encoder and decoder disagree: an internal invariant break that would
             * strip authorship from every sent row for the life of the process. Soft is still right
             * — throwing would lose a delivered message over a missing attestation — but soft and
             * unannounced is the silent-fallback pattern this milestone exists to find.
             */
            const dropAuthorship = (reason: string, error?: unknown, extra?: Record<string, unknown>): void => {
              this.#ctx.logger.warn("session.sent.authorship.unavailable", {
                sessionId,
                agentName,
                reason,
                // WHICH ROW lost its proof — review pass 2, M2. Without the sequence an operator knows
                // a message is unproven and not which one, in a transcript of hundreds.
                ...(witnessed.ok ? { relaySequence: witnessed.sequence_number } : {}),
                ...(extra ?? {}),
                ...(error === undefined ? {} : { error: error instanceof Error ? error.message : String(error) }),
                impact:
                  "this sent message is recorded with attribution 'self_authored' and NO signature, so the row " +
                  "asserts its author rather than proving one. It is indistinguishable in the database from a " +
                  "send the relay never witnessed — this log line is the only thing that tells them apart.",
                guidance:
                  "We produced these bytes ourselves, so a decode or shape failure here means this daemon's own " +
                  "encoder and decoder disagree. Treat it as an internal invariant break, not a peer problem.",
                correlationId,
              });
            };
            try {
              // Structure 1 = [version, content_hash, sender_pubkey, session_id, last_seen_seq,
              // timestamp] (+ last_seen_hash at 6 on a v2 claim — 020-ACKHASH). The sender pubkey is
              // index 2 in both; the same read `#recordFrameOrdering` does for the received half.
              const s1Decoded = decodeStructure1(witnessed.structure1_cbor);
              // NAMED AT ITS CAUSE. A failed decode falling through to the shape check below would
              // report `pubkey_shape` for bytes that never yielded a pubkey at all, sending the next
              // reader to audit a key when the layout is what disagreed.
              const pk = s1Decoded.ok ? s1Decoded.fields.senderPubkey : undefined;
              // The SIGNATURE is length-checked too (review F2): the guard checked the pubkey's 32
              // bytes and only truthiness on the signature, so a zero-length one would have stored an
              // uncheckable BLOB. Not reachable today — `sign()` returns 64 — and the asymmetry is
              // the kind that stops being unreachable quietly.
              /**
               * ⚠️ VERIFIED BEFORE IT IS STORED, NOT SHAPE-CHECKED — review pass 2, H2, and this is
               * worth more than any test of it.
               *
               * This used to accept the pair on 32 bytes and 64 bytes. A shape check cannot tell a
               * real proof from 96 bytes that resemble one, and **nothing downstream ever checks
               * either**: not at write time, and not at read time, because no production reader of
               * these columns exists yet. So a wrong Structure-1 index, a wrong key, or a pair from
               * two different submits would all have been persisted as a row that **looks checkable
               * to an auditor and fails** — strictly worse than the honest unproven row it replaced.
               *
               * The received half has always done this (`#verifyAuthorshipClaim` verifies before
               * storing and treats a failure as fatal). The sent half did not, and every ingredient
               * was already in scope on this line.
               *
               * What it buys over a test: a wrong index becomes **impossible to persist**. The row
               * gets NULL, the warn below fires, and it happens in production on the machine that
               * caused it — not in a suite someone has to remember to write.
               *
               * NOT fatal, unlike the received half, and the asymmetry is deliberate: there the
               * failure means a COUNTERPARTY sent something that does not verify, which is an
               * identity problem. Here it means our own encoder and decoder disagree — bad, but it
               * must not cost the operator a delivered message.
               */
              if (!s1Decoded.ok) {
                dropAuthorship("structure1_decode_failed", undefined, { structure1Reason: s1Decoded.reason });
              } else if (!(pk instanceof Uint8Array) || pk.length !== 32) {
                dropAuthorship("pubkey_shape", undefined, { pubkeyLen: pk instanceof Uint8Array ? pk.length : -1 });
              } else if (witnessed.sender_signature.length !== 64) {
                dropAuthorship("signature_shape", undefined, { sigLen: witnessed.sender_signature.length });
              } else if (!verify(pk, witnessed.structure1_cbor, witnessed.sender_signature)) {
                dropAuthorship("pair_does_not_verify");
              } else {
                sentAuthorship = { senderPubkey: pk, senderSig: witnessed.sender_signature };
              }
            } catch (err: unknown) {
              // NOT a decode failure — review F3. `decodeStructure1` never throws and its failure is
              // handled as the first branch above, with its own reason. What can still throw in here
              // is `verify()` and the Buffer work, so this names that instead of sending the reader
              // to audit a CBOR layout that decoded fine.
              dropAuthorship("authorship_verify_threw", err);
            }
          }
          // 1-BASED → 0-BASED. The relay numbers the first leaf of a session 1
          // (`relay-node.ts`: `const seq = state.seq_counter + 1`), and this tree is 0-indexed.
          // Every RECEIVE path in this file normalises with -1 and says so; the send path took the
          // raw number, which puts every comparison against `tree.size()` one position out — so a
          // perfectly healthy first message reads as "ahead of the tail" and is held behind a gap
          // that does not exist. Do not remove this without changing both receive sites too.
          assignedSeq = witnessed.sequence_number - 1;
          this.#ctx.logger.info("session.relay.hash.submitted", {
            sessionId,
            // BOTH SPACES, NAMED. The relay's number is 1-based and the leaf index is 0-based, and
            // reading one as the other is the defect this milestone exists to stop — so a log that
            // carries only "sequenceNumber" invites exactly that mistake on the next investigation.
            relaySequence: witnessed.sequence_number,
            leafIndex: assignedSeq,
            correlationId,
          });
        } else if (isTerminalRelayRefusal(witnessed.reason)) {
          // TERMINAL — REFUSE THE SEND, AND RETIRE THE SESSION. The relay has ended this session, so
          // this leaf can never enter the record and neither can any leaf after it. Continuing would
          // deliver content the conversation cannot prove it exchanged, and report `delivered: true`
          // while doing it.
          //
          // That is not hypothetical. Measured 2026-08-09: a session whose relay had sealed it after
          // both away-responders fired ran for 68 more minutes and 8 more messages, every send
          // reporting success, against a chain that had stopped growing at six leaves.
          //
          // Refused rather than parked: parking is for content the peer has not received YET. There
          // is no yet.
          //
          // DOD-MP-SESSION-RETIRE-1 — extracted to a function so the behaviour is REACHABLE BY A
          // TEST. Inline, it needed a live `#activeNodes` entry holding a real relay client, which
          // no unit test can construct — so nothing could assert what this daemon DOES about a
          // terminal refusal, and for a long time the answer was "logs it and carries on". The seam
          // that must be substituted is the relay's ANSWER; the thing under test is the response to
          // it. Splitting them makes the second testable without faking the first.
          return terminalRelayRefusal(
            {
              logger: this.#ctx.logger,
              // FULL TEARDOWN, not a status write. Every other terminal path goes through these,
              // and the difference is not bookkeeping: `destroySessionNode` also records the
              // terminal answer for a BLOCKED `cello_receive` (which otherwise hangs to timeout),
              // detaches the relay stream, stops the libp2p node, evicts the plaintext caches, and
              // re-arms the standing receiver — which on a fixed-port deployment is the moment the
              // port is freed. A DB-only flip leaves the corpse in `#activeNodes` holding the very
              // port the replacement session may need, which would defeat this fix's own purpose.
              //
              // THE TWO TERMINAL REASONS ARE NOT THE SAME FACT and must not share a status:
              //   session_sealed    — the seal really completed; a FROST certificate exists at the
              //                       directory and `cello_sealed_receipt` pulls it on a local miss.
              //   session_not_found — the relay never held it or lost it. There may be no
              //                       certificate anywhere, so writing "sealed" would be a
              //                       FABRICATED NOTARIZATION CLAIM: `cello_close_session` would
              //                       answer "already sealed, view its notarization" while the
              //                       receipt read answers "not sealed yet" — the two-answers-
              //                       pointing-at-each-other deadlock `seal-certificate-pull.ts`
              //                       exists to kill. `abandoned` is the state invented for
              //                       locally-terminal-with-nothing-to-notarize.
              // ONLY `session_sealed` RETIRES ANYTHING. The other terminal reason,
              // `session_not_found`, is documented THREE FUNCTIONS AWAY as **transient**
              // (DOD-FIRSTMSG-WITNESS-1): the relay does not hold the session YET, and in all 23
              // logged first-message failures the assignment landed 5ms–2.1s after the rejected
              // submit. Retiring on it would destroy a live session seconds old — trading a stuck
              // document for a killed conversation, which is a strictly worse bug than the one this
              // unit fixes. It still refuses the send; it just does not reach for the shovel.
              retireSession: (id) => {
                /**
                 * `session_sealed` retires as SEALED. `seal_refused` retires as ABANDONED —
                 * `DOD-M15-TERMINAL-REASON-1`, and the distinction is the whole reason that unit
                 * exists.
                 *
                 * A refused seal has NO certificate: a directory read it and rejected it. Writing
                 * `sealed` here would be a fabricated notarization claim — `cello_close_session`
                 * answering "already sealed, view its notarization" while the receipt read answers
                 * "not sealed yet", which is the two-answers-pointing-at-each-other deadlock
                 * described above. `abandoned` is the state invented for exactly this:
                 * locally terminal with nothing to notarize.
                 */
                if (witnessed.reason === "seal_refused") {
                  // `abandonSession`, not a hand-rolled flip-then-teardown: it already does the
                  // status write synchronously BEFORE the async teardown yields, which is the
                  // ordering the comment above spends a paragraph on. Reimplementing it here would
                  // be a second copy of that reasoning, free to drift from the first.
                  void this.#ctx.abandonSession(agentName, id);
                  return;
                }
                if (witnessed.reason !== "session_sealed") return;
                // STATUS FIRST AND SYNCHRONOUS, teardown second — the order `abandonSession` uses,
                // and for a sharper reason here: `destroySessionNode` returns early at its
                // `if (!entry) return` when the node is not in `#activeNodes`, and the status write
                // lives AFTER that guard. There is an entry on this path today (we are mid-send on
                // its relay client), but resting the whole fix on that is resting it on a
                // coincidence — a concurrent teardown would leave the row `active` and the loop
                // would resume. The flip is the load-bearing half; the teardown is what makes the
                // memory agree with it.
                this.#ctx.updateSessionStatus(agentName, id, "sealed");
                void this.#ctx.destroySessionNode(agentName, id, "sealed");
              },
            },
            { sessionId, reason: witnessed.reason, correlationId },
          );
        } else {
          this.#ctx.logger.warn("session.relay.hash.submit.failed", {
            sessionId,
            reason: witnessed.reason,
            // The relay's own words about what happened, when it sent any. `reason` is the class and
            // this is the cause — without it a refusal reaches the operator as a bare code, which is
            // the state this field existed to end and never actually did.
            ...(witnessed.detail === undefined ? {} : { detail: witnessed.detail }),
            correlationId,
          });
          /**
           * ─── 033-ACKEMIT: THIS ONE REACHES THE OPERATOR, NOT JUST THE LOG ─────────────────────
           *
           * Every other refusal on this branch is an availability answer — the relay is busy, the
           * session is not recorded, the stream died — and the send degrades to unwitnessed, which
           * is the documented path. These two are not availability. The WITNESS is telling us that
           * the acknowledgement this daemon signed disagrees with the record, and that is a
           * statement about the integrity of the conversation.
           *
           * `logger.warn` followed by a bare assignment is the exact shape Invariant 2's recurring
           * box names — a guard that fires correctly into a file nobody opens. The named surface is
           * `noteContentRefusal`, the same one every inbound refusal in this file uses, so it lands
           * where the operator already looks for "something was rejected and here is why".
           *
           * It does NOT stop the send. The relay refused to witness this leaf, so the message
           * degrades to unwitnessed exactly as any other refusal does and the operator keeps their
           * conversation; what changes is that they are told the record has stopped agreeing with
           * itself, at the moment it happens, instead of discovering it at the seal.
           */
          if (witnessed.reason === "ack_hash_mismatch" || witnessed.reason === "ack_hash_unverifiable") {
            const relayFault = witnessed.reason === "ack_hash_unverifiable";
            /**
             * THE SENTENCES LIVE IN `refusal-reasons.ts` — 033-ACKEMIT review F6. They were inline
             * here, behind a real relay answering a real refusal, so nothing could test them; and
             * the one that was wrong (a remedy naming a relay handover this system does not have)
             * was wrong for as long as that lasted.
             */
            const { impact, guidance } = relayAckHashRefusalNotice(relayFault, this.#ctx.mailboxRouteAvailable(agentName));
            this.#ctx.logger.error("session.relay.ack_hash.refused", {
              agentName, sessionId, correlationId, reason: witnessed.reason,
              ...(witnessed.detail === undefined ? {} : { detail: witnessed.detail }),
              impact, guidance,
            });
            this.#ctx.notices.noteContentRefusal(agentName, sessionId, witnessed.reason, {
              kind: REFUSAL_KINDS.REFUSED, impact, guidance,
            });
          }
          relayRefusal = witnessed.reason;
        }
      } catch (relayErr: unknown) {
        this.#ctx.logger.warn("session.relay.hash.submit.failed", {
          sessionId,
          reason: relayErr instanceof Error ? relayErr.message : String(relayErr),
          correlationId,
        });
      }
    }

    // Attempt direct peer↔peer content delivery. On success the receiver's `persisted` ACK
    // resolves the awaiting timer; on failure (counterparty offline) the hash is already
    // witnessed above, so the caller / TTF path parks the SEALED content to the relay
    // store-and-forward backstop and the recipient recovers it at the witnessed sequence (2b).
    // Held outside the try so the catch can retire a stream that was opened and then failed to
    // write. Without it every failure leaks the OUTBOUND half of the stream the receiver-side
    // `finally` retires — same defect, other end, other cap (64 outbound per protocol per
    // connection). See the note on #handleContentStream's finally.
    let sendStream: Stream | undefined;
    // 🔗 `DOD-M15-SELFCHAIN-1`: true when THIS side built the claim, so this side owns advancing its
    // chain once the message has gone. Declared out here because the PARK path — which is also a
    // delivery — runs in the catch below.
    let ownClaimAwaitingSend = false;
    /**
     * 034-CARRYLEAF — HOISTED OUT OF THE TRY so the PARK path in the catch can carry them.
     *
     * The park copy is built when the direct send fails, which is inside the catch below; declaring
     * these in the try left the parked envelope with only the relay-WITNESSED claim, so a message
     * its author deliberately did not witness was parked with no ordering claim at all and could
     * never be witnessed by its recipient.
     */
    let frameS1: Uint8Array | undefined;
    let frameSig: Uint8Array | undefined;
    try {
      /**
       * ─── EVERY FRAME CARRIES ITS OWN PROOF — `DOD-M15-AUTHORSHIP-ABSENT-1` ────────────────────
       *
       * Structure 1 used to be built and signed INSIDE the relay submit, so a send the relay never
       * witnessed put a frame on the wire with nothing on it to check — and the receiver, having no
       * proof to compare, ingested it and attributed it anyway. There was always something to sign;
       * nobody signed it.
       *
       * ⚠️ `structure2_cbor` IS DROPPED WHEN WE BUILD OUR OWN, and that pairing is load-bearing. The
       * relay's record commits its copy of the sender's signature to the EXACT Structure 1 that was
       * submitted; put it beside a Structure 1 built here (different timestamp, different
       * last_seen_seq) and the receiver's cross-check fails against bytes that were never altered —
       * a freeze on an honest message. The two travel together or the relay's half does not travel.
       *
       * ⚠️ SIGNED HERE, BEFORE THE SESSION KEY IS READ, and the order is load-bearing rather than
       * tidy. `sessionKey` below is read once and used to seal the body several `await`s later; a
       * key agreed with the counterparty inside that window leaves this side sealing under the key
       * it captured while the far side has already moved on, and every message is refused as
       * `decrypt_failed`. Signing costs two awaits, and putting them between the read and the seal
       * widened that window enough to break the live two-node round trip. Measured, not reasoned
       * about: seam-3 went red and both daemons logged `session.key.agreed` before the refusal.
       */
      frameS1 = orderingS1;
      frameSig = orderingSig;
      let frameS2 = orderingS2;
      // A relay-witnessed claim advanced the chain on its ack; this flag covers the other case.
      if (frameS1 === undefined || frameSig === undefined) {
        const own = await this.#signOwnContentClaim(agentName, sessionId, entry, contentHash);
        ownClaimAwaitingSend = true;
        frameS1 = own.structure1;
        frameSig = own.signature;
        frameS2 = undefined;
        /**
         * ⚠️ **AND OUR OWN TRANSCRIPT ROW GETS THE PROOF TOO** — review M3.
         *
         * `sentAuthorship` is set above only when the relay witnessed the leaf, because that was
         * the only path that ever produced a signature. This path produces one — and dropping it
         * here would leave the counterparty's transcript able to prove we wrote the message while
         * ours recorded `self_authored` with a NULL signature. That is exactly the half-provable
         * transcript `DOD-M15-SEALWIRE-1` bullet 5 exists to close, reappearing on the one path
         * that had no proof to lose before this unit and has one now.
         *
         * VERIFIED BEFORE IT IS STORED, the same discipline as the witnessed path: the pubkey comes
         * from INSIDE the bytes we signed, never from an agent lookup, and a pair that does not
         * verify is dropped loudly rather than persisted as a row that looks checkable and fails.
         * A failure here means this daemon's own encoder and decoder disagree.
         */
        const s1Decoded = decodeStructure1(own.structure1);
        const pk = s1Decoded.ok ? s1Decoded.fields.senderPubkey : undefined;
        if (!s1Decoded.ok) {
          this.#ctx.logger.warn("session.sent.authorship.unavailable", {
            agentName, sessionId, correlationId, reason: "own_structure1_decode_failed",
            structure1Reason: s1Decoded.reason,
            impact: "this sent message is recorded with attribution 'self_authored' and NO signature, so the row asserts its author rather than proving one — even though this side signed the claim it put on the wire.",
            guidance: "We produced these bytes ourselves moments ago, so a decode failure here means this daemon's own encoder and decoder disagree. Treat it as an internal invariant break, not a peer problem.",
          });
        } else if (!verify(pk!, own.structure1, own.signature)) {
          this.#ctx.logger.warn("session.sent.authorship.unavailable", {
            agentName, sessionId, correlationId, reason: "own_pair_does_not_verify",
            impact: "this sent message is recorded with attribution 'self_authored' and NO signature. The signature this side just produced does not verify against the key inside the bytes it signed.",
            guidance: "An internal invariant break: the signer and the encoder disagree. The message still went out; only the local proof was dropped.",
          });
        } else {
          sentAuthorship = { senderPubkey: pk!, senderSig: own.signature };
        }
      }
      /**
       * 🚨 NO KEY, NO DIRECT SEND — `DOD-M15-EPHEMERAL-AUTH-1`, and there is no plaintext fallback.
       *
       * Throwing here rather than sending in the open, because the catch below PARKS the content —
       * and the mailbox copy is sealed to the counterparty's long-term identity key, so the message
       * still travels encrypted and still arrives. The failure mode is a delay, never an exposure.
       *
       * A fallback to plaintext would be a thing an attacker steers a session into: strip the key
       * frame and a system that "carries on, degraded" gives up the body while the operator reads a
       * warning they have learned to scroll past. That is why this is a throw and not a warning.
       */
      // FAIL FAST, before a stream is opened for a message that cannot go out. The key this reads is
      // NOT the one that seals the body — see the read beside `sealSessionContent` below.
      const preflight = this.#ctx.ephemerals.contentEncryptionState(agentName, sessionId);
      if (preflight.key === null) {
        throw new Error(
          `content_not_encryptable: ${preflight.reason} — ${CONTENT_ENCRYPTION_GUIDANCE[preflight.reason]}`,
        );
      }
      const stream = await this.openContentStream(agentName, sessionId, entry, correlationId);
      sendStream = stream;
      // AC-001/AC-003: arm the TTF tracking BEFORE the frame goes on the wire. The
      // receiver's `persisted` ACK can come back fast (in-process / low-latency
      // transports), so registering the awaiting entry after send would let the ACK
      // race ahead of it and be dropped — the timer would then spuriously fire. The
      // content is delivered to the wire but NOT yet confirmed persisted; the ACK
      // resolves it (content.delivery.acked) and TTF expiry hands it to the park
      // backstop. The correlationId rides in the frame so the receiver's
      // session.content.received shares ONE flow id with the sender.
      /**
       * ⚠️ THE TRACKER KEEPS THE PLAINTEXT, AND THAT IS DELIBERATE — 007-CRYPTO.
       *
       * When live delivery times out, THIS is the copy the park backstop seals into the relay
       * mailbox, under `sealToRecipient` to the counterparty's long-term identity key. Encrypting
       * `content` in place would put a body locked under a session key — one about to be destroyed —
       * inside the mailbox envelope, and the recipient would open the outer seal onto bytes nothing
       * can read. It passes every live-delivery test and fails only for messages that park.
       *
       * So the session key encrypts the copy that goes ON THE WIRE, below, and nothing else.
       */
      // 034-CARRYLEAF: the SIGNED claim and its domain ride the awaiting entry, so a message that
      // ends up re-parked after a restart still reaches its recipient in a shape they can witness.
      this.#trackAwaitingAck(agentName, sessionId, content, contentHash, correlationId, frameS1 ?? orderingS1, orderingS2, contentHashAlg, frameSig, leafKind);
      /**
       * THE WIRE COPY. `content_hash` above was computed over the PLAINTEXT and stays that way: the
       * transcript, the seal and the salted hash all depend on it meaning what it means today, and
       * the receiver decrypts before it verifies.
       *
       * ⚠️ **THE KEY IS READ HERE, ADJACENT TO THE SEAL, AND IT USED TO BE READ FAR ABOVE.**
       *
       * The read sat before `#openContentStream`, so the captured key crossed an `await` — several,
       * once this unit added signing — before it sealed anything. A session key agreed with the
       * counterparty inside that window left this side sealing under the key it captured while the
       * far side had already moved on, and **every message was then refused as `decrypt_failed`**:
       * a false tamper report on honest content, on both sides, for the life of the session.
       *
       * Not theoretical. It is what reddened four live-libp2p fixtures when identity keys were first
       * wired into them — both daemons logged `session.key.agreed`, and the refusal followed.
       *
       * A window cannot be closed by reasoning about who wins it, only by removing it: nothing may
       * run between the read and the seal. The preflight above stays because failing before a stream
       * is opened is worth one extra read.
       *
       * ⚠️ THIS CLOSES THE LOCAL WINDOW AND NOT THE CLASS (review F8). The sender still seals at T
       * and the receiver still decrypts at T+flight, so a re-key landing in THAT interval produces
       * the same false tamper report. What is removed is the part this side controls; the rest is a
       * property of there being two machines.
       */
      const sealState = this.#ctx.ephemerals.contentEncryptionState(agentName, sessionId);
      if (sealState.key === null) {
        // Reachable only if the key vanished between the preflight and here — a re-key or a
        // teardown mid-send. Named as its own cause rather than reusing the preflight's, so a log
        // reader can tell "never had one" from "had one and lost it while sending".
        throw new Error(
          `content_not_encryptable: ${sealState.reason} — the key was present when this send began ` +
          `and gone by the time it sealed. ${CONTENT_ENCRYPTION_GUIDANCE[sealState.reason]}`,
        );
      }
      const wireBody = sealSessionContent(sealState.key, content);
      const frame = encodeCbor({
        type: "content_frame",
        session_id: sessionId,
        content_hash: contentHash,
        content_bytes: wireBody,
        // WHICH scheme the body is under. Present because the receiver must not have to guess from
        // a length, and absent is not a valid state — a frame without it is refused, not read raw.
        content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
        correlation_id: correlationId,
        // DOD-MSG-4 (self-ordering): the relay's signed ordering record, so the receiver verifies +
        // orders from the frame ALONE (no dependence on the separate leaf_deliver witness timing).
        // structure1_cbor = sender-signed bytes (verify); structure2_cbor = relay's committed seq +
        // prev_root (order). Structure 2 is omitted if the relay was unreachable — the receiver
        // falls back to the witness stream for POSITION. Structure 1 and its signature are never
        // omitted: `DOD-M15-AUTHORSHIP-ABSENT-1`, and a frame without them is refused on arrival.
        structure1_cbor: frameS1,
        sender_signature: frameSig,
        structure2_cbor: frameS2,
        // DOD-M15-SEALWIRE-1 part B2b: HOW `content_hash` was produced. An older peer ignores an
        // unknown CBOR key, so emitting it is safe for every build in existence; a newer one reads
        // it and verifies under the named algorithm instead of assuming.
        content_hash_alg: contentHashAlg,
        /**
         * 034-CARRYLEAF review F5 — WHICH LEAF DOMAIN this content belongs to.
         *
         * Documents and rejection envelopes ride this same frame, and the receiver had no way to
         * recover their kind: it appended them locally as "doc" from its own inspection of the
         * body, while anything it witnessed on the sender's behalf went to the relay as a MESSAGE
         * leaf. The certified root is over content hashes, so no root diverges — but the relay's
         * canonical log and the carried `leaf_kind` would describe the leaf as something it is not,
         * and a leaf kind selects a HASH DOMAIN everywhere else in this protocol.
         *
         * Same argument as `content_hash_alg` beside it: an older peer ignores an unknown CBOR key,
         * so emitting it is safe for every build in existence, and a receiver that does not see it
         * declines to witness rather than guessing (see `#witnessReceivedLeaf`).
         */
        leaf_kind: leafKind,
      }) as Uint8Array;
      // Injected dial failure — thrown from inside the try so it lands in exactly the catch the
      // real connection_lost lands in, and the whole downstream path (untrack → park → durable
      // enqueue) runs unmodified.
      if (this.#ctx.sendFaultRemaining > 0) {
        this.#ctx.sendFaultRemaining -= 1;
        this.#ctx.logger.warn("content.send.fault.injected", { sessionId, contentHash: Buffer.from(contentHash).toString("hex") });
        throw new Error("connection_lost: injected direct-send fault");
      }
      stream.send(lp.encode.single(frame));
      // NOT SWALLOWED. This was `try { await stream.close(); } catch { }` followed by
      // `delivered: true` — which reports a frame as delivered when the flush failed.
      //
      // `close()` waits for the write buffer to drain, so a reset mid-flush throws HERE, and that
      // is precisely the case where the bytes never left. Discarding it made `delivered: true` mean
      // "we called send and close did not visibly complain", while every caller reads it as "the
      // peer has it" — and the sender then never retries, because nothing told it to.
      //
      // Letting it reach the catch below is the honest outcome: that path parks the content against
      // the relay backstop and reports `delivered: false` if it can, or `ok: false` if it cannot.
      // A close that failed for a benign reason costs a redundant park, which the receiver dedups
      // on the content hash. A false delivered costs the message.
      await stream.close();
      /**
       * 🔗 THE MESSAGE HAS GONE, SO THE CHAIN ADVANCES — `DOD-M15-SELFCHAIN-1`, review F7.
       *
       * Below `stream.close()` deliberately: close waits for the write buffer to drain, so a reset
       * mid-flush throws above this line and the bytes never left. Advancing before it would point
       * the chain at a message the counterparty never saw, and every later message would then be
       * refused by them for a reason that names tampering.
       */
      if (ownClaimAwaitingSend) this.#advanceOwnChain(agentName, sessionId, entry, contentHash);
      this.#ctx.liveness.clearSessionImpairment(agentName, sessionId, "direct_send", correlationId);
      return { ok: true, delivered: true, ...(assignedSeq === undefined ? {} : { sequenceNumber: assignedSeq }), ...(sentAuthorship === undefined ? {} : { authorship: sentAuthorship }), ...(relayRefusal === undefined ? {} : { relayRefusal }) };
    } catch (err: unknown) {
      /**
       * Review F7: a content-key fault is NOT a transport fault, and labelling it `direct_send`
       * points the operator at the connection when the connection is fine. `content_not_encryptable`
       * is thrown twice above — once before the stream is opened, once at the seal — and both are
       * about this machine's key state.
       */
      const failure = err instanceof Error ? err.message : String(err);
      this.#ctx.liveness.markSessionImpaired(agentName, sessionId, {
        cause: failure.startsWith("content_not_encryptable") ? "content_key" : "direct_send",
        error: failure, correlationId,
      });
      if (sendStream !== undefined) {
        try { sendStream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
      // The send failed after (possibly) arming the awaiting tracking — drop it so a
      // never-delivered frame does not later fire a spurious TTF park.
      this.#untrackAwaitingAck(agentName, sessionId, contentHash);
      // 2b: direct delivery failed (counterparty offline). The hash is already witnessed (R1, the
      // sequence is assigned), so deposit the content to the relay store-and-forward backstop now;
      // the recipient pulls + recovers it on next online (DOD-MSG-3/4).
      // DOD-LEAVEMSG-1: the deposit is now AWAITED (was fire-and-forget) so a genuine park success
      // can be reported as "dispatched to relay" instead of a raw stream failure — the operator/
      // agent sees the truth (the message IS in flight, just not direct), not a false negative.
      const hashHex = Buffer.from(contentHash).toString("hex");
      // NAME THE CAUSE. This catch used to discard `err` outright, so a park reported only its exit
      // point — "dispatched to relay" — and never what went wrong. Measured 2026-08-17: 212 parks on
      // one daemon, not one of them recording a reason, which is what made a one-way session look
      // like a protocol mystery for a night.
      //
      // `counterpartySessionPeerId` is the load-bearing field. It is recorded ONCE at session
      // establishment and never refreshed. (CORRECTED 2026-08-18: this used to say a standing
      // receiver is rebuilt "on every signaling reconnect" — it is not. `ensureStandingReceiverForAgent`
      // no-ops on a healthy receiver; the only rebuild triggers are a LOST RELAY RESERVATION and the
      // one-shot upgrade when relay endpoints first arrive.) If the two ever cross, every send goes
      // one-way forever and nothing says so. With this line that becomes a single grep instead of a
      // night.
      this.#ctx.logger.warn("session.content.direct.send.failed", {
        agentName,
        sessionId,
        contentHash: hashHex,
        counterpartySessionPeerId: entry.counterpartySessionPeerId,
        error: err instanceof Error ? err.message : String(err),
        // "Cannot write to a stream that is closed" names where the write died, never why. The
        // why is almost always the per-protocol stream cap, and these two numbers are what turn
        // that from a log-measurement session into a grep.
        ...this.#ctx.streamCensus(entry.node, entry.counterpartySessionPeerId),
        correlationId,
      });
      /**
       * ⚠️ **THE PARKED COPY CARRIES THE SIGNED CLAIM, NOT ONLY THE WITNESSED ONE — 034-CARRYLEAF
       * review F1, and this is what closes the withholding attack on the MAILBOX route.**
       *
       * It passed `orderingS1`, which exists only when the relay witnessed this leaf — so a message
       * the sender deliberately did not witness was parked with no ordering claim at all, and the
       * recipient recovered it holding nothing the relay would accept as proof of authorship. They
       * could read it and could never put it in a receipt.
       *
       * `frameS1`/`frameSig` are the pair the DIRECT frame carries for this same message: the
       * relay's witnessed claim when there is one, and otherwise a claim this agent signed itself.
       * Either way it is the author's signature over the author's own ordering claim, which is the
       * only form the relay accepts when the recipient witnesses on their behalf.
       */
      const attempt = await this.#ctx.park.parkContent(agentName, sessionId, hashHex, content, frameS1, orderingS2, contentHashAlg, frameSig, leafKind);
      if (attempt.outcome === "parked") {
        /**
         * 🔗 A PARK IS A DELIVERY, so the chain advances here too — `DOD-M15-SELFCHAIN-1`.
         *
         * The mailbox copy is sealed to the counterparty's long-term key and they WILL open it, so
         * the message is part of the conversation. Leaving the chain behind here would make this
         * side's next message link to something the counterparty has already moved past, and they
         * would refuse it as a broken chain — a false tamper report caused by our own relay being
         * briefly unreachable.
         */
        if (ownClaimAwaitingSend) this.#advanceOwnChain(agentName, sessionId, entry, contentHash);
        this.#ctx.liveness.noteImpairmentRetention(agentName, sessionId, "parked");
        return { ok: true, delivered: false, parked: true, ...(assignedSeq === undefined ? {} : { sequenceNumber: assignedSeq }), ...(sentAuthorship === undefined ? {} : { authorship: sentAuthorship }), ...(relayRefusal === undefined ? {} : { relayRefusal }) };
      }
      // M12-P12: the deposit was refused, and #untrackAwaitingAck above already dropped the
      // in-memory entry — so without this, NOTHING holds the content and the TTF timer that would
      // have enqueued it is cancelled. The recipient has already witnessed this sequence, so it
      // holds every later message in the session behind the gap, forever, and tells no one.
      // Enqueue durably instead; the drain hook re-parks it the moment the standing receiver is
      // rebuilt. Only on a REFUSAL — a successful deposit must not be re-parked, and an
      // unconfigured session has no park target to retry against (F6).
      let durable = false;
      if (attempt.outcome === "refused") {
        try {
          // M12-P13 (review HIGH-1): `durable` is now OBSERVED from the enqueue, not asserted around
          // it. Two ways this used to lie, both of which now commit a chain leaf and so cannot be
          // allowed to: the queue's content-derived dedupe key collides and it silently drops the
          // copy, and the `?.` no-ops entirely when the composition root never wired the hook. An
          // absent hook is not a queue.
          if (this.#ctx.onParkFailed === null) {
            this.#ctx.logger.error("content.park.durable_enqueue.unwired", {
              sessionId, contentHash: hashHex, agentName,
              impact: "no durable queue is wired — the content is NOT retained and will NOT be retried",
            });
          } else {
            // B2b-1 review F1: the DURABLE writer. Without the 7th argument the column this unit
            // added has no producer at all — every queued row would carry NULL, and the crash
            // backstop would re-park a salted message as sha256 and have it refused forever.
            durable = this.#ctx.onParkFailed(agentName, sessionId, hashHex, content, orderingS1, orderingS2, contentHashAlg);
          }
          if (!durable) {
            if (this.#ctx.onParkFailed !== null) {
              this.#ctx.logger.error("content.park.durable_enqueue.dropped", {
                sessionId, contentHash: hashHex, agentName,
                impact: "the durable queue refused this copy (identical content already queued) — it is NOT separately retained",
              });
            }
          } else {
            // F5: the successful enqueue must be visible. Without this the live run that has to
            // PROVE this fix has nothing to point at, and this log is the sender-side counterpart to
            // `session.content.held` on the receiver — the two together make the trace readable.
            // M12-P13: `witnessed` rides along because the caller is about to commit a hash-chain
            // leaf on the strength of this. Without a relay ordering record the recipient recovers
            // in arrival order instead — the accepted degradation, but it must not be invisible.
            this.#ctx.logger.info("content.park.deferred", {
              sessionId, contentHash: hashHex, agentName,
              selfOrdering: Boolean(orderingS1 && orderingS2),
              witnessed: Boolean(orderingS1 && orderingS2),
            });
          }
        } catch (hookErr: unknown) {
          // F3: enqueueAwaitingContent throws ON PURPOSE when the persist fails, because that is
          // data loss. Swallowing it into the same response the durable case returns would tell the
          // operator "it will retry" about a message that is simply gone. Named for its own cause,
          // and the response says so below.
          this.#ctx.logger.error("content.park.durable_enqueue.failed", {
            sessionId, contentHash: hashHex, agentName,
            impact: "content is NOT durable and will NOT be retried — the message is lost",
            error: hookErr instanceof Error ? hookErr.message : String(hookErr),
          });
        }
      }
      // error.message extracted — never [object Object]. libp2p/cross-package errors are not
      // always `instanceof Error` in this realm, so fall back to a message property / JSON.
      const errMsg =
        err instanceof Error
          ? err.message
          : err && typeof err === "object" && typeof (err as { message?: unknown }).message === "string"
            ? (err as { message: string }).message
            : (() => {
                try {
                  return JSON.stringify(err);
                } catch {
                  return String(err);
                }
              })();
      // F3: the two failures are NOT interchangeable to the caller. `reason` is a contract string
      // and stays put; `guidance` carries the difference, because "we are retrying this" and "this
      // message is gone, send it again" demand opposite actions from the operator.
      //
      // The same distinction is recorded on the session, because `cello_receive` will be asked
      // about this later and would otherwise have to guess — and its guess ("it was parked, do not
      // resend") is the exact opposite of what the lost case needs.
      this.#ctx.liveness.noteImpairmentRetention(agentName, sessionId, durable ? "durable" : "lost");
      return {
        ok: false,
        reason: "session_stream_unavailable",
        error: errMsg,
        // Carried on the failure path too: a DURABLY QUEUED message still owns the position the
        // relay witnessed for it before delivery was attempted, and its leaf must go there.
        ...(assignedSeq === undefined ? {} : { sequenceNumber: assignedSeq }),
        // …and so does its PROOF, for the same reason. It was signed before the hand-off failed.
        ...(sentAuthorship === undefined ? {} : { authorship: sentAuthorship }),
        // M12-P13: the machine-readable half of the distinction below. M12-P12 shipped it in the
        // guidance SENTENCE only, so the callers that have to ACT on it — commit the leaf for a
        // queued message, never for a lost one — would have had to substring-match English. None
        // did, and the sequence the relay had already witnessed was left as a permanent hole.
        durable,
        // M12-P13 (review MEDIUM-5): the specific standing-receiver state, carried rather than
        // discarded. `reason` names where this surfaced; `cause` names what actually blocked it —
        // the exact distinction M12-P12 added `standingReceiverAbsenceReason()` for, which then
        // died inside #parkContent. An operator keying on `reason` alone is sent to the transport
        // when the blocker is the receiver.
        ...(attempt.cause !== undefined ? { cause: attempt.cause } : {}),
        /**
         * ⚠️ A FAULT THAT IS NOT THE RELAY MUST NOT SAY IT IS — B2b-2 constraint 6.
         *
         * The `durable` branch below is written for a relay that is down: queued, retried, nothing
         * for you to do. That is right for the case it was written for and WRONG for a producer-side
         * refusal, which reaches the same branch by the same route. There the relay was never asked,
         * and the drain re-parks the same entry into the same throw — so the message is genuinely
         * durable and will genuinely never leave. Telling that operator to wait costs them however
         * long they are willing to wait before they stop believing the message.
         *
         * This is the reason `cause` had to become a code first: the distinction is unbranchable
         * while the field holds an English paragraph.
         */
        guidance: parkRefusalGuidance(attempt.cause, durable, attempt.retryAfterMs),
      };
    }
  }

  /**
   * DOD-M12B-REDIAL-1 — open a content stream, re-dialling once if the connection has gone.
   *
   * `newStream` never dials. It looks for an already-open connection filed under the recorded peer
   * id and throws `connection_lost` when there is none — and NOTHING re-dialled: not on
   * `session.liveness.changed → gone`, not on signaling reconnect, not on agent offline→online, not
   * in the drain hook. So one blip and that session parked EVERY message for the rest of its life,
   * on both sides, permanently. The relay backstop kept the messages moving, which is exactly why
   * it hid: nothing was lost, the conversation just stopped being a conversation.
   *
   * DEMAND-DRIVEN, never a timer. A background re-dial loop is what produced the 2026-08-17
   * notification storm — surviving halves of abandoned sessions dialling continuously while the
   * operator saw connection requests from agents nobody was driving. This fires only when a send
   * actually needs the connection, and a cooldown bounds a burst against a peer that is genuinely
   * gone: five sends cost one dial, not five.
   */
  async openContentStream(
    agentName: string,
    sessionId: string,
    entry: { node: CelloNode; counterpartySessionPeerId: string },
    correlationId?: string,
  ): Promise<Stream> {
    const attempt = async (): Promise<Stream> => {
      if (this.#ctx.connectionLossRemaining > 0) {
        this.#ctx.connectionLossRemaining -= 1;
        throw { reason: "no_connection", message: "injected connection loss" };
      }
      return entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
    };
    try {
      return await attempt();
    } catch (err: unknown) {
      const reason = (err as { reason?: string } | null)?.reason;
      // ONLY for a missing connection, and `no_connection` is the reason that means exactly that.
      // NOT `connection_lost`, which is the transport's catch-all default and therefore also covers
      // a stream that failed on a healthy connection — the per-protocol stream cap of
      // DOD-M12B-ACK-1. Dialling there fixes nothing and shows the counterparty a connection
      // request caused by a defect on this side, which is the storm this unit exists to avoid.
      if (reason !== "no_connection") throw err;

      const key = this.#ctx.sessionKey(agentName, sessionId);
      const addrs = this.#ctx.counterpartyAddrs.get(key);
      if (!addrs || addrs.length === 0) {
        // ABSENT IS NOT FINE, and it is not silent. A session we never dialled — the responder's
        // half — has no addresses to dial back with, and that is a real limitation the operator
        // should be able to see rather than infer from a park.
        this.#ctx.logger.warn("session.transport.redial.unavailable", {
          sessionId, agentName, correlationId,
          impact: "the direct path is down and this side holds no address for the counterparty, so every send parks until they re-establish",
        });
        throw err;
      }
      const now = Date.now();
      const notBefore = this.#ctx.redialNotBefore.get(key) ?? 0;
      if (now < notBefore) {
        this.#ctx.logger.debug("session.transport.redial.cooldown", {
          sessionId, agentName, retryInMs: notBefore - now, correlationId,
        });
        throw err;
      }
      this.#ctx.redialNotBefore.set(key, now + REDIAL_COOLDOWN_MS);
      this.#ctx.logger.info("session.transport.redial.attempted", { sessionId, agentName, addrs: addrs.length, correlationId });
      const reconnected = await this.#ctx.connectToCounterparty(agentName, sessionId, addrs);
      if (!reconnected.ok) {
        this.#ctx.logger.warn("session.transport.redial.failed", {
          sessionId, agentName, reason: reconnected.reason, error: reconnected.error, correlationId,
        });
        throw err;
      }
      this.#ctx.logger.info("session.transport.redial.succeeded", { sessionId, agentName, correlationId });
      // Cleared so the NEXT blip is repaired immediately: the cooldown exists to bound a dead peer,
      // not to make a live one wait.
      this.#ctx.redialNotBefore.delete(key);
      return attempt();
    }
  }

  /**
   * DOD-M12B-INDEX-1 — commit THIS agent's own leaf at the position the relay assigned it.
   *
   * The receiver has always enforced "leaf index === canonical position": content witnessed ahead
   * of the next expected leaf is held, not appended out of order. The sender never did. It had the
   * position in hand — the relay answers about 4 ms before the append — and called a push-only
   * append that puts the leaf at the tail whatever the tail happens to be. While its own tree has
   * no gap the two agree and nothing shows; the first gap puts its leaf at someone else's index,
   * parts its root from the counterparty's, and the next seal gets `leaf_count_mismatch`, which is
   * terminal.
   *
   * DELIVERY IS NOT DEFERRED BY THIS. The caller has already put the bytes on the wire; only the
   * leaf waits for its slot, exactly as a received message does. Holding our own send is only
   * affordable because holds are durable (DOD-M12B-STRAND-1) — before that it would have risked
   * losing the message outright.
   *
   * `assignedSeq` absent means no ordering authority answered. That is the documented degradation
   * and it appends in arrival order as before: with no position there is no discipline to enforce,
   * and refusing would take messaging down whenever the relay is unreachable.
   */
  placeOwnLeaf(
    agentName: string,
    sessionId: string,
    contentHashHex: string,
    sentBytes: Uint8Array,
    assignedSeq: number | undefined,
    correlationId: string | undefined,
    /**
     * ⚠️ NO DEFAULT, for the same reason `authorship` has none.
     *
     * `kind = "msg"` meant a caller writing a `doc` or a `ctrl` leaf got a `msg` leaf by saying
     * nothing, and the tree recorded a leaf kind the author never chose. TypeScript also forbids a
     * required parameter after a defaulted one, so leaving the default here would have forced
     * `authorship` back to optional — which is the defect above. Every one of the seven call sites
     * already passed a kind or wanted "msg"; making it explicit cost nothing and removes a second
     * silent answer from the same signature.
     */
    kind: WritableSessionTreeLeafKind,
    /**
     * DOD-M15-SEALWIRE-1 bullet 5 — the proof for THIS send, so a held row keeps it.
     *
     * ⚠️ REQUIRED, AND `undefined` IS A VALID ANSWER — the two are not the same thing.
     *
     * This was `authorship?:` for exactly one review cycle, and in that cycle THREE of the seven
     * call sites omitted it: `daemon.ts` 1440, 1671, 1685 — the away-reply path, which is the
     * highest-traffic sent-writer in the daemon and the one with no human watching it. All three
     * had the proof **already in a local variable one line below**, handed to
     * `recordTranscriptMessage` and not to this method. Nothing went red, because an optional
     * parameter's whole behaviour on omission is to look deliberate.
     *
     * An unwitnessed send genuinely has no proof, so absence must stay expressible. Requiring the
     * parameter keeps that while making the caller SAY it: omission is now a type error, and
     * `undefined` is a claim the author made rather than one the signature made for them.
     */
    authorship: SentAuthorship | undefined,
  ): { placed: true; leafIndex: number; diverged?: true; unwitnessed?: true } | { placed: false; heldAt: number } {
    // Hydrate before reading the frontier: a durable hold this process has not read back yet would
    // make the tree look further along than it is.
    this.#ctx.held.ensureHeldRestored(agentName, sessionId);
    const nextExpected = this.#ctx.getSessionTree(agentName, sessionId).size();

    if (assignedSeq === undefined) {
      const { leafIndex } = this.#ctx.appendSessionLeaf(agentName, sessionId, kind, contentHashHex, correlationId);
      /**
       * ─── DOD-M15-UNWITNESSED-1(b): SAY IT HERE, where the code says the damage happens ────────
       *
       * This branch was entirely silent — no log, no flag — while the `position_behind_frontier`
       * branch twenty lines below logs at ERROR and its own comment says the loss occurred
       * *"at the unwitnessed append, not here."* So the system announced the consequence one send
       * later than it announced nothing about the cause.
       *
       * **This does NOT gate the seal, deliberately.** The DoD bar is explicit: do not gate on
       * suspicion, because a relay that has not witnessed a leaf YET is indistinguishable here from
       * one that never will, and refusing on the first would make a healthy session unsealable —
       * which is worse than the thing it guards. What was missing is not a refusal, it is the
       * ERROR at the moment the code already believes something was lost.
       */
      this.#ctx.logger.error("session.tree.own_leaf_unwitnessed", {
        sessionId,
        leafIndex,
        kind,
        correlationId,
        impact:
          "this message was appended to the local record with NO relay witness, so the ordering " +
          "authority has no copy of it. The counterparty's tree cannot gain this leaf from the " +
          "relay, so the two records may no longer agree — and a bilateral seal needs them to.",
        guidance:
          "Usually the relay was briefly unreachable and the next send re-establishes ordering. If " +
          "it repeats, the relay is not carrying this session: check connectivity before closing, " +
          "because sealing on a record the counterparty cannot match produces a receipt only one " +
          "side can verify.",
      });
      /**
       * ─── `016-RELAYLOSS`: CARRIED TO THE CALLER, because the log is not a consumer ────────────
       *
       * Measured with a real relay black-holed mid-conversation: the send stalls for the submit
       * timeout, then returns `{ok: true, sequence_number: N, delivered: true}` — BYTE-IDENTICAL to
       * the witnessed send that preceded it. The error above is correct, complete, and read by
       * nobody the operator can ask.
       *
       * Its two siblings twenty lines below already do this: `diverged` and the held case both
       * refuse to return an ordinary success, on the stated grounds that doing so "reports a
       * healthy send on a conversation that has silently lost the one thing the protocol exists to
       * produce." This branch is where that loss OCCURS — `position_behind_frontier`'s own comment
       * says the seal "was already lost at the unwitnessed append, not here" — so it is the branch
       * that most needed to say so, and it was the one that said nothing.
       */
      return { placed: true, leafIndex, unwitnessed: true };
    }

    if (assignedSeq === nextExpected) {
      const { leafIndex } = this.#ctx.appendSessionLeaf(agentName, sessionId, kind, contentHashHex, correlationId);
      return { placed: true, leafIndex };
    }

    if (assignedSeq < nextExpected) {
      // THE TREE AND THE RELAY HAVE ALREADY DIVERGED, and refusing here does not undo that.
      //
      // This side is AHEAD of the relay's counter, which happens by design: a message whose relay
      // submit failed still appends unwitnessed (the documented degradation). From then on every
      // ack comes back behind our frontier and the two can never agree again — the seal was already
      // lost at the unwitnessed append, not here.
      //
      // So the choice is between a record that is short by every subsequent message and one that is
      // complete but skewed. Appending at the tail keeps the operator's own words in their own
      // transcript, which is worth more than a tidiness the roots cannot recover anyway; writing
      // over the assigned slot is the one thing never done, because that rewrites a leaf a root has
      // already been computed over. The divergence is reported at ERROR and carried to the caller
      // rather than dressed up as an ordinary success.
      this.#ctx.logger.error("session.tree.position_behind_frontier", {
        agentName, sessionId, assignedSeq, nextExpected, contentHash: contentHashHex, correlationId,
        impact: "this side's tree is ahead of the relay's counter, so the two can no longer agree on a root — the message is kept in the local record and this session can no longer be sealed bilaterally",
      });
      this.#ctx.records.markSessionDiverged(agentName, sessionId);
      const { leafIndex } = this.#ctx.appendSessionLeaf(agentName, sessionId, kind, contentHashHex, correlationId);
      return { placed: true, leafIndex, diverged: true };
    }

    // Ahead of the tail: hold it, exactly as the receiver holds theirs, and let #releaseHeld put it
    // in at its own index when the gap fills.
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let held = this.#ctx.heldContent.get(key);
    if (!held) { held = new Map(); this.#ctx.heldContent.set(key, held); }
    held.set(assignedSeq, { content: sentBytes, contentHashHex, correlationId, origin: "sent", kind, ...(authorship ? { authorship } : {}) });
    this.#ctx.queries.persistHeldContent(agentName, sessionId, assignedSeq, sentBytes, sentBytes, contentHashHex, false, correlationId, "sent", kind);
    this.#ctx.logger.info("session.content.held", {
      sessionId, canonicalSeq: assignedSeq, nextExpected, gap: assignedSeq - nextExpected,
      origin: "sent", correlationId,
    });
    return { placed: false, heldAt: assignedSeq };
  }

  /**
   * Arm awaiting-ACK tracking for a just-sent content frame (AC-001/AC-003). Records
   * the content + a TTF timer keyed by content hash; a `persisted` ACK on the inbound
   * content stream resolves it, TTF expiry hands it to the park backstop. The timer is
   * `unref`'d so an in-flight wait never keeps the daemon process (or a test runner)
   * alive on its own.
   */
  /**
   * `contentHashAlg` is `string | undefined`, NOT optional — B2b-1 pass-2 F1.
   *
   * The previous fix applied this shape to `#parkContent` and left its SIBLING on the same code path
   * optional, so dropping the argument here compiled clean and no test could see it — the TTF park
   * route reads this map, and a v2 envelope omits the field entirely whenever the value is `sha256`,
   * which is every value in play today. That re-opened the exact finding the fix closed.
   */
  #trackAwaitingAck(agentName: string, sessionId: string, content: Uint8Array, contentHash: Uint8Array, correlationId: string | undefined, structure1Cbor: Uint8Array | undefined, structure2Cbor: Uint8Array | undefined, contentHashAlg: string | undefined, structure1Signature?: Uint8Array, leafKind?: number): void {
    const hashHex = Buffer.from(contentHash).toString("hex");
    const ackKey = this.#ctx.sessionKey(agentName, sessionId);
    let bySession = this.#ctx.awaitingAck.get(ackKey);
    if (!bySession) { bySession = new Map(); this.#ctx.awaitingAck.set(ackKey, bySession); }
    // Replace any prior timer for the same (session, hash) so we never leak a timer.
    const prior = bySession.get(hashHex);
    if (prior) clearTimeout(prior.timer);
    const timer = setTimeout(() => {
      this.#ctx.handleTtfExpiry(agentName, sessionId, hashHex);
    }, this.#ctx.contentTtfMs);
    if (typeof (timer as { unref?: () => void }).unref === "function") (timer as { unref: () => void }).unref();
    // DOD-MSG-4 (2b, review #1): retain the relay's ordering record so a TTF-triggered park carries
    // it too (not only the direct-dial-fail park) — so a TTF-parked entry is self-ordering on recover.
    // B2b-1 review F2: the algorithm rides WITH the entry. The TTF-expiry park route reads this map
    // minutes later, in-process, and without it that copy names nothing (= sha256) while the direct
    // frame named something else — the same message, two claims about what it is, no restart needed.
    bySession.set(hashHex, { timer, content, correlationId, structure1Cbor, structure2Cbor, contentHashAlg, structure1Signature, leafKind });
  }

  /**
   * Resolve an awaiting-ACK entry on a `persisted` delivery ACK (AC-001/AC-002): cancel
   * the TTF timer, emit content.delivery.acked, and clear the durable backstop entry.
   * A `received`-level ACK is NOT handled here — the protocol acts on `persisted` only,
   * so a received ACK leaves the timer armed.
   */
  resolveAwaitingAck(agentName: string, sessionId: string, contentHash: Uint8Array): void {
    const hashHex = Buffer.from(contentHash).toString("hex");
    const ackKey = this.#ctx.sessionKey(agentName, sessionId);
    const bySession = this.#ctx.awaitingAck.get(ackKey);
    const entry = bySession?.get(hashHex);
    if (!entry || !bySession) return; // unknown / already resolved — idempotent
    clearTimeout(entry.timer);
    bySession.delete(hashHex);
    if (bySession.size === 0) this.#ctx.awaitingAck.delete(ackKey);
    this.#ctx.logger.info("content.delivery.acked", {
      sessionId,
      contentHash: hashHex,
      level: "persisted",
      correlationId: entry.correlationId,
    });
    // Clear the durable crash-backstop entry so the startup flush does not re-park
    // already-delivered content.
    try {
      this.#ctx.onAwaitingPersisted?.(agentName, sessionId, hashHex);
    } catch (err: unknown) {
      this.#ctx.logger.error("content.delivery.ack.backstop.failed", {
        sessionId, contentHash: hashHex, error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** Cancel and drop a single awaiting-ACK entry (e.g. the send failed after arming). */
  #untrackAwaitingAck(agentName: string, sessionId: string, contentHash: Uint8Array): void {
    const hashHex = Buffer.from(contentHash).toString("hex");
    const ackKey = this.#ctx.sessionKey(agentName, sessionId);
    const bySession = this.#ctx.awaitingAck.get(ackKey);
    const entry = bySession?.get(hashHex);
    if (!entry || !bySession) return;
    clearTimeout(entry.timer);
    bySession.delete(hashHex);
    if (bySession.size === 0) this.#ctx.awaitingAck.delete(ackKey);
  }

  /** Cancel and drop all awaiting-ACK timers for a session (teardown). */
  clearAwaitingForSession(agentName: string, sessionId: string): void {
    const ackKey = this.#ctx.sessionKey(agentName, sessionId);
    const bySession = this.#ctx.awaitingAck.get(ackKey);
    if (!bySession) return;
    for (const entry of bySession.values()) clearTimeout(entry.timer);
    this.#ctx.awaitingAck.delete(ackKey);
  }

  /**
   * `DOD-M15-AUTHORSHIP-ABSENT-1` — SIGN OUR OWN CLAIM, with no relay involved.
   *
   * The relay submit has always built these bytes and signed them (`session-relay-client.ts`); this
   * is the same construction, for the path where no submit happens. It is not a fallback in the
   * silent sense — it produces exactly the artifact the witnessed path produces, minus the relay's
   * countersigned position, which was never part of the authorship claim.
   *
   * ⚠️ THROWS when this agent has no identity key, and the throw is the correct outcome. It lands in
   * the direct-send catch, which parks the message to the relay mailbox exactly as a failed dial
   * does — so the message is not lost, and the operator hears about a local fault instead of a
   * counterparty who mysteriously stopped receiving. Shipping the frame unsigned would guarantee a
   * refusal at the far end and blame the wrong machine for it.
   */
  async #signOwnContentClaim(
    agentName: string,
    sessionId: string,
    entry: ActiveSessionEntry,
    contentHash: Uint8Array,
  ): Promise<{ structure1: Uint8Array; signature: Uint8Array }> {
    const signer = this.#ctx.keyProvider(agentName);
    if (!signer) {
      throw new Error(
        "content_not_signable: this machine has no identity key for this agent, so it cannot sign " +
        "the message it is about to send and the counterparty would refuse it as unattributable",
      );
    }
    // The 16-byte relay session id when this session has one, so a frame built here is
    // byte-comparable with one built by the submit. Falling back to the local id is not a
    // second meaning: for every session created without an assignment the two are the same value
    // (`relaySessionIdBytes` is set from `sessionId` on exactly those paths).
    const sessionIdBytes = entry.relaySessionIdBytes ?? Uint8Array.from(Buffer.from(sessionId, "hex"));
    /**
     * ⚠️ **THIS COMMENT USED TO READ "v1 DELIBERATELY" AND IT WAS RIGHT UNTIL NOW — 033-ACKEMIT.**
     *
     * It said `last_seen_hash` was `WITHHOLD-SEAL-1`'s emitter and "not owed here", and that a v1
     * claim makes no content acknowledgement at all, "which is honest, where an invented one would
     * not be." Accurate for `020-ACKHASH`, which shipped the reader only. It is rewritten rather
     * than deleted because it is the sentence that would otherwise explain away the LAST production
     * path still emitting v1 — and this unit's own Definition of Done is that a grep finds none.
     *
     * The reasoning it rested on has been answered: nothing is invented here. The acknowledgement
     * is read from the same `#lastSeen` entry the submit reads, so a frame built on this path and
     * one built by a submit make the same claim about the same message.
     */
    const sessionIdHexForAck = Buffer.from(sessionIdBytes).toString("hex");
    /**
     * The pair, from ONE accessor. Falling back to the session's genesis when there is no relay
     * client at all is not an invention either: nothing has been witnessed on this session, so the
     * honest acknowledgement is position 0 and the agreed starting point of the chain.
     */
    const ack = entry.relayClient?.lastSeenAck(sessionIdHexForAck)
      ?? this.#ctx.lastAck.get(this.#ctx.sessionKey(agentName, sessionId))
      ?? (() => { const g = this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId); return g ? { seq: 0, hash: g } : undefined; })();
    if (!ack) {
      /**
       * ⚠️ NO STARTING POINT MEANS NO SEND — `DOD-M15-SELFCHAIN-1`.
       *
       * This used to emit a shorter claim: `last_seen_seq: 0` with no hashes, on the argument that
       * "I have seen nothing of yours" is honest and asserts nothing false. It IS honest, and it is
       * no longer a shape this protocol has. Both chain links are required, and a session with no
       * recorded starting point has nothing for them to anchor to.
       *
       * Refusing costs a message on a session that was brokered without an assignment. Sending one
       * costs the ability to prove the order of the whole conversation later, and the cost is
       * invisible until someone disputes it — which is exactly the failure this unit exists to end.
       * Refuse loudly, and say what to do about it.
       */
      throw new Error(
        "session_unchainable: this session has no recorded starting point on this machine, so a " +
        "message sent on it could not link to anything and its place in the conversation could " +
        "never be proven. Restart the session so it is registered with its genesis.",
      );
    }
    const structure1 = encodeStructure1({
      contentHash,
      senderPubkey: await signer.getPublicKey(),
      sessionId: sessionIdBytes,
      // The highest counterparty position this session has seen, from the same source the submit
      // reads — and now the content hash at it, taken from the same entry so the two cannot
      // describe different messages.
      lastSeenSeq: ack.seq,
      timestamp: Date.now(),
      lastSeenHash: ack.hash,
      /**
       * ─── THE SELF LINK ON THE UNWITNESSED PATH — `DOD-M15-SELFCHAIN-1` ────────────────────────
       *
       * This is the path that matters most for it. A conversation that ran while the relay was down
       * is precisely the one whose order gets disputed later, so the chain cannot depend on a relay
       * having been there to witness it.
       *
       * ⚠️ ONE CHAIN, READ THROUGH THE RELAY CLIENT FIRST. This used to read only the durable
       * store, while the witnessed path reads an in-memory map first — so a session that mixed the
       * two, which is every session where the relay comes and goes, walked two different chains and
       * the lagging one produced a link the counterparty refuses.
       *
       * ⚠️ AND THE LAST FALLBACK IS THE SESSION GENESIS, NOT `ack.hash`. `ack.hash` is what the
       * COUNTERPARTY last said; it is only the genesis until they have said anything. Falling back
       * to it meant this agent's own first message linked to the other party's message — refused by
       * every checker, and reported as tampering against a party that had done nothing.
       */
      prevOwnHash: this.#ctx.ownChainOf(agentName, sessionId, entry, await signer.getPublicKey())
        ?? this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId)
        ?? ack.hash,
    });
    /**
     * ⚠️ THE CHAIN IS NOT ADVANCED HERE, AND IT USED TO BE — review F7.
     *
     * `SessionOwnChainStore.record` says in capitals that it is called AFTER the send succeeds. This
     * ran at signing time, before a stream was even opened. Any failure between here and delivery
     * left the chain pointing at a message the counterparty never saw, and every later message was
     * then refused by them for a reason that names tampering. A retransmission must re-use the same
     * predecessor, because a retransmission is the same message.
     *
     * `#advanceOwnChain` is called by the send path at each point where the message has actually
     * gone — the direct send, and the relay park that is the fallback for it.
     */
    return { structure1, signature: await signer.sign(structure1) };
  }

  /**
   * Record what this agent just sent — called ONLY once the message has actually gone.
   *
   * Writes through the relay client when there is one, so the in-memory chain the witnessed path
   * reads and the durable row stay one chain rather than two. Falls back to the store directly for
   * a session with no relay client at all, which is exactly the unwitnessed case this unit exists
   * to cover.
   */
  #advanceOwnChain(
    agentName: string,
    sessionId: string,
    entry: { relayClient?: AgentRelayClient; relaySessionIdBytes?: Uint8Array } | undefined,
    contentHash: Uint8Array,
  ): void {
    const relayHex = entry?.relaySessionIdBytes
      ? Buffer.from(entry.relaySessionIdBytes).toString("hex")
      : sessionId;
    if (entry?.relayClient) {
      entry.relayClient.noteOwnLeaf(relayHex, contentHash);
      return;
    }
    const ownPubkeyHex = this.#ctx.queries.ownPubkeyHex(agentName);
    if (!ownPubkeyHex) return;
    this.#ctx.ownChainStore?.record(ownPubkeyHex, sessionId, contentHash, Date.now());
  }
}
