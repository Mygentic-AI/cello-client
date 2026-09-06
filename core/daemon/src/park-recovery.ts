/**
 * CELLO Daemon — MAIL THAT WAITED
 *
 * Split out of `session-node-manager.ts` by 036-GODFILE, Part 6. The relay store-and-forward path:
 * depositing content the counterparty could not take live, recovering it when they come back, and
 * the backstop sweep that drains it even when a trigger is missing.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ THE BACKSTOP SWEEP EXISTS BECAUSE THE INCIDENT WAS A MISSING TRIGGER, and a missing trigger is
 * invisible: the daemon looked healthy, the content was intact on the relay, and the only thing that
 * ever moved it was a human restarting the daemon. Do not delete it as redundant — the trigger-driven
 * drains are what deliver, and this is what bounds the cost of the next gap in trigger coverage to
 * one interval of latency.
 */
import type { Logger, SessionRecord } from "./types.js";
import type { SealCarryLeaf } from "./session-seal-leaf-store.js";
import type { SessionTree } from "./session-tree.js";
import { LEAF_KIND_CTRL } from "./session-relay-client.js";
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { decodeParkEnvelope, authenticateParkedEntry } from "./park-envelope.js";
import type { InboundRefusals } from "./inbound-refusals.js";
import { type ParkedDrainReason, type ParkAttempt, type ActiveSessionEntry, MAX_REFUSED_PARKED_ENTRIES } from "./session-node-types.js";
import { ParkEnvelopeError, type ParkAuthFailure } from "./park-envelope.js";
import { extractErrorMessage } from "./error-message.js";

/** What park recovery needs from the manager, stated explicitly rather than handed `this`. */
export interface ParkContext {
  readonly logger: Logger;
  readonly refusals: InboundRefusals;
  shuttingDown(): boolean;
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  ownPubkeyHex(agentName: string): string | null;
  /** The live session entry, when one exists. Park works for sessions that have none. */
  activeEntry(key: string): ActiveSessionEntry | undefined;
  /** Agents currently holding a standing receiver — the backstop sweep's population. */
  agentsWithLiveReceiver(): Iterable<string>;
  agentWantsReceiver(agentName: string): boolean;
  getSessionRecord(agentName: string, sessionId: string): SessionRecord | null;
  getSealCarry(agentName: string, sessionId: string): readonly SealCarryLeaf[];
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  recordOrderingRecord(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    structure2Cbor: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): number | null;
  ingestReceivedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
    recoveredSeq?: number,
    contentHashAlgIn?: string | null,
  ): Promise<{ ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number; screenedOut?: boolean } | { ok: false; reason: string }>;
  witnessReceivedLeaf(
    agentName: string,
    sessionId: string,
    contentHash: Uint8Array,
    structure1Cbor: Uint8Array,
    senderSignature: Uint8Array,
    leafKind: number,
    correlationId?: string,
  ): void;
  noteAcknowledgeable(agentName: string, sessionId: string, canonicalSeq: number, contentHash: Uint8Array): void;
}

export class ParkRecovery {
  readonly #ctx: ParkContext;

  constructor(ctx: ParkContext, parkedDrainBackstopMs: number) {
    this.#ctx = ctx;
    this.#parkedDrainBackstopMs = parkedDrainBackstopMs;
  }

  /**
   * Arm the backstop clock from the START of watching, not from the epoch — otherwise the first
   * tick always fires a sweep on top of the install drain that just ran.
   */
  armBackstopClock(now: number): void {
    this.#parkedDrainLastBackstopAt = now;
  }

  #parkFaultRemaining = 0;
  #parkFaultCause = "standing_receiver_creating";
  #contentParkHook:
    | ((args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array; structure1Signature?: Uint8Array; leafKind?: number; contentHashAlg: string | undefined }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string; retryAfterMs?: number }>)
    | null = null;
  /** DOD-PARK-DRAIN-1: the composition root's parked-mailbox drain — see setParkedDrainHook. */
  #parkedDrainHook: ((agentName: string, reason: ParkedDrainReason) => void) | null = null;
  #parkedDrainHookAbsenceLogged = false;
  /**
   * MSG-001-3b (2b): the live content-park deposit. The manager resolves the recipient + relay
   * endpoint from the session entry and calls this when a send is NOT confirmed delivered
   * (direct-fail or TTF expiry). The daemon's hook seals (sealToRecipient) + deposits via
   * ContentParkClient. Best-effort.
   */
  /**
   * SEC-1 / review M4: parked entries already refused by the authentication gate, keyed
   * `${agent}:${session}:${contentHash}` → the refusal reason. Bounded (see
   * #rememberRefusedParkedEntry) because its keys come from a REMOTE mailbox.
   */
  readonly #refusedParkedEntries = new Map<string, ParkAuthFailure>();
  #parkedDrainLastBackstopAt = 0;
  /** DOD-PARK-DRAIN-1: how often the backstop drain rides the watchdog grid — see #parkedDrainBackstopTick. */
  #parkedDrainBackstopMs: number;
  /** Arm the park-deposit fault. Returns the count now armed. */
  injectParkFault(count: number, cause?: string): number {
    this.#parkFaultRemaining = Math.max(0, count);
    if (cause) this.#parkFaultCause = cause;
    return this.#parkFaultRemaining;
  }
  /** Remaining armed park faults — so a test can assert the fault was actually consumed. */
  getParkFaultRemaining(): number {
    return this.#parkFaultRemaining;
  }
  /**
   * MSG-001-3b (2b): inject the live content-park deposit (seal + ContentParkClient.deposit).
   * Injected by the composition root (daemon.ts). When absent, a not-confirmed send still records
   * the durable awaiting entry (crash backstop) but does not deposit live.
   * DOD-LEAVEMSG-1 (cello-unit-reviewer HIGH fix): the hook returns a TYPED result — `{ok:true}` or
   * `{ok:false, reason}` — mirroring RetryQueue's ParkFn contract. It must NEVER resolve `{ok:true}`
   * merely because it didn't throw: the production hook's own failure branches (standing receiver
   * unavailable, relay explicitly rejects the deposit) log-and-return without throwing, and a
   * throw-only contract would silently report those as success — the exact "system lies about its
   * own health" bug the reviewer caught (a park that never happened reported to the operator as
   * "dispatched to relay," with the durable retry_queue backstop skipped because sendContent's own
   * caller only enqueues on an honest {ok:false}).
   */
  setContentParkHook(
    fn: (args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array; structure1Signature?: Uint8Array; leafKind?: number; contentHashAlg: string | undefined }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string; retryAfterMs?: number }>,
  ): void {
    this.#contentParkHook = fn;
  }
  /**
   * DOD-PARK-DRAIN-1: inject the parked-mailbox drain (daemon.ts → contentPark.autoRecoverForAgent).
   *
   * The manager owns the two events that mean "content may be waiting for this agent on a relay":
   * a standing receiver was (re)built, and the slow backstop sweep. It does not own the drain
   * itself — that needs the agent's key provider and the inbound ingest funnel. So it calls out.
   *
   * Injected by the composition root, not passed to the constructor: the manager is built long
   * before the content park exists (content-park.ts documents why that ordering is load-bearing).
   */
  setParkedDrainHook(fn: (agentName: string, reason: ParkedDrainReason) => void): void {
    this.#parkedDrainHook = fn;
  }
  /** Ask for a drain. Never throws — a broken drain must never cost the caller its receiver. */
  fireParkedDrain(agentName: string, reason: ParkedDrainReason): void {
    const hook = this.#parkedDrainHook;
    if (this.#ctx.shuttingDown()) return;
    if (!hook) {
      // DOD-PARK-DRAIN-1 (review F4): an unwired hook silently reverts this entire unit, and the
      // defect it fixes was itself a trigger that silently was not there. Say so — once, because
      // the fire points are on a timer grid. Not an error: a SessionNodeManager built by a test
      // that does not exercise the drain is legitimate.
      if (!this.#parkedDrainHookAbsenceLogged) {
        this.#parkedDrainHookAbsenceLogged = true;
        this.#ctx.logger.warn("content.recover.drain.hook.absent", { agentName, reason });
      }
      return;
    }
    // The success-side trail. Without it, a live run cannot say WHICH trigger delivered the
    // content — which is exactly the claim the outstanding acceptance clause has to evidence.
    this.#ctx.logger.info("content.recover.drain.triggered", { agentName, reason });
    try {
      hook(agentName, reason);
    } catch (err: unknown) {
      this.#ctx.logger.warn("content.recover.drain.hook.failed", {
        agentName,
        reason,
        error: extractErrorMessage(err),
      });
    }
  }
  /**
   * MSG-001-3b (2b): deposit un-confirmed content to the relay store-and-forward backstop — keyed
   * to the recipient, on the SAME relay this session is witnessed by — so an offline recipient
   * recovers it (at the sequence the witness already assigned, R1). Best-effort, never throws.
   * DOD-LEAVEMSG-1: returns whether the deposit actually succeeded (false if no hook/relay is
   * configured, or the hook rejects) so a caller with a live response to shape (sendContent) can
   * distinguish "genuinely parked" from "nothing recoverable" instead of guessing. Callers that
   * fire this from an async backstop with no live caller (the TTF-expiry path) may ignore the
   * result — the deposit itself and its logging are unchanged either way.
   */
  /**
   * `contentHashAlg` is `string | undefined`, NOT optional — B2b-1 review F4's shape, applied to the
   * last place it was missing.
   *
   * Optional, dropping it at a call site was neither a typecheck error nor a test failure, because
   * absent silently means `sha256` and that is the only value in play today. Measured: the
   * direct-dial-fail route's mutant SURVIVED the whole daemon suite. Requiring the argument — even
   * when its value is `undefined` — forces each of the three callers to state what this message was
   * hashed under, so a new fourth caller cannot omit it by accident.
   */
  async parkContent(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor: Uint8Array | undefined, structure2Cbor: Uint8Array | undefined, contentHashAlg: string | undefined, structure1Signature?: Uint8Array, parkLeafKind?: number): Promise<ParkAttempt> {
    // Fault injection FIRST, so it reproduces the real shape: the refusal happens at the same point
    // the live hook refuses (before any deposit), with the same event and the same `cause`.
    if (this.#parkFaultRemaining > 0) {
      this.#parkFaultRemaining -= 1;
      this.#ctx.logger.warn("content.park.deposit.failed", {
        sessionId,
        contentHash: contentHashHex,
        reason: "standing_receiver_unavailable",
        cause: this.#parkFaultCause,
        injected: true,
      });
      return { outcome: "refused", cause: this.#parkFaultCause };
    }
    const hook = this.#contentParkHook;
    const entry = this.#ctx.activeEntry(this.#ctx.sessionKey(agentName, sessionId));
    // M12-P12 (review F6): "no park target configured" is NOT a refused deposit. Content in a
    // session with no relay was never recoverable through the park, so queuing it for re-park would
    // be a lie that grows the DB forever — every boot and every agent start would retry a row whose
    // only possible outcome is no_persisted_relay_endpoint. Reported as unconfigured, not refused.
    if (!hook || !entry || !entry.relayPeerId || !entry.relayAddrs) return { outcome: "unconfigured" };
    try {
      const result = await hook({
        // SEC-1: the hook must sign as the SENDING agent — it needs to know who that is.
        agentName,
        sessionId,
        recipientPubkeyHex: entry.counterpartyPubkey,
        relayPeerId: entry.relayPeerId,
        relayAddrs: entry.relayAddrs,
        contentHashHex,
        content,
        // DOD-MSG-4 (2b): carry the relay's signed ordering record so the parked entry is self-ordering
        // on recover too (sealed INTO the ciphertext envelope — INV-3: the relay still sees only ciphertext).
        structure1Cbor,
        structure2Cbor,
        // 034-CARRYLEAF: the author's signature over `structure1Cbor`, so the RECIPIENT can witness
        // this leaf if its author never does. Without it the mailbox route stays truncatable.
        structure1Signature,
        // 034-CARRYLEAF: the leaf DOMAIN, so a recovered leaf is never witnessed under a guess.
        leafKind: parkLeafKind,
        // B2b: the park route must name the same algorithm the direct frame did, or the recipient
        // verifies the same message two different ways depending on which route it took.
        contentHashAlg,
      });
      // DOD-LEAVEMSG-1 (reviewer HIGH fix): check the TYPED result, not just "didn't throw" — the
      // production hook's own failure branches (standing receiver unavailable, relay explicitly
      // rejects) resolve normally after logging, they never throw. A throw-only check would report
      // those as success.
      if (!result.ok) {
        this.#ctx.logger.warn("content.park.deposit.failed", {
          sessionId,
          contentHash: contentHashHex,
          reason: result.reason,
          cause: result.cause,
        });
        return {
          outcome: "refused",
          cause: result.cause ?? result.reason,
          ...(result.retryAfterMs !== undefined ? { retryAfterMs: result.retryAfterMs } : {}),
        };
      }
      return { outcome: "parked" };
    } catch (err: unknown) {
      /**
       * THE CODE GOES IN `cause`, THE PARAGRAPH GOES IN THE LOG — B2b-2 constraint 6.
       *
       * `cause` is documented as the machine-readable half and is handed to callers that branch on
       * it. Putting `err.message` there meant a producer-side refusal — this build cannot seal that
       * algorithm — was indistinguishable from a relay outage, so it inherited the relay's guidance:
       * *"queued, and will be re-sent when the relay link is back."* The relay was never asked, and
       * every re-park throws in the same place, so that sends the operator to the wrong subsystem
       * and then tells them to wait for a recovery that cannot happen.
       *
       * `instanceof`, not a string test: an untyped failure keeps the old behaviour exactly, so this
       * narrows what the caller can distinguish without changing anything it could not.
       */
      const coded = err instanceof ParkEnvelopeError ? err : null;
      this.#ctx.logger.warn("content.park.deposit.failed", {
        sessionId,
        contentHash: contentHashHex,
        ...(coded === null ? {} : { reason: coded.reason, detail: coded.detail }),
        error: err instanceof Error ? err.message : String(err),
      });
      return {
        outcome: "refused",
        cause: coded?.reason ?? (err instanceof Error ? err.message : String(err)),
      };
    }
  }
  /** DOD-M12B-INDEX-1 — this agent's own K_local pubkey, for attributing its own held content.
   *  Null when it cannot be resolved: an UNATTRIBUTED annex row is true, a falsely attributed one
   *  is not, and this is the record that outlives the session. */
  /**
   * Test seam for `#recoverOwnSealCtrlLeaf` (documented on the method itself, below). The
   * distinction it draws — "there is none" versus "I could not tell" — is the whole safety
   * property, and it had no coverage at any level.
   */
  recoverOwnSealCtrlLeafForTest(agentName: string, sessionId: string): { reportedRootHex: string; sequenceNumber: number } | "none" | "unknown" {
    return this.recoverOwnSealCtrlLeaf(agentName, sessionId);
  }
  /**
   * DOD-M12B-INTERRUPTED-ESCALATE-1 — our own SEAL ctrl leaf, if a previous run already posted one.
   *
   * Returns the two values a unilateral escalation runs on, rebuilt from durable state:
   * the ctrl leaf's relay-assigned sequence, and the root the tree WOULD have with that leaf
   * appended. The content hash cannot be recomputed — the seal payload embeds a `close_timestamp`
   * — so it is read out of the signed Structure 1 the store already holds.
   *
   * Null when there is no own ctrl leaf, which is the ordinary first-close case.
   */
  recoverOwnSealCtrlLeaf(agentName: string, sessionId: string): { reportedRootHex: string; sequenceNumber: number } | "none" | "unknown" {
    const ownPubkey = this.#ctx.ownPubkeyHex(agentName);
    // "I CANNOT TELL" IS NOT "THERE IS NONE". Returning the absent answer here would let the caller
    // submit a second SEAL ctrl leaf — the exact permanent loss this method exists to prevent — on
    // the strength of a lookup that failed. Every path that could not determine the answer says so.
    if (!ownPubkey) {
      this.#ctx.logger.warn("session.seal.leaf.recover.failed", {
        sessionId, agentName, reason: "own_pubkey_unresolved",
        impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
      });
      return "unknown";
    }
    let own: SealCarryLeaf | undefined;
    try {
      own = this.#ctx.getSealCarry(ownPubkey, sessionId)
        .find((l) => l.leafKind === LEAF_KIND_CTRL && l.senderPubkeyHex === ownPubkey);
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.seal.leaf.recover.failed", {
        sessionId, agentName, reason: "carry_read_failed",
        error: err instanceof Error ? err.message : String(err),
        impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
      });
      return "unknown";
    }
    if (!own) return "none";
    try {
      // Canonical Structure 1 is [version, content_hash, sender_pubkey, session_id, last_seen_seq,
      // timestamp], plus last_seen_hash at index 6 on a v2 claim (020-ACKHASH). content_hash is
      // index 1 in both.
      const s1 = decodeStructure1(own.structure1Cbor);
      if (!s1.ok) {
        this.#ctx.logger.warn("session.seal.leaf.recover.failed", {
          // NAMED AT ITS CAUSE — review F2. This read `structure1_content_hash_missing`, which was
          // accurate when the only check was `contentHash instanceof Uint8Array`. It now fires for an
          // unknown layout, undecodable CBOR and a malformed field too, and sends an operator to
          // audit a content hash when the layout is what disagreed. `structure1Reason` carries which.
          sessionId, agentName, reason: "structure1_decode_failed", structure1Reason: s1.reason,
          impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
        });
        return "unknown";
      }
      const contentHashHex = Buffer.from(s1.fields.contentHash).toString("hex");
      return {
        reportedRootHex: this.#ctx.getSessionTree(agentName, sessionId).rootWithAppendedHex(contentHashHex),
        sequenceNumber: own.sequenceNumber,
      };
    } catch (err: unknown) {
      // NOT a decode failure — review F3. `decodeStructure1` never throws, so the only thrower left
      // inside this try is the tree derivation below it. Calling this `structure1_decode_failed`
      // pointed at CBOR for a fault in `rootWithAppendedHex`, and made one reason string mean two
      // unrelated things in the same log event.
      this.#ctx.logger.warn("session.seal.leaf.recover.failed", {
        sessionId, agentName, reason: "seal_root_derivation_threw",
        error: err instanceof Error ? err.message : String(err),
        impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
      });
      return "unknown";
    }
  }
  /**
   * SEC-1 — THE ONLY WAY PARKED CONTENT ENTERS THE TRANSCRIPT.
   *
   * Authentication and ingest are FUSED here on purpose, and must stay fused. A caller cannot ingest
   * parked content without passing the signature gate, because this is the only entry point. Exposing
   * a separate `decode → ingest` path — with the signature check as its own optional step — is a
   * downgrade attack: an attacker omits the thing that triggers the check, and the check never runs.
   * A gate the caller can skip by leaving a field out is not a gate.
   *
   * FAILS CLOSED. No signature / bad signature / signer is not this session's counterparty / no
   * session at all → REFUSED, nothing is appended, nothing is written, and the caller MUST NOT
   * confirm-delete the entry from the relay (a forgery must not be able to evict itself, and a
   * genuine bug must not silently eat mail).
   */
  async recoverParkedEntry(
    agentName: string,
    sessionId: string,
    recipientPubkey: Uint8Array,
    unsealed: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): Promise<
    | { ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number; screenedOut?: boolean }
    | { ok: false; reason: string }
  > {
    const contentHashHex = Buffer.from(contentHash).toString("hex");

    // Review M4: a refused entry is deliberately NOT confirm-deleted (a forgery must not be able to
    // evict itself), which means an adversary could otherwise make us unseal + Ed25519-verify the
    // same forged entries on EVERY reconnect, forever — turning the mailbox into an amplification
    // vector against our own recover path. Remember what we already refused and skip the crypto on
    // re-pull. Still never confirmed, so nothing is destroyed. In-memory and BOUNDED: the cost of
    // forgetting across a restart is one more verify, which is exactly the pre-existing behavior.
    const refusalKey = `${this.#ctx.sessionKey(agentName, sessionId)}:${contentHashHex}`;
    const remembered = this.#refusedParkedEntries.get(refusalKey);
    if (remembered) {
      this.#ctx.logger.warn("content.recover.unauthenticated", {
        agentName,
        sessionId,
        contentHash: contentHashHex,
        reason: remembered,
        repeat: true,
        correlationId,
      });
      return { ok: false, reason: remembered };
    }

    const env = decodeParkEnvelope(unsealed);
    const verdict = authenticateParkedEntry({
      env,
      sessionIdHex: sessionId,
      recipientPubkey,
      contentHash,
      counterpartyPubkeyHex: this.#ctx.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
    });

    if (!verdict.ok) {
      // SEC-1: loud, and specific about WHICH gate refused — a silent drop here would look
      // identical to "no mail", which is how an injection attempt would go unnoticed.
      this.rememberRefusedParkedEntry(refusalKey, verdict.reason);
      this.#ctx.logger.warn("content.recover.unauthenticated", {
        agentName,
        sessionId,
        contentHash: contentHashHex,
        reason: verdict.reason,
        envelopeVersion: env.version,
        correlationId,
      });
      return { ok: false, reason: verdict.reason };
    }

    // Authenticated. The ordering record (when present) is still verified independently by
    // #recordFrameOrdering — it answers a different question (WHERE this message sits in the
    // canonical sequence, per the relay) and is still best-effort: a bad record must not block a
    // message whose AUTHORSHIP we have now proven.
    // DOD-FRONTIER-STRAND-1 AC1: keep the VERIFIED position and hand it to ingest, so dedup can
    // tell a redelivery (same position) from a genuinely new identical message (new position).
    let recoveredSeq: number | null = null;
    if (env.structure1Cbor && env.structure2Cbor) {
      recoveredSeq = this.#ctx.recordOrderingRecord(agentName, sessionId, env.structure1Cbor, env.structure2Cbor, contentHash, correlationId);
    }

    this.#ctx.logger.info("content.recover.verified", {
      agentName,
      sessionId,
      contentHash: contentHashHex,
      correlationId,
    });

    /**
     * DOD-M15-SEALWIRE-1 part B1 — RECOVERED-FROM-PARK CONTENT CARRIES NO ALGORITHM NAME, and that
     * is correct today rather than an oversight.
     *
     * The park envelope has no field for one, so this passes `undefined`, which resolves to
     * `sha256`. In part B1 that was exactly right and provably so: no sender salted, so every parked
     * entry in existence had been hashed unsalted.
     *
     * ✅ FIXED IN PART B2a, at BOTH sites: here, and the independent verifier in `content-park.ts`.
     * The envelope carries the algorithm from v3 onward, and a v2 envelope's absent field resolves to
     * `sha256` — which is what a peer predating the field actually used.
     *
     * > **⛔ THE LAST SENTENCE HERE READ "Every envelope this build emits is still v2, because
     * > nothing salts yet." THAT IS FALSE NOW.** B2b-2 turned salting on: a session holding an
     * > agreed salt hashes under `hmac-sha256-salt-v1`, so this build DOES emit v3 envelopes.
     * > Rewritten rather than deleted, per `DOD-M15-CLAIM-COMMENTS-1` — the sentence is why the
     * > staleness survived, and an absence would read as deliberate.
     * >
     * > The consequence is not theoretical: a v2 envelope carrying a SALTED hash recomputes unsalted
     * > at the far end and reports `content_hash_mismatch` — a false tamper claim on honest content,
     * > which also blocks auto-co-sign at seal. Measured on 2026-08-24.
     *
     * ─── AND THE REFUSAL DOES NOT HOLD — review F2 ────────────────────────────────────────────
     *
     * A direct-path refusal sends no delivery ACK, so the sender's TTF backstop parks the message
     * and it arrives here seconds later, where `undefined` means `sha256` and it may well succeed.
     * A frame refused BY NAME on one path is then accepted on the other, with nothing tying the two
     * together in the log — an operator sees an ERROR and, ten seconds on, a healthy delivery.
     *
     * That is not repaired by refusing here as well: today's park entry genuinely IS `sha256`, and
     * refusing it would drop good mail. What is wrong is the SILENCE, so the reconciliation is
     * logged instead — the two events become one story, and B2 removes the ambiguity for real by
     * putting the name in the envelope.
     */
    /**
     * ⚠️ LOGGED AFTER THE INGEST, NOT BEFORE IT — review B2a F1, and the previous version of this
     * block ANNOUNCED A DELIVERY THAT DOES NOT HAPPEN.
     *
     * It fired on a memo hit and said *"the message is being delivered by the other route"*, which
     * was true-by-construction only while the park path passed `undefined` for the algorithm. Part
     * B2a made the park path carry `env.contentHashAlg` — so a peer that names an unreadable
     * algorithm on the direct path AND parks the same content as v3 with the same name is refused
     * AGAIN here, re-arms the memo, is never confirm-deleted, and repeats on every drain. An
     * unbounded stream of warnings asserting a delivery that never occurs, drowning the real
     * reconciliation when the sender eventually re-parks as v2.
     *
     * The claim is only sound once the ingest has actually succeeded, so it is made there.
     */
    const priorDeclaredAlg = this.#ctx.refusals.priorUnreadableAlg(agentName, sessionId, contentHashHex);
    /**
     * `DOD-M15-AUTHORSHIP-ABSENT-1` review H1 — READ BEFORE THE INGEST, reported after it.
     *
     * Same reasoning as `priorDeclaredAlg` directly above: the memo says what THIS side did to this
     * content on the direct path, and the ingest below is what decides whether the other route
     * succeeded. Reading it after would race the clear.
     */
    /**
     * ⚠️ **REFUSING AN UNNOTARIZABLE MAILBOX MESSAGE WAS TRIED HERE AND REVERTED — recorded so the
     * next attempt starts from what actually blocks it, not from the compatibility argument that
     * does not.**
     *
     * The mailbox is the remaining route for the withholding attack: a counterparty who parks a
     * message with no ordering record AND no signature over its ordering claim delivers something
     * readable that can never enter a receipt. The obvious fix is to refuse it here.
     *
     * **It cannot ship yet, and the reason is our OWN path, not an older peer's.** `SEC-1` AC5 is
     * explicit: the crash-backstop shape — signed by the sender, no ordering record — is legal and
     * must be accepted. That envelope is produced when content is queued before anything witnessed
     * it, and from the recipient's side it is INDISTINGUISHABLE from an attacker's stripped one. So
     * this refusal rejects our own crash recovery along with the attack.
     *
     * **What closes it:** make the crash backstop sign an ordering claim at enqueue time, the way
     * the live park path now does (`#signOwnContentClaim` already produces exactly this artifact).
     * Then "no ordering record and no signed claim" is a shape only a modified client emits, and
     * refusing it costs nothing real. The retry queue already carries the two columns for it —
     * `structure1_sig` and `leaf_kind` — which were added for this and are populated on the live
     * path today.
     */
    const refusedForAuthorship = this.#ctx.refusals.wasRefusedOnDirectPath(agentName, sessionId, contentHashHex);
    const result = await this.#ctx.ingestReceivedContent(
      agentName, sessionId, env.content, contentHash, correlationId, recoveredSeq ?? undefined,
      // The envelope's own claim, verbatim — `undefined` on a v2 envelope, which resolves to
      // `sha256` and is exactly right for a peer that predates the field.
      env.contentHashAlg,
    );
    /**
     * `ok` IS NOT "DELIVERED" — review B2a pass-2 F1, and this is the same class the F1 fix was
     * raised for, one predicate over.
     *
     * `ingestReceivedContent` returns `ok` in three shapes and only one is a delivery:
     *   `{ok, held: true}`       — buffered behind an ordering gap; not appended, not shown YET.
     *   `{ok, screenedOut: true}` — leafed and PERMANENTLY never shown to the agent.
     * Announcing *"the message was delivered by the other route"* for either is a false all-clear on
     * the operator's one line about this message, and the memo is deleted in the same breath, so
     * nothing ever re-raises it.
     *
     * Leaving the memo ARMED on `held` is deliberate: the release path re-enters ingest, which is
     * when delivery actually happens, and the claim becomes true there.
     *
     * ⚠️ THE `screenedOut` CLAUSE IS UNREACHABLE TODAY and is kept anyway — said out loud so nobody
     * reads it as covered. A terminal inbound block needs a detector the shipping security gateway
     * does not wire, so it returns only `allow` and a fail-closed non-terminal `block`. Measured: a
     * mutant dropping just that clause SURVIVES the suite. It stays because the day a detector is
     * wired, this line is the difference between an all-clear and a permanent silent discard — and
     * finding that then costs more than the clause costs now.
     */
    /**
     * ─── WITNESS A RECOVERED MESSAGE ITS SENDER NEVER WITNESSED — 034-CARRYLEAF review F1 ────────
     *
     * The mailbox route's half of the withholding fix. `recoveredSeq` absent means no relay ordering
     * record came with it, which is the same shape the direct path treats as "their submit never
     * happened" — and it is reached the same two ways: their relay was briefly unreachable, or they
     * are withholding on purpose.
     *
     * ⚠️ THE SIGNATURE COMES FROM THE ENVELOPE, AND ONLY A v4 ENVELOPE HAS ONE. `parkSig`
     * authenticates the DEPOSIT — it signs `(session_id, recipient_pubkey, content_hash)` — and the
     * relay will not accept it, because a counter-submit is admissible only against the author's own
     * signature over their own ordering claim. A v2 or v3 envelope therefore cannot be witnessed on
     * its author's behalf, and is left alone rather than guessed at.
     *
     * **So this route is closed against a peer running a stock client, and open to one that
     * deliberately emits an older envelope.** Requiring v4 is the step that closes it completely,
     * and it waits on nothing in the field emitting v2 or v3 — the same tolerate-then-enforce
     * sequence every bilateral wire change in this milestone follows.
     */
    if (
      result.ok && result.held !== true && result.screenedOut !== true &&
      recoveredSeq === null && env.structure1Cbor && env.structure1Signature
    ) {
      const kind = env.leafKind;
      if (typeof kind === "number") {
        this.#ctx.witnessReceivedLeaf(agentName, sessionId, contentHash, env.structure1Cbor, env.structure1Signature, kind, correlationId);
      }
    }
    if (priorDeclaredAlg !== undefined && result.ok && result.held !== true && result.screenedOut !== true) {
      // Cleared ONLY on a real reconciliation. Clearing on the lookup (as this did) forgets the
      // refusal even when the recovery fails, so the next genuine reconciliation says nothing.
      this.#ctx.refusals.clearUnreadableAlg(agentName, sessionId, contentHashHex);
      this.#ctx.logger.warn("content.recover.alg_refusal_reconciled", {
        agentName, sessionId, correlationId,
        contentHash: contentHashHex,
        priorDeclaredAlg,
        recoveredAlg: env.contentHashAlg ?? "(absent → sha256)",
        impact: "THIS EXACT MESSAGE was refused on the direct path because it named an algorithm this build cannot read, and the same content has now been accepted via the relay park under an algorithm this build CAN read. The refusal did not hold: the message was delivered by the other route.",
      });
    }
    /**
     * ⚠️ **THE AUTHORSHIP REFUSAL DOES NOT HOLD EITHER, AND THIS IS WHERE IT SAYS SO** — review H1.
     *
     * `DOD-M15-AUTHORSHIP-ABSENT-1` refuses a direct-path frame with no usable proof of who wrote
     * it. Refusing sends no delivery ACK, so the sender's TTF backstop parks the message and it
     * arrives here — where the ENVELOPE's signature over (session_id, recipient_pubkey,
     * content_hash) is what authenticates it, and `authenticateParkedEntry` above has already
     * accepted it. That is correct and it is deliberately NOT changed here: gating mail retrieval
     * on a per-message record the relay-degraded path is allowed to omit is the false-positive shape
     * this whole unit is careful to avoid, and the order that added the refusal scopes the park
     * envelope out explicitly.
     *
     * What must not stand is the SILENCE. Without this line the operator reads "refused" and then
     * watches the message appear, with nothing connecting the two — the same reconciliation gap the
     * algorithm refusal above already pays for. What they need to know is the part that is really
     * lost: the message arrived, and its INDIVIDUAL author is attested by the mailbox envelope
     * rather than by a signature over that message's own bytes.
     *
     * Same `ok && !held && !screenedOut` predicate as above, and for the same reason: `ok` is not
     * "delivered".
     */
    if (refusedForAuthorship && result.ok && result.held !== true && result.screenedOut !== true) {
      this.#ctx.refusals.clearRefusedOnDirectPath(agentName, sessionId, contentHashHex);
      /**
       * ⚠️ RENAMED FROM `…authorship_refusal_reconciled` by `029c` review F4, because the memo it
       * reads now covers EVERY direct-path refusal and not only the authorship one. Keeping the old
       * name would have put "no usable proof of who wrote it" on a message that was actually
       * refused for not decrypting — a wrong cause is worse than a general one.
       *
       * The specific reason is already on the operator's notice; what this event adds is that the
       * refusal did not hold.
       */
      this.#ctx.logger.warn("content.recover.refusal_reconciled", {
        agentName, sessionId, correlationId,
        contentHash: contentHashHex,
        impact: "THIS EXACT MESSAGE was refused on the direct path and the same content has now been accepted from the relay mailbox, where the sealed envelope proves the sender. The refusal did not hold: the message WAS delivered by the other route. What the direct path could not confirm is still unconfirmed — the mailbox proves WHO sent it and nothing about the check that refused it — so the receipt can show this message arrived without showing everything a directly-delivered one would.",
        guidance: "Nothing to do about this message. The fix named on the original refusal still stands: until the cause clears, every message on this session takes the slower route and lands with less attached to it.",
      });
    }
    return result;
  }
  /**
   * Review M4: bounded memo of parked entries we have already refused, so a mailbox stuffed with
   * forgeries cannot force an unbounded unseal+verify on every reconnect. FIFO-capped — the cap
   * matters more than the retention: forgetting an entry only costs one extra verification, whereas
   * an unbounded map would be a memory leak fed by a remote party (the exact class the DOD-MSG-4
   * review already caught once in the offered-moniker map).
   */
  rememberRefusedParkedEntry(key: string, reason: ParkAuthFailure): void {
    if (this.#refusedParkedEntries.size >= MAX_REFUSED_PARKED_ENTRIES) {
      const oldest = this.#refusedParkedEntries.keys().next();
      if (!oldest.done) this.#refusedParkedEntries.delete(oldest.value);
    }
    this.#refusedParkedEntries.set(key, reason);
  }
  /**
   * DOD-PARK-DRAIN-1: the backstop sweep — every agent holding a standing receiver gets a drain
   * every #parkedDrainBackstopMs, whether or not anything happened.
   *
   * The trigger-driven drains (agent start, receiver rebuild, signaling reconnect) are what
   * actually deliver. This exists because the incident was a MISSING trigger, and a missing
   * trigger is invisible: the daemon looked healthy, the content was intact on the relay, and the
   * only thing that ever moved it was a human restarting the daemon. With the sweep, the worst a
   * future gap in trigger coverage can cost is one interval of latency. Safe by construction —
   * ingest is deduped and the relay is delete-on-confirm, so a redundant drain pulls nothing.
   */
  parkedDrainBackstopTick(now: number): void {
    if (this.#parkedDrainHook === null) return;
    if (now - this.#parkedDrainLastBackstopAt < this.#parkedDrainBackstopMs) return;
    this.#parkedDrainLastBackstopAt = now;
    for (const agentName of this.#ctx.agentsWithLiveReceiver()) {
      if (!this.#ctx.agentWantsReceiver(agentName)) continue; // agent went offline
      this.fireParkedDrain(agentName, "periodic_backstop");
    }
  }
}
