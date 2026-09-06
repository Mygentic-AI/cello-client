/**
 * CELLO Daemon — THE PER-SESSION CONTENT SALT
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE, Unit 1. The two sides agree a salt for
 * this session, and every content hash is taken under it — so a hash from one conversation cannot be
 * recognised in another, and an observer holding the plaintext cannot confirm a guess by hashing it.
 *
 * Moved verbatim, comments included. The operator-facing strings in here are unusually careful and
 * they must stay that way: several exist specifically to distinguish "your counterparty is on a
 * build that predates the salt" from "our own write failed", because those have opposite remedies
 * and people have already been sent the wrong way once.
 *
 * ⚠️ THIS CLASS OWNS ELEVEN PER-SESSION SALT MAPS, of which **TEN** were cleared by hand in
 * `#evictSessionCaches`. One `evictSession` call replaces those ten.
 *
 * ⚠️ **`#saltPending` IS THE ELEVENTH AND IT IS NOT ONE OF THEM — DO NOT ADD IT TO `evictSession`.**
 * It holds a PROMISE that an outbound send is awaiting, and teardown must SETTLE it, not drop it.
 * The caller does that on the next line (`settleSaltPending(..., "closed")`), which is what lets a
 * send in flight return `session_torn_down` instead of waiting forever.
 *
 * This is not hypothetical: it was added to `evictSession` for tidiness, and because `evictSession`
 * runs first, `settleSaltPending` then found nothing and returned — so the promise never resolved,
 * its 5-second timer found nothing either, and `cello_send` hung with no error, no log and no
 * timeout. The whole suite stayed green, because nothing covers that branch.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger, SessionRecord } from "./types.js";
import type { SessionTree } from "./session-tree.js";
import type { ActiveSessionEntry } from "./session-node-types.js";
import { extractErrorMessage } from "./error-message.js";
import { generateSaltContribution, SESSION_SALT_BYTES } from "@cello-protocol/crypto";
import {
  onPeerSaltFrame,
  SALT_ADOPTION_LABELS,
  SALT_FREEZE_GUIDANCE,
  type SaltAgreementFrame,
} from "./session-salt-agreement.js";
import {
  UNSALTED_REASONS,
  UNSALTED_GUIDANCE,
  SALT_AGREEMENT_WAIT_MS,
  type UnsaltedReason,
} from "./session-node-types.js";
import { contentHashFor, CONTENT_HASH_ALGS, type ContentHashAlg } from "./wire-content-hash.js";
import {
  CONTENT_ENCRYPTION_REASONS,
  type ContentEncryptionReason,
} from "./content-encryption-status.js";

/** What the salt agreement needs from the manager, stated explicitly rather than handed `this`. */
export interface SaltContext {
  readonly logger: Logger;
  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  /** The live session entry, when one exists. */
  activeEntry(key: string): ActiveSessionEntry | undefined;
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  getSessionRecord(agentName: string, sessionId: string): SessionRecord | null;
  /** Content held behind an ordering gap — the hash domain has to account for it. */
  heldContentFor(key: string): Map<number, { contentHashHex: string }> | undefined;
  ensureHeldRestored(agentName: string, sessionId: string, opts?: { release: boolean }): void;
  /** Put a salt frame on the session's control stream. The stream is the manager's to own. */
  sendSaltFrame(agentName: string, sessionId: string, correlationId?: string, override?: SaltAgreementFrame): Promise<void>;
  readonly awaitingAck: Map<string, Map<string, unknown>>;
  contentEncryptionState(
    agentName: string,
    sessionId: string,
  ): { key: Uint8Array; reason?: undefined } | { key: null; reason: ContentEncryptionReason };
  freezeSession(
    agentName: string,
    sessionId: string,
    reason: string,
    narrative: { event: string; observation: string; impact: string; reviveReason: string; reviveGuidance: string },
    correlationId?: string,
  ): Promise<void>;
}

export class SessionSalts {
  readonly #ctx: SaltContext;

  constructor(ctx: SaltContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * DOD-M15-SEALWIRE-1 bullet 6 (part A) — the salt agreement's two pieces of per-session state.
   *
   * `#saltContributions` — OUR random half, MINTED ONCE PER SESSION. This being a map rather than a
   * fresh call at each send is the whole correctness of the exchange: we re-announce on every
   * counterparty connect, and a contribution regenerated per reconnect would have both sides
   * deriving against a moving value with the fingerprints never settling — a session that
   * reconnects and still disagrees, which reads as a network fault rather than a bug here.
   *
   * `#sessionSalts` — a CACHE over `sessions.content_salt`, which is the durable copy. Both are
   * cleared by `#evictSessionCaches`: the contribution is worthless once a salt exists, and the
   * salt is re-read from the row on revival, which is exactly what Decision #8 persists it for.
   */
  #saltContributions = new Map<string, Uint8Array>();
  /**
   * ─── B2b-2 state: what the SEND path needs that the row cannot answer ─────────────────────────
   *
   * `#saltPending` — an agreement that has actually gone out and not yet been answered. The first
   * send waits on it (constraint 2). Absent means *nothing is in flight*, which is not the same as
   * "no salt": a park-only session never starts one at all, and must not wait (constraint 5).
   *
   * `#hashedWithoutSalt` — this session has already computed an unsalted content hash. Decision #8
   * closes adoption at the moment content is HASHED, and for a session's first message that is a
   * full network round trip before any leaf, held row or in-flight entry exists. Without this flag
   * the frontier count reads empty for exactly the window in which adopting would split the
   * transcript.
   *
   * `#unsaltedAnnounced` — the fallback has been stated for this session. Decision #15 says once per
   * session; a per-message warning is a filter waiting to be written.
   *
   * All three are per-session and in-memory by design, and are dropped with the rest of a session's
   * caches on eviction — a revived session re-reads its salt from the row, re-derives its frontier
   * from durable state, and starts a fresh agreement if it reconnects.
   */
  #saltPending = new Map<string, {
    settled: Promise<"agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed">;
    resolve: (v: "agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed") => void;
    timer: ReturnType<typeof setTimeout>;
    boundMs: number;
  }>();
  /**
   * HOW THE LAST AGREEMENT ENDED, kept after `#saltPending` is cleared.
   *
   * ⚠️ FOUND BY FALSIFYING MY OWN FIX. `#settleSaltPending` deletes the pending entry, so a send that
   * arrives AFTER an agreement has already failed finds nothing pending and is told
   * `no_agreement_started` — *"your counterparty was not connected"* — when in fact they were
   * connected and our own dial to them failed. The outcome was observable only to a send that
   * happened to already be waiting, which is the minority case.
   *
   * So the verdict outlives the wait. An ABSENT entry still means what it always meant — no
   * agreement was ever started, the park-only case — and that distinction is the whole reason this
   * is a separate map rather than a default.
   */
  #saltLastOutcome = new Map<string, "timeout" | "closed" | "persist_failed" | "announce_failed">();
  #unsaltedAnnounced = new Set<string>();
  #sessionSalts = new Map<string, Uint8Array>();
  /**
   * The peer half we last answered with a repair, hex — review F14, and it is what makes the repair
   * TERMINATE. Without it, two daemons that already hold the same salt trade contributions forever
   * once a reconnect leaves a stale copy queued on each side. See `onPeerSaltFrame`'s
   * `alreadyRepairedAgainstPeerHalf`.
   */
  #saltRepairedAgainst = new Map<string, string>();
  /**
   * THE MIRROR OF THE ABOVE — the peer FINGERPRINT we last answered with our half, hex.
   *
   * 006-CRYPTO finding 1. `#saltRepairedAgainst` terminates the salt-HOLDER's direction only. A side
   * holding no salt answered every fingerprint with its contribution, and a latched holder answers
   * every contribution with its fingerprint — so after one failed persist plus a reconnect, two
   * healthy daemons repair at each other for the life of the session, one new stream and one INFO
   * line each per round trip. Keyed on the peer's fingerprint BYTES for the same reason the other
   * map is keyed on its half: a genuinely NEW fingerprint is new information and must still be
   * answered; only an identical re-offer is the loop.
   */
  #saltRepairedAgainstFingerprint = new Map<string, string>();
  /**
   * `#saltSuspended` — the peer has told us it can never hold a salt, so ours must not be USED. The
   * bytes stay on disk (`DOD-M15-SALTSPLIT-1`, the other lane's authorization argument).
   *
   * ⚠️ THIS REPLACED AN IMMEDIATE, IRREVERSIBLE ERASE, AND THE REFRAMING IS THE WHOLE POINT.
   *
   * I defended the erase as a compatibility question — a legacy peer might send the misleading frame,
   * we are pre-launch, do not carry weight for a state nobody is in. All true, and it does not reach
   * the question. **It is an AUTHORIZATION question:** the receiver performed an irreversible
   * destruction of durable key material on a peer's bare assertion with nothing to check it against.
   * Re-derived against an empty database — *would I let one side erase the other's key material on an
   * unauthenticated claim carrying no evidence?* No. My own empty-database rule argued FOR a guard,
   * not against one.
   *
   * And my own trigger was the proof I walked past: `frontier_unreadable` is not a legacy peer, it is
   * a **healthy current peer having one bad second**. Fixing the producer made our side stop emitting
   * it wrongly and left the receiver built to obey it — *one side of that exchange correct by
   * construction, the other still correct by luck.*
   *
   * A salt that cannot be used is inert. The destruction is what turned a transient disagreement into
   * a permanent one, so **nothing irreversible hangs on the claim any more** and proving the claim
   * stops being load-bearing.
   *
   * ⚠️ IN MEMORY ON PURPOSE, AND THE ERASE IS DEFERRED RATHER THAN CANCELLED. A durable mark needs a
   * column, and this milestone has lost data twice in the rebuild DDL. In-memory alone would split
   * the transcript at the next restart — unsalted now, salted after a reboot — so the salt IS erased,
   * at the first unsalted hash, which is the moment erasing becomes both harmless (nothing was hashed
   * under it) and REQUIRED (keeping it would re-salt after a restart). Before that moment a corrected
   * announce carrying a matching fingerprint un-suspends and the session recovers fully salted, which
   * erasure makes impossible even in principle: the far side cannot re-derive without both halves.
   *
   * A restart before either outcome loses the mark, we are salted again, the peer refuses one message,
   * and the announce re-runs and re-suspends. **One refused message, then convergence** — against a
   * dead session.
   */
  #saltSuspended = new Set<string>();
  #hashedWithoutSalt = new Map<string, number>();
  /**
   * `#hashedWithSalt` — how many content hashes this session has computed UNDER its salt and not yet
   * landed anywhere a count can see (`DOD-M15-SALTSPLIT-1`, review HIGH-2).
   *
   * The mirror of `#hashedWithoutSalt`, and it exists for the same window: a hash is computed, then a
   * relay round trip happens, and only afterwards does the message appear as a leaf, a hold or an
   * awaiting-ack entry. In between, every count reads zero.
   *
   * It is read by `#discardUnspentSalt` alone. "Unspent" must mean *nothing has been hashed under
   * it*, and without this the answer is *nothing has FINISHED being hashed under it* — which is the
   * question nobody asked, answered destructively.
   *
   * Never decremented on success: a salted hash that reaches the wire is spent forever, and unlike
   * the unsalted counter there is no `abandonUnsaltedHash` equivalent to undo. It is cleared only
   * with the rest of the session's caches. **For a discard decision, erring toward "spent" is the
   * safe direction** — a salt kept is recoverable, a salt erased is not.
   */
  #hashedWithSalt = new Map<string, number>();
  /**
   * THE LABEL THE PEER GAVE when it closed adoption — 006-CRYPTO finding 2.
   *
   * The wire carries WHY, `session-salt-agreement.ts` makes it a union so a caller cannot close
   * without saying why, and the agreement's `detail` puts it in the log. It was going no further:
   * `#settleSaltPending(..., "closed")` recorded only that it was closed, so every one of the four
   * reasons arrived at the operator as "they had already hashed messages".
   *
   * Stored raw and rendered through `#peerClosedReason`, which maps anything outside the known set
   * to a non-asserting reason — the peer chooses these bytes.
   */
  #saltPeerClosedLabel = new Map<string, string>();
  /**
   * cello_list_sessions: every persisted session for one agent, regardless of
   * status (active, interrupted, sealed, seal_interrupted_pending). Ordered most
   * recently updated first so the live session surfaces at the top. This is the
   * discovery surface that the by-id reads (cello_get_transcript /
   * cello_get_sealed_receipt) depend on — without it an agent has no way to learn
   * its own session ids after a restart or from a fresh MCP connection.
   */
  /**
   * DOD-M15-REFUSED-INBOUND-SILENT-1, the DECLINED PROTECTION half — a FIELD, not an alert.
   *
   * An unsalted session is exactly as verifiable as every session shipped before salting existed,
   * so there is nothing to interrupt the operator with and no event to fire. What was missing is
   * STATE: nothing let anyone tell *"unsalted because this build predates the feature"* from
   * *"unsalted because adoption was refused"* — and only the second says something about their
   * setup. The session's own status now answers it, which costs nothing per message and cannot
   * become a flood.
   *
   * The raw salt is dropped on the way out rather than passed through. `SELECT *` was handing the
   * BLOB to a listing surface that has no use for it; the boolean is the whole question a reader of
   * this list is asking, and shipping key material to answer a yes/no is not a trade worth making.
   */
  /**
   * ⚠️ THE STORED COLUMN IS NOT THE ANSWER ON ITS OWN — 006-CRYPTO finding 3.
   *
   * A SUSPENDED salt keeps its bytes on disk deliberately (`DOD-M15-SALTSPLIT-1`: a salt kept is
   * recoverable, a salt erased is not), while `#saltForHashing` returns null for it and every
   * message goes out `sha256`. Reading the column alone therefore reported `true` at the exact
   * moment the session had STOPPED salting — and because the field is emitted only when `false`,
   * the agent saw nothing at all, which reads as "not unsalted".
   *
   * That is precisely the case this field was added for. Its own note above says it exists to tell
   * *"unsalted because this build predates the feature"* from *"unsalted because adoption was
   * refused"*, and the refused case was the one it could not report.
   */
  saltStatusOf(row: SessionRecord, agentName: string | null): SessionRecord {
    const { content_salt, ...rest } = row as SessionRecord & { content_salt?: Uint8Array | null };
    const stored = content_salt != null && content_salt.length > 0;
    const suspended =
      agentName !== null && this.#saltSuspended.has(this.#ctx.sessionKey(agentName, String(row.session_id)));
    /**
     * 007-CRYPTO: the REAL state, not a constant. In 006 this was hardcoded `false` with a single
     * reason, because nothing exchanged keys and saying so was the honest answer. It exchanges now,
     * so a hardcode would be the stale claim that unit existed to remove.
     *
     * A row with no live agent name cannot be looked up in memory — an orphaned session, whose key
     * (if it ever had one) died with the process. Reported as not-agreed rather than guessed at.
     */
    const enc: { key: Uint8Array; reason?: undefined } | { key: null; reason: ContentEncryptionReason } =
      agentName === null
        ? { key: null, reason: CONTENT_ENCRYPTION_REASONS.NOT_YET_AGREED }
        : this.#ctx.contentEncryptionState(agentName, String(row.session_id));
    return {
      ...rest,
      content_hashes_salted: stored && !suspended,
      content_encrypted: enc.key !== null,
      ...(enc.key === null ? { content_encryption_reason: enc.reason } : {}),
    } as SessionRecord;
  }
  saltContributionFor(agentName: string, sessionId: string): Uint8Array {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let contribution = this.#saltContributions.get(key);
    if (!contribution) {
      contribution = generateSaltContribution();
      this.#saltContributions.set(key, contribution);
    }
    return contribution;
  }
  /**
   * Our half for a session, **without minting one** — review F1, and the distinction is the whole
   * safety of the repair.
   *
   * A session that already holds a salt must never mint a fresh half. If it did, the repair would
   * offer the peer a half the stored salt was NOT derived from, they would compute a different salt,
   * and both sides would believe they had agreed — silently, which is the one outcome worse than
   * refusing. So `null` from here means exactly "we hold a salt and the half behind it is gone",
   * and that is the only state the agreement is allowed to call unrepairable.
   */
  ownSaltHalf(agentName: string, sessionId: string): Uint8Array | null {
    return this.#saltContributions.get(this.#ctx.sessionKey(agentName, sessionId)) ?? null;
  }
  /**
   * Test seam: force this session's own salt half, so the LOCAL-defect path is reachable.
   *
   * `generateSaltContribution` cannot produce a degenerate half, which is the point of it — so the
   * only way to exercise "our own random source is broken" end-to-end is to stand in for the broken
   * source. Named `…ForTest` like every other seam, and it writes the same map production writes
   * rather than a parallel one, so a test cannot pass against state the daemon never reads.
   *
   * ⚠️ This block stayed in `session-node-manager.ts` when the method moved here, and ended up
   * stacked on an unrelated test seam — the fourth found doing that. `#saltContributions` above is
   * "the same map production writes"; the sentence was true where it was written and unverifiable
   * where it landed.
   */
  setSaltContributionForTest(agentName: string, sessionId: string, contribution: Uint8Array): void {
    this.#saltContributions.set(this.#ctx.sessionKey(agentName, sessionId), contribution);
  }
  /**
   * Test seam: drop this session's own half while leaving the stored salt in place — the state every
   * teardown produces, because `#evictSessionCaches` clears the map and the row survives.
   *
   * It clears the SAME map the eviction clears rather than a stand-in, so a test cannot pass against
   * a state the daemon never reaches. Reproducing it through a real teardown/revive would also drag
   * in node rebuild and relay reconnection, none of which this is about.
   */
  forgetSaltContributionForTest(agentName: string, sessionId: string): void {
    this.#saltContributions.delete(this.#ctx.sessionKey(agentName, sessionId));
  }
  /**
   * THE ONE PLACE THAT DECIDES HOW A SESSION'S OUTBOUND CONTENT IS HASHED —
   * `DOD-M15-SEALWIRE-1` part B2b.
   *
   * Returns the hash AND the algorithm that produced it, together, because the two must not be
   * decided separately. `wire-content-hash.ts` exists for exactly this reason and says so in its own
   * header: the expression was written out at five call sites, the two added last got it wrong, and
   * the failure was invisible — *"the send succeeds, `parked: false`, the sender's log says the frame
   * left, and the receiver discards it at the authenticity check."* It took two real daemons.
   *
   * There are FOUR outbound sites (`session-content-handlers.ts`, two in `daemon.ts`,
   * `document-delivery-transport.ts`). Once salting is switchable, each of them independently
   * deciding whether to salt is that defect again with a worse failure mode — a message hashed one
   * way and LABELLED another is refused by every peer, including a correct one.
   *
   * ⚠️ ASYNC, AND THAT IS THE POINT — B2b-2 constraint 2, not an implementation detail.
   *
   * The agreement is in flight while the operator composes their first message. Hash without waiting
   * and it comes out unsalted, and that first unsalted hash closes adoption for the LIFE of the
   * session (Decision #8, unit 1). Every session would fall back permanently while every log line
   * about it stayed true — the feature present, wired, tested, and never once reached.
   *
   * The wait lives HERE rather than at the four call sites for the same reason `contentHashAlg` is a
   * required parameter rather than a defaulted one: a site that forgets it must fail to compile. A
   * caller that drops the `await` gets a `Promise` where bytes belong, which is a typecheck error;
   * a caller that forgot to call a separate `awaitSaltSettled()` would silently send unsalted.
   */
  async contentHashForSession(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
  ): Promise<{ hash: Uint8Array; alg: ContentHashAlg }> {
    const { salt, reason } = await this.saltForHashing(agentName, sessionId);
    if (salt !== null) {
      /**
       * ⚠️ THE SALTED HASH MARKS ITSELF SPENT — `DOD-M15-SALTSPLIT-1` review pass 1, HIGH-2.
       *
       * The unsalted branch below has counted itself since review pass 2 F1, for a reason stated
       * there in full: between hashing and `#trackAwaitingAck` there is a relay round trip, and in
       * that window leaves, held content and awaiting-ack ALL read zero. **The salted direction was
       * left with no counterpart**, which was harmless while nothing acted on the answer — and
       * `#discardUnspentSalt` is the first code that acts on it destructively.
       *
       * Without this, a peer's `adoption_closed` frame arriving inside that window finds adoption
       * "open", discards the salt, and the message already on the wire carries
       * `content_hash_alg: hmac-salt-v1` with a hash **nobody — including this daemon — can ever
       * recompute**. The alg is copied verbatim into the parked envelope on TTF expiry, so it
       * survives the round trip that would otherwise have hidden it.
       *
       * A COUNT, not a bit, for the same reason the unsalted side is a count: two connections can be
       * mid-send at once, and one finishing must not clear the claim the other is still relying on.
       */
      const key = this.#ctx.sessionKey(agentName, sessionId);
      this.#hashedWithSalt.set(key, (this.#hashedWithSalt.get(key) ?? 0) + 1);
      const alg = CONTENT_HASH_ALGS.HMAC_SALT_V1;
      return { hash: contentHashFor(content, { alg, salt }), alg };
    }
    /**
     * ⚠️ MARKED BEFORE THE HASH IS RETURNED, and this closes a window the row cannot see.
     *
     * `#saltAdoptionClosed` counts leaves, held content and in-flight sends. For the FIRST message of
     * a session none of the three exists at this moment — the leaf lands after `sendContent` returns,
     * which is a network round trip later. A peer contribution arriving in that gap would be adopted,
     * and the message already on the wire would become the single unsalted leaf in an otherwise
     * salted transcript: the exact split Decision #8 forbids, reached by the one route every count
     * reads as empty.
     *
     * In memory rather than in a column, and that is sufficient rather than convenient: if this
     * process survives, the flag holds; if it does not, the message it protects either reached a
     * durable form (leaf, held row, queued row — all of which the counts see) or never left, in which
     * case there is nothing to split. The one remaining case — hashed, sent, and no local record —
     * is covered from the other side, because the peer DID leaf it and closes its own adoption, and
     * the wire state added in unit 1 tells us so.
     */
    /**
     * ⚠️ NOT FOR A TORN-DOWN SESSION — review Finding 5. `#evictSessionCaches` settles the wait and
     * clears both of these sets; a `.add()` afterwards re-populates a map whose eviction has already
     * run, and the entries then outlive the session they describe. There is also nothing to protect:
     * a session that no longer exists cannot adopt a salt or split a transcript.
     */
    /**
     * ⚠️ THE DEFERRED ERASE — `DOD-M15-SALTSPLIT-1`. This is the moment a suspended salt becomes both
     * harmless to erase and NECESSARY to erase, and it must run BEFORE the count below.
     *
     * Harmless: this session has hashed nothing under the salt, which is what let it be suspended.
     * Necessary: we are about to hash unsalted, and a salt left on disk reads back fine after a
     * restart — so the next process would hash salted and the transcript would be split down the
     * middle by a reboot rather than by any frame.
     *
     * **Before the `#hashedWithoutSalt` increment on purpose.** `#discardUnspentSalt` refuses to erase
     * once adoption is closed, and that counter is one of the things that closes it — increment first
     * and the erase we just decided is correct gets refused by our own guard, leaving exactly the
     * split this ordering exists to prevent.
     */
    if (reason !== UNSALTED_REASONS.SESSION_TORN_DOWN && this.#saltSuspended.has(this.#ctx.sessionKey(agentName, sessionId))) {
      /**
       * ⚠️ GOING UNSALTED AND ERASING THE SALT ARE ONE DECISION — pass 2, F2 (HIGH), and this is my
       * regression, not a pre-existing one.
       *
       * The note above claimed the ordering was sufficient because `#hashedWithoutSalt` is what
       * closes adoption. **It is one of FOUR contributors.** Leaves, held rows and awaiting-ack close
       * it too — and the most ordinary event in the protocol closes it: *the peer sends us its next
       * message.* Reproduced through the real inbound path: suspend, peer's message lands as leaf 0,
       * we hash `sha256`, and the erase is REFUSED with `already_hashing` while the bytes stay on
       * disk. One teardown-and-revive later — no process restart required — we hash `hmac` again.
       * That is the split transcript, produced by the fix for the split transcript.
       *
       * Worth naming precisely: **the immediate-erase design this replaced could NOT produce it.**
       * There, a refused discard simply kept the session salted — one rule throughout, and loud.
       * Suspension is what made "unsalted now, salted later" reachable. Same shape as pass 1: the fix
       * worse than the defect on one path.
       *
       * So the two are atomic. If the salt cannot be erased, we do **not** go unsalted — we keep
       * hashing under the held salt, which is one rule for the whole session, and say so at ERROR.
       * The counterparty may refuse those messages, and that is the honest failure: a dead session
       * beats a transcript no single rule can verify. The durable column remains the real answer.
       */
      if (!this.discardUnspentSalt(agentName, sessionId)) {
        const stillHeld = this.getSessionSalt(agentName, sessionId);
        if (stillHeld !== null) {
          const key = this.#ctx.sessionKey(agentName, sessionId);
          this.#ctx.logger.error("session.salt.split", {
            agentName, sessionId, reason: "suspended_but_unerasable",
            impact: "this session stays SALTED even though the counterparty says it can never hold a salt, because the salt could not be erased and hashing unsalted now would leave half this transcript under each rule — verifiable by nobody. Expect the counterparty to refuse messages sent from here.",
            guidance: "Start a new session with this counterparty: the salt agreement runs at open, before anything is hashed. This one cannot be repaired — look for session.salt.discard.refused immediately above for why the salt could not be released.",
          });
          this.#hashedWithSalt.set(key, (this.#hashedWithSalt.get(key) ?? 0) + 1);
          const alg = CONTENT_HASH_ALGS.HMAC_SALT_V1;
          return { hash: contentHashFor(content, { alg, salt: stillHeld }), alg };
        }
      }
    }
    if (reason !== UNSALTED_REASONS.SESSION_TORN_DOWN) {
      /**
       * ⚠️ A COUNT, NOT A BIT — review pass 2, F1 (HIGH). It was a `Set`, and that made it ONE FLAG
       * PER SESSION for a fact that is per MESSAGE.
       *
       * The `sibling_send_in_flight` refusal path exists precisely when another connection is
       * mid-send with an unsalted hash it computed itself — and `sendContent` awaits a full relay
       * round trip before `#trackAwaitingAck` records anything. So: connection A hashes and sets the
       * flag; A enters that round trip, visible in no count; connection B hashes, sees A's claim,
       * refuses, and calls `abandonUnsaltedHash` — **deleting the flag A is still relying on.** The
       * frontier then reads entirely empty, a salt frame arriving in that window is adopted, and A's
       * message lands as leaf 0 hashed sha256 in a session that hashes everything after it under
       * HMAC.
       *
       * That is the split transcript this unit exists to prevent, through a window a relay round
       * trip wide. A count makes each in-flight hash hold its own claim.
       */
      const key = this.#ctx.sessionKey(agentName, sessionId);
      this.#hashedWithoutSalt.set(key, (this.#hashedWithoutSalt.get(key) ?? 0) + 1);
    }
    /**
     * NO `??` DEFAULT — review pass 2, F6. It read `reason ?? ADOPTION_CLOSED_LOCALLY`, which is the
     * shape the closed set was built to eliminate: a seventh return path forgetting its reason would
     * have been silently labelled *"you already hashed"* and inherited guidance about a frontier that
     * never moved. `#saltForHashing` returns a discriminated union now, so a null salt without a
     * reason does not compile.
     */
    this.announceUnsaltedOnce(agentName, sessionId, reason);
    const alg = CONTENT_HASH_ALGS.SHA256;
    return { hash: contentHashFor(content, { alg, salt: null }), alg };
  }
  /**
   * The salt to hash this session's next message under, waiting for a pending agreement if one is
   * genuinely in flight — B2b-2 constraints 2 and 5.
   *
   * Three exits, and the order matters:
   *
   *   1. We already hold one. No wait, ever.
   *   2. Adoption is closed — this session has hashed or leafed something already, so a salt could
   *      never be adopted now even if one arrived. Waiting would be waiting for a value we would
   *      then have to refuse.
   *   3. Nothing is pending. **This is the park-only case (constraint 5)**: the announcement hangs
   *      off `onPeerConnect`, an offline counterparty never connects, so no agreement was ever
   *      started. Waiting the full bound there pauses every message to an offline peer and falls
   *      back anyway — a stall bought for nothing.
   *
   * Only a session with an agreement actually in flight waits, and only until it settles or the
   * bound expires.
   */
  async saltForHashing(
    agentName: string,
    sessionId: string,
  ): Promise<{ salt: Uint8Array; reason?: undefined } | { salt: null; reason: UnsaltedReason }> {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const held = this.getSessionSalt(agentName, sessionId);
    if (held !== null) {
      /**
       * SUSPENDED BEATS HELD — `DOD-M15-SALTSPLIT-1`. The peer has said it can never hold a salt, so
       * hashing under ours produces a message it must refuse. We hold one and deliberately do not
       * use it.
       *
       * ⚠️ An earlier note here said `PEER_CLOSED_ADOPTION` "already carries exactly the right
       * guidance, so no new reason is needed and none is invented." That was right about not
       * inventing a reason and wrong about which one applies: the peer can suspend us for any of
       * four reasons, and the one hardcoded here asserted the most flattering of them. It now asks
       * the same mapping every other closed path asks (006-CRYPTO finding 2).
       */
      if (this.#saltSuspended.has(key)) {
        return { salt: null, reason: this.peerClosedReason(key) };
      }
      return { salt: held };
    }
    if (this.saltAdoptionClosed(agentName, sessionId).closed) {
      return { salt: null, reason: UNSALTED_REASONS.ADOPTION_CLOSED_LOCALLY };
    }

    const pending = this.#saltPending.get(key);
    if (pending === undefined) {
      // An agreement that already ENDED is not an agreement that never started. Only the second is
      // "your counterparty was not connected", and only an absent entry means it.
      const last = this.#saltLastOutcome.get(key);
      if (last !== undefined) return { salt: null, reason: this.reasonForOutcome(key, last) };
      return { salt: null, reason: UNSALTED_REASONS.NO_AGREEMENT_STARTED };
    }

    const settled = await pending.settled;
    if (settled === "agreed") {
      const agreed = this.getSessionSalt(agentName, sessionId);
      /**
       * A settled-`agreed` that reads back NULL is a READ failure, not a persist failure — pass 2,
       * F4. `persist_failed` has its own outcome now, so the only way to arrive here empty is
       * `#getSessionSalt` returning null after the salt was stored: a throwing read, or a
       * wrong-width row, with the cache evicted in the microtask between settle and resume. Rare —
       * and labelling it `our_persist_failed` sent the operator to look for a
       * `session.salt.persist.failed` line that will not be there.
       */
      return agreed !== null
        ? { salt: agreed }
        : { salt: null, reason: UNSALTED_REASONS.OUR_READ_FAILED };
    }
    if (settled === "announce_failed") {
      return { salt: null, reason: UNSALTED_REASONS.ANNOUNCE_FAILED };
    }
    if (settled === "persist_failed") {
      // Named separately from the timeout on purpose: the peer answered in time and OUR write
      // failed, so nothing about their build is involved and sending the operator there wastes them.
      return { salt: null, reason: UNSALTED_REASONS.OUR_PERSIST_FAILED };
    }
    if (settled === "closed") {
      /**
       * Two very different things reach `closed`, and only one of them is about the counterparty.
       *
       * `#handleSaltFrame`'s terminal branch — the peer told us it cannot adopt — is a settled
       * bilateral outcome and the session is fine. `#evictSessionCaches` — this session is being
       * torn down underneath us — is not: there is no session left to be unsalted, and a caller that
       * marks `#hashedWithoutSalt` for it re-populates a map whose eviction has already run
       * (review Finding 5). `#saltPending` is gone by the time we look, so the live node is what
       * distinguishes them.
       */
      return {
        salt: null,
        reason: this.#ctx.activeEntry(key) !== undefined
          ? UNSALTED_REASONS.PEER_CLOSED_ADOPTION
          : UNSALTED_REASONS.SESSION_TORN_DOWN,
      };
    }
    if (settled === "timeout") {
      /**
       * A DECISION, NOT A RETRY. Logged once, here, because this is the moment the session became
       * permanently unsalted — and an operator reading a later `session.content.unsalted` needs to
       * be able to find out WHY this session has no salt when their others do.
       */
      this.#ctx.logger.warn("session.salt.agreement.timeout", {
        agentName, sessionId, waitedMs: pending.boundMs,
        impact: "the counterparty did not answer the salt agreement in time, so this session is unsalted FOR ITS LIFE — the message is being sent now rather than held any longer. Nothing is lost and nothing is degraded relative to any shipped release.",
        // Review F4: `session.salt.persist.failed` reaches this same timeout by a completely
        // different route — the peer answered promptly and OUR OWN write failed, so we returned
        // before announcing and nothing came back. Omitting it sent that operator to ask their
        // counterparty about a version mismatch that was never involved.
        guidance: "Most often the counterparty is on a build that predates the salt agreement, in which case this is expected and permanent for this session — a newer one will agree normally. If you know they are on the same version, look for session.salt.persist.failed on THIS side first (our own write failing produces this same timeout), then session.salt.announce.failed on either side.",
      });
      return { salt: null, reason: UNSALTED_REASONS.AGREEMENT_TIMED_OUT };
    }
    return { salt: null, reason: UNSALTED_REASONS.AGREEMENT_TIMED_OUT };
  }
  /**
   * Decision #15's fallback announcement — ONCE per session, never per message.
   *
   * A warning that fires on every message of every unsalted session is not a signal, it is a reason
   * to build a filter; and the operator who filters it also filters the one session where it meant
   * something. Stated once, with what the session actually loses.
   */
  announceUnsaltedOnce(agentName: string, sessionId: string, reason: UnsaltedReason): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#unsaltedAnnounced.has(key)) return;
    this.#unsaltedAnnounced.add(key);
    this.#ctx.logger.info("session.content.unsalted", {
      agentName, sessionId,
      // The REASON is the field that makes this line diagnosable, and it was the missing one. The
      // impact is the same for all six; what to do about it is not.
      reason,
      impact: "this session hashes its messages the way every build before this feature did. Nothing is degraded relative to any shipped release and no message is affected — it only means a relay holding the hashes could confirm a guess at a short message in THIS conversation, which a salt would have prevented.",
      guidance: UNSALTED_GUIDANCE[reason],
    });
  }
  /**
   * Register that a salt agreement is IN FLIGHT for this session, so the first send waits for it.
   *
   * Called where we announce our own state — not at session creation. That distinction is
   * constraint 5: an agreement exists to be waited for only once a frame has actually gone out.
   */
  markSaltPending(agentName: string, sessionId: string, boundMs = SALT_AGREEMENT_WAIT_MS): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#saltPending.has(key)) return;
    let resolve: (v: "agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed") => void = () => { };
    const settled = new Promise<"agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed">((r) => { resolve = r; });
    const timer = setTimeout(() => this.settleSaltPending(agentName, sessionId, "timeout"), boundMs);
    // The daemon must be able to exit with this outstanding — a pending agreement is not a reason to
    // hold the process open.
    if (typeof timer.unref === "function") timer.unref();
    this.#saltPending.set(key, { settled, resolve, timer, boundMs });
  }
  /**
   * WHICH of the four terminal answers the peer actually gave — 006-CRYPTO finding 2.
   *
   * The default is the NON-ASSERTING reason, not the most common one. An unknown label means a build
   * we do not understand, and rendering that as "they had already hashed messages" states something
   * about a counterparty that may be untrue — which is what sends an operator to raise a
   * non-problem with them. The label is peer-supplied, so nothing outside the known set is repeated
   * back as our own diagnosis.
   *
   * A missing entry maps to the already-hashing case: `PEER_CLOSED_FIRST` and an absent label both
   * mean the peer is answering a closure of OURS, and `#saltForHashing` answers that with
   * `ADOPTION_CLOSED_LOCALLY` one branch earlier — this is only the fallback if it did not.
   */
  peerClosedReason(key: string): UnsaltedReason {
    const label = this.#saltPeerClosedLabel.get(key);
    if (label === undefined || label === SALT_ADOPTION_LABELS.PEER_CLOSED_FIRST) {
      return UNSALTED_REASONS.PEER_CLOSED_ADOPTION;
    }
    if (label === SALT_ADOPTION_LABELS.ALREADY_HASHING) return UNSALTED_REASONS.PEER_CLOSED_ADOPTION;
    if (label === SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE) return UNSALTED_REASONS.PEER_FRONTIER_UNREADABLE;
    if (label === SALT_ADOPTION_LABELS.EXCHANGE_STALLED) return UNSALTED_REASONS.PEER_EXCHANGE_STALLED;
    return UNSALTED_REASONS.PEER_CLOSED_UNSPECIFIED;
  }
  /** Resolve a pending agreement. Idempotent: the first outcome wins and the timer is cleared. */
  settleSaltPending(agentName: string, sessionId: string, outcome: "agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed"): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const pending = this.#saltPending.get(key);
    if (pending === undefined) return;
    this.#saltPending.delete(key);
    // `agreed` is not recorded: the salt itself is the record, and `#getSessionSalt` answers first.
    if (outcome !== "agreed") this.#saltLastOutcome.set(key, outcome);
    clearTimeout(pending.timer);
    pending.resolve(outcome);
  }
  /**
   * THIS SESSION'S UNSALTED HASH NEVER BECAME A MESSAGE — release the permanent closure it caused.
   *
   * ⚠️ REVIEW FINDING 3, and it is the opposite of the direction the flag was written to defend.
   * `#hashedWithoutSalt` closes adoption at hash time, because for a session's first message the
   * leaf is a network round trip away and every frontier count reads zero in between. Correct — but
   * `cello_send` has three paths that compute the hash and then produce NOTHING: a sibling send
   * holding the in-flight claim, the frontier moving under the send, and a non-durable send failure
   * whose bytes go to a queue with no production consumer.
   *
   * In all three the session was permanently unsalted for a message that exists nowhere: no leaf, no
   * wire, no copy at the peer. And B2b-2 made two of them MORE likely on a first message, because
   * the five-second wait widens the very window the frontier re-check is watching.
   *
   * Only safe because it is called on paths that provably sent nothing. It deliberately does NOT
   * clear `#unsaltedAnnounced`: the announcement was true when it fired and re-announcing on the
   * retry would be the per-message flood Decision #15 forbids.
   *
   * ─── THREE OTHER SITES HASH AND MAY SEND NOTHING, AND ARE EXEMPT ON PURPOSE (pass 2, F8) ──────
   *
   * `daemon.ts`'s one-shot rejection and away reply, and `document-delivery-transport.ts`'s frame
   * send, can all fail after hashing. None of them needs to abandon, and the reason is the same in
   * each: every one is a REPLY. The inbound message that triggered it has already been leafed on
   * this side, so `#saltAdoptionClosed` is already closed by the leaf count and would stay closed
   * whatever this flag said. Calling abandon there would be a no-op that looks like a guarantee.
   *
   * Written down rather than left to be re-derived: the next reader's first question is why the
   * list is three and not six.
   */
  abandonUnsaltedHash(agentName: string, sessionId: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const held = this.#hashedWithoutSalt.get(key) ?? 0;
    if (held === 0) return;
    // DECREMENT, never delete — F1. Deleting released a sibling's claim along with this one.
    if (held > 1) { this.#hashedWithoutSalt.set(key, held - 1); return; }
    this.#hashedWithoutSalt.delete(key);
    /**
     * INFO, not DEBUG — review pass 2, F3. `session.content.unsalted` has already told this operator
     * at INFO that the session is unsalted *"permanently… start a new session if you want the
     * protection."* That statement is now false, and a retraction logged below the level of the
     * claim it retracts is not a retraction. The announcement itself is deliberately NOT re-armed —
     * re-announcing on the retry is the per-message flood Decision #15 forbids.
     */
    this.#ctx.logger.info("session.content.unsalted.retracted", {
      agentName, sessionId,
      impact: "a hash computed unsalted never became a message — no leaf, nothing on the wire, no copy at the counterparty — so this session CAN still adopt a salt. An earlier session.content.unsalted line said the session was permanently unsalted; that no longer applies.",
    });
  }
  /**
   * PUBLIC read of a session's agreed salt — `DOD-M15-SEALWIRE-1` part B2a.
   *
   * `content-park.ts` runs a SECOND, independent content-hash verifier (the park signature does not
   * cover the envelope content, so it checks before `ingestReceivedContent` is ever reached), and it
   * hardcoded `sha256`. It needs the salt to verify a v3 envelope, and it is outside this class.
   *
   * Read-only and cache-backed, so exposing it adds no way to CHANGE the salt from outside — the
   * only writer remains `#persistSessionSalt`, behind the one-salt-per-session predicate.
   */
  /**
   * IS THIS SESSION ACTUALLY PROTECTED BY ITS SALT RIGHT NOW — pass 2, F3.
   *
   * Distinct from `getSessionContentSalt`, which is POSSESSION and is what the verifier needs: a
   * message parked before suspension was hashed under this salt and must still be checkable against
   * it, so that accessor must keep answering with the bytes.
   *
   * This one answers the OPERATOR's question, and it is a different question. A suspended session
   * holds a salt it will not use, so every hash it produces is `sha256` — reporting `contentSalted:
   * true` there is not a gap, it is an affirmatively false security claim on the surface whose own
   * comment reads *"a security property must not be inferable from a gap."* Same predicate
   * `#saltForHashing` uses, so the flag cannot drift from the behaviour it describes.
   */
  isContentSaltActive(agentName: string, sessionId: string): boolean {
    if (this.#saltSuspended.has(this.#ctx.sessionKey(agentName, sessionId))) return false;
    return this.getSessionSalt(agentName, sessionId) !== null;
  }
  /**
   * This session's agreed salt, or null. Reads the durable row through a cache, because Decision #8
   * persists it for exactly one reason: *"a restart silently splits the transcript"* if the lookup
   * misses and a fresh salt is minted.
   *
   * A read failure returns null WITH a log rather than throwing — except the bare `!this.#db` guard,
   * which is this file's convention at 60+ sites and only reachable during shutdown. Null means "we
   * hold no salt", which drives the agreement to offer a contribution — and against a peer that does
   * hold one that is a named, loud `salt_state_divergent` refusal. So the degraded path ends in a
   * diagnosis, not in a session that quietly hashes under the wrong value.
   *
   * ⚠️ THIS PARAGRAPH SPENT A UNIT STRANDED 180 LINES AWAY, directly above `contentHashForSession`
   * and followed by that method's own block — so a reader hovering the hash decision got prose about
   * salt read failures. Harmless and exactly the kind of drift that makes a comment stop being read.
   */
  getSessionSalt(agentName: string, sessionId: string): Uint8Array | null {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const cached = this.#sessionSalts.get(key);
    if (cached) return cached;
    if (!this.#db) return null;
    try {
      const row = this.#db
        .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#ctx.requireAgentId(agentName), sessionId) as { content_salt?: Uint8Array | null } | undefined;
      const stored = row?.content_salt;
      if (!stored || stored.length === 0) return null;
      /**
       * A WRONG-WIDTH ROW IS NOT A SALT — review F8.
       *
       * Any non-empty blob used to be accepted, so a truncated row became "our salt", the digests
       * then differed, and the operator was told *"one of you is running an older build — compare
       * versions with them"*: sent to their counterparty over corruption on their own disk. Refusing
       * it here makes this side hold NO salt, which re-offers a contribution and repairs.
       */
      if (stored.length !== SESSION_SALT_BYTES) {
        this.#ctx.logger.error("session.salt.read.failed", {
          agentName, sessionId, storedBytes: stored.length, expected: SESSION_SALT_BYTES,
          reason: "wrong_width",
          impact: "the stored salt is the wrong size, so it is not used; this session is treated as holding no salt and will re-agree one with the counterparty rather than comparing a corrupt value and blaming their build",
        });
        return null;
      }
      const salt = new Uint8Array(stored);
      this.#sessionSalts.set(key, salt);
      return salt;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.salt.read.failed", {
        agentName, sessionId, error: extractErrorMessage(err),
        impact: "this session is treated as holding no salt, so it will offer a fresh contribution; against a counterparty that still holds theirs the agreement refuses by name rather than hashing under a value only one side has",
      });
      return null;
    }
  }
  /**
   * Is this session past the point where a salt can be adopted? — Decision #8, part B2b-2.
   *
   * ⚠️ THE PREDICATE IS "HAS ANYTHING BEEN HASHED", NOT "IS THERE A LEAF" — review F5. A leaf is
   * APPENDED after `await sendContent(...)` returns, so a message can be hashed, put on the wire, and
   * still be invisible to `tree.size()`. Adopting inside that window makes leaf 0 unsalted and the
   * rest salted — the exact split this exists to prevent, with the guard green.
   *
   * ⚠️ HELD CONTENT COUNTS, AND MUST BE HYDRATED FIRST — review F6. `#ensureHeldRestored` is lazy and
   * is not called at session-node creation, so a revived session whose first inbound frame is the
   * salt frame reads a frontier that excludes durable `held_content` rows — rows already hashed
   * unsalted, which `#releaseHeld` will append moments later. Every other frontier reader in this
   * file hydrates first, for this reason. `release: false`, because a salt frame must never deliver
   * messages as a side effect.
   *
   * ⚠️ "CANNOT TELL" IS CLOSED, NOT OPEN. `#requireAgentId` throws for a retired agent, and inferring
   * "zero leaves" from a failure to count them is how a guard becomes a formality. The cost of
   * refusing is an unsalted session; the cost of permitting is a transcript neither rule can verify.
   */
  saltAdoptionClosed(agentName: string, sessionId: string): { closed: boolean; label: string; leafCount: number; why: string } {
    try {
      this.#ctx.ensureHeldRestored(agentName, sessionId, { release: false });
    } catch { /* hydration is best-effort; the counts below still refuse on their own failure */ }
    try {
      const key = this.#ctx.sessionKey(agentName, sessionId);
      const leaves = this.#ctx.getSessionTree(agentName, sessionId).size();
      const held = this.#ctx.heldContentFor(key)?.size ?? 0;
      const inFlight = this.#ctx.awaitingAck.get(key)?.size ?? 0;
      /**
       * ⚠️ THE HASH ITSELF COUNTS — B2b-2, and none of the three counts above can see it.
       *
       * Decision #8 closes adoption when content is HASHED. For a session's first message the leaf
       * lands after `sendContent` returns, a network round trip later; there is no held row and no
       * in-flight entry yet either. So between the hash and the leaf every count reads zero, and a
       * peer contribution arriving in that window would be adopted — leaving the message already on
       * the wire as the one unsalted leaf in a salted transcript.
       */
      const hashed = this.#hashedWithoutSalt.get(key) ?? 0;
      const total = leaves + held + inFlight + hashed;
      return {
        closed: total > 0,
        // The label crosses the WIRE, so it carries no counts and no error text — only which of the
        // two refusals this is. The counts stay in `why`, which stays local.
        label: SALT_ADOPTION_LABELS.ALREADY_HASHING,
        leafCount: total,
        why: `leaves=${leaves} held=${held} awaiting_ack=${inFlight} hashed=${hashed}`,
      };
    } catch (err: unknown) {
      return {
        closed: true,
        label: SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE,
        leafCount: -1,
        why: `frontier_unreadable: ${extractErrorMessage(err)}`,
      };
    }
  }
  /**
   * Persist the agreed salt, and DO NOT ANNOUNCE ONE WE FAILED TO STORE.
   *
   * The caller sends its fingerprint only if this returns true. A salt held in memory and not on
   * disk would confirm agreement to the counterparty and then be gone at the next restart — turning
   * a loud `salt_state_divergent` refusal, which is the whole point of Decision #10, into the silent
   * split it exists to prevent, one restart later.
   *
   * ⚠️ SECOND ORPHAN OF THE SAME KIND. This paragraph was stranded above `#saltAdoptionClosed` and
   * followed by that method's own block, exactly like the `#getSessionSalt` one re-homed in the
   * previous pass — which walked straight past this one sixty lines below it. Two in one file is not
   * coincidence: inserting a method between a doc block and its subject leaves no error, no lint,
   * and no test, so the drift is invisible until someone reads for it.
   */
  persistSessionSalt(agentName: string, sessionId: string, salt: Uint8Array): boolean {
    if (!this.#db) {
      // NOT a silent return — review F7. The other two persist failures each emit an event, so a
      // derive that could not store because the handle is closed was the ONE salt path producing no
      // record at all. Only reachable during shutdown, which is exactly when a lone unexplained
      // gap in the log is hardest to account for later.
      this.#ctx.logger.error("session.salt.persist.failed", {
        agentName, sessionId, reason: "db_closed",
        impact: "the salt was NOT stored and is not announced; the agreement stays open and re-runs on the next connect",
      });
      return false;
    }
    try {
      /**
       * ORDER MATTERS HERE, and getting it wrong cost three findings — review F3, F4, F7.
       *
       * The adoption guard used to run FIRST, above `!this.#db` and outside this `try`. That:
       *   - short-circuited the `salt_already_stored` discrimination below, so a session that DOES
       *     hold a valid salt was told it "stays unsalted FOR THE LIFE of the session" after a
       *     transient read failure — a refusal asserting something false about the row (F4);
       *   - put `getSessionTree`'s `#requireAgentId` throw outside the `try`, where it surfaced as
       *     *"the stream read failed"* instead of a named salt-persist failure (F7).
       *
       * So the row's own state is established first, and only a session with no salt at all reaches
       * the adoption question.
       */
      const existingRow = this.#db
        .prepare("SELECT length(content_salt) AS n FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#ctx.requireAgentId(agentName), sessionId) as { n: number | null } | undefined;
      if (existingRow?.n === SESSION_SALT_BYTES) {
        this.#ctx.logger.error("session.salt.persist.failed", {
          agentName, sessionId, reason: "salt_already_stored",
          impact: "this session already has a salt and it was NOT replaced — Decision #8 is one salt per session. Reaching here means a read failure made this side believe it had none; the stored salt is intact, nothing was announced, and the agreement re-runs against it on the next connect.",
        });
        return false;
      }
      const adoption = this.saltAdoptionClosed(agentName, sessionId);
      if (adoption.closed) {
        this.#ctx.logger.warn("session.salt.adoption.refused", {
          agentName, sessionId, reason: "already_hashing", leafCount: adoption.leafCount, frontier: adoption.why,
          impact: "this session has already hashed content under the unsalted rule, so the salt was NOT adopted — it stays unsalted FOR THE LIFE of the session. Adopting now would hash the rest of the conversation differently and leave a transcript that neither rule can verify end to end.",
          guidance: "Nothing is broken and no message was lost: an unsalted session is exactly as verifiable as every session before this feature existed. It only means a relay holding the hashes could confirm a guess at a short message in THIS conversation. If you want the protection, start a new session — the agreement runs at open, before anything is hashed.",
        });
        return false;
      }
      /**
       * THE ROW COUNT IS THE CHECK, and without it this method reported success for a write that
       * stored nothing.
       *
       * An `UPDATE` that matches no row does not throw — it returns `changes: 0`. So a session whose
       * row is missing (retired agent, a row that failed to write at creation, an id that does not
       * line up) took the success branch, cached the salt in memory, and announced our fingerprint
       * to the counterparty. Agreement confirmed, nothing on disk, and the failure surfaces at the
       * next restart as the divergence this whole design exists to make loud — except one restart
       * late and with both sides believing they had agreed.
       *
       * Found by a mutant that removed the caller's `if (!persisted) return`: the suite stayed green,
       * because nothing could produce a false from here.
       */
      /**
       * ONE SALT PER SESSION, ENFORCED AT THE WRITE — review F18.
       *
       * This `UPDATE` was unconditional, so it could replace an already-stored VALID salt. The path
       * is real: `#getSessionSalt` returns null on a transient read failure, which sends this side
       * down the derive path, which then overwrote the perfectly good salt on disk. The read error
       * was logged; the destruction of the durable value was not — and the read log actively said
       * the wrong thing, promising only that we would "offer a fresh contribution".
       *
       * The predicate has to allow ONE overwrite: a wrong-width blob is refused by `#getSessionSalt`
       * (F8) precisely so a corrupt row can be replaced rather than stranding the session forever.
       * So: write when there is nothing there, or when what is there is not a salt.
       */
      const written = this.#db
        .prepare(
          "UPDATE sessions SET content_salt = ? WHERE agent_id = ? AND session_id = ? " +
          "AND (content_salt IS NULL OR length(content_salt) <> ?)",
        )
        .run(Buffer.from(salt), this.#ctx.requireAgentId(agentName), sessionId, SESSION_SALT_BYTES);
      if (Number(written.changes) !== 1) {
        // WHICH of the two it was. "No row" is a broken session record; "a salt is already there" is
        // this guard doing its job, and telling an operator the row is missing when it is not would
        // send them to look at the wrong thing.
        // The `salt_already_stored` case is decided above now, before the adoption question, so
        // reaching here with a valid salt in the row is not possible. Re-read anyway rather than
        // assume: a wrong-width blob also fails the predicate and must not be reported as a missing
        // row, which would send the operator to look at session state for a corrupt value.
        const existing = this.#db
          .prepare("SELECT length(content_salt) AS n FROM sessions WHERE agent_id = ? AND session_id = ?")
          .get(this.#ctx.requireAgentId(agentName), sessionId) as { n: number | null } | undefined;
        const alreadyStored = existing?.n === SESSION_SALT_BYTES;
        this.#ctx.logger.error("session.salt.persist.failed", {
          agentName, sessionId, changes: Number(written.changes),
          reason: alreadyStored ? "salt_already_stored" : "no_session_row",
          impact: alreadyStored
            ? "this session already has a salt and it was NOT replaced — Decision #8 is one salt per session. Reaching here means a read failure made this side believe it had none; the stored salt is intact, nothing was announced, and the agreement re-runs against it on the next connect."
            : "the salt was NOT stored — no session row matched — so it is not announced either; the agreement stays open rather than being confirmed against a value that exists only in memory",
        });
        return false;
      }
      this.#sessionSalts.set(this.#ctx.sessionKey(agentName, sessionId), salt);
      return true;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.salt.persist.failed", {
        agentName, sessionId, error: extractErrorMessage(err),
        impact: "the salt was NOT stored, so it is not announced to the counterparty either; the agreement stays open rather than being confirmed against a value that would vanish at the next restart",
      });
      return false;
    }
  }
  /**
   * DROP AN UNSPENT SALT — `DOD-M15-SALTSPLIT-1`. The second writer of `content_salt`, and the only
   * one that clears it.
   *
   * Reached when the counterparty tells us it can never adopt a salt for this session. Keeping ours
   * would mean every message we send from here is refused by them with
   * `content_hash_salt_unavailable` — a conversation that dies while looking merely quiet, which is
   * the failure this exists to prevent.
   *
   * ⚠️ THE ADOPTION CHECK IS REPEATED HERE ON PURPOSE, not because the caller is untrusted.
   *
   * The caller has already computed `adoption`, so this looks redundant — and it is, for today's one
   * call site. It stays because the cost of a future caller getting it wrong is a transcript that no
   * single rule can verify: leaves hashed under a salt that has just been erased, with nothing
   * recording that they were. A guard whose failure mode is silent and permanent belongs next to the
   * destructive act, not only at the place that currently decides to perform it. Same reasoning that
   * made `placeOwnLeaf`'s authorship parameter required rather than optional.
   *
   * Returns true only if a salt was actually cleared.
   */
  /**
   * SUSPEND, don't destroy — `DOD-M15-SALTSPLIT-1`, the authorization argument. Returns true if a
   * salt is now suspended (or already was).
   *
   * This is the frame handler's entry point. It runs the same two refusals as the erase below —
   * a spent salt and one mid-flight are not ours to set aside either, because the messages already
   * hashed under them would become unverifiable the moment we stop using it — and where they do not
   * fire it records the suspension instead of doing anything irreversible.
   */
  suspendSalt(agentName: string, sessionId: string, correlationId?: string): boolean {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.getSessionSalt(agentName, sessionId) === null) return false;
    if (this.#saltSuspended.has(key)) return true;

    const inFlight = this.#hashedWithSalt.get(key) ?? 0;
    const adoption = this.saltAdoptionClosed(agentName, sessionId);
    if (inFlight > 0 || adoption.closed) {
      /**
       * SPENT, or mid-send. Suspending is not destructive, but it IS a split: content already hashed
       * under this salt stays hashed under it while everything after would be hashed the other way,
       * in one session, with nothing recording where the change happened. That is the one thing
       * Decision #8 forbids outright, so the salt keeps being used and the session stays honestly
       * broken rather than becoming dishonestly half-verifiable.
       */
      this.#ctx.logger.info("session.salt.suspend.refused", {
        agentName, sessionId, correlationId,
        reason: inFlight > 0 ? "salted_hash_in_flight" : adoption.label,
        ...(inFlight > 0 ? { inFlight } : { frontier: adoption.why }),
        impact: "the salt stays IN USE, because content in this session is already hashed under it and switching now would split the transcript — half verifiable by one rule, half by another. The counterparty cannot hold this salt, so it will keep refusing messages sent from here. See session.salt.split.",
      });
      return false;
    }

    this.#saltSuspended.add(key);
    this.#ctx.logger.info("session.salt.suspended", {
      agentName, sessionId, correlationId,
      impact: "the counterparty can never adopt a salt for this session, so this side has STOPPED USING its own — messages are hashed the way every build before content salting hashed them, and every message continues to be accepted. Nothing was hashed under it, so nothing is split.",
      guidance: "No action. The salt bytes are kept, not erased: if the counterparty was merely unable to read its own state for a moment, its next announcement carrying a matching fingerprint restores this session to salted automatically. The bytes are erased only when this session actually hashes a message unsalted, which is the point after which keeping them would re-salt the session at the next restart.",
    });
    return true;
  }
  /** Un-suspend: the peer answered with a fingerprint matching the salt we kept. */
  resumeSalt(agentName: string, sessionId: string, correlationId?: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (!this.#saltSuspended.has(key)) return;

    /**
     * ⚠️ REFUSE THE RESUME IF THIS SESSION HAS ALREADY HASHED UNSALTED — pass 2, F1 (HIGH).
     *
     * `#resumeSalt` deleted the mark unconditionally, and the reviewer produced the counter-example
     * in ONE process with no restart: suspend, the peer keeps talking so a leaf lands, we send `m1`
     * under `sha256`, the peer's frontier recovers and announces `fingerprint(S)`, we resume, and
     * `m2` goes out under `hmac`. Two rules, one session — and `session.salt.resumed` asserted
     * *"No message was hashed while suspended, so the transcript is uniform"* while it was happening.
     * **The code never checked the thing its own log line claimed**, which is this milestone's
     * signature defect committed inside the fix for it.
     *
     * `#unsaltedAnnounced` is exactly that fact and is already maintained, so the check costs a
     * lookup. Once it is set the salt can never be used again, so it is erased here rather than left
     * to be found by a later restart.
     */
    if (this.#unsaltedAnnounced.has(key)) {
      this.#ctx.logger.warn("session.salt.resume.refused", {
        agentName, sessionId, correlationId,
        impact: "the counterparty now confirms a salt this side is holding, but this session has ALREADY hashed at least one message unsalted. Resuming would put half the transcript under each rule, which no single rule can verify — so the session stays unsalted for its whole life and the salt is released.",
        guidance: "Nothing to do here, and nothing is lost: the transcript stays uniform and every message is intact. If you want the salt protection with this counterparty, start a new session — the agreement runs at open, before anything is hashed.",
      });
      this.#saltSuspended.delete(key);
      this.discardUnspentSalt(agentName, sessionId, correlationId);
      return;
    }

    this.#saltSuspended.delete(key);
    /**
     * THE RECOVERY THE ERASE MADE IMPOSSIBLE. Keeping the bytes is what allows this line to exist:
     * the peer's earlier terminal frame was wrong (a frontier it could not read for a moment), it can
     * read again, and the fingerprints match — so the session resumes salted with nothing lost. An
     * erased salt cannot be re-derived from one side.
     */
    this.#ctx.logger.info("session.salt.resumed", {
      agentName, sessionId, correlationId,
      impact: "the counterparty now confirms the same salt this side kept, so this session is salted again. It was suspended earlier because the counterparty reported it could never hold one; that has resolved. No message was hashed while suspended, so the transcript is uniform.",
    });
  }
  discardUnspentSalt(agentName: string, sessionId: string, correlationId?: string): boolean {
    const held = this.getSessionSalt(agentName, sessionId);
    if (held === null) return false;

    /**
     * ⚠️ IN-FLIGHT FIRST — `DOD-M15-SALTSPLIT-1` review HIGH-2. `#saltAdoptionClosed` cannot see a
     * hash that has been computed under the salt but has not yet become a leaf, a hold or an
     * awaiting-ack entry, and that gap is a full relay round trip wide.
     */
    /**
     * ⚠️ MEASURED UNREACHABLE FROM TODAY'S CALLERS, AND KEPT ANYWAY — pass 2 test-teeth, survivor 2.
     *
     * Deleting this block leaves the whole salt suite GREEN. That is the definition this unit has
     * used all along for *"not a guard, a comment that happens to execute"*, so it is labelled rather
     * than quietly left to look load-bearing. `#suspendSalt` refuses on `inFlight > 0` before a
     * session can ever be marked, and both callers of this method require the mark — so the deferred
     * erase cannot observe a non-zero count.
     *
     * It stays for one reason: **it sits at an irreversible write.** The earlier instance of this
     * question in this same unit was resolved by making the guard the actual decision-maker, and that
     * option does not exist here — `#suspendSalt` genuinely must refuse early, so the duplication is
     * structural rather than a mistake about where responsibility lives. For a destructive act, the
     * safe direction is to keep a check that cannot fire over removing one that turns out it could.
     *
     * What must NOT happen is claiming it as coverage. It is not tested and it is not testable from
     * outside; if a third caller ever reaches this method without the suspension mark, this becomes
     * reachable and needs a test in the same commit.
     */
    const inFlight = this.#hashedWithSalt.get(this.#ctx.sessionKey(agentName, sessionId)) ?? 0;
    if (inFlight > 0) {
      this.#ctx.logger.info("session.salt.discard.refused", {
        agentName, sessionId, correlationId, reason: "salted_hash_in_flight", inFlight,
        impact: "the salt was NOT dropped: a message has already been hashed under it and is mid-send, so erasing it now would put a hash on the wire that nothing — including this daemon — could ever recompute. The session stays salted and the counterparty, which cannot adopt, will refuse what is in flight.",
      });
      return false;
    }

    const adoption = this.saltAdoptionClosed(agentName, sessionId);
    if (adoption.closed) {
      /**
       * SPENT. Something is already hashed under this salt, so it is not ours to drop.
       *
       * INFO, not ERROR, and the level is a judgement rather than a downgrade: this is the guard
       * doing its job correctly, and the FAILURE it accompanies — the session is split and unusable
       * — is reported by `session.salt.split` at ERROR from the caller that has the operator-facing
       * detail. Two ERRORs for one condition trains people to read neither. This line stays so the
       * refusal itself is correlatable when someone asks why the salt is still on disk.
       */
      this.#ctx.logger.info("session.salt.discard.refused", {
        agentName, sessionId, correlationId, reason: adoption.label, frontier: adoption.why,
        impact: "the salt was NOT dropped, because content in this session is already hashed under it and erasing it would leave a transcript no single rule can verify. The session stays split: the counterparty holds no salt and refuses everything sent from here.",
      });
      return false;
    }

    if (!this.#db) {
      this.#ctx.logger.error("session.salt.discard.failed", {
        agentName, sessionId, correlationId, reason: "db_closed",
        impact: "the salt is still stored, so after the next restart this side hashes salted while the counterparty refuses every message. Only reachable during shutdown; the agreement re-runs on the next connect, which discards it then.",
      });
      return false;
    }

    try {
      const cleared = this.#db
        .prepare("UPDATE sessions SET content_salt = NULL WHERE agent_id = ? AND session_id = ?")
        .run(this.#ctx.requireAgentId(agentName), sessionId);
      if (Number(cleared.changes) !== 1) {
        // The row-count check that `#persistSessionSalt` learned the hard way: an UPDATE matching no
        // row does not throw, and reporting success here would leave the durable salt in place while
        // the cache said otherwise — salted after a restart, unsalted before one.
        this.#ctx.logger.error("session.salt.discard.failed", {
          agentName, sessionId, correlationId, changes: Number(cleared.changes), reason: "no_session_row",
          impact: "the stored salt was NOT cleared, so this side hashes unsalted now and salted again after a restart — the transcript splits at the restart rather than here",
        });
        return false;
      }
    } catch (err: unknown) {
      this.#ctx.logger.error("session.salt.discard.failed", {
        agentName, sessionId, correlationId, error: extractErrorMessage(err),
        impact: "the stored salt was NOT cleared, so this side hashes unsalted now and salted again after a restart — the transcript splits at the restart rather than here",
      });
      return false;
    }

    /**
     * CACHE AFTER ROW, and both or the session is worse off than before.
     *
     * `#saltForHashing` reads the cache on its first line and never consults the row, so clearing
     * one without the other produces a session that hashes one way in this process and the other way
     * in the next — the split transcript, arriving at a daemon restart instead of at a frame.
     */
    this.#sessionSalts.delete(this.#ctx.sessionKey(agentName, sessionId));
    /**
     * ⚠️ THE MARK GOES WITH THE BYTES — pass 2, F5. Leaving the key in `#saltSuspended` after a
     * successful erase means a LATER agreed salt is silently never used: `#persistSessionSalt`'s
     * predicate explicitly allows a write when the column is NULL, and `abandonUnsaltedHash` can
     * re-open adoption — so the session would log `session.salt.agreed`, surface as protected, and
     * hash `sha256` for the rest of its life. A stale suppression is indistinguishable from a
     * feature that does not work.
     */
    this.#saltSuspended.delete(this.#ctx.sessionKey(agentName, sessionId));
    this.#ctx.logger.info("session.salt.discarded", {
      agentName, sessionId, correlationId,
      impact: "the counterparty can never adopt a salt for this session, so this side dropped its own before spending it. Both sides now hash unsalted — exactly as verifiable as every session shipped before content salting existed, and every message continues to be accepted. Nothing was hashed under the discarded salt.",
    });
    return true;
  }
  /** Apply one inbound salt-agreement frame. The verdict is the pure function's; this executes it. */
  async handleSaltFrame(
    agentName: string,
    sessionId: string,
    frame: SaltAgreementFrame,
    correlationId?: string,
  ): Promise<void> {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const peerHalfHex = frame.contribution ? Buffer.from(frame.contribution).toString("hex") : null;
    const peerFingerprintHex = frame.fingerprint ? Buffer.from(frame.fingerprint).toString("hex") : null;
    // WHY the peer closed, kept for the operator-facing reason — 006-CRYPTO finding 2. Recorded here
    // rather than in the `adoption_closed` handler because that action fires for OUR closure too,
    // and only the frame says what the PEER said.
    if (typeof frame.adoptionClosed === "string") {
      this.#saltPeerClosedLabel.set(key, frame.adoptionClosed);
    }
    const adoption = this.saltAdoptionClosed(agentName, sessionId);
    const action = onPeerSaltFrame({
      ...this.saltState(agentName, sessionId),
      // Review F2: the frontier is what decides whether THIS side can still adopt, and only the
      // caller can count it. Without this the state machine derives, the persist refuses, and the
      // peer never learns — which is how the two sides end up on opposite verdicts.
      ownAdoption: adoption.closed
        ? { closed: true, label: adoption.label, why: adoption.why }
        : { closed: false },
      // Keyed on the peer's BYTES, not on a repair counter: a genuinely NEW half from the peer must
      // still get our contribution back, and only an identical re-offer is the loop (review F14).
      alreadyRepairedAgainstPeerHalf: peerHalfHex !== null && this.#saltRepairedAgainst.get(key) === peerHalfHex,
      // The mirror, 006-CRYPTO finding 1: without it a saltless side answers a latched holder's
      // fingerprint forever. Same keying rule — an identical re-offer is the loop, a new one is not.
      alreadyRepairedAgainstPeerFingerprint:
        peerFingerprintHex !== null && this.#saltRepairedAgainstFingerprint.get(key) === peerFingerprintHex,
      frame,
    });
    if (action.action === "confirmed") {
      // DOD-M15-SALTSPLIT-1: the peer confirms the salt we KEPT while suspended — resume before logging
      // agreement, so a resumed session is never reported as agreed while still suspended.
      this.resumeSalt(agentName, sessionId, correlationId);
      this.#ctx.logger.info("session.salt.agreed", {
        agentName, sessionId, correlationId, via: "fingerprint_match",
      });
      // B2b-2: release a first send that is waiting on this agreement. Both `confirmed` and
      // `derive_and_announce` end with a salt this side can hash under, so both settle the wait.
      this.settleSaltPending(agentName, sessionId, "agreed");
      return;
    }
    if (action.action === "derive_and_announce") {
      /**
       * ⚠️ I DEFENDED THE OPPOSITE OF THIS TWICE, AND BOTH DEFENCES WERE WRONG. The code now does
       * what the "surviving mutant" did; recording that rather than quietly switching, because the
       * reasoning is the useful part.
       *
       * A failed persist used to fall through with no settle, so a waiting first send sat out the
       * FULL FIVE SECONDS and was then told, by the timeout path, to go and check its counterparty's
       * build version — for a fault that was this machine's own disk.
       *
       * Defence #1 said releasing the waiter "would hand it a null it would hash unsalted under."
       * True, and not a consequence: that is exactly what the timeout does. Defence #2 said the
       * remaining bound gave a repair a chance to land — and the review showed that essentially
       * cannot fire. This branch returns BEFORE the announce, so nothing goes out and nothing comes
       * back; all five of `#sendSaltFrame`'s callers are triggered by a peer connect or an inbound
       * frame. Only a counterparty reconnect inside those seconds could do it.
       *
       * So the real trade was a rare reconnect-within-five-seconds repair against five seconds of
       * visible latency on the operator's first message AND a diagnosis pointing at the wrong
       * machine. The repair loses. Settle immediately under its own name, so `#saltForHashing` can
       * say *our own write failed* instead of *they did not answer*.
       */
      if (!this.persistSessionSalt(agentName, sessionId, action.salt)) {
        this.settleSaltPending(agentName, sessionId, "persist_failed");
        return;
      }
      this.#ctx.logger.info("session.salt.agreed", {
        agentName, sessionId, correlationId, via: "derived",
      });
      this.settleSaltPending(agentName, sessionId, "agreed");
      // `void`, not `await` — review F10. This runs inside the INBOUND content-stream handler, so
      // awaiting an outbound `newStream` here lets a stalled dial hold up the stream we are reading.
      // The connect-side call is `void`-ed for the same reason and this is now consistent with it.
      void this.#ctx.sendSaltFrame(agentName, sessionId, correlationId);
      return;
    }
    if (action.action === "adoption_closed") {
      // B2b-2: terminal means there is nothing left to wait for. A send still holding on the bound
      // would otherwise sit out the full five seconds for an answer that has already arrived and
      // said no — the slowest possible way to reach a decision both sides already agree on.
      this.settleSaltPending(agentName, sessionId, "closed");
      /**
       * Terminal, and NOT a freeze — review F1/F2. Both sides stay unsalted, which is exactly as
       * verifiable as every session shipped before the salt existed; the thing that was broken was
       * them disagreeing about it silently.
       *
       * WHICH SIDE DECLINED decides the level, and it is not decoration.
       *
       * If WE closed, an operator has lost a protection they could otherwise have had, and there is
       * something they can do about it — that is a WARN under `session.salt.adoption.refused`, which
       * keeps meaning what it has always meant.
       *
       * If we are merely LEARNING the peer closed, nothing about this machine is at fault and there
       * is nothing for its operator to do. Logging that at WARN would fire on the innocent side of
       * every such session and train them to ignore the name.
       */
      /**
       * DOD-M15-SALTSPLIT-1 — ONE PLACE DECIDES WHETHER THE SALT GOES, and it is not here.
       *
       * ⚠️ THIS CALL WAS INSIDE THE `else` BELOW, AND THE REVERT TEST CAUGHT IT.
       *
       * Guarding it by `adoption.closed` here meant `#discardUnspentSalt`'s own adoption check could
       * never be reached, so deleting that check left all three tests GREEN — the survivor. A guard
       * nothing can redden is not a guard; it is a comment that happens to execute, which is the
       * shape this milestone keeps finding.
       *
       * Called unconditionally now. The method owns the spent/unspent decision, both outcomes run
       * through it, and deleting its check reddens the spent test immediately. That also removes the
       * duplicated condition: two places deciding the same thing is one place being wrong later.
       */
      /**
       * The return is CONSUMED, not decorative — review LOW-5. `true` means a salt was actually
       * cleared, which settles the question below without a second read; `false` is ambiguous (we
       * held none, or we refused to drop one), so that case still asks.
       */
      const suspended = this.suspendSalt(agentName, sessionId, correlationId);
      /**
       * "Still holds a salt it is USING" — suspension is what settles it, not possession. A suspended
       * session keeps the bytes on disk deliberately, and reporting that as an unrecoverable split
       * would fire the ERROR below on the one case that recovers by itself.
       */
      const stillHoldsSalt = !suspended && this.getSessionSalt(agentName, sessionId) !== null;

      const shared = {
        agentName, sessionId, correlationId, detail: action.detail,
        /**
         * ⚠️ *"no message is affected"* IS FALSE WHEN WE ARE STILL HOLDING A SALT — review MEDIUM-4,
         * second instance. The sentence was written for a session where neither side ever adopted
         * one, and it stayed attached to a branch that now also covers the case where this side
         * kept a spent salt and every message it sends is about to be refused. Two log lines from
         * one event contradicting each other is worse than either alone.
         */
        impact: stillHoldsSalt
          ? "the counterparty will not use a content salt, and this side is still holding one it cannot drop — see session.salt.split on the next line for what that costs and what to do about it."
          : "neither side will use a content salt for this session, and both now know it. Messages are hashed the way every build before this feature hashed them — nothing is degraded relative to any shipped release, and no message is affected.",
      };
      if (adoption.closed) {
        /**
         * ⚠️ TWO REFUSALS, TWO DIFFERENT THINGS TO DO — and this used to report both as
         * `already_hashing`.
         *
         * A session that has already sent messages is the feature working: the fix is a new session,
         * and it will work. A frontier this side could not READ is local storage trouble: a new
         * session will refuse in exactly the same way, so sending the operator to open one is
         * sending them somewhere that cannot help. `frontier` carries the counts (or the error) so
         * the two are separable from the log alone.
         */
        const unreadable = adoption.label === SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE;
        this.#ctx.logger.warn("session.salt.adoption.refused", {
          ...shared,
          reason: adoption.label,
          leafCount: adoption.leafCount,
          frontier: adoption.why,
          guidance: unreadable
            ? "This side could not read its own message frontier, so it refused the salt rather than risk hashing half the session one way and half the other. Starting a new session will NOT help — it will refuse the same way. Look for session.content.held.restore.failed or other storage errors around this line; the conversation still works and every message is intact, it is just unsalted."
            : "Nothing is broken and no message was lost: an unsalted session is exactly as verifiable as every session before this feature existed. It only means a relay holding the hashes could confirm a guess at a short message in THIS conversation. If you want the protection, start a new session — the agreement runs at open, before anything is hashed.",
        });
      } else {
        /**
         * DOD-M15-SALTSPLIT-1 — CARRY OUT THE CLAIM ABOVE INSTEAD OF ONLY STATING IT.
         *
         * `shared.impact` says *"neither side will use a content salt for this session, and both now
         * know it."* Nothing made that true: a salt already agreed on this side stayed on disk and in
         * the cache, and `#saltForHashing` returns it before it ever looks at adoption. Our adoption
         * is still open here, so nothing has been hashed under it and dropping it is free.
         *
         * Ordering matters — discard BEFORE the log, so the line cannot claim an outcome that the
         * write then failed to produce.
         */
        this.#ctx.logger.info("session.salt.adoption.closed", shared);
      }

      /**
       * ⚠️ OUTSIDE THE ADOPTION BRANCH — pass 2, F4. This used to live inside `if (adoption.closed)`,
       * so the one case that needed it most never got it: suspension refused for
       * `salted_hash_in_flight` while adoption is still OPEN leaves us holding a salt the peer can
       * never accept, and it took the `else` path. Measured on that exact scenario:
       * `suspend.refused = 1`, `adoption.closed = 1`, **`split = 0`** — while two other log lines
       * told the operator to *"see session.salt.split on the next line"*, a line that was never
       * written. Guidance pointing at an event that does not fire is worse than no guidance: it
       * spends the reader's trust and their time.
       *
       * The condition was always `stillHoldsSalt`; only its placement disagreed.
       *
       * ─── What this event means, moved here with the code it describes ─────────────────────────
       *
       * We hold a salt AND the peer has told us it can never hold one. Either our frontier closed
       * with the salt already spent, or a salted hash is mid-flight — both mean the salt cannot be
       * released, so the peer will refuse every message we send with `content_hash_salt_unavailable`.
       *
       * `session.salt.adoption.refused` may fire alongside, saying *"nothing is degraded relative to
       * any shipped release, and no message is affected"* — true for the ordinary refusal and FALSE
       * here, at the exact moment every message stops being accepted. Hence its own event at ERROR
       * rather than a tightened sentence on that one: an operator filtering for the refusal is
       * looking at a benign condition, and this is not it.
       */
      if (stillHoldsSalt) {
          /**
           * ⚠️ TWO REASONS REACH `adoption.closed`, AND ONLY ONE IS ABOUT CONTENT — review MEDIUM-4.
           *
           * This fired for both with a single impact asserting *"content here is already hashed
           * under a salt"*. For `frontier_unreadable` that is a claim about content made from a
           * database read that FAILED — we do not know what was hashed; that is the whole condition.
           *
           * The WARN twenty lines above was explicitly corrected for this exact collapse — its
           * comment reads *"TWO REFUSALS, TWO DIFFERENT THINGS TO DO — and this used to report both
           * as `already_hashing`"* — and I reintroduced it one severity level up, with the guidance
           * that WARN was fixed to stop giving. Branching on the label the way it already does.
           */
          const unreadable = adoption.label === SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE;
          this.#ctx.logger.error("session.salt.split", {
            agentName, sessionId, correlationId, reason: adoption.label, frontier: adoption.why,
            impact: unreadable
              ? "this side holds a salt, the counterparty can never hold one, and this side could NOT read its own message frontier — so whether anything has been hashed under that salt is unknown. The salt is kept rather than dropped, because dropping one that HAS been spent leaves a transcript no single rule can verify. Until the read succeeds, expect the counterparty to refuse messages sent from here."
              : "this session cannot continue. Content here is already hashed under a salt the counterparty can never hold, so they refuse every message sent from this side — the conversation looks quiet rather than broken, and the session can never be sealed because the two transcripts no longer agree on a leaf.",
            guidance: unreadable
              ? "Do NOT start a new session yet — it would refuse in exactly the same way, because the fault is this side's storage rather than this conversation. Look for session.content.held.restore.failed or other storage errors around this line. Once the frontier reads again, this resolves to either an ordinary salted session or the split case, and the log will say which."
              : "Start a new session with this counterparty: the salt agreement runs at open, before anything is hashed, so a fresh session agrees or declines cleanly on both sides. This one cannot be repaired — the salt cannot be dropped without leaving a transcript no single rule can verify, and it cannot be shared with a peer that has already closed adoption.",
          });
        }
      if (action.announce) {
        void this.#ctx.sendSaltFrame(agentName, sessionId, correlationId, action.announce);
      }
      return;
    }
    if (action.action === "repair") {
      /**
       * THE REPAIR — review F1. The two sides are out of step and CAN converge, so re-send our half
       * rather than destroying the session.
       *
       * At INFO because it is a real event an operator may need to correlate with a
       * `session.salt.announce.failed` or `session.salt.persist.failed` on either machine, and
       * because a session that repairs REPEATEDLY is a signal even though each repair is benign.
       */
      this.#ctx.logger.info("session.salt.repair", {
        agentName, sessionId, correlationId, detail: action.detail,
        answeredWith: action.frame.contribution ? "contribution" : "fingerprint",
      });
      // Recorded ONLY for a repair that sent our half, because that is the one a second identical
      // offer must not repeat (review F14).
      if (peerHalfHex && action.frame.contribution) this.#saltRepairedAgainst.set(key, peerHalfHex);
      // AND THE MIRROR (006-CRYPTO finding 1): we answered the peer's FINGERPRINT with our half. An
      // earlier note here said recording this "says nothing, that branch is already terminal for the
      // peer" — it is terminal only for a peer that HOLDS a salt, and the loop is the case where we
      // do not. A second identical fingerprint now closes adoption instead of repairing again.
      if (peerFingerprintHex && action.frame.contribution) {
        this.#saltRepairedAgainstFingerprint.set(key, peerFingerprintHex);
      }
      void this.#ctx.sendSaltFrame(agentName, sessionId, correlationId, action.frame);
      return;
    }
    // `detail` is the primitive's own sentence wherever the primitive produced it — never a code of
    // ours substituted for it (Invariant 2). `guidance` is what the operator can DO, and it comes
    // from the total map so a reason can never reach a log without one.
    this.#ctx.logger.error("session.salt.disagreement", {
      agentName, sessionId, correlationId,
      reason: action.reason,
      detail: action.detail,
      guidance: SALT_FREEZE_GUIDANCE[action.reason],
    });
    /**
     * TELL THE PEER BEFORE TEARING DOWN — review F1's mirror.
     *
     * Only the fingerprint mismatch carries a notice, and only it can: the peer holds everything
     * needed to run the identical comparison and has simply not been given our side of it. Without
     * this the session stops answering and the far operator gets no reason at all, while ours gets a
     * full explanation — Decision #10 asks for BOTH sides to refuse by name.
     *
     * Awaited, unlike the other sends, because `destroySessionNode` on the next line takes the node
     * away and an un-awaited write would race its own transport. A failure is already handled
     * inside — the refusal here has happened either way.
     */
    if (action.notifyPeer) {
      await this.#ctx.sendSaltFrame(agentName, sessionId, correlationId, action.notifyPeer);
    }
    await this.#ctx.freezeSession(agentName, sessionId, action.reason, {
      event: "session.salt.frozen",
      observation: `the salt agreement could not be completed with this counterparty: ${action.detail}`,
      impact: "the session was stopped rather than left to hash under a value the two sides do not share; no message was lost and the transcript is unaffected — only a NEW session moves this forward",
      reviveReason: `session_frozen_${action.reason}`,
      // The operator-facing sentence comes from the TOTAL guidance map, so a reason can never reach
      // this refusal without one — and it is what stops a salt disagreement being reported to them
      // as their counterparty failing a key check.
      reviveGuidance: SALT_FREEZE_GUIDANCE[action.reason],
    }, correlationId);
  }

  /**
   * Forget every salt fact this module holds for one session.
   *
   * ⚠️ ELEVEN MAPS BEHIND ONE CALL, and that is the point. These were eleven of the twenty-four
   * per-session containers the manager's cache eviction cleared by hand — so forgetting a session
   * meant knowing every map that might hold a piece of it, and adding a twelfth meant remembering to
   * add a twelfth delete. Missing one leaves a per-session entry alive for the life of the process.
   * The list of what to forget now lives beside the code that fills them.
   */
  evictSession(agentName: string, sessionId: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    this.#saltContributions.delete(key);
    this.#sessionSalts.delete(key);
    this.#saltRepairedAgainst.delete(key);
    this.#saltRepairedAgainstFingerprint.delete(key);
    this.#saltPeerClosedLabel.delete(key);
    this.#hashedWithoutSalt.delete(key);
    this.#hashedWithSalt.delete(key);
    this.#saltSuspended.delete(key);
    this.#unsaltedAnnounced.delete(key);
    this.#saltLastOutcome.delete(key);
  }

  /**
   * The pair the agreement reasons over: our salt, and the half that goes with it.
   *
   * Minting is deliberate and conditional. With NO salt we are certain to need a half — to offer, or
   * to derive with — so minting here is what makes the exchange work at all. WITH a salt we must
   * never mint; see `#ownSaltHalf`.
   */
  saltState(agentName: string, sessionId: string): { ownSalt: Uint8Array | null; ownContribution: Uint8Array | null } {
    const ownSalt = this.getSessionSalt(agentName, sessionId);
    return {
      ownSalt,
      ownContribution: ownSalt
        ? this.ownSaltHalf(agentName, sessionId)
        : this.saltContributionFor(agentName, sessionId),
    };
  }
  /**
   * ONE mapping from a settled outcome to the operator-facing reason, so the send that WAITED and the
   * send that arrived afterwards cannot disagree about what happened.
   */
  reasonForOutcome(
    key: string,
    outcome: "timeout" | "closed" | "persist_failed" | "announce_failed",
  ): UnsaltedReason {
    if (outcome === "announce_failed") return UNSALTED_REASONS.ANNOUNCE_FAILED;
    if (outcome === "persist_failed") return UNSALTED_REASONS.OUR_PERSIST_FAILED;
    if (outcome === "closed") return this.peerClosedReason(key);
    return UNSALTED_REASONS.AGREEMENT_TIMED_OUT;
  }
}
