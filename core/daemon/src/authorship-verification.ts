/**
 * CELLO Daemon — WHO SENT THIS, AND DID THEY SEE WHAT THEY CLAIM
 *
 * Split out of `session-node-manager.ts` by 036-GODFILE, Part 1. Two questions about one signed
 * blob: did this really come from this conversation's counterparty, and is what they say they saw
 * actually what we sent. Everything is moved verbatim — the comments are the asset and several of
 * them record a defect that came back once already.
 *
 * ⚠️ THE ORDER OF THE CHECKS IS ITSELF A SECURITY PROPERTY — decode → signature → signer → what the
 * proof is about. Everything after the signer answers `unusable`, which refuses the message and
 * leaves the session alive; signature and signer answer `refuted`, which FREEZES it. A check that
 * can answer before the signature is verified hands a peer a switch for choosing the softer
 * outcome. Do not reorder these, and do not add a cheap early check above the signature.
 *
 * ⚠️ THIS CLASS OWNS ITS OWN STATE, which is what made it a seam rather than a split.
 * `#receivedFromCounterparty` and `#lastFromCounterparty` are read and written nowhere else in the
 * daemon, so they moved with the code that maintains them. Everything else it needs arrives through
 * `AuthorshipContext` — a narrow, explicit list. No field of the manager was widened to make this
 * possible, and the manager is not passed in as a whole.
 */
import type { Logger, SessionRecord } from "./types.js";
import type { SessionTree } from "./session-tree.js";
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { verify } from "@cello-protocol/crypto";
import { pubkeyMatchesHex } from "./park-envelope.js";
import {
  type AuthorshipVerdict,
  AUTHORSHIP_CONTENT_HASH_MISMATCH,
  AUTHORSHIP_SESSION_MISMATCH,
  AUTHORSHIP_SELF_CHAIN_MISMATCH,
  AUTHORSHIP_ACK_HASH_MISMATCH,
  AUTHORSHIP_ACK_HASH_UNKNOWN,
  SELF_CHAIN_MEMORY,
  bytesEqual,
} from "./session-node-types.js";

/**
 * Everything the verifier needs from the manager, stated explicitly rather than handed the manager
 * itself. If this list ever grows long, that is the signal the seam has moved — not a reason to
 * widen it.
 */
export interface AuthorshipContext {
  readonly logger: Logger;
  sessionKey(agentName: string, sessionId: string): string;
  getSessionRecord(agentName: string, sessionId: string): SessionRecord | null;
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  isSessionDiverged(agentName: string, sessionId: string): boolean;
  sessionGenesisPrevRoot(agentName: string, sessionId: string): Uint8Array | undefined;
  /** The relay's session id for this session, when a live node holds one. */
  relaySessionIdBytes(agentName: string, sessionId: string): Uint8Array | undefined;
  /**
   * Content received and verified but not yet appended, because it sits behind an ordering gap.
   *
   * ⚠️ RETURNS THE MAP, not a flattened list, and that is deliberate: the call site's expression
   * (`[...heldHere.values()].some(...)`) moves across unchanged. Handing back a pre-computed array
   * of hashes would read as a tidy-up and would be a behaviour change wearing a refactor's clothes.
   */
  heldContentFor(agentName: string, sessionId: string): ReadonlyMap<number, { contentHashHex: string }> | undefined;
}

export class AuthorshipVerifier {
  readonly #ctx: AuthorshipContext;

  constructor(ctx: AuthorshipContext) {
    this.#ctx = ctx;
  }

/**
   * Every content hash accepted from the counterparty on a session, so a link to one of THEIR
   * earlier messages can be told apart from a link to something they never sent.
   *
   * ⚠️ BOUNDED, because it is fed by a peer. A conversation must not cost unbounded memory because
   * the other side kept talking: the oldest entries are dropped past the cap, and a link older than
   * that is refused. That is the right way round — the cap makes the check STRICTER as it bites,
   * never looser.
   */
  readonly #receivedFromCounterparty = new Map<string, Set<string>>();

/** The MOST RECENT of those, which is what an honest next message links to. */
  readonly #lastFromCounterparty = new Map<string, Uint8Array>();

/**
   * `DOD-M15-AUTHORSHIP-ABSENT-1` — DID THIS SENDER PROVE THEY WROTE THIS MESSAGE?
   *
   * The one place that answers it, for both callers, so "checked" cannot mean two different things
   * in two places. It takes the signature as an ARGUMENT rather than digging it out of a structure,
   * which is the whole of the fix: the signature used to be read only from `structure2_cbor` — the
   * RELAY's record — so a receiver could not check authorship without a relay record, and refusing
   * on its absence would have made the relay a precondition for reading mail. The content frame now
   * carries the signature beside the bytes it signs, exactly as `hash_submit` always has, and this
   * method does not care which of the two handed it over.
   *
   * It VERIFIES and it does not LOG. The severity of each verdict differs by caller — the content
   * frame refuses an `unusable`, the park path shrugs at one — and a method that logged its own
   * conclusion would either report a refusal that did not happen or stay silent on one that did.
   */
  verifyAuthorshipClaim(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    senderSignature: Uint8Array,
    contentHash: Uint8Array,
  ): AuthorshipVerdict {
    // Structure 1 content_hash is index 1 and sender_pubkey index 2 in BOTH layouts — 020-ACKHASH
    // appended last_seen_hash at 6 rather than inserting it, so neither read moved. A v2 claim
    // decodes here exactly as a v1 one does; its hash is not consulted, because this unit ships
    // reading and not enforcing.
    const s1 = decodeStructure1(structure1Cbor);
    // A layout this build cannot name yields no pubkey and no hash, so there is nothing to check the
    // signature against. Its reason is carried out so an unreadable CLAIM and a wrong SIGNATURE stay
    // distinguishable — they take the same outcome by different routes.
    if (!s1.ok) return { verdict: "unusable", reason: s1.reason };
    const s1Hash = s1.fields.contentHash;
    const s1Pubkey = s1.fields.senderPubkey;
    // The SENDER's Ed25519 signature over the exact signed bytes — the same check the relay
    // performs. `verify` never throws, so a wrong-width or garbage signature lands here as `false`:
    // supplied and refuted, which is a different fact from not supplied at all.
    if (!verify(s1Pubkey, structure1Cbor, senderSignature)) {
      return { verdict: "refuted", reason: "bad_signature" };
    }
    // Sovereign-node cross-check: the signer MUST be THIS session's counterparty, not an unrelated
    // key. Review M1: compare BYTES, not hex strings — `counterparty_pubkey` is stored verbatim from
    // the IPC param and is never case-normalized, so a string compare would fail for a mixed-case
    // pubkey and silently strip the canonical ordering from every message in that session.
    const counterparty = this.#ctx.getSessionRecord(agentName, sessionId)?.counterparty_pubkey;
    if (!pubkeyMatchesHex(s1Pubkey, counterparty)) {
      /**
       * REFUTED when the counterparty is KNOWN and the signer is someone else.
       *
       * This is the session-open MITM detection from the 2026-08-21 T-of-N investigation, which
       * found this check *"fires correctly, and its answer is thrown away."* A rogue quorum of the
       * directories holding shares for agent B can sign a false SessionAssignment naming M's key as
       * B's, and everything downstream is genuinely real — M signs with M's own valid key. Nothing
       * is missing for A to notice. This comparison is where the substitution shows, because
       * `counterparty_pubkey` comes from A's own request and is untouched by anything the directory
       * returns.
       *
       * ⚠️ AN EARLIER VERSION OF THIS COMMENT ADDED "it shows only when the record is present" —
       * true when the proof was optional, and no longer the shape of the code: a content frame with
       * no checkable proof is refused before it reaches ingest, so M cannot decline to supply one
       * and be admitted anyway. Rewritten rather than deleted, because that sentence is the evidence
       * of what the gap was. The park envelope is the remaining path where the ordering record is
       * genuinely optional, and there the sender's authorship is proven by the envelope's own
       * signature instead.
       *
       * `verified_unmatched` stays soft deliberately: with no counterparty on record we cannot prove
       * the signer either way, and refusing there would strand a session whose row we failed to read
       * rather than one that is under attack. It is also the only signal the orphan branch has.
       */
      return counterparty
        ? { verdict: "refuted", reason: "signer_not_counterparty" }
        : { verdict: "verified_unmatched", senderPubkey: s1Pubkey };
    }
    /**
     * ─── THE BINDING CHECKS RUN LAST, AND THE ORDER IS A SECURITY PROPERTY ───────────────────────
     *
     * ⚠️ **THEY USED TO RUN FIRST, AND THAT HANDED THE ATTACKER A FREEZE-SUPPRESSION SWITCH** —
     * review of `029b`, and it is the finding that mattered most.
     *
     * Everything below this line is `unusable`: the message is REFUSED and the session lives.
     * Everything above it is `refuted`: the session FREEZES. So a check that can answer `unusable`
     * before the signature has been verified lets a peer choose the softer outcome — flip one
     * unauthenticated byte of `session_id` inside your own claim and a garbage signature, or a
     * signature by a MITM's own key, stops being an identity incident and becomes a quiet refusal.
     * The session-open MITM detection this function exists to serve was bypassable by exactly the
     * party it detects.
     *
     * So the order is: decode → SIGNATURE → SIGNER → then what the proof is about. By the time
     * either check below runs, the claim provably came from this session's counterparty, and the
     * only question left is which message and which conversation they made it for.
     *
     * `seal-frontier-verify` already does it in this order (verify at :55, session id at :77). This
     * code had it inverted.
     */
    // The claim must bind to THIS content. A signature over somebody else's bytes verifies perfectly
    // and proves nothing about this message — without this, one signed claim could be replayed onto
    // every frame that follows it.
    if (!bytesEqual(s1Hash, contentHash)) {
      return { verdict: "unusable", reason: AUTHORSHIP_CONTENT_HASH_MISMATCH };
    }
    /**
     * ⚠️ **AND IT MUST BIND TO THIS CONVERSATION** — review M4, ruled in by Andre 2026-09-04.
     *
     * Binding the content and the signer is not enough on its own: a claim the counterparty
     * genuinely signed in another session verifies unchanged here for the same bytes. Not a
     * stranger and not forged content — a real line of theirs, landing in a transcript it was never
     * written for, with a signature that checks out. That is worse than an unsigned message,
     * because the receipt then PROVES something that did not happen.
     *
     * `session_id` has been in Structure 1 since v1 and this path never read it.
     * `seal-frontier-verify` already compares it; the live receive path simply did not.
     *
     * **THE TWO VALUES CANNOT DIVERGE, and that is what makes this safe to enforce.** Both are
     * derived from ONE session id on each side, by construction:
     *   initiator — `sessionId = hex(assignment.session_id)` (`initiate-session-handler`) and
     *               `relayParams.sessionIdBytes = assignment.session_id` (`daemon.ts`);
     *   responder — `acceptSession(parsed.sessionIdHex)` and
     *               `sessionIdBytes = Buffer.from(parsed.sessionIdHex, "hex")` (`inbound-sessions`);
     *   direct/persisted — `relaySessionIdBytes = Buffer.from(sessionId, "hex")`.
     * The two names exist because one keys the in-memory maps and one goes on the wire, not because
     * they can hold different values. Getting this wrong would refuse EVERY message on EVERY live
     * session, so it is stated rather than assumed.
     *
     * REFUSED, not frozen — and the sentence is TRUE where it now stands. The signature has
     * verified and the signer has been matched to this session's counterparty three lines above;
     * what is wrong is only the conversation the claim was made for, which is a replay rather than
     * an identity fault. Said because an earlier version of this comment made the same claim from
     * ABOVE the verification, where none of it had happened yet.
     */
    const expectedSessionId = this.#ctx.relaySessionIdBytes(agentName, sessionId)
      ?? Uint8Array.from(Buffer.from(sessionId, "hex"));
    if (!bytesEqual(s1.fields.sessionId, expectedSessionId)) {
      return { verdict: "unusable", reason: AUTHORSHIP_SESSION_MISMATCH };
    }
    /**
     * ─── AND IT MUST ACKNOWLEDGE SOMETHING THAT WAS ACTUALLY SAID — 033-ACKEMIT ──────────────────
     *
     * **THIS IS THE HALF THAT NEEDS NO RELAY, and it is the reason the unit exists.** Everything the
     * check consumes is on this machine: the counterparty's own signed bytes, and our own tree. We
     * do not ask the relay what position 7 held — we already know, because we placed the leaf there.
     *
     * Until now a signed acknowledgement was a NUMBER. "I saw position 7" attests to a position and
     * never to content, so the only thing binding the acknowledgement to a message was the relay's
     * separate receipt over `content_hash ‖ seq ‖ timestamp`. Withhold the relay's half and the
     * signed claim is an unbacked number — which is how a counterparty seals one message short.
     * With the hash signed, the claim stands on its own and the relay is no longer load-bearing for
     * it.
     *
     * It runs LAST for the reason the two checks above run last: everything from here down answers
     * `unusable`, which refuses the message and leaves the session alive, while a `refuted` FREEZES
     * it. A check that could answer before the signature and the signer were established would hand
     * a peer a switch for choosing the softer outcome. By this line the claim provably came from
     * this session's counterparty, about this content, in this conversation — the only question
     * left is whether what they say they saw is what we sent.
     */
    const ackVerdict = this.#verifyAcknowledgedContent(agentName, sessionId, s1.fields);
    if (ackVerdict) return ackVerdict;
    /**
     * ─── AND IT MUST LINK TO THEIR OWN PREVIOUS MESSAGE — `DOD-M15-SELFCHAIN-1` ──────────────────
     *
     * The check above asks whether they are right about what WE said. This one asks whether they
     * are right about what THEY said, and it is the check that makes the ORDER of the conversation
     * provable rather than merely its contents.
     *
     * **THIS IS THE HALF THAT NEEDS NO RELAY**, in the strongest sense: the expected value is the
     * last message we received from them, which is a fact about our own inbox. A relay that is
     * absent, slow, colluding or lying cannot change it, and cannot wave a broken chain past us.
     */
    const chainVerdict = this.#verifySenderSelfChain(agentName, sessionId, s1.fields);
    if (chainVerdict) return chainVerdict;
    return { verdict: "verified", senderPubkey: s1Pubkey, senderSig: senderSignature };
  }

/**
   * Does this claim's `last_seen_hash` name content this side actually put at that position?
   *
   * Returns `undefined` when the acknowledgement holds, or the `unusable` verdict to refuse with.
   * Split out of `#verifyAuthorshipClaim` so the three refusal causes can be named separately —
   * a claim that carries NO hash, one that names a position we never reached, and one that names
   * the wrong content — rather than collapsing into a single "the proof was bad".
   *
   * ⚠️ MISSING, MALFORMED AND MISMATCHED TAKE ONE PATH (§5). Treating an unverifiable claim as
   * "fine, skip the check" would recreate the fail-open this unit closes one layer down: an
   * attacker who wants to evade a mismatch check simply never supplies a checkable proof.
   * `decodeStructure1` refuses any claim whose hash is absent or the wrong width, so every claim
   * reaching this method carries one and the only questions left are position and content.
   */
  /**
   * Does this claim link to the last message we actually received from this sender?
   *
   * ─── Why the expected value is our INBOX and not our tree ──────────────────────────────────────
   *
   * The tree holds every leaf in canonical order and records no authorship, so it cannot say which
   * of them this sender wrote. What can is the acknowledgement state this daemon already keeps: the
   * last content hash received from the counterparty, updated on every message as it is ingested.
   * That IS their previous message, by definition.
   *
   * It is seeded at session registration with the session GENESIS, so a sender's first message has
   * a real expected value rather than a special case — "they have not spoken here yet" is a value,
   * derived per session, and not an absence.
   *
   * ⚠️ RUNS BEFORE THIS MESSAGE IS INGESTED, which is what makes the comparison meaningful: the
   * state still holds their PREVIOUS message. Moving this after ingest would compare a message to
   * itself and pass every time.
   */
  #verifySenderSelfChain(
    agentName: string,
    sessionId: string,
    fields: { prevOwnHash: Uint8Array },
  ): { verdict: "unusable"; reason: string } | undefined {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const genesis = this.#ctx.sessionGenesisPrevRoot(agentName, sessionId);
    /**
     * ⚠️ THE EXPECTED VALUE IS OUR INBOX — `#lastAck` — AND NOT THE SESSION GENESIS.
     *
     * `#lastFromCounterparty` is the last content hash we accepted FROM THIS COUNTERPARTY, written
     * on every successful ingest. That IS their previous message, by definition. The genesis is only
     * the answer before they have said anything.
     *
     * It used to read the relay client's acknowledgement with the genesis as a fallback, which is
     * the same conflation the emitter had: on a session with no relay client the fallback never
     * moved, so the counterparty's SECOND message was refused as a broken chain for the rest of the
     * conversation. Four live-transport fixtures caught it the moment the emitter started producing
     * a real chain.
     */
    const expected = this.#lastFromCounterparty.get(key) ?? genesis;
    /**
     * ⚠️ NO EXPECTED VALUE MEANS NO COMPARISON, AND THIS IS THE ONE PLACE THAT IS NOT A FAIL-OPEN —
     * because of WHO CONTROLS THE ABSENCE. Whether this side holds a starting point for the session
     * depends on our own assignment and our own database. Nothing the sender puts on the wire can
     * cause it, so it is not a switch they can reach for. A session restored from a row written
     * before this existed is the real case, and refusing there would refuse every message on it for
     * something the counterparty did not do.
     */
    if (!expected) {
      this.#ctx.logger.info("session.content.self_chain.unverifiable", {
        agentName, sessionId,
        impact:
          "this side holds no record of this sender's previous message in this session, so the " +
          "link inside their signed bytes was not compared. The message is accepted; it is already " +
          "bound to this conversation and to its author by the checks above.",
      });
      return undefined;
    }
    if (bytesEqual(fields.prevOwnHash, expected)) return undefined;
    /**
     * ─── OUR OWN GAP IS NOT THEIR TAMPERING, AND THE DIFFERENCE IS DECIDABLE ─────────────────────
     *
     * `expected` is the last message from them we ACCEPTED. Our record can legitimately be behind
     * theirs: a message of theirs can arrive out of order and be HELD, be refused by the inbound
     * screen, or be lost in flight. In every one of those cases their next message links to
     * something real that we simply do not have at the front of our record — and refusing it would
     * be a fabricated tamper report caused by our own gap, against a party that did nothing.
     *
     * So a link naming ANY message we have accepted from them is accepted, and the gap is reported
     * as OUR problem. A link naming something we have never held from them is the actual accusation:
     * it is either invented or it belongs to a conversation this is not.
     *
     * ⚠️ THIS IS DELIBERATELY WEAKER THAN THE RELAY'S CHECK, AND SAYING SO IS THE POINT. The relay
     * holds the whole ordered log and refuses anything but the immediate predecessor; the directory
     * does the same at seal time. This side holds only what reached it, so the strongest honest
     * question it can ask is "did you name something you actually said to me?". Two strict checkers
     * plus one honest one beats three checkers where the weakest one fabricates accusations.
     */
    const seen = this.#receivedFromCounterparty.get(key);
    if (seen?.has(Buffer.from(fields.prevOwnHash).toString("hex"))) {
      this.#ctx.logger.info("session.content.self_chain.behind", {
        agentName, sessionId,
        impact:
          "this message links to an earlier message from your counterparty than the last one this " +
          "side accepted, so this side's copy of the conversation has a gap in it. The message is " +
          "accepted — the link names something they really did send you. The gap is on this side.",
      });
      return undefined;
    }
    return { verdict: "unusable", reason: AUTHORSHIP_SELF_CHAIN_MISMATCH };
  }

noteReceivedFromCounterparty(agentName: string, sessionId: string, contentHash: Uint8Array): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    this.#lastFromCounterparty.set(key, Uint8Array.from(contentHash));
    let seen = this.#receivedFromCounterparty.get(key);
    if (!seen) { seen = new Set<string>(); this.#receivedFromCounterparty.set(key, seen); }
    seen.add(Buffer.from(contentHash).toString("hex"));
    while (seen.size > SELF_CHAIN_MEMORY) {
      // Sets iterate in insertion order, so the first entry is the oldest.
      const oldest = seen.values().next().value as string | undefined;
      if (oldest === undefined) break;
      seen.delete(oldest);
    }
  }

#verifyAcknowledgedContent(
    agentName: string,
    sessionId: string,
    fields: { lastSeenSeq: number; lastSeenHash: Uint8Array },
  ): { verdict: "unusable"; reason: string } | undefined {
    /**
     * ⚠️ **A v1 CLAIM IS REFUSED THE MOMENT IT NAMES A POSITION — and accepted when it names none.
     * The split is the whole rule, so it is stated rather than left to the reader.**
     *
     * `last_seen_seq >= 1` with no hash IS the defect: "I saw position 7" attests to a position and
     * never to content, which is the unbacked number this unit exists to stop accepting. Treating
     * that as "fine, skip the check" would recreate `DOD-M15-AUTHORSHIP-ABSENT-1` one layer down —
     * an attacker evading a mismatch check simply never supplies a checkable proof.
     *
     * `last_seen_seq === 0` with no hash claims nothing about our messages, so there is no check to
     * skip and nothing to bind. A sender genuinely in that state — a session brokered without a
     * relay assignment, which the directory does not always return — has nothing to acknowledge,
     * and refusing them would stop the product's own advertised journey to close a hole they are
     * not in.
     *
     * **THE BOUND, SAID PLAINLY:** a peer can decline to bind by never acknowledging anything.
     * That costs them their own ratification of our history rather than falsifying it, and it is
     * the same under-claiming the relay has always allowed (it refuses a `last_seen_seq` that runs
     * AHEAD of its counter, never one that lags). This unit does not change that either way, and
     * the follow-on that does is the receiver submitting a hash for what it received.
     */
    /**
     * ⚠️ THERE IS NO "NO ACKNOWLEDGEMENT AT ALL" BRANCH, and its absence is the point.
     *
     * A claim carrying no `last_seen_hash` cannot exist: there is one Structure 1 layout and both
     * chain links are required, so such a claim does not decode and never reaches this method.
     * Nothing here may treat a missing acknowledgement as "fine, skip the check" — that is the
     * fail-open where an attacker evades a mismatch check by supplying nothing checkable.
     */
    /**
     * THE GENESIS IS A VALUE, NEVER AN ABSENCE. The first message of a session has seen nothing, and
     * that case is a defined 32 bytes — the agreed starting point of this two-party chain, derived
     * from both keys, the session id and the session timestamp. Not 32 zero bytes: a constant
     * identical across every session is one an attacker can present for any session, so the one
     * position most exposed to a forged acknowledgement would be the only one nobody could check.
     */
    if (fields.lastSeenSeq <= 0) {
      const genesis = this.#ctx.sessionGenesisPrevRoot(agentName, sessionId);
      /**
       * ⚠️ **SOFT HERE, AND THIS IS THE ONE BRANCH WHERE THAT IS NOT A FAIL-OPEN — the reasoning is
       * the load-bearing part, so it is written down rather than assumed.**
       *
       * `last_seen_seq` 0 means "I have received nothing from you", and the hash that goes with it
       * is the session's agreed starting point. It is a genuine value and this daemon always emits
       * it — but as a CHECK it is close to redundant, because the thing it establishes (that this
       * claim was made for THIS session) has already been established three lines above by the
       * session-id binding, against a value derived from the same session id.
       *
       * **What an attacker gains by reaching this branch: nothing.** They cannot skip the real
       * comparison by claiming 0, because claiming 0 is claiming to have acknowledged NOTHING of
       * ours — it removes their own ratification of our history rather than falsifying it, and the
       * positional check below is what a claim about our messages has to survive. And they cannot
       * cause the absence either: whether we hold a genesis depends on our own assignment and our
       * own database, never on anything they send.
       *
       * The alternative was refusing, and it would have been the wrong kind of strict: a session
       * restored from a row written before this column existed holds no genesis, and every first
       * message on it would be refused for something the counterparty did not do.
       */
      if (!genesis) {
        this.#ctx.logger.info("session.content.ack_hash.genesis_unavailable", {
          agentName, sessionId,
          impact:
            "this message acknowledges nothing yet, and this side holds no recorded starting point " +
            "for the session, so the acknowledgement was not compared. The message is accepted: it " +
            "is already bound to this conversation by the session id inside the signed bytes.",
        });
        return undefined;
      }
      return bytesEqual(fields.lastSeenHash, genesis)
        ? undefined
        : { verdict: "unusable", reason: AUTHORSHIP_ACK_HASH_MISMATCH };
    }
    /**
     * ─── THE ACKNOWLEDGED CONTENT MUST BE SOMETHING THIS SIDE ACTUALLY HOLDS ─────────────────────
     *
     * ⚠️ **AN EARLIER VERSION OF THIS CHECK WAS POSITION-ONLY AND HAD A HOLE THE ATTACKER COULD
     * OPEN THEMSELVES. It is kept described, not deleted, because the false reasoning is the part
     * worth not repeating.**
     *
     * It compared `hashAt(last_seen_seq - 1)` and WAIVED the whole comparison on a session marked
     * diverged, on this stated ground: *"Who controls this absence? Not the peer: divergence is
     * caused by OUR submit failing, and nothing the counterparty sends can produce it."*
     *
     * **That was false, and the party who could falsify it is the exact attacker this line names.**
     * Send a message direct-only and never submit its hash: we have no ordering record, so it is
     * appended at the tail and our tree runs one ahead of the relay's counter. Our very next send
     * then gets an assigned position BEHIND our frontier, `placeOwnLeaf` takes its
     * `position_behind_frontier` branch and calls `markSessionDiverged` — and from that moment every
     * inbound acknowledgement skipped the check entirely. **One withheld message plus one reply from
     * us disabled the guard, using the behaviour the guard exists to catch.**
     *
     * A second defect sat beside it: a claim naming a position our tree has not reached was refused
     * outright, and a HELD own leaf is exactly that — `placeOwnLeaf` returns `{placed: false}` when
     * the relay hands us a position ahead of our tail, so the leaf is not in the tree while the
     * counterparty has already received it and is acknowledging it. We refused their reply for a
     * transient gap on our own machine.
     *
     * **So the question asked is now about CONTENT, not about an index.** Is the hash they name
     * something this side has — placed in the tree, or held pending a gap? That cannot be switched
     * off by divergence (it consults no positions), it cannot false-refuse a held leaf, and it still
     * refuses a hash we have never held, which is the falsehood the check exists to catch.
     *
     * The POSITION is then used only to make the check STRONGER where it is safe to: on a session
     * whose indices still mean relay positions, the hash must sit exactly where they say it does.
     * Divergence loses that strengthening and keeps the membership test, rather than losing both.
     */
    const tree = this.#ctx.getSessionTree(agentName, sessionId);
    const ackHex = Buffer.from(fields.lastSeenHash).toString("hex");
    const heldHere = this.#ctx.heldContentFor(agentName, sessionId);
    const held = heldHere ? [...heldHere.values()].some((e) => e.contentHashHex === ackHex) : false;
    if (tree.indexOfHash(ackHex) === -1 && !held) {
      return { verdict: "unusable", reason: AUTHORSHIP_ACK_HASH_UNKNOWN };
    }
    /**
     * THE POSITIONAL STRENGTHENING. Skipped — with a WARN, never silently — when this side's indices
     * no longer mean relay positions, or when the leaf at that position is still held. Neither is
     * a pass: the membership test above has already run and refused anything we do not hold.
     */
    const atPosition = tree.hashAt(fields.lastSeenSeq - 1);
    if (this.#ctx.isSessionDiverged(agentName, sessionId) || atPosition === null) {
      this.#ctx.logger.warn("session.content.ack_hash.position_unverifiable", {
        agentName, sessionId, lastSeenSeq: fields.lastSeenSeq,
        diverged: this.#ctx.isSessionDiverged(agentName, sessionId),
        impact:
          "the acknowledged content IS in this side's record, so the claim was accepted — but its " +
          "POSITION was not checked, because this session's local positions no longer line up with " +
          "the relay's, or the leaf at that position has not been placed yet.",
      });
      return undefined;
    }
    return ackHex === atPosition
      ? undefined
      : { verdict: "unusable", reason: AUTHORSHIP_ACK_HASH_MISMATCH };
  }
}
