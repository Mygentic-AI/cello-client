/**
 * CELLO Daemon — THE PER-SESSION EPHEMERAL KEY AND THE CONTENT KEY IT AGREES
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. Each side mints a throwaway keypair for
 * the session, announces the public half, and the two halves agree the key that encrypts content at
 * the application layer — so the bytes on the wire are not readable by anything between them, relay
 * included.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ THE SECRET IS DESTROYED EXPLICITLY, NOT LEFT TO THE GARBAGE COLLECTOR. `destroySessionEphemeral`
 * zeroes the bytes; dropping the reference would leave them in the heap for as long as the process
 * lives, which is the difference between a throwaway key and one an attacker can find in a core
 * dump. Every PER-SESSION teardown goes through `destroySessionEphemeralFor`; shutdown goes through
 * `destroyAll`, which does the same zeroing for every live session at once rather than one at a
 * time. Two entry points, one guarantee — said precisely because "every path goes through one
 * method" was the earlier wording and it was not true of shutdown.
 */
import type { Logger } from "./types.js";
import type { ActiveSessionEntry } from "./session-node-types.js";
import {
  generateSessionEphemeral,
  destroySessionEphemeral,
  deriveSessionSecrets,
  signSessionEphemeral,
  verifySessionEphemeral,
  type SessionEphemeral,
  type KeyProvider,
} from "@cello-protocol/crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import {
  CONTENT_ENCRYPTION_REASONS,
  CONTENT_ENCRYPTION_GUIDANCE,
  type ContentEncryptionReason,
} from "./content-encryption-status.js";
import { CELLO_CONTENT_PROTOCOL_ID } from "@cello-protocol/transport";
import * as lp from "it-length-prefixed";
import {
  SESSION_KEY_ANNOUNCE_RETRIES,
  SESSION_KEY_ANNOUNCE_RETRY_MS,
} from "./session-node-types.js";

/** What the ephemeral key agreement needs from the manager. */
export interface SessionEphemeralContext {
  readonly logger: Logger;
  sessionKey(agentName: string, sessionId: string): string;
  activeEntry(key: string): ActiveSessionEntry | undefined;
  /**
   * ⚠️ A FUNCTION, NOT A CAPTURED VALUE. The daemon injects the per-agent key providers AFTER the
   * manager is constructed (`setKeyProviderResolver`), so a resolver snapshotted at wiring time is
   * null for the life of the process — and the failure is silent in the worst way: signing simply
   * does not happen, the exchange never completes, and the session falls back to unencrypted.
   */
  keyProvider(agentName: string): KeyProvider | undefined;
  /**
   * ⚠️ THE REASON TYPE IS WIDER THAN `ContentEncryptionReason` ON PURPOSE. The freeze is reached
   * from the ephemeral AUTH refusals too, and narrowing here would have forced a cast at the call
   * site — which is how a reason ends up reported as a neighbouring one it is not.
   */
  freezeSessionForKeyRefusal(
    agentName: string,
    sessionId: string,
    reason: string,
    correlationId?: string,
  ): Promise<void>;
}

export class SessionEphemerals {
  readonly #ctx: SessionEphemeralContext;

  constructor(ctx: SessionEphemeralContext) {
    this.#ctx = ctx;
  }

  /**
   * THIS SESSION'S THROWAWAY KEYPAIR — `DOD-M15-KEYAGREE-1`, the lifecycle half (006-CRYPTO).
   *
   * **A `Map`, never a field on the session row, and that is the whole point.** The secret is held
   * in memory and nowhere else: not in SQLite, not in a backup, not in an export. Forward secrecy is
   * not a property of minting a fresh key — it is a property of the old one being GONE — so anything
   * that made this durable would void it permanently and silently.
   *
   * Minted ONCE per session, at the moment the session becomes active, and destroyed at every site
   * that drops the `#activeNodes` entry — see `#destroySessionEphemeralFor`, which explains why it
   * is keyed to the entry rather than to the cache eviction. A revived session therefore mints a
   * FRESH one and re-keys, which is Decisions Carried #5; that is only true because the interrupt
   * path destroys, and an earlier version of this comment asserted it while the interrupt path
   * silently kept the old key for hours.
   *
   * ⚠️ NOTHING SENDS THE PUBLIC HALF YET. The exchange, the signature over it, and encrypting
   * content with the agreed secret are `007-CRYPTO`, and they are one wire format that ships
   * together. Until that lands, this keypair is minted, held and destroyed correctly and no message
   * is encrypted with it — which `#contentEncryptionStatus` states on the session itself rather than
   * leaving a reader to assume.
   */
  #sessionEphemerals = new Map<string, SessionEphemeral>();
  /**
   * THE AGREED CONTENT KEY — `DOD-M15-EPHEMERAL-AUTH-1` (007-CRYPTO).
   *
   * Present only once the peer's SIGNED ephemeral has been verified against the counterparty
   * identity this session is with. Absent means every message body on this session goes out under
   * the transport's protection alone, and `#contentEncryptionState` says which of the reasons that
   * is — never silence.
   *
   * In memory only, and destroyed with the ephemeral it came from. It is the same secret one step
   * on, so persisting it would void forward secrecy exactly as persisting the ephemeral would.
   */
  #sessionContentKeys = new Map<string, Uint8Array>();
  /**
   * WHICH peer ephemeral produced the key we hold, hex — 007-CRYPTO, review F1.
   *
   * The idempotence guard keys on THIS rather than on "a key exists", because a re-keying peer sends
   * a DIFFERENT half and must be adopted, while the same half re-announced on every connect must
   * not churn. Keying on presence meant the side that never restarted kept a stale key and every
   * message failed to decrypt — reported to its operator as possible tampering.
   */
  #sessionContentKeyPeerHalf = new Map<string, string>();
  /**
   * WHY this session has no content key, when it has none. A closed reason, never a free string.
   */
  #contentEncryptionReasons = new Map<string, ContentEncryptionReason>();
  /**
   * DOD-M15-FRAME-1 — a proven identity failure ends the session, and says so as an OBSERVATION.
   *
   * SESSION-ENDING, NOT PER-MESSAGE. One frame that fails to verify against the expected
   * counterparty is not a bad message to drop while hoping the next is better — it is evidence
   * about the CONNECTION. Dropping the frame and continuing leaves the same peer able to try again
   * with a frame that omits the proof entirely.
   *
   * THE WORDING IS NOT A VERDICT, and that is deliberate rather than squeamish. The identical
   * signal comes from a real impersonation attempt and from our own infrastructure mishandling a
   * fallback — a relay bug, a bad deploy, an uncovered edge in the direct-connection failover. The
   * daemon cannot tell those apart from this signal, so it must not pretend to. This mirrors the
   * account-recovery pattern already in the codebase, which anchors a compromise window to logged
   * events and accepts that some evidence cannot separate misconduct from an innocent cause.
   *
   * IT MUST NEVER FEED A TRUST SIGNAL. An automatic reputation consequence driven by a signal this
   * ambiguous would let a hostile peer — or a bad deploy of ours — manufacture a mark against an
   * innocent counterparty. Recorded here because the absence of that wiring is a decision, not an
   * omission, and the next person to reach for it should find this comment first.
   *
   * The accusatory half stays local for the same reason. Freezing what THIS daemon trusts is always
   * safe unilaterally; asserting on the record that a counterparty misbehaved needs corroboration
   * from a party the accusing client does not control, which is `DOD-M15-CORROBORATE-1` (the relay
   * holds the sender's signed hash independently and never routes it through the receiver).
   */
  /**
   * DOD-M15-SEALWIRE-1 bullet 6 (part A) — THE SALT AGREEMENT, the I/O half.
   *
   * The decisions live in `session-salt-agreement.ts` as a pure function; everything here is the
   * three things that function cannot do: read and write the durable row, put a frame on the wire,
   * and stop a session.
   *
   * ─── Where a contribution may travel, and it is the one rule that cannot be fixed later ───────
   *
   * `/cello/content/1.0.0` ONLY. It rides circuit-relay-v2 carrying its own Noise session, so a
   * relay forwarding it sees ciphertext. It must never be added to `session_offer` /
   * `session_offer_accept` or anything a DIRECTORY brokers — and that is the trap, because the only
   * round trip at session open today runs on the directory's signaling stream, which makes it the
   * obvious place to put one. A session that shipped it there could not be repaired: the relay
   * would already hold the salt and every hash it protects.
   */
  /**
   * MINT THIS SESSION'S THROWAWAY KEYPAIR — once, at the moment the session becomes active.
   *
   * Idempotent on purpose. Three paths make a session active (open, hand-off from the standing
   * receiver, revive) and a reconnect can re-enter them; minting a second keypair mid-session would
   * leave the two sides deriving against a moving value, and the symptom — a session that reconnects
   * and still cannot agree — reads as a network fault rather than as a bug here. `#saltContributionFor`
   * mints once for exactly the same reason.
   *
   * A REVIVED session is not an exception, and this guard is why it took a fix to make that true.
   * Revival requires status `interrupted`, and the producer of `interrupted` drops the entry without
   * evicting — so while the secret outlived that path, this guard found it still present and
   * silently kept a key that had been resident for hours, on the one path where re-keying was
   * explicitly decided. The interrupt path now destroys it, so the map really is empty by the time
   * a revival reaches here and it mints fresh (Decisions Carried #5).
   */
  mintSessionEphemeral(agentName: string, sessionId: string, correlationId?: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#sessionEphemerals.has(key)) return;
    this.#sessionEphemerals.set(key, generateSessionEphemeral());
    this.#ctx.logger.debug("session.ephemeral.minted", {
      agentName, sessionId, correlationId,
      // The PUBLIC half only, and only a prefix of it. The secret must never reach a log line, and
      // an operator correlating two daemons needs an identifier rather than the value.
      publicKeyPrefix: Buffer.from(this.#sessionEphemerals.get(key)!.publicKey.subarray(0, 8)).toString("hex"),
    });
  }
  /**
   * DESTROY THIS SESSION'S THROWAWAY SECRET — 006-CRYPTO, and this is what forward secrecy IS.
   *
   * ⚠️ CALLED FROM EVERY SITE THAT DROPS THE `#activeNodes` ENTRY, not from `#evictSessionCaches`,
   * and review pass 2 finding 2 is why. The first version rode the evict, which sounded right and
   * was wrong on the path an interrupted session actually takes:
   *
   *   `markInterruptedWithDetails` drops the entry and DELIBERATELY does not evict — the received
   *   plaintext has to stay drainable and the TTF park timers have to stay armed. So the secret
   *   survived. Then, when that session later sealed, `destroySessionNode` returned at its
   *   `if (!entry) return` — the entry was already gone — and never reached the evict either. The
   *   receipt landed, the session was over, and the secret stayed resident until the process exited.
   *
   * A relay blip is the ORDINARY way a session ends badly, so that was the common path, not a corner.
   * The evict's reasons for keeping the other caches are real and do not transfer: buffered plaintext
   * must stay readable, and a secret nothing reads must not stay alive.
   *
   * Zero THEN drop. Dropping alone leaves the bytes wherever the collector last moved them;
   * `destroySessionEphemeral` overwrites the one copy this process controls.
   */
  destroySessionEphemeralFor(agentName: string, sessionId: string, correlationId?: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    // 007-CRYPTO: the AGREED KEY goes with the ephemeral it was derived from. It is the same secret
    // one step on — leaving it behind would keep the thing the destruction exists to remove.
    const agreed = this.#sessionContentKeys.get(key);
    if (agreed) {
      agreed.fill(0);
      this.#sessionContentKeys.delete(key);
    }
    this.#sessionContentKeyPeerHalf.delete(key);
    this.#contentEncryptionReasons.delete(key);
    const ephemeral = this.#sessionEphemerals.get(key);
    if (!ephemeral) return;
    destroySessionEphemeral(ephemeral);
    this.#sessionEphemerals.delete(key);
    this.#ctx.logger.debug("session.ephemeral.destroyed", { agentName, sessionId, correlationId });
  }
  /**
   * AN INBOUND SIGNED EPHEMERAL — verify, THEN derive. Never the other way round.
   *
   * 🚨 A FAILED VERIFICATION IS A SECURITY EVENT AND IT STOPS THE SESSION. It is not a degradation
   * to unencrypted, and the difference is the whole unit: an unsigned or wrongly-signed key is what
   * a relay substituting its own looks like, and carrying on unencrypted would hand that relay
   * exactly the plaintext it was reaching for. Missing, malformed and mismatched take this same
   * path — a check that is lenient about a missing proof is a check an attacker skips.
   *
   * Contrast with a peer that says NOTHING at all: that is an old build, it is not evidence of
   * anything about them, and it is recorded as `PEER_SILENT` — which still blocks sending, because
   * there is no unencrypted path to fall back to.
   */
  async handleEphemeralFrame(
    agentName: string,
    sessionId: string,
    frame: { ephemeralPublic?: Uint8Array; signature?: Uint8Array },
    correlationId?: string,
  ): Promise<void> {
    const entry = this.#ctx.activeEntry(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) return;

    /**
     * THE IDENTITY WE EXPECT is the session's own counterparty record — and its provenance differs
     * by side, which review F10 measured and an earlier version of this comment overstated.
     *
     *   INITIATOR: what the OPERATOR asked for (`initiate-session-handler` takes `target_pubkey`).
     *   RESPONDER: the initiator identity the DIRECTORY attested in the offer/assignment.
     *
     * So this binds the ephemeral to that identity, whichever it is. The attack it closes is the
     * RELAY substituting its own key — a different actor from the directory — and that is closed in
     * both directions. What it does NOT do is move the responder's trust off the directory; the
     * inbound path says as much itself ("a single compromised directory still controls both frames
     * here"), and that is a separate line.
     *
     * The distinction is written down rather than smoothed over because this is a public repo and
     * the sentence it replaces — "never from anything the directory handed back" — was absolute and
     * false on one of the two sides.
     */
    const expected = Buffer.from(entry.counterpartyPubkey, "hex");
    const sessionIdBytes = Buffer.from(sessionId, "hex");
    const verdict = verifySessionEphemeral({
      expectedIdentityPublic: new Uint8Array(expected),
      sessionId: sessionIdBytes,
      peerEphemeralPublic: frame.ephemeralPublic,
      peerSignature: frame.signature,
    });

    if (!verdict.ok) {
      this.#ctx.logger.error("session.key.refused", {
        agentName, sessionId, correlationId,
        reason: verdict.reason,
        detail: verdict.detail,
        guidance:
          "STOPPED ON PURPOSE. The session key your counterparty sent could not be tied to them, so " +
          "this session has been stopped rather than continued in the open. The ordinary cause is a " +
          "build mismatch; the one that matters is something in the middle of your connection " +
          "substituting its own key so it can read what you send. Confirm with your counterparty OUT " +
          "OF BAND — not over CELLO — before opening another session with them.",
      });
      // Session-ending, not per-message: one proven wrong signer is evidence about the CONNECTION,
      // not about the frame that carried it.
      await this.#ctx.freezeSessionForKeyRefusal(agentName, sessionId, verdict.reason, correlationId);
      return;
    }

    /**
     * ALREADY AGREED WITH **THIS** PEER HALF — idempotence keyed on the bytes, not on presence.
     *
     * ⚠️ KEYING IT ON PRESENCE WAS A DEFECT, and a routine relay roll was enough to trigger it.
     * Only the side whose witness stream closed interrupts, so only that side destroys its key and
     * re-keys on revival. The OTHER side is never torn down — nothing else clears this map — so it
     * saw the peer's NEW ephemeral, found a key already present, and kept the old one.
     *
     * Two different keys, and the damage is worse than a dead path: every message then fails GCM,
     * and the receiving daemon reports *"the message did not decrypt — it was modified in flight, or
     * encrypted under a different key"* and tells the operator to confirm OUT OF BAND. Nothing was
     * modified. Two people have a security conversation about a local key skew.
     *
     * I MEASURED THIS TWICE AND CALLED IT A HARNESS QUIRK — the notes in `seam-4` and `m9-core-001`
     * about seeding "before the settle" leaving the two ends on different keys are this defect,
     * observed and worked around instead of read.
     *
     * So: the same half re-announced on every connect is still a no-op, and a DIFFERENT half — which
     * only a re-keying peer sends — is adopted. The peer is identity-authenticated by the time we
     * get here, so letting them move the key is not a new capability.
     */
    const peerHalfHex = Buffer.from(frame.ephemeralPublic!).toString("hex");
    if (this.#sessionContentKeyPeerHalf.get(this.#ctx.sessionKey(agentName, sessionId)) === peerHalfHex) return;

    const ownEphemeral = this.sessionEphemeralFor(agentName, sessionId);
    if (!ownEphemeral) {
      this.#ctx.logger.error("session.key.refused", {
        agentName, sessionId, correlationId, reason: "no_local_ephemeral",
        detail: "the peer's key verified but this side holds no throwaway keypair to agree with, so nothing can be derived. This is a LOCAL defect, not something the peer did.",
      });
      this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED);
      return;
    }

    try {
      const secrets = deriveSessionSecrets({
        ownEphemeralSecret: ownEphemeral.secretKey,
        peerEphemeralPublic: frame.ephemeralPublic!,
        sessionId: sessionIdBytes,
      });
      const prior = this.#sessionContentKeyPeerHalf.get(this.#ctx.sessionKey(agentName, sessionId));
      this.#sessionContentKeys.set(this.#ctx.sessionKey(agentName, sessionId), secrets.contentKey);
      this.#sessionContentKeyPeerHalf.set(this.#ctx.sessionKey(agentName, sessionId), peerHalfHex);
      this.#contentEncryptionReasons.delete(this.#ctx.sessionKey(agentName, sessionId));
      this.#ctx.logger.info("session.key.agreed", {
        agentName, sessionId, correlationId,
        // A RE-KEY is a different event from a first agreement and an operator correlating two
        // daemons needs to tell them apart: a re-key means the other side restarted.
        rekey: prior !== undefined && prior !== peerHalfHex,
        impact: "message bodies on this session are now encrypted by CELLO under a key both sides agreed and neither sent, and which is destroyed when the session ends",
      });
    } catch (err: unknown) {
      // The primitive owns every rule about the peer's half — a degenerate point, a non-canonical
      // encoding, a reflection — and owns the WORDING. Substituting a code of our own here would
      // destroy the only explanation that exists at the only moment anyone reads it.
      this.#ctx.logger.error("session.key.refused", {
        agentName, sessionId, correlationId, reason: "derivation_failed",
        detail: err instanceof Error ? err.message : String(err),
      });
      await this.#ctx.freezeSessionForKeyRefusal(agentName, sessionId, "derivation_failed", correlationId);
    }
  }
  /**
   * The agreed content key for a session, or `null` with the reason there is none.
   *
   * ONE place decides this, so the send path, the receive path and the status surface cannot
   * disagree about whether a session is encrypted — the failure `wire-content-hash.ts` already
   * records for the hash, where the expression was written out at five call sites and the two added
   * last got it wrong.
   */
  contentEncryptionState(
    agentName: string,
    sessionId: string,
  ): { key: Uint8Array; reason?: undefined } | { key: null; reason: ContentEncryptionReason } {
    const k = this.#ctx.sessionKey(agentName, sessionId);
    const agreed = this.#sessionContentKeys.get(k);
    if (agreed) return { key: agreed };
    // No recorded fault means the exchange simply has not finished yet — the ordinary state in the
    // instant between a session opening and its first connect completing.
    return { key: null, reason: this.#contentEncryptionReasons.get(k) ?? CONTENT_ENCRYPTION_REASONS.NOT_YET_AGREED };
  }
  noteContentEncryptionReason(agentName: string, sessionId: string, reason: ContentEncryptionReason): void {
    const k = this.#ctx.sessionKey(agentName, sessionId);
    // FIRST reason wins. A later, vaguer one must not overwrite the specific cause already recorded
    // — "they never answered" written over "we could not sign" points the operator at the wrong
    // machine, which is the substitution this closed set exists to end.
    if (!this.#contentEncryptionReasons.has(k)) this.#contentEncryptionReasons.set(k, reason);
  }
  /**
   * ANNOUNCE THIS SIDE'S SIGNED EPHEMERAL — `DOD-M15-EPHEMERAL-AUTH-1`.
   *
   * 🚨 ON THE PEER-TO-PEER CONTENT STREAM ONLY, exactly like the salt contribution and for the same
   * unrepairable reason: it rides circuit-relay-v2 carrying its own Noise session, so a forwarding
   * relay sees ciphertext. It must NEVER be added to `session_offer` / `session_offer_accept` or
   * anything a DIRECTORY brokers — and that is the trap, because the only round trip at session open
   * is the directory's signaling stream.
   *
   * Fire-and-forget on the connect handler, like the salt: a failed announcement must not turn a
   * peer-connect handler into a rejected promise, and we re-announce on the next connect.
   */
  async sendEphemeralFrame(agentName: string, sessionId: string, correlationId?: string): Promise<void> {
    const entry = this.#ctx.activeEntry(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) return;
    const ephemeral = this.sessionEphemeralFor(agentName, sessionId);
    if (!ephemeral) {
      this.#ctx.logger.error("session.key.announce.failed", {
        agentName, sessionId, correlationId, reason: "no_ephemeral",
        impact: "this session is active with no throwaway keypair, so there is nothing to announce; content stays unencrypted by CELLO",
      });
      this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED);
      return;
    }
    const signer = this.#ctx.keyProvider(agentName);
    if (!signer) {
      /**
       * A LOCAL fault, and it is named as one. Without this branch the peer simply never hears from
       * us and blames a build that is fine — the operator whose machine cannot sign reads a message
       * about their counterparty, which is the exact substitution the salt work already paid for.
       */
      this.#ctx.logger.error("session.key.announce.failed", {
        agentName, sessionId, correlationId, reason: "no_identity_key",
        impact: "this machine has no identity key for the agent, so it cannot sign its half of the session key; every session it opens is unencrypted by CELLO and the counterparty is not involved",
        guidance: CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY],
      });
      this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY);
      return;
    }

    let stream: Awaited<ReturnType<typeof entry.node.newStream>> | null = null;
    try {
      const sessionIdBytes = Buffer.from(sessionId, "hex");
      const signature = await signSessionEphemeral(signer, sessionIdBytes, ephemeral.publicKey);
      stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      stream.send(lp.encode.single(encodeCbor({
        type: "session_key_agreement",
        session_id: sessionId,
        ephemeral_public: ephemeral.publicKey,
        ephemeral_sig: signature,
      }) as Uint8Array).subarray());
      await stream.close();
      this.#ctx.logger.debug("session.key.announced", {
        agentName, sessionId, correlationId,
        publicKeyPrefix: Buffer.from(ephemeral.publicKey.subarray(0, 8)).toString("hex"),
      });
    } catch (err: unknown) {
      // The frame never left. Say so as a LOCAL fault rather than letting the session look like a
      // counterparty on an old build — a re-announce rides the next connect.
      this.#ctx.logger.error("session.key.announce.failed", {
        agentName, sessionId, correlationId, reason: "stream_failed",
        error: err instanceof Error ? err.message : String(err),
        impact: "this side's half of the session key never reached the counterparty, so content stays unencrypted by CELLO until a later connect succeeds",
      });
      this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED);
      /**
       * ABORT, don't just close — review F13. A `close()` on a broken stream can itself fail and
       * leave the slot held, which is the per-protocol stream-cap failure this file's longest
       * comment documents. Every other failed write on this protocol aborts.
       */
      if (stream) { try { stream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ } }
      /**
       * AND RETRY — review F5, and without it a single failed stream open kills encryption for the
       * life of the session.
       *
       * The announce otherwise rides `onPeerConnect` only. If the connection then stays up there is
       * no next connect, so nothing re-announces, every send parks forever, and the guidance's
       * "it re-announces on the next connect" names an event that never arrives. It also compounds
       * the re-key path: a revived session announces its FRESH half exactly once, and if that one
       * attempt loses the race with the reconnect, the two ends sit on different keys.
       *
       * Bounded and self-cancelling: it stops when the session is no longer active, when a key has
       * been agreed, and after `SESSION_KEY_ANNOUNCE_RETRIES` attempts.
       */
      this.retryEphemeralAnnounce(agentName, sessionId, correlationId, 1);
    }
  }
  /**
   * Re-announce this side's ephemeral after a failed attempt — review F5.
   *
   * Backs off, and gives up rather than looping: a peer that is simply gone must not have a timer
   * chasing it for the life of the process.
   */
  retryEphemeralAnnounce(agentName: string, sessionId: string, correlationId: string | undefined, attempt: number): void {
    if (attempt > SESSION_KEY_ANNOUNCE_RETRIES) {
      this.#ctx.logger.warn("session.key.announce.gave_up", {
        agentName, sessionId, correlationId, attempts: SESSION_KEY_ANNOUNCE_RETRIES,
        impact: "this side never managed to send its half of the session key, so every message on this session takes the relay mailbox instead of the direct path",
        guidance: CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED],
      });
      return;
    }
    const timer = setTimeout(() => {
      // Stop if the session went away, or if a key has since been agreed by any route.
      if (this.#ctx.activeEntry(this.#ctx.sessionKey(agentName, sessionId)) === undefined) return;
      if (this.#sessionContentKeys.has(this.#ctx.sessionKey(agentName, sessionId))) return;
      void this.sendEphemeralFrame(agentName, sessionId, correlationId);
    }, SESSION_KEY_ANNOUNCE_RETRY_MS * attempt);
    // Never hold the process open for a retry.
    if (typeof timer.unref === "function") timer.unref();
  }
  /**
   * Our throwaway keypair for a session, WITHOUT minting one — the read-only counterpart.
   *
   * `null` means the session is not active here. It never means "mint one now": minting outside
   * `#mintSessionEphemeral` is how a second keypair appears mid-session.
   */
  sessionEphemeralFor(agentName: string, sessionId: string): SessionEphemeral | null {
    return this.#sessionEphemerals.get(this.#ctx.sessionKey(agentName, sessionId)) ?? null;
  }
  /**
   * Test seams: re-enter the mint path, and read back the PUBLIC half — 006-CRYPTO.
   *
   * `#mintSessionEphemeral` is idempotent because a reconnect can re-enter an activation path, and a
   * second keypair mid-session would leave the two sides deriving against a moving value. Proving
   * that needs the path called TWICE, and the alternative — driving a real reconnect — drags in node
   * rebuild and relay reconnection, none of which the property is about. Same justification as
   * `forgetSaltContributionForTest` above.
   *
   * It calls the REAL private method, so a test cannot pass against a decision production does not
   * make. The reader returns the public half ONLY: a seam that could hand out the secret is a way
   * for the secret to leave this object, which is the one thing the whole unit is about.
   */
  mintSessionEphemeralForTest(agentName: string, sessionId: string): void {
    this.mintSessionEphemeral(agentName, sessionId);
  }
  sessionEphemeralPublicForTest(agentName: string, sessionId: string): Uint8Array | null {
    const e = this.sessionEphemeralFor(agentName, sessionId);
    return e ? Uint8Array.from(e.publicKey) : null;
  }
  /**
   * Test seam: INSTALL a keypair the caller already holds — the only way to prove ZEROING.
   *
   * Presence is easy to assert and is not the property. `destroySessionEphemeral` overwrites the
   * buffer before the entry is dropped, and a mutant that drops without overwriting leaves the
   * secret wherever the collector last moved it while passing every presence check — which is
   * exactly what happened: the shutdown zeroing shipped with a surviving mutant, and the transport
   * seeds four lines above it have the same untested gap today.
   *
   * The direction matters. Nothing here HANDS OUT a secret — the test supplies an object it already
   * owns and then inspects its own reference. A reader that returned the live keypair would be a
   * path for the secret to leave this object, which is the one thing this unit exists to prevent.
   */
  setSessionEphemeralForTest(agentName: string, sessionId: string, ephemeral: SessionEphemeral): void {
    this.#sessionEphemerals.set(this.#ctx.sessionKey(agentName, sessionId), ephemeral);
  }
  /**
   * Test seam: put a session into the state a COMPLETED exchange leaves it in — 007-CRYPTO.
   *
   * A live send now requires an agreed key, because there is no plaintext path to fall back to. In
   * production the exchange completes on connect, before any send. A fixture with no real peer never
   * completes it, so without this every content test in the repo would be exercising the refusal
   * path instead of the thing it was written for.
   *
   * ⚠️ IT SHORT-CIRCUITS HOW THE KEY GOT THERE, NEVER WHAT THE KEY IS FOR. The state it produces —
   * a session holding an agreed content key — is exactly the production state, which is what makes
   * it legitimate; `setSaltContributionForTest` exists for the same reason. Tests of the EXCHANGE
   * itself drive the real signed frames and must not use this.
   */
  setSessionContentKeyForTest(agentName: string, sessionId: string, key: Uint8Array): void {
    this.#sessionContentKeys.set(this.#ctx.sessionKey(agentName, sessionId), Uint8Array.from(key));
    this.#contentEncryptionReasons.delete(this.#ctx.sessionKey(agentName, sessionId));
  }
  /**
   * Test seam: drop the agreed key while leaving the session up — the state before an exchange
   * completes, and after a teardown evicts one. Its mirror above is what a completed exchange
   * leaves; both are needed, or a status field stuck in one position passes either test alone.
   */
  forgetSessionContentKeyForTest(agentName: string, sessionId: string): void {
    this.#sessionContentKeys.delete(this.#ctx.sessionKey(agentName, sessionId));
  }
  /**
   * Test seam: produce THIS side's signed ephemeral, using the manager's own identity resolver.
   *
   * For harnesses whose connectivity is one-directional — one side dials, so only one announce ever
   * lands. Carrying the other side's half across with a REAL signature is what completes the
   * exchange, and it beats seeding a key: a seeded key has no peer half recorded against it, so the
   * first genuine announce replaces it and the two ends drift apart (which is correct behaviour —
   * see the re-key guard — and exactly what made seeding fragile here).
   *
   * It signs with the same provider production signs with, so a test cannot pass against a signature
   * production would have refused.
   */
  async signOwnEphemeralForTest(
    agentName: string,
    sessionId: string,
  ): Promise<{ ephemeralPublic: Uint8Array; signature: Uint8Array } | null> {
    const eph = this.sessionEphemeralFor(agentName, sessionId);
    const signer = this.#ctx.keyProvider(agentName);
    if (!eph || !signer) return null;
    const signature = await signSessionEphemeral(signer, Buffer.from(sessionId, "hex"), eph.publicKey);
    return { ephemeralPublic: Uint8Array.from(eph.publicKey), signature };
  }
  /**
   * Test seam: deliver a peer's signed ephemeral, exactly as the content-stream decoder does.
   *
   * For harnesses whose connectivity is one-directional — one side dials, so only one announce ever
   * lands — this is what completes the exchange instead of stuffing a key in. It runs the REAL
   * verification and the REAL derivation, so a test cannot pass against a signature production would
   * have refused.
   */
  async handleEphemeralFrameForTest(
    agentName: string,
    sessionId: string,
    frame: { ephemeralPublic?: Uint8Array; signature?: Uint8Array },
    correlationId = "test",
  ): Promise<void> {
    await this.handleEphemeralFrame(agentName, sessionId, frame, correlationId);
  }

  /**
   * Zero and drop EVERY session's ephemeral secret. Called on shutdown.
   *
   * ⚠️ THE ZEROING IS THE POINT, not the map clear. Shutdown marks rows `interrupted` by direct SQL,
   * so no per-session teardown fires for them — and this process is known to linger (a `cello
   * logout` has been seen still alive 30+ seconds later). Without this, every live session's key
   * survives the shutdown in memory for as long as the process does.
   */
  destroyAll(): void {
    for (const ephemeral of this.#sessionEphemerals.values()) destroySessionEphemeral(ephemeral);
    this.#sessionEphemerals.clear();
  }
}
