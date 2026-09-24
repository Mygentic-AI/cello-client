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
  mlKemEncapsulate,
  mlKemDecapsulate,
  EPHEMERAL_AUTH_REFUSALS,
  type SessionEphemeral,
  type SessionKeyAgreementFields,
  type KeyProvider,
  type MlDsaKeyProvider,
} from "@cello-protocol/crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { extractErrorMessage } from "./error-message.js";
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
   * M9D 003-PQSESSION: the agent's registered ML-DSA key, which signs the announce beside K_local.
   * A function for the same reason as `keyProvider`: the daemon injects it after construction.
   */
  mlDsaProvider(agentName: string): MlDsaKeyProvider | undefined;
  /**
   * M9D 003-PQSESSION: the counterparty's post-quantum keys, verified through its v2 key binding and
   * recorded on the session row. The ONLY key `ephemeral_pq_sig` is checked against.
   */
  counterpartyPqKeys(agentName: string, sessionId: string): { mlDsa: Uint8Array; mlKem: Uint8Array } | null;
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
   * M9D 003-PQSESSION: the ML-KEM ciphertext THIS side encapsulated to the counterparty's current
   * ML-KEM key, re-sent on every announce while we are the encapsulator. Public; no zeroing needed.
   * Cleared with the ephemeral, because a re-key recomputes the roles.
   */
  #ownCiphertexts = new Map<string, Uint8Array>();
  /** Sessions where we are the decapsulator and hold the peer's half but not yet its ciphertext. */
  #awaitingPqCiphertext = new Set<string>();
  /**
   * Content that arrived while `#awaitingPqCiphertext` — held, not refused as tampered, because the
   * encapsulator can send the moment it has derived and we derive one frame later. Drained in arrival
   * order on derivation; refused as `pq_ciphertext_not_received` on cap or timeout; dropped with the
   * session on every destroy path.
   */
  #heldContent = new Map<string, { frames: Array<{ replay: () => Promise<void>; refuse: () => void }>; bytes: number; timer: ReturnType<typeof setTimeout> }>();
  #holdLimits = { ms: 30_000, maxFrames: 64, maxBytes: 4 * 1024 * 1024 };
  /** Test seam: sees every ML-KEM shared secret at creation, to prove it is zeroed after use. */
  #ssPqObserver: ((ssPq: Uint8Array) => void) | null = null;
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
  async mintSessionEphemeral(agentName: string, sessionId: string, correlationId?: string): Promise<void> {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#sessionEphemerals.has(key)) return;
    const minted = await generateSessionEphemeral();
    // Re-checked after the await: a concurrent activation may have minted first, and a second
    // keypair mid-session is exactly what this guard exists to stop.
    if (this.#sessionEphemerals.has(key)) { destroySessionEphemeral(minted); return; }
    this.#sessionEphemerals.set(key, minted);
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
    // 003-PQSESSION: the role state goes with the ephemeral it was computed from, and content held
    // for this session's ciphertext is dropped with the session.
    this.#ownCiphertexts.delete(key);
    this.#awaitingPqCiphertext.delete(key);
    this.#dropHeld(key);
    const ephemeral = this.#sessionEphemerals.get(key);
    if (!ephemeral) return;
    // Zeroes the X25519 secret AND the ML-KEM seed (D12).
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
    frame: SessionKeyAgreementFields,
    correlationId?: string,
  ): Promise<void> {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const entry = this.#ctx.activeEntry(key);
    if (!entry) return;

    /**
     * THE IDENTITY WE EXPECT is the session's own counterparty record — and its provenance differs
     * by side, which review F10 measured and an earlier version of this comment overstated.
     *
     *   INITIATOR: what the OPERATOR asked for (`initiate-session-handler` takes `target_pubkey`).
     *   RESPONDER: the initiator identity the DIRECTORY attested in the offer/assignment.
     *
     * The ML-DSA key is the counterparty's REGISTERED key, recorded from the assignment after its v2
     * key binding verified (002-PQKEYS) — the only key `ephemeral_pq_sig` is checked against.
     */
    const expected = Buffer.from(entry.counterpartyPubkey, "hex");
    const sessionIdBytes = Buffer.from(sessionId, "hex");
    const verdict = await verifySessionEphemeral({
      expectedIdentityPublic: new Uint8Array(expected),
      expectedPqPublic: this.#ctx.counterpartyPqKeys(agentName, sessionId)?.mlDsa,
      sessionId: sessionIdBytes,
      peerEphemeralPublic: frame.ephemeralPublic,
      peerMlKemPublic: frame.mlkemPublic,
      peerCiphertext: frame.mlkemCiphertext,
      peerSignature: frame.signature,
      peerPqSignature: frame.pqSignature,
    });

    if (!verdict.ok) {
      await this.#refuseKey(agentName, sessionId, verdict.reason, verdict.detail, correlationId);
      return;
    }
    const peerX25519 = frame.ephemeralPublic!;
    const peerMlKem = frame.mlkemPublic!;
    const peerCt = frame.mlkemCiphertext;

    const ownEphemeral = this.sessionEphemeralFor(agentName, sessionId);
    if (!ownEphemeral) {
      this.#ctx.logger.error("session.key.refused", {
        agentName, sessionId, correlationId, reason: "no_local_ephemeral",
        detail: "the peer's key verified but this side holds no throwaway keypair to agree with, so nothing can be derived. This is a LOCAL defect, not something the peer did.",
      });
      this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED);
      return;
    }

    /**
     * KEM ROLE — Contract 4: the side whose X25519 public sorts LOWER encapsulates to the other's
     * ML-KEM key. Never decided by who initiated, and recomputed on every frame, because a re-key on
     * either side can swap the order.
     */
    const weEncapsulate = lexLess(ownEphemeral.publicKey, peerX25519);
    if (weEncapsulate && peerCt !== undefined) {
      await this.#refuseKey(
        agentName, sessionId, EPHEMERAL_AUTH_REFUSALS.PQ_ROLE_VIOLATION,
        "the peer sent a post-quantum ciphertext, but its session key sorts higher than ours, so it is the side that must NOT encapsulate. Two ciphertexts would leave the two sides on different keys.",
        correlationId,
      );
      return;
    }

    /**
     * ALREADY AGREED WITH **THIS** PEER HALF — idempotence keyed on the WHOLE half: X25519 key, ML-KEM
     * key and ciphertext (decision 8, D10).
     *
     * Keyed on the X25519 bytes alone, the encapsulator's second announce — same X25519 key, now
     * carrying the ciphertext — was dropped as a duplicate, and the decapsulator never derived. Every
     * message then failed GCM and was reported as *"modified in flight"* when nothing was modified.
     *
     * ⚠️ KEYING IT ON PRESENCE WAS THE EARLIER DEFECT, and a routine relay roll was enough to trigger
     * it: only the side whose witness stream closed re-keyed, the other kept its old key, and every
     * message failed GCM. So the same half re-announced on every connect is still a no-op, and a
     * DIFFERENT half — a re-key, or the ciphertext arriving — is processed.
     */
    const peerHalfHex = Buffer.concat([peerX25519, peerMlKem, peerCt ?? new Uint8Array(0)]).toString("hex");
    const prior = this.#sessionContentKeyPeerHalf.get(key);
    if (prior === peerHalfHex) return;

    if (!weEncapsulate && peerCt === undefined) {
      // We decapsulate and the ciphertext has not come yet: record the half and wait. An older key
      // (the peer re-keyed) is dropped, so content under the new key is HELD rather than failing GCM.
      this.#sessionContentKeyPeerHalf.set(key, peerHalfHex);
      this.#awaitingPqCiphertext.add(key);
      const old = this.#sessionContentKeys.get(key);
      if (old) { old.fill(0); this.#sessionContentKeys.delete(key); }
      this.#ctx.logger.debug("session.key.awaiting_pq_ciphertext", { agentName, sessionId, correlationId });
      return;
    }

    let ssPq: Uint8Array;
    let transcript: Uint8Array;
    let ciphertextToAnnounce: Uint8Array | undefined;
    try {
      if (weEncapsulate) {
        const kem = await mlKemEncapsulate(peerMlKem);
        ssPq = kem.sharedSecret;
        transcript = Buffer.concat([kem.ciphertext, peerMlKem]);
        ciphertextToAnnounce = kem.ciphertext;
      } else {
        ssPq = await mlKemDecapsulate(ownEphemeral.mlKemSeed, peerCt!);
        transcript = Buffer.concat([peerCt!, ownEphemeral.mlKemPublic]);
      }
    } catch (err: unknown) {
      this.#ctx.logger.error("session.key.refused", {
        agentName, sessionId, correlationId,
        reason: weEncapsulate ? "pq_encaps_failed" : "pq_decaps_failed",
        detail: extractErrorMessage(err),
        errorName: (err as { name?: string } | null)?.name,
        errorCode: (err as { code?: string } | null)?.code,
      });
      await this.#ctx.freezeSessionForKeyRefusal(agentName, sessionId, weEncapsulate ? "pq_encaps_failed" : "pq_decaps_failed", correlationId);
      return;
    }
    this.#ssPqObserver?.(ssPq);

    try {
      const secrets = deriveSessionSecrets({
        ownEphemeralSecret: ownEphemeral.secretKey,
        peerEphemeralPublic: peerX25519,
        sessionId: sessionIdBytes,
        extraSharedSecret: ssPq,
        pqTranscript: transcript,
      });
      const old = this.#sessionContentKeys.get(key);
      if (old) old.fill(0);
      this.#sessionContentKeys.set(key, secrets.contentKey);
      this.#sessionContentKeyPeerHalf.set(key, peerHalfHex);
      this.#contentEncryptionReasons.delete(key);
      this.#awaitingPqCiphertext.delete(key);
      if (ciphertextToAnnounce) this.#ownCiphertexts.set(key, ciphertextToAnnounce);
      this.#ctx.logger.info("session.key.agreed", {
        agentName, sessionId, correlationId,
        role: weEncapsulate ? "encapsulator" : "decapsulator",
        // A RE-KEY is a different event from a first agreement and an operator correlating two
        // daemons needs to tell them apart: a re-key means the other side restarted.
        rekey: old !== undefined,
        impact: "message bodies on this session are now encrypted by CELLO under a hybrid X25519 + ML-KEM-768 key both sides agreed and neither sent, and which is destroyed when the session ends",
      });
    } catch (err: unknown) {
      // The primitive owns every rule about the peer's half — a degenerate point, a non-canonical
      // encoding, a reflection — and owns the WORDING. Substituting a code of our own here would
      // destroy the only explanation that exists at the only moment anyone reads it.
      this.#ctx.logger.error("session.key.refused", {
        agentName, sessionId, correlationId, reason: "derivation_failed",
        detail: extractErrorMessage(err),
        errorName: (err as { name?: string } | null)?.name,
        errorCode: (err as { code?: string } | null)?.code,
      });
      await this.#ctx.freezeSessionForKeyRefusal(agentName, sessionId, "derivation_failed", correlationId);
      return;
    } finally {
      // D12: the ML-KEM shared secret never outlives the function that produced it.
      ssPq.fill(0);
    }

    if (ciphertextToAnnounce) {
      // The encapsulator re-announces so the peer can derive; the frame now carries the ciphertext.
      await this.sendEphemeralFrame(agentName, sessionId, correlationId);
    }
    await this.#drainHeld(agentName, sessionId, correlationId);
  }

  /**
   * A PROVEN KEY FAILURE ENDS THE SESSION — logged at error with its reason, then frozen.
   *
   * 🚨 NOT A DEGRADATION TO UNENCRYPTED. An unsigned or wrongly-signed key is what a relay
   * substituting its own looks like, and carrying on in the open would hand it the plaintext.
   * `ephemeral_pq_peer_keys_unknown` is the exception in WORDING only: it is a fault on this
   * machine, so its guidance never blames the counterparty.
   */
  async #refuseKey(agentName: string, sessionId: string, reason: string, detail: string, correlationId?: string): Promise<void> {
    const localFault = reason === EPHEMERAL_AUTH_REFUSALS.PQ_PEER_KEYS_UNKNOWN;
    this.#ctx.logger.error("session.key.refused", {
      agentName, sessionId, correlationId, reason, detail,
      guidance: localFault
        ? "STOPPED ON PURPOSE, and the fault is on THIS machine: it holds no verified post-quantum key " +
          "for your counterparty, which should have been recorded from the session assignment. Your " +
          "counterparty did nothing wrong. Report this as a CELLO defect with the log lines above."
        : "STOPPED ON PURPOSE. The session key your counterparty sent could not be tied to them, so " +
          "this session has been stopped rather than continued in the open. The ordinary cause is a " +
          "build mismatch; the one that matters is something in the middle of your connection " +
          "substituting its own key so it can read what you send. Confirm with your counterparty OUT " +
          "OF BAND — not over CELLO — before opening another session with them.",
    });
    // Session-ending, not per-message: one proven wrong signer is evidence about the CONNECTION,
    // not about the frame that carried it.
    await this.#ctx.freezeSessionForKeyRefusal(agentName, sessionId, reason, correlationId);
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
  /**
   * `attempt` is WHICH RETRY THIS IS, and it is a parameter because the catch below is the only
   * place that can advance it. It was hardcoded to 1 at the retry call site, which made
   * `SESSION_KEY_ANNOUNCE_RETRIES` unreachable: every failure re-entered the chain at 1, so the
   * bound was never tested and `session.key.announce.gave_up` was never once logged in production.
   * Measured 2026-09-08 on session `0646b474`: 49,137 failures, ~17/second, still running eleven
   * hours after the session went quiet. Do not reintroduce a literal here.
   */
  async sendEphemeralFrame(agentName: string, sessionId: string, correlationId?: string, attempt = 0): Promise<void> {
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

    const mlDsa = this.#ctx.mlDsaProvider(agentName);
    if (!mlDsa) {
      // Same shape as `no_identity_key`: a LOCAL fault, named as one, so the operator whose machine
      // cannot sign is not told their counterparty misbehaved.
      this.#ctx.logger.error("session.key.announce.failed", {
        agentName, sessionId, correlationId, reason: "no_pq_identity",
        impact: "this machine has no post-quantum identity key for the agent, so it cannot sign its half of the session key; no session it opens can agree a key and the counterparty is not involved",
        guidance: CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY],
      });
      this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY);
      return;
    }

    let stream: Awaited<ReturnType<typeof entry.node.newStream>> | null = null;
    try {
      const sessionIdBytes = Buffer.from(sessionId, "hex");
      // Decision 2: the ciphertext rides every announce while we are the encapsulator for the peer's
      // current ML-KEM key; the decapsulator's announces never carry one.
      const ct = this.#ownCiphertexts.get(this.#ctx.sessionKey(agentName, sessionId));
      const { sig, pqSig } = await signSessionEphemeral(signer, mlDsa, sessionIdBytes, ephemeral.publicKey, ephemeral.mlKemPublic, ct);
      stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      stream.send(lp.encode.single(encodeCbor({
        type: "session_key_agreement",
        session_id: sessionId,
        ephemeral_public: ephemeral.publicKey,
        mlkem_public: ephemeral.mlKemPublic,
        ...(ct ? { mlkem_ciphertext: ct } : {}),
        ephemeral_sig: sig,
        ephemeral_pq_sig: pqSig,
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
        // `extractErrorMessage`, not `String(err)`: libp2p errors are not `instanceof Error` in
        // this realm, so the ternary printed `[object Object]` on every one of the 49,137 lines
        // this loop produced — the cause was in the throw and none of it reached the log.
        error: extractErrorMessage(err),
        /**
         * Review F3 — `reason: "stream_failed"` names WHERE this surfaced, never why, and
         * `extractErrorMessage` drops the two fields that name the subsystem. libp2p's `code` IS
         * the diagnosis and the three common values send an operator to three different places:
         * `ERR_UNSUPPORTED_PROTOCOL` (counterparty on an old build), `ERR_NO_VALID_ADDRESSES`
         * (transport), `ERR_TOO_MANY_OUTBOUND_PROTOCOL_STREAMS` (the stream-cap failure this
         * file's longest comment documents). Without them this line cannot tell them apart, which
         * is why the 49,137-line loop went unnoticed for eleven hours.
         */
        errorName: (err as { name?: string } | null)?.name,
        errorCode: (err as { code?: string } | null)?.code,
        attempt,
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
      this.retryEphemeralAnnounce(agentName, sessionId, correlationId, attempt + 1);
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
      /**
       * Review F6: `error`, not `warn`. Every TRANSIENT failure on this path logs at error; the
       * one TERMINAL, actionable line — encryption is now permanently off for this session — was
       * the quietest of them, so an operator filtering on error read five noisy lines and missed
       * the conclusion.
       *
       * Review F5: `attempts: attempt`, not the constant. Five announce attempts are made (`attempt`
       * 0 through `SESSION_KEY_ANNOUNCE_RETRIES`) and the constant printed four — a hardcoded
       * literal standing in for a live value, which is the exact shape this unit exists to remove,
       * and the same bug `submission-retry.ts:115` records having made before. `attempt` is the
       * index, `attempts` is the total; that is the difference between the two field names here.
       */
      this.#ctx.logger.error("session.key.announce.gave_up", {
        agentName, sessionId, correlationId, attempts: attempt,
        impact: "this side never managed to send its half of the session key, so every message on this session takes the relay mailbox instead of the direct path",
        guidance: CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED],
      });
      return;
    }
    const timer = setTimeout(() => {
      // Stop if the session went away, or if a key has since been agreed by any route.
      if (this.#ctx.activeEntry(this.#ctx.sessionKey(agentName, sessionId)) === undefined) return;
      if (this.#sessionContentKeys.has(this.#ctx.sessionKey(agentName, sessionId))) return;
      // Carry `attempt` INTO the send, so its catch can advance it. Dropping it here is what
      // pinned the chain at 1 and made the give-up branch dead code.
      void this.sendEphemeralFrame(agentName, sessionId, correlationId, attempt);
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
  async mintSessionEphemeralForTest(agentName: string, sessionId: string): Promise<void> {
    await this.mintSessionEphemeral(agentName, sessionId);
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
  ): Promise<SessionKeyAgreementFields | null> {
    const eph = this.sessionEphemeralFor(agentName, sessionId);
    const signer = this.#ctx.keyProvider(agentName);
    const mlDsa = this.#ctx.mlDsaProvider(agentName);
    if (!eph || !signer || !mlDsa) return null;
    // The v2 frame, both signatures, through the production builder (decision 15).
    const ct = this.#ownCiphertexts.get(this.#ctx.sessionKey(agentName, sessionId));
    const { sig, pqSig } = await signSessionEphemeral(signer, mlDsa, Buffer.from(sessionId, "hex"), eph.publicKey, eph.mlKemPublic, ct);
    return {
      ephemeralPublic: Uint8Array.from(eph.publicKey),
      mlkemPublic: Uint8Array.from(eph.mlKemPublic),
      ...(ct ? { mlkemCiphertext: Uint8Array.from(ct) } : {}),
      signature: sig,
      pqSignature: pqSig,
    };
  }
  /** Test seam: this side's PUBLIC halves — X25519 and ML-KEM. Never a secret. */
  sessionEphemeralPublicsForTest(agentName: string, sessionId: string): { x25519: Uint8Array; mlKem: Uint8Array } | null {
    const e = this.sessionEphemeralFor(agentName, sessionId);
    return e ? { x25519: Uint8Array.from(e.publicKey), mlKem: Uint8Array.from(e.mlKemPublic) } : null;
  }
  /** Test seam: see each ML-KEM shared secret when it is produced, to prove it is zeroed after use (D12). */
  observeSsPqForTest(cb: (ssPq: Uint8Array) => void): void {
    this.#ssPqObserver = cb;
  }
  /** Test seam: shorten the hold window (or caps) for content awaiting the post-quantum ciphertext. */
  setPqCiphertextHoldForTest(limits: { ms?: number; maxFrames?: number; maxBytes?: number }): void {
    this.#holdLimits = { ...this.#holdLimits, ...limits };
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
    frame: SessionKeyAgreementFields,
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
    // Zeroes every X25519 secret AND every ML-KEM seed (D12).
    for (const ephemeral of this.#sessionEphemerals.values()) destroySessionEphemeral(ephemeral);
    this.#sessionEphemerals.clear();
    for (const k of [...this.#heldContent.keys()]) this.#dropHeld(k);
    this.#ownCiphertexts.clear();
    this.#awaitingPqCiphertext.clear();
  }

  /** Drop a session's held content without refusing it — the session itself is going away. */
  #dropHeld(key: string): void {
    const held = this.#heldContent.get(key);
    if (!held) return;
    clearTimeout(held.timer);
    this.#heldContent.delete(key);
  }

  /**
   * HOLD a content frame that arrived before the post-quantum ciphertext — decision 11.
   *
   * Returns `false` when this session is NOT waiting for a ciphertext, so the caller refuses as it
   * always has. Otherwise the frame is queued (cap 64 frames or 4 MiB, 30 s from the first) and
   * `replay` runs it through the normal path once the key is derived. On cap or timeout every held
   * frame's `refuse` runs, which refuses it as `pq_ciphertext_not_received`.
   */
  holdForPqCiphertext(
    agentName: string,
    sessionId: string,
    sizeBytes: number,
    replay: () => Promise<void>,
    refuse: () => void,
  ): boolean {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (!this.#awaitingPqCiphertext.has(key)) return false;
    let held = this.#heldContent.get(key);
    if (!held) {
      const timer = setTimeout(() => this.#refuseHeld(agentName, sessionId, "timeout"), this.#holdLimits.ms);
      if (typeof timer.unref === "function") timer.unref();
      held = { frames: [], bytes: 0, timer };
      this.#heldContent.set(key, held);
    }
    held.frames.push({ replay, refuse });
    held.bytes += sizeBytes;
    if (held.frames.length > this.#holdLimits.maxFrames || held.bytes > this.#holdLimits.maxBytes) {
      this.#refuseHeld(agentName, sessionId, "cap");
    }
    return true;
  }

  #refuseHeld(agentName: string, sessionId: string, cause: "timeout" | "cap"): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const held = this.#heldContent.get(key);
    if (!held) return;
    clearTimeout(held.timer);
    this.#heldContent.delete(key);
    this.#ctx.logger.warn("session.key.pq_ciphertext_timeout", {
      agentName, sessionId, cause, heldFrames: held.frames.length, heldBytes: held.bytes,
      impact: "the counterparty's post-quantum ciphertext never arrived, so the messages it had already sent could not be opened and were refused unread",
      guidance: CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.PQ_CIPHERTEXT_NOT_RECEIVED],
    });
    this.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.PQ_CIPHERTEXT_NOT_RECEIVED);
    for (const f of held.frames) f.refuse();
  }

  /** Replay held content in arrival order through the normal decrypt path, now that a key exists. */
  async #drainHeld(agentName: string, sessionId: string, correlationId?: string): Promise<void> {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const held = this.#heldContent.get(key);
    if (!held) return;
    clearTimeout(held.timer);
    this.#heldContent.delete(key);
    for (const f of held.frames) {
      try {
        await f.replay();
      } catch (err: unknown) {
        this.#ctx.logger.error("session.key.held_content.replay_failed", {
          agentName, sessionId, correlationId, error: extractErrorMessage(err),
        });
      }
    }
  }
}

/** Byte-wise order, shorter-is-lower on a shared prefix — the same rule the key derivation sorts by. */
function lexLess(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i] as number;
    const y = b[i] as number;
    if (x !== y) return x < y;
  }
  return a.length < b.length;
}
