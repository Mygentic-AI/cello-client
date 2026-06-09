/**
 * SealManager — SESSION-003, SESSION-005, PERSIST-015
 *
 * Extracted from CelloClientImpl. Handles the complete seal ceremony lifecycle:
 *   - Bilateral seal initiation (initiateSessionSeal)
 *   - Unilateral seal initiation (initiateUnilateralSeal)
 *   - FROST seal verification (handleSealVerified, handleFrostSealed)
 *   - Directory seal notifications (handleDirectorySessionSealed, handleSessionFrostSealed)
 *   - Seal rejection and tree-mismatch reconciliation
 *   - Ceremony request participation (handleCeremonyRequest)
 */

import { createHash } from "node:crypto";
import { Encoder } from "cbor-x";
import * as lp from "it-length-prefixed";
import { encodeSealPayload, buildSealTbs } from "@cello-protocol/protocol-types";
import { verify, buildMerkleTree, merkleRoot, verifyFrostSignature } from "@cello-protocol/crypto";
import type { LeafInput, IThresholdSigner, KeyProvider } from "@cello-protocol/crypto";
import type { Stream } from "@libp2p/interface";
import type { SessionRecord } from "./types.js";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

/**
 * Narrow interface exposing only what SealManager needs from CelloClientImpl.
 */
export interface SealContext {
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  readonly keyProvider: KeyProvider;
  getMyPubkeyHex(): string | null;
  getThresholdSigner(): IThresholdSigner | undefined;
  // From SessionManager
  getSession(sessionIdHex: string): SessionRecord | undefined;
  getSessions(): Map<string, SessionRecord>;
  getOwnPendingContent(sessionIdHex: string): Map<string, { content_bytes: Uint8Array; arrived_at: number }> | undefined;
  getPendingAckResolver(sessionIdHex: string): ((ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void) | undefined;
  setPendingAckResolver(sessionIdHex: string, resolve: (ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void): void;
  deletePendingAckResolver(sessionIdHex: string): void;
  // From SignalingManager
  getPersistentSignalingStream(): Stream | null;
  setPersistentSignalingStream(stream: Stream | null): void;
  setPersistentSignalingIter(iter: AsyncIterator<Uint8Array> | null): void;
  openPersistentSignalingStream(): Promise<boolean>;
  // From RelayStreamManager
  getRelayStream(sessionIdHex: string): Stream | undefined;
  getDirectoryStream(sessionIdHex: string): Stream | undefined;
  // Callbacks into SessionManager
  enqueueSessionSealedEvent(sessionIdHex: string, sealedRoot: Uint8Array, closeTimestamp: number): void;
  sendContentFrame(session: SessionRecord, content: Uint8Array, contentHash: Uint8Array): Promise<void>;
  waitForOwnEcho(sessionIdHex: string, seqNum: number): Promise<void>;
  // Callback into RelayStreamManager
  performGapFillReconciliation(sessionIdHex: string, fromSeq: number, toSeq: number, correlationId: string): Promise<void>;
}

export class SealManager {
  readonly #ctx: SealContext;
  readonly #sealFrostTimeoutMs: number;

  // ─── Owned state ─────────────────────────────────────────────────────────────

  // SESSION-005: session_id_hex → resolve fn for seal-frost-timeout Promise
  readonly #sealFrostResolvers = new Map<string, () => void>();

  // SESSION-005: session_id_hex → { leafCount, timestamp } from seal_verified frame.
  readonly #sealVerifiedData = new Map<string, { leafCount: number; timestamp: number }>();

  // Session IDs where THIS client is the FROST ceremony participant
  readonly #frostCeremonyParticipant = new Set<string>();

  // Session IDs where seal was initiated by this client
  readonly #sealInitiatedSessions = new Set<string>();

  // Pending resolver for seal_unilateral_confirmed / seal_unilateral_too_early (PERSIST-015)
  #pendingUnilateralSealResolve: ((frame: Record<string, unknown>) => void) | null = null;

  // SESSION-005: track the primary_pubkey for this client (set after bootstrapKeyShares)
  #myPrimaryPubkey: Uint8Array | null = null;

  constructor(ctx: SealContext, sealFrostTimeoutMs: number) {
    this.#ctx = ctx;
    this.#sealFrostTimeoutMs = sealFrostTimeoutMs;
  }

  // ─── State accessors (called by facade.closeSession, loadPersistedState) ──────

  setMyPrimaryPubkey(pubkey: Uint8Array): void {
    this.#myPrimaryPubkey = pubkey;
  }

  getMyPrimaryPubkey(): Uint8Array | null {
    return this.#myPrimaryPubkey;
  }

  /** Mark a session as seal-initiated by this client (called from injectTestSession). */
  markSealInitiated(sessionIdHex: string): void {
    this.#sealInitiatedSessions.add(sessionIdHex);
  }

  /** Mark a session as having a FROST ceremony participant (called from injectTestSession). */
  markFrostCeremonyParticipant(sessionIdHex: string): void {
    this.#frostCeremonyParticipant.add(sessionIdHex);
  }

  /**
   * Resolve the pending unilateral seal waiter (if any) with the given frame.
   * Called from facade.#dispatchSignalingFrame for seal_unilateral_confirmed and
   * seal_unilateral_too_early frames. Clears the resolver after calling it.
   */
  resolvePendingUnilateralSeal(frame: Record<string, unknown>): void {
    if (this.#pendingUnilateralSealResolve) {
      const resolve = this.#pendingUnilateralSealResolve;
      this.#pendingUnilateralSealResolve = null;
      resolve(frame);
    }
  }

  closeSession(sessionIdHex: string): void {
    // Resolve seal-frost-timeout waiter so initiateSessionSeal doesn't hang
    this.#sealFrostResolvers.get(sessionIdHex)?.();
    this.#sealFrostResolvers.delete(sessionIdHex);
    this.#sealVerifiedData.delete(sessionIdHex);
    this.#sealInitiatedSessions.delete(sessionIdHex);
    this.#frostCeremonyParticipant.delete(sessionIdHex);
  }

  async initiateSessionSeal(sessionIdHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return { ok: false, reason: "session_not_found" };
    if (session.status !== "active" && session.status !== "sealing") {
      return { ok: false, reason: "session_not_active" };
    }

    // If the counterparty already initiated a seal (status === "sealing"), act as responder.
    // The relay needs both parties' ctrl leaves; blocking the responder here was the deadlock.
    // Guard: if this client already initiated (#sealInitiatedSessions set), don't double-submit.
    if (session.status === "sealing") {
      if (this.#sealInitiatedSessions.has(sessionIdHex)) {
        return { ok: true };
      }

      // Ensure the signaling stream is alive — the directory's seal_verified response (which
      // triggers the FROST ceremony) arrives on this stream. A dead stream means the ceremony
      // never starts and the session stays "sealing" forever.
      const sigStreamR = this.#ctx.getPersistentSignalingStream();
      if (!sigStreamR || sigStreamR.status !== "open") {
        const correlationId = Buffer.from(session.session_id).toString("hex");
        this.#ctx.logger.info("seal.reconnect.attempted", { sessionId: sessionIdHex, correlationId });
        this.#ctx.setPersistentSignalingStream(null);
        this.#ctx.setPersistentSignalingIter(null);
        const opened = await this.#ctx.openPersistentSignalingStream();
        if (!opened || !this.#ctx.getPersistentSignalingStream()) {
          return { ok: false, reason: "directory_unreachable" };
        }
        // Re-check after async gap: a concurrent call may have already set #sealInitiatedSessions.
        if (this.#sealInitiatedSessions.has(sessionIdHex)) {
          return { ok: true };
        }
      }

      this.#sealInitiatedSessions.add(sessionIdHex);
      const result = await this.#submitSealLeaf(sessionIdHex, session, "responder");
      if (!result.ok) {
        // Clear the guard so a retry is possible when the transport comes back.
        this.#sealInitiatedSessions.delete(sessionIdHex);
        return result;
      }

      // If a threshold signer is configured, wait for the FROST ceremony to complete
      // (same fallback logic as the initiator path — timeout → seal_deferred).
      if (this.#ctx.getThresholdSigner()) {
        // Only register a resolver if one isn't already set — prevents overwriting the
        // initiator's waiter if both parties call initiateSessionSeal concurrently.
        if (!this.#sealFrostResolvers.has(sessionIdHex)) {
          const sealReceived = new Promise<void>((resolve) => {
            this.#sealFrostResolvers.set(sessionIdHex, resolve);
          });
          const timeout = new Promise<void>((resolve) =>
            setTimeout(resolve, this.#sealFrostTimeoutMs)
          );
          await Promise.race([sealReceived, timeout]);
          this.#sealFrostResolvers.delete(sessionIdHex);
        }

        const sessAfter = this.#ctx.getSession(sessionIdHex);
        if (sessAfter && sessAfter.status === "sealing") {
          sessAfter.status = "seal_deferred";
          sessAfter.seal_type = "bilateral";
          const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
          if (sealVerifiedEntry) {
            sessAfter.close_timestamp = sealVerifiedEntry.timestamp;
          }
          void this.#ctx.persistence?.persistSession(sessionIdHex, sessAfter);
        }
      }

      return { ok: true };
    }

    // Fix 1: ensure the signaling stream is alive before mutating session state.
    // The directory replies (seal_verified / session_frost_sealed) on this stream.
    // If the stream dropped silently (libp2p TCP idle disconnect), the reply is lost,
    // the 15-second FROST timeout fires, and the session permanently ends as seal_deferred.
    // Reconnecting first guarantees the directory's response lands on a live reader loop.
    // Status mutation is deferred until after reconnect succeeds to avoid a sealing-stuck
    // crash window (if the process restarts between the persist and the rollback, the session
    // would be permanently unresealable).
    const sigStream = this.#ctx.getPersistentSignalingStream();
    if (!sigStream || sigStream.status !== "open") {
      const correlationId = Buffer.from(session.session_id).toString("hex");
      this.#ctx.logger.info("seal.reconnect.attempted", { sessionId: sessionIdHex, correlationId });
      this.#ctx.setPersistentSignalingStream(null);
      this.#ctx.setPersistentSignalingIter(null);
      const opened = await this.#ctx.openPersistentSignalingStream();
      if (!opened || !this.#ctx.getPersistentSignalingStream()) {
        return { ok: false, reason: "directory_unreachable" };
      }
      // Re-validate after the async reconnect: a concurrent caller may have already
      // mutated session status while this call was awaiting the stream open.
      // TypeScript narrows session.status to "active" at this point (line 1732 guard), but
      // async suspension means the actual value may have changed — re-read via a typed cast.
      // Mirror the guard at #sendMessageLocked: sealing/sealed/seal_deferred/seal_rejected → "session_sealed".
      const statusNow = (session as SessionRecord).status;
      if (statusNow === "sealing" || statusNow === "sealed" || statusNow === "seal_deferred" || statusNow === "seal_rejected") {
        return { ok: false, reason: "session_sealed" };
      }
      if (statusNow !== "active") return { ok: false, reason: "session_not_active" };
    }

    session.status = "sealing";
    this.#sealInitiatedSessions.add(sessionIdHex);
    // CRIT-1: persist sealing status
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);

    const result = await this.#submitSealLeaf(sessionIdHex, session, "initiator");
    if (!result.ok) return result;

    // SESSION-005: if a threshold signer is configured, wait for the FROST seal ceremony.
    // The directory runs verification and FROST ceremony; if it doesn't reply within
    // sealFrostTimeoutMs, this is a bilateral seal (directory unreachable).
    // Without a threshold signer (M1 compatibility), return immediately —
    // the M1 single-key seal notification will arrive asynchronously.
    if (this.#ctx.getThresholdSigner()) {
      const sealReceived = new Promise<void>((resolve) => {
        this.#sealFrostResolvers.set(sessionIdHex, resolve);
      });

      const timeout = new Promise<void>((resolve) =>
        setTimeout(resolve, this.#sealFrostTimeoutMs)
      );

      await Promise.race([sealReceived, timeout]);

      // Clean up resolver
      this.#sealFrostResolvers.delete(sessionIdHex);

      // Check if session_sealed arrived (status would be 'sealed' by now)
      const sess = this.#ctx.getSession(sessionIdHex);
      if (sess && sess.status === "sealing") {
        // Timeout elapsed without session_sealed — bilateral fallback (DB-001)
        sess.status = "seal_deferred";
        sess.seal_type = "bilateral";
        // M-003: store the verified timestamp so handleSessionFrostSealed can reconstruct
        // the exact TBS if the directory later completes the deferred FROST ceremony.
        const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
        if (sealVerifiedEntry) {
          sess.close_timestamp = sealVerifiedEntry.timestamp;
        }
        // CRIT-1: persist seal_deferred status
        void this.#ctx.persistence?.persistSession(sessionIdHex, sess);
      }
    }

    return { ok: true };
  }

  // PERSIST-015: send seal_unilateral to the directory after delivery_grace_seconds elapses.
  async initiateUnilateralSeal(
    sessionIdHex: string,
  ): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  > {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return { ok: false, reason: "session_not_found" };
    if (session.status !== "active" && session.status !== "sealing") {
      return { ok: false, reason: "session_not_active" };
    }

    const sigStream = this.#ctx.getPersistentSignalingStream();
    if (!sigStream || sigStream.status !== "open") {
      this.#ctx.setPersistentSignalingStream(null);
      this.#ctx.setPersistentSignalingIter(null);
      const opened = await this.#ctx.openPersistentSignalingStream();
      if (!opened || !this.#ctx.getPersistentSignalingStream()) {
        return { ok: false, reason: "directory_unreachable" };
      }
    }

    const localRoot = this.#computeLocalRoot(session) ?? session.genesis_prev_root;
    const reportedSeq = session.next_expected_seq - 1;

    const frame = CBOR_ENC.encode({
      type: "seal_unilateral",
      session_id: session.session_id,
      reported_root: localRoot,
      reported_seq: reportedSeq,
    }) as Uint8Array;

    this.#ctx.getPersistentSignalingStream()!.send(lp.encode.single(frame));

    const UNILATERAL_TIMEOUT_MS = 15_000;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const responseFrame = await Promise.race<Record<string, unknown>>([
      new Promise<Record<string, unknown>>((resolve) => {
        this.#pendingUnilateralSealResolve = resolve;
      }),
      new Promise<Record<string, unknown>>((resolve) => {
        timeoutHandle = setTimeout(() => {
          this.#pendingUnilateralSealResolve = null;
          resolve({ type: "seal_unilateral_error", reason: "timeout" });
        }, UNILATERAL_TIMEOUT_MS);
      }),
    ]);
    clearTimeout(timeoutHandle);

    if (responseFrame["type"] === "seal_unilateral_confirmed") {
      const sealedRootRaw = responseFrame["sealed_root"];
      const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
        : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer)
        : new Uint8Array(32);
      const sealedAt = typeof responseFrame["sealed_at"] === "number" ? responseFrame["sealed_at"] : Date.now();
      return { ok: true, sealed_root: sealedRoot, sealed_at: sealedAt };
    }

    if (responseFrame["type"] === "seal_unilateral_too_early") {
      const remainingSeconds = typeof responseFrame["remaining_seconds"] === "number"
        ? responseFrame["remaining_seconds"] : 0;
      return { ok: false, reason: "too_early", remaining_seconds: remainingSeconds };
    }

    return { ok: false, reason: (responseFrame["reason"] as string | undefined) ?? "unknown" };
  }

  async #submitSealLeaf(
    sessionIdHex: string,
    session: SessionRecord,
    _role: "initiator" | "responder",
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const relayStream = this.#ctx.getRelayStream(sessionIdHex);
    if (!relayStream || relayStream.status !== "open") {
      return { ok: false, reason: "transport_unavailable" };
    }

    // Compute current local tree root (R_tail for initiator, root-after-initiator-SEAL for responder)
    const finalRoot = session.local_tree_leaves.length === 0
      ? session.genesis_prev_root
      : (() => {
          const inputs: LeafInput[] = session.local_tree_leaves.map(l => ({
            kind: l.kind,
            data: l.s2_cbor,
          }));
          return merkleRoot(buildMerkleTree(inputs));
        })();

    const close_timestamp = Date.now();
    const sealPayload = encodeSealPayload({
      session_id: session.session_id,
      final_root: finalRoot,
      close_timestamp,
      attestation: "PENDING",
    });

    // content_hash = SHA-256(0x02 || seal_payload) — ctrl leaf kind byte is 0x02
    const contentHash = new Uint8Array(
      createHash("sha256").update(new Uint8Array([0x02])).update(sealPayload).digest()
    );

    const myPubkeyHex = this.#ctx.getMyPubkeyHex()!;
    const myPubkeyBytes = Buffer.from(myPubkeyHex, "hex");

    const tbs = CBOR_ENC.encode([
      1,
      contentHash,
      myPubkeyBytes,
      session.session_id,
      session.last_seen_seq,
      close_timestamp,
    ]) as Uint8Array;
    const signature = await this.#ctx.keyProvider.sign(tbs);

    const hashSubmitFrame = CBOR_ENC.encode({
      type: "hash_submit",
      session_id: session.session_id,
      leaf_kind: 0x02,
      structure1_cbor: tbs,
      sender_signature: signature,
    }) as Uint8Array;

    const contentHashHex = Buffer.from(contentHash).toString("hex");
    this.#ctx.getOwnPendingContent(sessionIdHex)?.set(contentHashHex, {
      content_bytes: sealPayload,
      arrived_at: Date.now(),
    });

    if (this.#ctx.getPendingAckResolver(sessionIdHex)) {
      this.#ctx.getOwnPendingContent(sessionIdHex)?.delete(contentHashHex);
      return { ok: false, reason: "ack_resolver_conflict" };
    }
    let ackResolve!: (v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void;
    const ackPromise = new Promise<{ ok: true; sequence_number: number } | { ok: false; reason: string }>(
      (r) => { ackResolve = r; }
    );
    this.#ctx.setPendingAckResolver(sessionIdHex, ackResolve);

    try {
      relayStream.send(lp.encode.single(hashSubmitFrame));
    } catch {
      this.#ctx.deletePendingAckResolver(sessionIdHex);
      this.#ctx.getOwnPendingContent(sessionIdHex)?.delete(contentHashHex);
      return { ok: false, reason: "transport_unavailable" };
    }

    const ack = await ackPromise;
    if (!ack.ok) return { ok: false, reason: "relay_rejected" };

    const mySeq = ack.sequence_number;

    // Send SEAL payload as content_frame to counterparty so they can cross-check
    const sess2 = this.#ctx.getSession(sessionIdHex);
    if (sess2 && !sess2.desynchronized) {
      void this.#ctx.sendContentFrame(sess2, sealPayload, contentHash);
    }

    // Wait for own echo
    await this.#ctx.waitForOwnEcho(sessionIdHex, mySeq);

    const sess3 = this.#ctx.getSession(sessionIdHex);
    if (!sess3 || sess3.desynchronized) return { ok: false, reason: "session_desynchronized" };

    return { ok: true };
  }

  // ─── Directory signaling stream (SESSION-003) ────────────────────────────────

  handleDirectorySessionSealed(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    directoryPubkey: Uint8Array,
  ): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;

    const signatureType = frame["signature_type"];

    // If this client has a threshold signer (M2 mode), enforce FROST-only.
    if (this.#ctx.getThresholdSigner()) {
      // SI-003: reject M1-era single-key seal notarizations in M2 mode
      if (signatureType === "single") {
        this.#ctx.logger.warn("seal.signature.type.unsupported", { sessionId: sessionIdHex, signatureType: "single" });
        return;
      }
      if (signatureType !== "frost") {
        // Unknown signature_type — ignore
        return;
      }
      this.#handleFrostSealed(sessionIdHex, frame, session);
    } else {
      // M1 compatibility mode: no threshold signer — verify directory_signature
      this.#handleSingleSealed(sessionIdHex, frame, directoryPubkey, session);
    }
  }

  /** No-threshold-signer path: handles both 'single' (Ed25519 dir sig) and 'frost' seal frames. */
  #handleSingleSealed(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    directoryPubkey: Uint8Array,
    session: SessionRecord,
  ): void {
    const signatureType = frame["signature_type"];
    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const ctRaw = frame["close_timestamp"];
    const closeTimestamp = typeof ctRaw === "number" ? ctRaw : typeof ctRaw === "bigint" ? Number(ctRaw) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;

    if (!sealedRoot || sealedRoot.length !== 32) return;
    if (closeTimestamp === null) return;
    if (!sessionId) return;

    if (signatureType === "frost") {
      // FROST seal received by an M1 client (no threshold signer).
      // Verify using the signer_pubkey embedded in the frame (initiator's primary_pubkey).
      const frostSigRaw = frame["frost_signature"];
      const frostSig = frostSigRaw instanceof Uint8Array ? frostSigRaw
        : Buffer.isBuffer(frostSigRaw) ? new Uint8Array(frostSigRaw as Buffer) : null;
      const signerPubkeyRaw = frame["signer_pubkey"];
      const signerPubkey = signerPubkeyRaw instanceof Uint8Array ? signerPubkeyRaw
        : Buffer.isBuffer(signerPubkeyRaw) ? new Uint8Array(signerPubkeyRaw as Buffer) : null;
      if (!frostSig || frostSig.length !== 64) return;
      if (!signerPubkey || signerPubkey.length !== 32) return;

      // Use sealVerifiedData if available (responder also gets seal_verified when M2 initiator),
      // else fall back to local_tree_leaves.length.
      const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
      const leafCount = sealVerifiedEntry?.leafCount ?? session.local_tree_leaves.length;
      const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, closeTimestamp);

      if (!verifyFrostSignature(frostSig, tbs, "cello-frost-seal-v1", signerPubkey)) {
        this.#ctx.logger.warn("seal.frost.signature.invalid", { sessionId: sessionIdHex, path: "m1_compat_frost" });
        return;
      }

      session.status = "sealed";
      session.sealed_root = sealedRoot;
      session.frost_signature = frostSig;
      session.signer_pubkey = signerPubkey;
      session.seal_type = "frost";
      session.close_timestamp = closeTimestamp;
      this.#sealVerifiedData.delete(sessionIdHex);
      // CRIT-1: persist sealed state
      void this.#ctx.persistence?.persistSession(sessionIdHex, session);
      // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
      this.#ctx.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
    } else {
      // M1 single-key: verify directory_signature against pinned directory pubkey
      const dirSigRaw = frame["directory_signature"];
      const dirSig = dirSigRaw instanceof Uint8Array ? dirSigRaw
        : Buffer.isBuffer(dirSigRaw) ? new Uint8Array(dirSigRaw as Buffer) : null;
      if (!dirSig || dirSig.length !== 64) return;

      // SI-005 (M1): verify directory signature against pinned directory pubkey
      const tbs = CBOR_ENC.encode([
        sessionId,
        sealedRoot,
        closeTimestamp > 0xffffffff ? BigInt(closeTimestamp) : closeTimestamp,
      ]) as Uint8Array;

      if (!verify(directoryPubkey, tbs, dirSig)) {
        this.#ctx.logger.warn("seal.directory.signature.invalid", { sessionId: sessionIdHex });
        return;
      }

      session.status = "sealed";
      session.sealed_root = sealedRoot;
      session.directory_signature = dirSig;
      session.close_timestamp = closeTimestamp;
      // CRIT-1: persist sealed state
      void this.#ctx.persistence?.persistSession(sessionIdHex, session);
      // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
      this.#ctx.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
    }

    // Resolve the seal-frost-timeout waiter
    this.#sealFrostResolvers.get(sessionIdHex)?.();
  }

  /** M2 FROST seal verification. */
  #handleFrostSealed(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    session: SessionRecord,
  ): void {
    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const frostSigRaw = frame["frost_signature"];
    const frostSig = frostSigRaw instanceof Uint8Array ? frostSigRaw
      : Buffer.isBuffer(frostSigRaw) ? new Uint8Array(frostSigRaw as Buffer) : null;
    const signerPubkeyRaw = frame["signer_pubkey"];
    const signerPubkey = signerPubkeyRaw instanceof Uint8Array ? signerPubkeyRaw
      : Buffer.isBuffer(signerPubkeyRaw) ? new Uint8Array(signerPubkeyRaw as Buffer) : null;
    const ctRaw = frame["close_timestamp"];
    const closeTimestamp = typeof ctRaw === "number" ? ctRaw : typeof ctRaw === "bigint" ? Number(ctRaw) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;
    const leafCountRaw = frame["leaf_count"];
    // Prefer stored sealVerifiedData so we use the same leafCount that was used during
    // the FROST ceremony, even if local_tree_leaves is incomplete due to a desync race.
    const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
    const leafCount = typeof leafCountRaw === "number" ? leafCountRaw
      : (sealVerifiedEntry?.leafCount ?? session.local_tree_leaves.length);
    const resolvedCloseTimestamp = closeTimestamp ?? sealVerifiedEntry?.timestamp ?? null;

    if (!sealedRoot || sealedRoot.length !== 32) return;
    if (!frostSig || frostSig.length !== 64) return;
    if (!signerPubkey || signerPubkey.length !== 32) return;
    if (resolvedCloseTimestamp === null) return;
    if (!sessionId) return;

    const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, resolvedCloseTimestamp);

    // Determine verification key.
    // Use #myPrimaryPubkey only if this client ran the FROST ceremony (received seal_verified).
    // #frostCeremonyParticipant is set by handleSealVerified before the ceremony runs —
    // a concurrent-close counterparty (in sealInitiatedSessions but NOT frostCeremonyParticipant)
    // must use signerPubkey from the frame (the actual initiator's key).
    const isFrostInitiator = this.#frostCeremonyParticipant.has(sessionIdHex);
    let verifyKey: Uint8Array;
    if (isFrostInitiator) {
      const myPrimaryPubkey = this.#myPrimaryPubkey;
      if (!myPrimaryPubkey) {
        this.#ctx.logger.warn("seal.frost.initiator.no.primary.pubkey", { sessionId: sessionIdHex });
        return;
      }
      verifyKey = myPrimaryPubkey;
    } else {
      verifyKey = signerPubkey;
    }

    // SI-001: verify FROST signature before transitioning to sealed.
    if (!this.#ctx.getThresholdSigner()!.verifySignature(frostSig, tbs, "cello-frost-seal-v1", verifyKey)) {
      this.#ctx.logger.warn("seal.frost.signature.invalid", { sessionId: sessionIdHex, path: "m2_frost" });
      return;
    }

    session.status = "sealed";
    session.sealed_root = sealedRoot;
    session.frost_signature = frostSig;
    session.signer_pubkey = signerPubkey;
    session.seal_type = "frost";
    session.close_timestamp = resolvedCloseTimestamp;
    this.#sealVerifiedData.delete(sessionIdHex);
    // CRIT-1: persist sealed state
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);
    // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
    this.#ctx.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, resolvedCloseTimestamp);

    // Resolve the seal-frost-timeout waiter so initiateSessionSeal returns promptly
    this.#sealFrostResolvers.get(sessionIdHex)?.();
  }

  handleDirectorySessionSealRejected(sessionIdHex: string, _frame: Record<string, unknown>): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;
    session.status = "seal_rejected";
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);
    // Also resolve the seal-frost-timeout waiter so initiateSessionSeal doesn't wait for the timeout
    this.#sealFrostResolvers.get(sessionIdHex)?.();
  }

  /**
   * PERSIST-014: Handle seal_rejected_tree_mismatch from the directory.
   * Determines if this client is the behind party and initiates gap-fill reconciliation.
   */
  handleSealRejectedTreeMismatch(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;

    const partyASequence = typeof frame["party_a_sequence"] === "number" ? frame["party_a_sequence"] : 0;
    const partyBSequence = typeof frame["party_b_sequence"] === "number" ? frame["party_b_sequence"] : 0;

    // Determine this client's local sequence (highest seq in its Merkle tree).
    // next_expected_seq is 1-indexed: the next seq the relay will assign, so local highest = next - 1.
    const mySequence = session.next_expected_seq - 1;
    const aheadSequence = Math.max(partyASequence, partyBSequence);

    if (mySequence >= aheadSequence) {
      // We are NOT the behind party — wait for the behind party to reconcile and retry
      return;
    }

    // We are the behind party — initiate gap-fill reconciliation
    const gapSize = aheadSequence - mySequence;
    const correlationId = Buffer.from(session.session_id).toString("hex") + "-" + Date.now().toString(36);

    this.#ctx.logger.info("session.reconciliation.started", {
      sessionId: sessionIdHex,
      gapSize,
      fromSequence: mySequence,
      toSequence: aheadSequence,
      correlationId,
    });

    void this.#ctx.performGapFillReconciliation(sessionIdHex, mySequence, aheadSequence, correlationId);
  }

  /**
   * PERSIST-015: Handle seal_unilateral_confirmed from the directory.
   * The submitting party receives this when the unilateral seal succeeds.
   */
  handleSealUnilateralConfirmed(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;

    session.status = "sealed";
    if (sealedRoot) session.sealed_root = sealedRoot;
    session.seal_type = "unilateral";
    session.close_timestamp = typeof frame["sealed_at"] === "number" ? frame["sealed_at"] : Date.now();
    // CRIT-1: persist sealed state
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);

    const correlationId = Buffer.from(session.session_id).toString("hex");
    this.#ctx.logger.info("session.sealed", {
      sessionId: sessionIdHex,
      sealType: "UNILATERAL",
      rootHash: sealedRoot ? Buffer.from(sealedRoot).toString("hex") : "unknown",
      correlationId,
    });

    // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
    if (sealedRoot) {
      this.#ctx.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, session.close_timestamp ?? Date.now());
    }

    // Resolve the FROST ceremony waiter only if a bilateral seal was in-flight for this session.
    // The unilateral and FROST paths are mutually exclusive once the session seals — resolving an
    // absent FROST waiter is harmless (map miss returns undefined), but resolving a present one
    // spuriously would confuse the bilateral seal flow. Guard on whether the session was actually
    // in sealing state via the FROST path before the unilateral confirmation arrived.
    if (this.#sealInitiatedSessions.has(sessionIdHex)) {
      this.#sealFrostResolvers.get(sessionIdHex)?.();
    }
  }

  /**
   * PERSIST-015: Handle seal_unilateral_notification from the directory.
   * The absent party receives this on reconnect — verifies sealed root against local state.
   */
  handleSealUnilateralNotification(sessionIdHex: string, frame: Record<string, unknown>): void {
    let session = this.#ctx.getSession(sessionIdHex);
    if (!session) {
      // Absent party reconnecting after session was sealed without them — create a minimal
      // sealed session record so the notification is observable via listSessions().
      const sessionIdRaw = frame["session_id"];
      const sessionId = sessionIdRaw instanceof Uint8Array ? sessionIdRaw
        : Buffer.isBuffer(sessionIdRaw) ? new Uint8Array(sessionIdRaw as Buffer)
        : Buffer.from(sessionIdHex, "hex");
      // Build the stub as sealed from the start — no transient "active" state visible to readers.
      // Fields like counterparty_pubkey and directory_pubkey are zeroed because the absent party
      // does not have session state; computeLocalRoot handles the empty-leaves case explicitly.
      const stub: SessionRecord = {
        session_id: sessionId,
        counterparty_pubkey: new Uint8Array(32),
        counterparty_peer_id: "",
        counterparty_multiaddrs: [],
        relay_endpoint: { peer_id: "", multiaddrs: [] },
        directory_endpoint: { peer_id: "", multiaddrs: [] },
        directory_pubkey: new Uint8Array(32),
        genesis_prev_root: new Uint8Array(32),
        last_seen_seq: 0,
        last_sent_seq: 0,
        status: "sealed",
        seal_type: "unilateral",
        local_tree_leaves: [],
        next_expected_seq: 1,
        desynchronized: false,
      };
      this.#ctx.getSessions().set(sessionIdHex, stub);
      session = stub;
    }

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const closeTimestamp = typeof frame["sealed_at"] === "number" ? frame["sealed_at"] : Date.now();

    // AC-004: Verify sealed root against local Merkle state BEFORE committing sealed status.
    // If local state exists and the roots differ, reject the notification — a tampered or
    // mismatched root must not be committed as a valid sealed record.
    const localRoot = this.#computeLocalRoot(session);

    if (localRoot != null) {
      const match = sealedRoot != null && Buffer.from(localRoot).equals(Buffer.from(sealedRoot));
      if (!match) {
        this.#ctx.logger.warn("session.unilateral.mismatch", {
          sessionId: sessionIdHex,
          localRoot: Buffer.from(localRoot).toString("hex"),
          sealedRoot: sealedRoot ? Buffer.from(sealedRoot).toString("hex") : "null",
          correlationId: sessionIdHex,
        });
        return;
      }
      this.#ctx.logger.info("session.unilateral.verified", {
        sessionId: sessionIdHex,
        match: true,
        correlationId: sessionIdHex,
      });
    } else {
      // Cannot verify — no local leaves received yet; proceed but log distinctly.
      this.#ctx.logger.info("session.unilateral.no.local.state", {
        sessionId: sessionIdHex,
        correlationId: sessionIdHex,
      });
    }

    session.status = "sealed";
    if (sealedRoot) session.sealed_root = sealedRoot;
    session.seal_type = "unilateral";
    session.close_timestamp = closeTimestamp;
    // CRIT-1: persist sealed state
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);

    // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
    if (sealedRoot) {
      this.#ctx.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, session.close_timestamp!);
    }
  }

  /**
   * PERSIST-015: Compute the local Merkle root from the session's accepted leaves.
   */
  computeLocalRoot(session: SessionRecord): Uint8Array | null {
    return this.#computeLocalRoot(session);
  }

  #computeLocalRoot(session: SessionRecord): Uint8Array | null {
    if (!session.local_tree_leaves || session.local_tree_leaves.length === 0) return null;
    const leafInputs: LeafInput[] = session.local_tree_leaves.map((l) => ({
      kind: l.kind,
      data: l.s2_cbor,
    }));
    const tree = buildMerkleTree(leafInputs);
    return merkleRoot(tree);
  }

  /**
   * SESSION-005: Handle seal_verified event from the directory.
   * The directory has verified the Merkle tree; the initiator must now coordinate
   * the FROST ceremony and return the combined signature.
   */
  async handleSealVerified(sessionIdHex: string, frame: Record<string, unknown>): Promise<void> {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;
    const thresholdSigner = this.#ctx.getThresholdSigner();
    if (!thresholdSigner) return; // no FROST signer — bilateral only

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;
    const leafCountRaw = frame["leaf_count"];
    const leafCount = typeof leafCountRaw === "number" ? leafCountRaw : null;
    const tsRaw = frame["timestamp"];
    const timestamp = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;

    if (!sealedRoot || !sessionId || leafCount === null || timestamp === null) return;

    // Store for handleSessionFrostSealed so it can use the authoritative leafCount/timestamp
    // even if local_tree_leaves is incomplete due to a desync race.
    this.#sealVerifiedData.set(sessionIdHex, { leafCount, timestamp });
    // Mark this client as the FROST ceremony participant so handleFrostSealed uses
    // myPrimaryPubkey for verification (anti-substitution guard).
    this.#frostCeremonyParticipant.add(sessionIdHex);

    const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, timestamp);

    // Participate in the FROST seal ceremony as coordinator
    const ceremonyId = `seal:${sessionIdHex}`;
    let result;
    try {
      result = await thresholdSigner.participateInCeremony(
        ceremonyId,
        tbs,
        "cello-frost-seal-v1",
      );
    } catch {
      // Ceremony failed — bilateral fallback; do not send seal_frost_signature
      return;
    }

    if (!result.ok) {
      // DB-002: ceremony failed (threshold not met) — bilateral fallback
      return;
    }

    // Send seal_frost_signature to directory.
    // Prefer the per-session directory stream; fall back to the persistent signaling stream
    // (which is used when receiveSessionAssignment detects a persistent stream is already open).
    const dirStream = this.#ctx.getDirectoryStream(sessionIdHex);
    const sendStream = (dirStream && dirStream.status === "open") ? dirStream : this.#ctx.getPersistentSignalingStream();
    if (!sendStream) return;

    const sealFrostSigFrame = CBOR_ENC.encode({
      type: "seal_frost_signature",
      session_id: sessionId,
      frost_signature: result.signature,
    }) as Uint8Array;

    try {
      sendStream.send(lp.encode.single(sealFrostSigFrame));
    } catch {
      // Stream closed — bilateral fallback
    }
  }

  /**
   * Handle ceremony_request from the directory.
   * The directory sends this when a session_request requires a FROST ceremony but
   * the directory is not the coordinator. The client runs participateInCeremony
   * and sends back a ceremony_result with the combined signature.
   */
  async handleCeremonyRequest(
    stream: Stream,
    frame: Record<string, unknown>,
  ): Promise<void> {
    const thresholdSigner = this.#ctx.getThresholdSigner();
    this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: thresholdSigner=${thresholdSigner ? "SET" : "NULL"}` });
    if (!thresholdSigner) {
      this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: ABORT thresholdSigner is null — sending null ceremony_result` });
      const ceremonyId = frame["ceremony_id"] as string | undefined;
      if (ceremonyId) {
        stream.send(lp.encode.single(CBOR_ENC.encode({ type: "ceremony_result", ceremony_id: ceremonyId, signature: null })));
      }
      return;
    }

    const ceremonyId = frame["ceremony_id"] as string | undefined;
    const tbsRaw = frame["tbs"];
    const tbs = tbsRaw instanceof Uint8Array ? tbsRaw
      : Buffer.isBuffer(tbsRaw) ? new Uint8Array(tbsRaw as Buffer) : null;
    const context = frame["context"] as string | undefined;

    this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: ceremonyId=${ceremonyId?.slice(0,16)} tbs=${tbs ? `Uint8Array(${tbs.length})` : "NULL"} context=${context}` });

    if (!ceremonyId || !tbs || !context) {
      this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: ABORT missing fields ceremonyId=${!!ceremonyId} tbs=${!!tbs} context=${!!context}` });
      return;
    }

    try {
      this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: calling participateInCeremony` });
      const result = await thresholdSigner.participateInCeremony(
        ceremonyId,
        tbs,
        context as import("@cello-protocol/crypto/frost/types.js").FrostContext,
      );
      this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: participateInCeremony returned ok=${result.ok} reason=${!result.ok ? (result as { error: { reason: string } }).error?.reason : "N/A"}` });

      const sig = result.ok ? result.signature : null;
      stream.send(lp.encode.single(CBOR_ENC.encode({
        type: "ceremony_result",
        ceremony_id: ceremonyId,
        signature: sig ? new Uint8Array(sig) : null,
      })));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.#ctx.logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: CAUGHT ERROR: ${msg}` });
      stream.send(lp.encode.single(CBOR_ENC.encode({
        type: "ceremony_result",
        ceremony_id: ceremonyId,
        signature: null,
      })));
    }
  }

  /**
   * SESSION-005: Handle session_frost_sealed event — deferred FROST seal completed.
   * Sent by the directory when a previously deferred seal ceremony completes.
   * Updates the session from seal_deferred/bilateral to sealed/frost.
   */
  handleSessionFrostSealed(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const frostSigRaw = frame["frost_signature"];
    const frostSig = frostSigRaw instanceof Uint8Array ? frostSigRaw
      : Buffer.isBuffer(frostSigRaw) ? new Uint8Array(frostSigRaw as Buffer) : null;
    const signerPubkeyRaw = frame["signer_pubkey"];
    const signerPubkey = signerPubkeyRaw instanceof Uint8Array ? signerPubkeyRaw
      : Buffer.isBuffer(signerPubkeyRaw) ? new Uint8Array(signerPubkeyRaw as Buffer) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;

    if (!sealedRoot || frostSig === null || !signerPubkey || !sessionId) return;
    if (!frostSig || frostSig.length !== 64) return;
    if (!signerPubkey || signerPubkey.length !== 32) return;

    const thresholdSigner = this.#ctx.getThresholdSigner();
    if (!thresholdSigner) return;

    // Prefer stored sealVerifiedData leafCount (same as handleFrostSealed) so verification
    // uses the count from the FROST ceremony even if local_tree_leaves is incomplete.
    const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
    const leafCount = sealVerifiedEntry?.leafCount ?? session.local_tree_leaves.length;
    // M-003: close_timestamp must be set (stored during bilateral fallback from seal_verified).
    // Without it we cannot reconstruct the exact TBS and verification would be unsound.
    const closeTimestamp = session.close_timestamp ?? sealVerifiedEntry?.timestamp;
    if (closeTimestamp === undefined) {
      this.#ctx.logger.warn("seal.frost.sealed.missing.close.timestamp", { sessionId: sessionIdHex });
      return;
    }
    const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, closeTimestamp);

    const isFrostInitiator = this.#frostCeremonyParticipant.has(sessionIdHex);
    let verifyKey: Uint8Array;
    if (isFrostInitiator) {
      const myPrimaryPubkey = this.#myPrimaryPubkey;
      if (!myPrimaryPubkey) return;
      verifyKey = myPrimaryPubkey;
    } else {
      verifyKey = signerPubkey;
    }

    if (!thresholdSigner.verifySignature(frostSig, tbs, "cello-frost-seal-v1", verifyKey)) {
      this.#ctx.logger.warn("seal.frost.sealed.signature.invalid", { sessionId: sessionIdHex });
      return;
    }

    // AC-004: update session from bilateral to frost
    session.status = "sealed";
    session.sealed_root = sealedRoot;
    session.frost_signature = frostSig;
    session.signer_pubkey = signerPubkey;
    session.seal_type = "frost";
    // CRIT-1: persist sealed state
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);
  }
}
