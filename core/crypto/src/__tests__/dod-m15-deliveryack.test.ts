/**
 * DOD-M15-DELIVERYACK-1 — the recipient signs for what their machine received.
 *
 * ─── What these tests are about ────────────────────────────────────────────────────────────────
 *
 * Until this unit a delivery acknowledgement was a transport nod: four fields on a
 * Noise-authenticated stream, retained nowhere, with nothing a sender could ever hand a third
 * party. So "it never reached me" was unanswerable, and every one of the innocent reasons a
 * message really does go missing — the relay parked it, the recipient's daemon died, the
 * per-recipient queue dropped the oldest frame, the screener refused it — looked identical to
 * someone choosing not to answer.
 *
 * The statement below binds two things and no more: the SESSION and the exact CONTENT HASH. It
 * says a machine received bytes. It says nothing about attention and nothing about agreement.
 *
 * Ed25519 — RFC 8032. SHA-256 — FIPS 180-4.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { InMemoryKeyProvider } from "../ed25519.js";
import {
  deliveryAckSigningMessage,
  signDeliveryAck,
  verifyDeliveryAck,
  DELIVERY_ACK_REFUSALS,
  DELIVERY_ACK_SIG_BYTES,
} from "../delivery-ack-auth.js";

const SID = new Uint8Array(16).fill(0x68);
const HASH = new Uint8Array(32).fill(0xa7);

async function agent() {
  const kp = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
  return { kp, pub: await kp.getPublicKey() };
}

describe("DELIVERYACK: the signature verifies, and only against the session's own participants", () => {
  it("★ an acknowledgement signed by the recipient VERIFIES against their identity", async () => {
    const bob = await agent();
    const sig = await signDeliveryAck(bob.kp, SID, HASH);

    expect(
      verifyDeliveryAck({
        participantIdentityPublics: [bob.pub],
        sessionId: SID,
        contentHash: HASH,
        signature: sig,
      }),
    ).toEqual({ ok: true, signerPublic: bob.pub });
  });

  it("★★ an acknowledgement signed by SOMEONE ELSE is refused — a valid signature is not a relevant one", async () => {
    /**
     * The signature here is cryptographically perfect. It simply is not one of this session's two
     * parties. This is the case that makes the unit worth anything: the ack a sender keeps has to
     * be checkable against a key the sender did not take from the ack itself.
     */
    const bob = await agent();
    const stranger = await agent();
    const sig = await signDeliveryAck(stranger.kp, SID, HASH);

    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [bob.pub],
      sessionId: SID,
      contentHash: HASH,
      signature: sig,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.SIGNATURE_MISMATCH);
  });

  it("★★ an acknowledgement for a DIFFERENT session does not verify here", async () => {
    const bob = await agent();
    const otherSession = new Uint8Array(16).fill(0x69);
    const sig = await signDeliveryAck(bob.kp, otherSession, HASH);

    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [bob.pub],
      sessionId: SID,
      contentHash: HASH,
      signature: sig,
    });
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.SIGNATURE_MISMATCH);
  });

  it("★★ an acknowledgement for a DIFFERENT content hash does not verify here", async () => {
    const bob = await agent();
    const otherHash = new Uint8Array(32).fill(0xa8);
    const sig = await signDeliveryAck(bob.kp, SID, otherHash);

    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [bob.pub],
      sessionId: SID,
      contentHash: HASH,
      signature: sig,
    });
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.SIGNATURE_MISMATCH);
  });

  it("★ the verdict names WHICH participant signed, so the caller never has to guess", async () => {
    const alice = await agent();
    const bob = await agent();
    const sig = await signDeliveryAck(bob.kp, SID, HASH);

    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [alice.pub, bob.pub],
      sessionId: SID,
      contentHash: HASH,
      signature: sig,
    });
    expect(verdict.ok).toBe(true);
    expect(verdict.ok === true && Buffer.from(verdict.signerPublic).toString("hex")).toBe(
      Buffer.from(bob.pub).toString("hex"),
    );
  });
});

describe("DELIVERYACK: missing, malformed and mismatched all fail", () => {
  /**
   * The reasons differ because they send a reader somewhere different. The OUTCOME does not,
   * because an attacker evading a mismatch check does not send a wrong signature — it sends none.
   */
  it("★★★ a MISSING signature is refused, not waved through", () => {
    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [new Uint8Array(32).fill(1)],
      sessionId: SID,
      contentHash: HASH,
      signature: undefined,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.SIGNATURE_MISSING);
  });

  it("★★★ a SHORT signature is refused rather than zero-extended", () => {
    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [new Uint8Array(32).fill(1)],
      sessionId: SID,
      contentHash: HASH,
      signature: new Uint8Array(DELIVERY_ACK_SIG_BYTES - 1),
    });
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.MALFORMED);
  });

  it("★★★ a wrong-width CONTENT HASH is refused — the field the whole statement is about", () => {
    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [new Uint8Array(32).fill(1)],
      sessionId: SID,
      contentHash: new Uint8Array(31),
      signature: new Uint8Array(DELIVERY_ACK_SIG_BYTES),
    });
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.MALFORMED);
  });

  it("★★★ NO participant keys at all is refused — there is nothing to check against", () => {
    const verdict = verifyDeliveryAck({
      participantIdentityPublics: [],
      sessionId: SID,
      contentHash: HASH,
      signature: new Uint8Array(DELIVERY_ACK_SIG_BYTES),
    });
    expect(verdict.ok === false && verdict.reason).toBe(DELIVERY_ACK_REFUSALS.NO_PARTICIPANT_KEYS);
  });

  it("★★ every refusal carries a detail a reader can act on — never a bare code", () => {
    for (const signature of [undefined, new Uint8Array(3)]) {
      const verdict = verifyDeliveryAck({
        participantIdentityPublics: [new Uint8Array(32).fill(1)],
        sessionId: SID,
        contentHash: HASH,
        signature,
      });
      expect(verdict.ok).toBe(false);
      expect(verdict.ok === false && verdict.detail.length).toBeGreaterThan(40);
    }
  });
});

describe("DELIVERYACK: the signed bytes cannot be moved between contexts", () => {
  it("★★★ the statement is DOMAIN-SEPARATED — it is not the ephemeral-signing statement", async () => {
    /**
     * An agent signs several different things with the same identity key. A statement valid in two
     * contexts is a statement an attacker moves from one to the other, so the label goes first.
     */
    const bytes = deliveryAckSigningMessage(SID, HASH);
    expect(Buffer.from(bytes).toString("utf8")).toContain("cello/session/v1/delivery-ack");
    expect(Buffer.from(bytes).toString("utf8")).not.toContain("ephemeral");
  });

  it("★★★ the session id is LENGTH-PREFIXED, so two different inputs cannot make the same bytes", () => {
    /**
     * Without the prefix, `sessionId ‖ contentHash` can be re-split at a different boundary. The
     * exemplar is chosen to actually collide: one byte moved across the join.
     */
    const longSid = new Uint8Array([1, 2, 3, 4, 5]);
    const shortSid = new Uint8Array([1, 2, 3, 4]);
    const a = deliveryAckSigningMessage(longSid, HASH);
    const b = deliveryAckSigningMessage(shortSid, new Uint8Array([5, ...HASH.subarray(0, 31)]));
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
  });

  it("★ signer and verifier build the statement from the SAME function", async () => {
    const bob = await agent();
    const sig = await signDeliveryAck(bob.kp, SID, HASH);
    const direct = await bob.kp.sign(deliveryAckSigningMessage(SID, HASH));
    expect(Buffer.from(sig).toString("hex")).toBe(Buffer.from(direct).toString("hex"));
  });
});
