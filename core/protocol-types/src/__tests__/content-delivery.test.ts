/**
 * CELLO-M7-MSG-001 — content-delivery wire types + size cap.
 *
 * AC-018: the message content cap is a single named constant strictly below the
 * 4 MB it-length-prefixed transport default so the application cap always fires
 * first. We reuse the existing MAX_CONTENT_BYTES (1 MB) as that canonical cap.
 *
 * AC-002 / D-c: the delivery-ACK level is an OPEN enum (received → persisted, with
 * room for future levels) and the protocol acts on 'persisted' only.
 */

import { describe, it, expect } from "vitest";
import { MAX_CONTENT_BYTES } from "../limits.js";
import {
  IT_LENGTH_PREFIX_DEFAULT_MAX,
  isContentDeliveryAck,
  isContentResendRequest,
  type ContentDeliveryAck,
  type ContentAckLevel,
  type ContentParkDeposit,
} from "../content-delivery.js";

describe("content-delivery types (MSG-001)", () => {
  it("the application content cap is strictly below the transport it-length-prefix default (AC-018)", () => {
    expect(MAX_CONTENT_BYTES).toBe(1_048_576);
    expect(MAX_CONTENT_BYTES).toBeLessThan(IT_LENGTH_PREFIX_DEFAULT_MAX);
    expect(IT_LENGTH_PREFIX_DEFAULT_MAX).toBe(4 * 1024 * 1024);
  });

  it("ContentAckLevel accepts received, persisted, and future levels (open enum, AC-002)", () => {
    const received: ContentAckLevel = "received";
    const persisted: ContentAckLevel = "persisted";
    const future: ContentAckLevel = "archived"; // open enum — no wire break
    expect([received, persisted, future]).toEqual(["received", "persisted", "archived"]);
  });

  it("isContentDeliveryAck recognizes a persisted ack frame and rejects others", () => {
    const ack: ContentDeliveryAck = {
      type: "content_delivery_ack",
      session_id: new Uint8Array([1, 2, 3]),
      content_hash: new Uint8Array(32),
      level: "persisted",
    };
    expect(isContentDeliveryAck(ack)).toBe(true);
    expect(isContentDeliveryAck({ type: "content_frame" })).toBe(false);
    expect(isContentDeliveryAck(null)).toBe(false);
    expect(isContentDeliveryAck({ type: "content_delivery_ack" })).toBe(false); // missing fields
  });

  it("the delivery ack carries no signature field (D-c — unsigned, transport-authenticated)", () => {
    const ack: ContentDeliveryAck = {
      type: "content_delivery_ack",
      session_id: new Uint8Array([9]),
      content_hash: new Uint8Array(32),
      level: "persisted",
    };
    expect("signature" in ack).toBe(false);
  });

  it("isContentResendRequest recognizes the recovery reverse-channel frame", () => {
    expect(
      isContentResendRequest({
        type: "content_resend_request",
        session_id: new Uint8Array([1]),
        content_hash: new Uint8Array(32),
      }),
    ).toBe(true);
    expect(isContentResendRequest({ type: "content_delivery_ack" })).toBe(false);
  });

  it("ContentParkDeposit gives the ciphertext and recipient their own named slots (API parsimony)", () => {
    const deposit: ContentParkDeposit = {
      type: "content_park_deposit",
      recipient_pubkey: new Uint8Array(32),
      content_hash: new Uint8Array(32),
      session_id: new Uint8Array([7]),
      ciphertext: new Uint8Array([0xaa, 0xbb]),
    };
    expect(deposit.ciphertext).toBeInstanceOf(Uint8Array);
    expect(deposit.recipient_pubkey).toBeInstanceOf(Uint8Array);
    // ciphertext is never buried inside another field
    expect("content_bytes" in deposit).toBe(false);
  });
});
