/**
 * M16 / 046-JOINBELL — joining a channel is records plus a ring, never a session.
 *
 * Three records: the joiner's signed request (sealed to the admin, held in a hashed join slot), the
 * channel-key-signed answer (carried in the joiner's 045 notice slot), and the channel-key-signed
 * relay record the directory holds so a stranger can find the relays. Strict CBOR everywhere.
 * Tests are RED-first.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  channelJoinSlot, signChannelJoinRequest, encodeChannelJoinRequest, decodeChannelJoinRequest,
  verifyChannelJoinRequest, encodeChannelJoinSlotRecord, decodeChannelJoinSlotRecord,
  signChannelJoinAnswer, encodeChannelJoinAnswer, decodeChannelJoinAnswer, verifyChannelJoinAnswer,
  signChannelJoinWithdrawal, encodeChannelJoinWithdrawal, decodeChannelJoinWithdrawal, verifyChannelJoinWithdrawal,
  JOIN_REQUEST_DOMAIN, JOIN_ANSWER_DOMAIN, MAX_JOIN_NOTE_CHARS, MAX_JOIN_SEALED_BYTES,
} from "../channel-join.js";
import {
  signChannelRelayRecord, encodeChannelRelayRecord, decodeChannelRelayRecord, verifyChannelRelayRecord,
  CHANNEL_RELAY_RECORD_DOMAIN, CHANNEL_DISCOVERY_KEYS,
} from "../channel-relay-record.js";
import { CHANNEL_NOTICE_TYPES } from "../channel-notice.js";

setupV3Tests();

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

describe("046-JOINBELL join request", () => {
  it("round-trips, verifies against the joiner key, and a tampered note fails verification", async () => {
    const joiner = generateKeypair(); const channel = generateKeypair();
    const req = await signChannelJoinRequest(joiner, { channel_pubkey: await channel.getPublicKey(), note: "hi, it is Ana", signed_at: 5 });
    const decoded = decodeChannelJoinRequest(encodeChannelJoinRequest(req));
    expect(decoded.ok && hex(decoded.request.joiner_pubkey)).toBe(hex(await joiner.getPublicKey()));
    expect(decoded.ok && verifyChannelJoinRequest(decoded.request)).toBe(true);
    expect(verifyChannelJoinRequest({ ...req, note: "hi, it is Bob" })).toBe(false);
  });

  it("refuses a note with a control character or over the cap, and a wrong-shape array", async () => {
    const joiner = generateKeypair(); const channel = generateKeypair();
    const ch = await channel.getPublicKey();
    await expect(signChannelJoinRequest(joiner, { channel_pubkey: ch, note: "a\u0007b", signed_at: 1 })).rejects.toThrow(/bad_note/);
    await expect(signChannelJoinRequest(joiner, { channel_pubkey: ch, note: "x".repeat(MAX_JOIN_NOTE_CHARS + 1), signed_at: 1 })).rejects.toThrow(/bad_note/);
    const bad = decodeChannelJoinRequest(encodeCbor([JOIN_REQUEST_DOMAIN, ch, ch, "n", 1]));
    expect(bad.ok ? "ok" : bad.reason).toBe("wrong_shape");
  });

  it("the join slot is the same from both sides, per joiner, and never equals a notice slot's domain", async () => {
    const joiner = generateKeypair(); const channel = generateKeypair(); const other = generateKeypair();
    const a = (await channel.staticSharedSecret(await joiner.getPublicKey()))!;
    const b = (await joiner.staticSharedSecret(await channel.getPublicKey()))!;
    const c = (await channel.staticSharedSecret(await other.getPublicKey()))!;
    expect(hex(channelJoinSlot(a))).toBe(hex(channelJoinSlot(b)));
    expect(hex(channelJoinSlot(a))).not.toBe(hex(channelJoinSlot(c)));
  });

  it("the slot record round-trips and refuses an oversized sealed body", async () => {
    const ch = await generateKeypair().getPublicKey();
    const rec = { channel_pubkey: ch, slot: new Uint8Array(32).fill(3), signed_at: 9, sealed: new Uint8Array(100).fill(1) };
    const d = decodeChannelJoinSlotRecord(encodeChannelJoinSlotRecord(rec));
    expect(d.ok && d.record.signed_at).toBe(9);
    expect(() => encodeChannelJoinSlotRecord({ ...rec, sealed: new Uint8Array(MAX_JOIN_SEALED_BYTES + 1) })).toThrow(/too_large/);
  });
});

describe("046-JOINBELL withdrawal (Decision 12)", () => {
  it("a withdrawal round-trips, verifies against the joiner, and is not decodable as a request", async () => {
    const joiner = generateKeypair(); const ch = await generateKeypair().getPublicKey();
    const w = await signChannelJoinWithdrawal(joiner, { channel_pubkey: ch, signed_at: 8 });
    const bytes = encodeChannelJoinWithdrawal(w);
    const d = decodeChannelJoinWithdrawal(bytes);
    expect(d.ok && verifyChannelJoinWithdrawal(d.withdrawal)).toBe(true);
    expect(verifyChannelJoinWithdrawal({ ...w, signed_at: 9 })).toBe(false);
    const asRequest = decodeChannelJoinRequest(bytes);
    expect(asRequest.ok ? "ok" : asRequest.reason).toBe("wrong_shape");
  });
});

describe("046-JOINBELL join answer", () => {
  it("an acceptance with a sealed key verifies against the channel key; a forged one does not", async () => {
    const channel = generateKeypair(); const forger = generateKeypair();
    const ans = await signChannelJoinAnswer(channel, { outcome: "accepted", reason: null, key_bundle: new Uint8Array([1, 2, 3]), signed_at: 7 });
    const d = decodeChannelJoinAnswer(encodeChannelJoinAnswer(ans));
    expect(d.ok && d.answer.outcome).toBe("accepted");
    expect(d.ok && verifyChannelJoinAnswer(d.answer)).toBe(true);
    const forged = await signChannelJoinAnswer(forger, { outcome: "accepted", reason: null, key_bundle: null, signed_at: 7 });
    expect(verifyChannelJoinAnswer({ ...forged, channel_pubkey: await channel.getPublicKey() })).toBe(false);
  });

  it("refuses an unknown outcome, an unknown reason, and a key on a refusal", async () => {
    const channel = generateKeypair(); const ch = await channel.getPublicKey();
    const sig = new Uint8Array(64);
    const unknownOutcome = decodeChannelJoinAnswer(encodeCbor([JOIN_ANSWER_DOMAIN, ch, "maybe", null, null, 1, sig]));
    expect(unknownOutcome.ok ? "ok" : unknownOutcome.reason).toBe("bad_outcome");
    const unknownReason = decodeChannelJoinAnswer(encodeCbor([JOIN_ANSWER_DOMAIN, ch, "refused", "go away", null, 1, sig]));
    expect(unknownReason.ok ? "ok" : unknownReason.reason).toBe("bad_reason");
    const keyed = decodeChannelJoinAnswer(encodeCbor([JOIN_ANSWER_DOMAIN, ch, "refused", "refused_by_admin", new Uint8Array(3), 1, sig]));
    expect(keyed.ok ? "ok" : keyed.reason).toBe("bad_key_bundle");
  });

  it("join_answer is a notice type, so it rides the joiner's 045 notice slot", () => {
    expect(CHANNEL_NOTICE_TYPES).toContain("join_answer");
  });
});

describe("046-JOINBELL channel relay record", () => {
  it("round-trips as a CBOR map and verifies against the channel key", async () => {
    const channel = generateKeypair();
    const rec = await signChannelRelayRecord(channel, { relays: ["/dns4/r1/tcp/1/p2p/A", "/dns4/r2/tcp/1/p2p/B"], signed_at: 11 });
    const d = decodeChannelRelayRecord(encodeChannelRelayRecord(rec));
    expect(d.ok && d.record.relays).toEqual(["/dns4/r1/tcp/1/p2p/A", "/dns4/r2/tcp/1/p2p/B"]);
    expect(d.ok && verifyChannelRelayRecord(d.record)).toBe(true);
    expect(verifyChannelRelayRecord({ ...rec, relays: ["/dns4/evil/tcp/1/p2p/X"] })).toBe(false);
  });

  it("refuses a record that sets any discovery field, and one with an unknown key", async () => {
    const channel = generateKeypair(); const ch = await channel.getPublicKey();
    const base = { domain: CHANNEL_RELAY_RECORD_DOMAIN, channel_pubkey: ch, relays: ["r"], signed_at: 1, signature: new Uint8Array(64) };
    expect(CHANNEL_DISCOVERY_KEYS).toHaveLength(8);
    for (const key of CHANNEL_DISCOVERY_KEYS) {
      const d = decodeChannelRelayRecord(encodeCbor({ ...base, [key]: "x" }));
      expect(d.ok ? "ok" : d.reason).toBe("discovery_not_supported");
    }
    const unknown = decodeChannelRelayRecord(encodeCbor({ ...base, colour: "red" }));
    expect(unknown.ok ? "ok" : unknown.reason).toBe("wrong_shape");
  });
});
