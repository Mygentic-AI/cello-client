/**
 * M16 / 045-NOTICEBELL Part A — the sealed channel notice record.
 *
 * One record per (channel, member, type), signed by the CHANNEL key, sealed to the member, stored on
 * the relays under slot = H(domain ‖ type ‖ X25519(channel key, member key)). Tests are RED-first.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { InMemoryKeyProvider, generateKeypair, sealToRecipient } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  CHANNEL_NOTICE_DOMAIN,
  CHANNEL_NOTICE_MAX_SEALED_BYTES,
  channelNoticeSlot,
  decodeChannelNotice,
  decodeNoticePassBody,
  encodeChannelNotice,
  encodeNoticePassBody,
  signChannelNotice,
  verifyChannelNotice,
} from "../channel-notice.js";

setupV3Tests();

function kp(): InMemoryKeyProvider {
  return generateKeypair();
}

describe("045-NOTICEBELL channel notice record", () => {
  it("the slot is the same from both sides and differs per type and per member", async () => {
    const channel = kp(); const member = kp(); const other = kp();
    const fromAdmin = (await channel.staticSharedSecret(await member.getPublicKey()))!;
    const fromMember = (await member.staticSharedSecret(await channel.getPublicKey()))!;
    const toOther = (await channel.staticSharedSecret(await other.getPublicKey()))!;
    const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
    expect(hex(channelNoticeSlot(fromAdmin, "eject"))).toBe(hex(channelNoticeSlot(fromMember, "eject")));
    expect(hex(channelNoticeSlot(fromAdmin, "eject"))).not.toBe(hex(channelNoticeSlot(fromAdmin, "pass")));
    expect(hex(channelNoticeSlot(fromAdmin, "eject"))).not.toBe(hex(channelNoticeSlot(toOther, "eject")));
    expect(channelNoticeSlot(fromAdmin, "group_key").length).toBe(32);
  });

  it("round-trips, verifies against its channel key, and a flipped byte fails verification", async () => {
    const channel = kp(); const member = kp();
    const slot = channelNoticeSlot((await channel.staticSharedSecret(await member.getPublicKey()))!, "eject");
    const sealed = sealToRecipient(await member.getPublicKey(), new Uint8Array([1, 2, 3]));
    const n = await signChannelNotice(channel, { slot, type: "eject", issued_at: 1000, sealed });
    const bytes = encodeChannelNotice(n);
    const back = decodeChannelNotice(bytes);
    expect(back.ok).toBe(true);
    if (!back.ok) return;
    expect(back.notice.type).toBe("eject");
    expect(back.notice.issued_at).toBe(1000);
    expect(verifyChannelNotice(back.notice)).toBe(true);
    const tampered = { ...back.notice, issued_at: 1001 };
    expect(verifyChannelNotice(tampered)).toBe(false);
  });

  it("strict decode: wrong domain, unknown type, oversize sealed body and non-canonical bytes are refused by name", async () => {
    const channel = kp();
    const slot = new Uint8Array(32).fill(7);
    const n = await signChannelNotice(channel, { slot, type: "eject", issued_at: 5, sealed: new Uint8Array(10) });
    const good = encodeChannelNotice(n);
    const slots = [CHANNEL_NOTICE_DOMAIN, n.channel_pubkey, n.slot, n.type, n.issued_at, n.sealed, n.signature];
    expect(decodeChannelNotice(encodeCbor(["nope", ...slots.slice(1)]))).toMatchObject({ ok: false, reason: "wrong_domain" });
    expect(decodeChannelNotice(encodeCbor([...slots.slice(0, 3), "free_text", ...slots.slice(4)]))).toMatchObject({ ok: false, reason: "bad_type" });
    const big = new Uint8Array(CHANNEL_NOTICE_MAX_SEALED_BYTES.eject + 1);
    expect(decodeChannelNotice(encodeCbor([...slots.slice(0, 5), big, n.signature]))).toMatchObject({ ok: false, reason: "too_large" });
    expect(decodeChannelNotice(new Uint8Array([0xff, 0x00]))).toMatchObject({ ok: false, reason: "not_cbor" });
    expect(decodeChannelNotice(good).ok).toBe(true);
    await expect(signChannelNotice(channel, { slot, type: "eject", issued_at: 5, sealed: big })).rejects.toThrow(/too_large/);
  });

  it("the pass body carries the pass bytes and the member list, and decodes strictly", () => {
    const pass = new Uint8Array([9, 9, 9]);
    const members = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    const body = decodeNoticePassBody(encodeNoticePassBody(pass, members));
    expect(body).not.toBeNull();
    expect(Array.from(body!.pass_cbor)).toEqual([9, 9, 9]);
    expect(body!.members.length).toBe(2);
    expect(decodeNoticePassBody(encodeCbor([pass, [new Uint8Array(31)]]))).toBeNull();
    expect(decodeNoticePassBody(encodeCbor(["text"]))).toBeNull();
  });
});
