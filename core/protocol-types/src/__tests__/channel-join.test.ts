/**
 * M16 019-MEMBERSHIP Part B — the join frames.
 *
 * A channel never converses, but its ADMIN is an ordinary agent, so joining is a typed exchange
 * inside a normal sealed session with that admin. No new transport, no relay frames — these are the
 * four shapes that travel on the session content channel.
 *
 * Written before the implementation. These cover the FRAMES; the admin-side and subscriber-side
 * decisions they carry are tested against the daemon.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import {
  encodeChannelJoinRequest, decodeChannelJoinRequest,
  encodeChannelJoinAccepted, decodeChannelJoinAccepted,
  encodeChannelJoinRefused, decodeChannelJoinRefused,
  encodeChannelRekey, decodeChannelRekey,
  encodeChannelMembershipEnded, decodeChannelMembershipEnded,
  encodeChannelPosterPassFrame, decodeChannelPosterPassFrame,
  isChannelJoinFrame,
  channelJoinFrameType,
  MAX_JOIN_NOTE_CHARS,
  MAX_JOIN_FRAME_BYTES,
  JOIN_REQUEST_TYPE, JOIN_ACCEPTED_TYPE, JOIN_REFUSED_TYPE, REKEY_TYPE, MEMBERSHIP_ENDED_TYPE, POSTER_PASS_FRAME_TYPE,
} from "../channel-join.js";
import { signChannelPosterPass, encodeChannelPosterPass } from "../channel-poster-pass.js";
import {
  encodeChannelPosterRemovedNotice, decodeChannelPosterRemovedNotice, POSTER_REMOVED_NOTICE_TYPE,
} from "../channel-join.js";
import { encodeCbor } from "../cbor.js";

const CHANNEL = new Uint8Array(Buffer.alloc(32, 0xa1));
const SUBSCRIBER = new Uint8Array(Buffer.alloc(32, 0xb2));
const BUNDLE = new Uint8Array(Buffer.alloc(120, 0xc3));
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X";

describe("M16 019 Part B — the join frames", () => {
  it("a join request round-trips, and the note is bounded", () => {
    const bytes = encodeChannelJoinRequest({
      channel_pubkey: CHANNEL, subscriber_pubkey: SUBSCRIBER, note: "I work with Andre",
    });
    const decoded = decodeChannelJoinRequest(bytes);
    expect(decoded.ok, decoded.ok ? "" : decoded.reason).toBe(true);
    if (!decoded.ok) return;
    expect(Buffer.from(decoded.frame.subscriber_pubkey).equals(Buffer.from(SUBSCRIBER))).toBe(true);
    expect(decoded.frame.note).toBe("I work with Andre");

    // ⚠️ The note is shown to a human admin deciding whether to admit a stranger. An unbounded one
    // is a wall of text in a terminal, and control characters can rewrite what they appear to say.
    const long = "x".repeat(MAX_JOIN_NOTE_CHARS + 1);
    expect(() => encodeChannelJoinRequest({ channel_pubkey: CHANNEL, subscriber_pubkey: SUBSCRIBER, note: long }))
      .toThrow(/bad_note/);
    expect(() => encodeChannelJoinRequest({ channel_pubkey: CHANNEL, subscriber_pubkey: SUBSCRIBER, note: "ab" }))
      .toThrow(/bad_note/);
  });

  it("an acceptance carries the key bundle, the relay pair, guidance and retention", () => {
    const bytes = encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, guidance: "release notes",
      retention_seconds: 7 * 24 * 3600, access: "invite_only",
      relays: [RELAY_A, RELAY_B], members_visible: false,
    });
    const decoded = decodeChannelJoinAccepted(bytes);
    expect(decoded.ok, decoded.ok ? "" : decoded.reason).toBe(true);
    if (!decoded.ok) return;
    // Everything a subscriber needs to start reading arrives in ONE frame: without the relays it
    // knows the channel's name and cannot fetch a thing.
    expect(decoded.frame.relays).toEqual([RELAY_A, RELAY_B]);
    expect(decoded.frame.retention_seconds).toBe(7 * 24 * 3600);
    expect(Buffer.from(decoded.frame.key_bundle).equals(Buffer.from(BUNDLE))).toBe(true);
    expect(decoded.frame.access).toBe("invite_only");
  });

  it("036-PUBLICSUB test 1: a PUBLIC acceptance carries an EMPTY bundle and round-trips; OPEN with an empty bundle is refused", () => {
    // A public channel's posts are not encrypted, so admission carries no key — the bundle MUST be
    // empty. The relays, guidance and retention still travel: that is what lets the reader fetch.
    const bytes = encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: new Uint8Array(0), guidance: "the bulletin",
      retention_seconds: 3600, access: "public", relays: [RELAY_A, RELAY_B], members_visible: true,
    });
    const decoded = decodeChannelJoinAccepted(bytes);
    expect(decoded.ok, decoded.ok ? "" : decoded.reason).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.access).toBe("public");
    expect(decoded.frame.key_bundle.length).toBe(0);
    expect(decoded.frame.relays).toEqual([RELAY_A, RELAY_B]);
    expect(decoded.frame.guidance).toBe("the bulletin");

    // ⚠️ The empty bundle is legal ONLY for public. An OPEN or invite-only channel has a key, so an
    // empty bundle would be an acceptance that admits without one — refused at both encode and decode.
    expect(() => encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: new Uint8Array(0), guidance: "", retention_seconds: 3600,
      access: "open", relays: [RELAY_A], members_visible: false,
    })).toThrow(/bad_key_bundle/);
    const openEmpty = encodeCbor([JOIN_ACCEPTED_TYPE, CHANNEL, new Uint8Array(0), "", 3600, "open", [RELAY_A], false]);
    expect(decodeChannelJoinAccepted(openEmpty).ok).toBe(false);
  });

  it("036-PUBLICSUB test 2: a PUBLIC acceptance carrying a NON-EMPTY bundle is refused", () => {
    // Public posts have no key, so a non-empty bundle on a public acceptance is a key for a channel
    // that has none — a frame the subscriber must not act on. Refused at encode and at decode.
    expect(() => encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, guidance: "", retention_seconds: 3600,
      access: "public", relays: [RELAY_A], members_visible: false,
    })).toThrow(/bad_key_bundle/);
    const publicWithKey = encodeCbor([JOIN_ACCEPTED_TYPE, CHANNEL, BUNDLE, "", 3600, "public", [RELAY_A], false]);
    expect(decodeChannelJoinAccepted(publicWithKey).ok).toBe(false);
  });

  it("every refusal reason is carried by name", () => {
    // 038-RETESTFIX Part E: `ejected` STAYS a refusal reason (the admin refusing an ejected member's
    // re-request). `channel_closed` is gone — a deleted channel is never a refusal, only a
    // `ChannelMembershipEnded` reason.
    for (const reason of [
      "not_admin_of_channel", "pending_approval", "refused_by_admin", "already_member", "ejected",
    ] as const) {
      const decoded = decodeChannelJoinRefused(encodeChannelJoinRefused({ channel_pubkey: CHANNEL, reason }));
      expect(decoded.ok && decoded.frame.reason).toBe(reason);
    }
    // `channel_closed` no longer decodes as a refusal — it belongs to the membership-ended frame.
    expect(decodeChannelJoinRefused(encodeCbor([JOIN_REFUSED_TYPE, CHANNEL, "channel_closed"])).ok,
      "channel_closed is no longer a refusal reason").toBe(false);
    // ⚠️ AN UNKNOWN REASON IS REFUSED, not passed through. These are shown to an operator, and a
    // reason invented by the far side would put its words on our screen.
    expect(decodeChannelJoinRefused(encodeChannelJoinRefused({
      channel_pubkey: CHANNEL, reason: "made_up" as "already_member",
    })).ok).toBe(false);
  });

  it("038 Part E — a membership-ended frame round-trips ejected and channel_closed, and refuses anything else", () => {
    for (const reason of ["ejected", "channel_closed"] as const) {
      const decoded = decodeChannelMembershipEnded(encodeChannelMembershipEnded({ channel_pubkey: CHANNEL, reason }));
      expect(decoded.ok && decoded.frame.reason).toBe(reason);
    }
    // A refusal reason is NOT a membership-ended reason, and neither is an invented one.
    for (const bad of ["refused_by_admin", "made_up"]) {
      expect(decodeChannelMembershipEnded(encodeCbor([MEMBERSHIP_ENDED_TYPE, CHANNEL, bad])).ok,
        `${bad} is not a membership-ended reason`).toBe(false);
    }
    // A membership-ended frame is classified as its own type, and never decodes as a refusal.
    const ended = encodeChannelMembershipEnded({ channel_pubkey: CHANNEL, reason: "ejected" });
    expect(channelJoinFrameType(ended)).toBe(MEMBERSHIP_ENDED_TYPE);
    expect(isChannelJoinFrame(ended)).toBe(true);
    expect(decodeChannelJoinRefused(ended).ok).toBe(false);
  });

  it("a re-key carries its generation, and the generation must be a real one", () => {
    const decoded = decodeChannelRekey(encodeChannelRekey({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, generation: 4,
    }));
    expect(decoded.ok && decoded.frame.generation).toBe(4);

    expect(() => encodeChannelRekey({ channel_pubkey: CHANNEL, key_bundle: BUNDLE, generation: 0 }))
      .toThrow(/bad_generation/);
    expect(() => encodeChannelRekey({ channel_pubkey: CHANNEL, key_bundle: BUNDLE, generation: -1 }))
      .toThrow(/bad_generation/);
  });

  it("a conversation message is NEVER classified as a join frame", () => {
    /**
     * ⚠️ THE SAME PROPERTY THE DOCUMENT ROUTER RESTS ON. These frames share the session content
     * channel with what people actually say, so misclassification in one direction puts CBOR in a
     * transcript and in the other makes a person's message vanish. A message is UTF-8 by
     * construction; these frames begin with a CBOR array header, which is not a valid UTF-8 start.
     */
    for (const message of ["hello", "Bonjour, ça va?", "مرحبا", "你好", "{\"looks\":\"structured\"}"]) {
      expect(isChannelJoinFrame(new TextEncoder().encode(message))).toBe(false);
    }
    // And the real frames ARE classified.
    expect(isChannelJoinFrame(encodeChannelJoinRequest({
      channel_pubkey: CHANNEL, subscriber_pubkey: SUBSCRIBER, note: "",
    }))).toBe(true);
    expect(isChannelJoinFrame(encodeChannelRekey({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, generation: 2,
    }))).toBe(true);
  });

  it("garbage never throws and never decodes", () => {
    for (const junk of [new Uint8Array(0), new Uint8Array([0xff]), new Uint8Array(Buffer.alloc(40, 0x9f))]) {
      expect(decodeChannelJoinRequest(junk).ok).toBe(false);
      expect(decodeChannelJoinAccepted(junk).ok).toBe(false);
      expect(decodeChannelJoinRefused(junk).ok).toBe(false);
      expect(decodeChannelRekey(junk).ok).toBe(false);
      expect(isChannelJoinFrame(junk)).toBe(false);
    }
  });

  it("a frame of one type does not decode as another", () => {
    // The type is in the frame, so a refusal cannot be read as an acceptance — which would have a
    // subscriber store a key bundle built from whatever those bytes happened to contain.
    const refused = encodeChannelJoinRefused({ channel_pubkey: CHANNEL, reason: "refused_by_admin" });
    expect(decodeChannelJoinAccepted(refused).ok).toBe(false);
    expect(decodeChannelRekey(refused).ok).toBe(false);
    expect(decodeChannelJoinRequest(refused).ok).toBe(false);
  });
});

describe("025-JOINSCREEN — channelJoinFrameType is strict, by full decode", () => {
  // Test 1: each of the four valid frames still classifies to its own type.
  it("each valid frame classifies to its own type", () => {
    expect(channelJoinFrameType(encodeChannelJoinRequest({
      channel_pubkey: CHANNEL, subscriber_pubkey: SUBSCRIBER, note: "hi",
    }))).toBe(JOIN_REQUEST_TYPE);
    expect(channelJoinFrameType(encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, guidance: "release notes",
      retention_seconds: 3600, access: "invite_only", relays: [RELAY_A, RELAY_B], members_visible: false,
    }))).toBe(JOIN_ACCEPTED_TYPE);
    expect(channelJoinFrameType(encodeChannelJoinRefused({
      channel_pubkey: CHANNEL, reason: "refused_by_admin",
    }))).toBe(JOIN_REFUSED_TYPE);
    expect(channelJoinFrameType(encodeChannelRekey({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, generation: 3,
    }))).toBe(REKEY_TYPE);
  });

  // Test 2: a valid type string in slot 0 with a body the decoder rejects is NOT a join frame.
  // Built with encodeCbor directly, because the encoders refuse exactly these bodies. Red before
  // the rewrite: the loose classifier returned the type on slot 0 alone.
  it("a valid type in slot 0 with a bad body is not a join frame", () => {
    // request with a 31-byte channel key
    expect(channelJoinFrameType(encodeCbor([
      JOIN_REQUEST_TYPE, new Uint8Array(31).fill(0xa1), SUBSCRIBER, "",
    ]))).toBeNull();
    // refused with an invented reason
    expect(channelJoinFrameType(encodeCbor([
      JOIN_REFUSED_TYPE, CHANNEL, "made_up",
    ]))).toBeNull();
    // accepted naming a PUBLIC channel WITH a key bundle — public posts have no key, so a bundle
    // here is a key for a channel that has none (036-PUBLICSUB); the decoder rejects it.
    expect(channelJoinFrameType(encodeCbor([
      JOIN_ACCEPTED_TYPE, CHANNEL, BUNDLE, "", 3600, "public", [RELAY_A], false,
    ]))).toBeNull();
    // rekey to generation 0 — "no key has ever been issued"
    expect(channelJoinFrameType(encodeCbor([
      REKEY_TYPE, CHANNEL, BUNDLE, 0,
    ]))).toBeNull();
  });

  // Test 4: the cap admits the LARGEST legitimate frame. (Test 3 is deliberately not written — see
  // the order: an "oversized → null" test passes with the cap deleted, so the cap is proven here and
  // by the reviewer reading that the length check precedes decodeCbor.)
  it("the cap admits the largest legitimate acceptance", () => {
    const bigBundle = new Uint8Array(4096).fill(0xc3);
    const clef = "\u{1D11E}"; // 𝄞 — 4 UTF-8 bytes, one code point
    const guidance = clef.repeat(2000);
    const relays = Array.from({ length: 8 }, () => clef.repeat(512));
    const frame = encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: bigBundle, guidance,
      retention_seconds: 3600, access: "open", relays, members_visible: true,
    });
    expect(frame.length).toBeLessThanOrEqual(MAX_JOIN_FRAME_BYTES);
    expect(channelJoinFrameType(frame)).toBe(JOIN_ACCEPTED_TYPE);
  });

  // 044-POSTERBELL: the pass frame now carries the channel's current members, outside the signed
  // pass, so a poster knows who to ring the moment it posts.
  it("a poster pass frame round-trips its member list, and rejects a wrong-length member", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const pass = await signChannelPosterPass(channel, {
      poster_pubkey: await poster.getPublicKey(), issued_at: 1_000, expires_at: 8_000,
    });
    const passCbor = encodeChannelPosterPass(pass);
    const members = [new Uint8Array(32).fill(0xaa), new Uint8Array(32).fill(0xbb)];

    const bytes = encodeChannelPosterPassFrame(passCbor, members);
    expect(channelJoinFrameType(bytes)).toBe(POSTER_PASS_FRAME_TYPE);
    const decoded = decodeChannelPosterPassFrame(bytes);
    expect(decoded.ok, decoded.ok ? "" : decoded.reason).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.members).toHaveLength(2);
    expect(Buffer.from(decoded.frame.members[0]!).equals(Buffer.from(members[0]!))).toBe(true);

    // A member that is not 32 bytes cannot identify an agent, so it is refused, never truncated.
    expect(() => encodeChannelPosterPassFrame(passCbor, [new Uint8Array(16)])).toThrow(/bad_members/);
    const badWire = encodeCbor([POSTER_PASS_FRAME_TYPE, passCbor, [new Uint8Array(16)]]);
    const badDecoded = decodeChannelPosterPassFrame(badWire);
    expect(badDecoded.ok).toBe(false);
    if (!badDecoded.ok) expect(badDecoded.reason).toBe("bad_members");
  });

  // 044-POSTERBELL Part E3: the poster-removed notice round-trips and rejects a wrong-length channel.
  it("a poster-removed notice round-trips and rejects a bad channel key", () => {
    const channel = new Uint8Array(32).fill(0xa1);
    const bytes = encodeChannelPosterRemovedNotice(channel);
    expect(channelJoinFrameType(bytes)).toBe(POSTER_REMOVED_NOTICE_TYPE);
    const decoded = decodeChannelPosterRemovedNotice(bytes);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(Buffer.from(decoded.frame.channel_pubkey).equals(Buffer.from(channel))).toBe(true);
    expect(() => encodeChannelPosterRemovedNotice(new Uint8Array(16))).toThrow(/bad_channel_pubkey/);
  });
});
