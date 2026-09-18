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
import {
  encodeChannelJoinRequest, decodeChannelJoinRequest,
  encodeChannelJoinAccepted, decodeChannelJoinAccepted,
  encodeChannelJoinRefused, decodeChannelJoinRefused,
  encodeChannelRekey, decodeChannelRekey,
  isChannelJoinFrame,
  MAX_JOIN_NOTE_CHARS,
} from "../channel-join.js";

const CHANNEL = new Uint8Array(Buffer.alloc(32, 0xa1));
const SUBSCRIBER = new Uint8Array(Buffer.alloc(32, 0xb2));
const BUNDLE = new Uint8Array(Buffer.alloc(120, 0xc3));
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";

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

  it("a PUBLIC channel cannot be accepted into — there is nothing to join", () => {
    // Public channels have no join, no keys and nothing to eject. An acceptance naming one would be
    // a frame the subscriber could act on to store a key for a channel that has none.
    expect(() => encodeChannelJoinAccepted({
      channel_pubkey: CHANNEL, key_bundle: BUNDLE, guidance: "", retention_seconds: 3600,
      access: "public" as "open", relays: [RELAY_A], members_visible: false,
    })).toThrow(/bad_access/);
  });

  it("every refusal reason is carried by name", () => {
    for (const reason of [
      "not_admin_of_channel", "pending_approval", "refused_by_admin",
      "already_member", "ejected", "channel_is_public",
    ] as const) {
      const decoded = decodeChannelJoinRefused(encodeChannelJoinRefused({ channel_pubkey: CHANNEL, reason }));
      expect(decoded.ok && decoded.frame.reason).toBe(reason);
    }
    // ⚠️ AN UNKNOWN REASON IS REFUSED, not passed through. These are shown to an operator, and a
    // reason invented by the far side would put its words on our screen.
    expect(decodeChannelJoinRefused(encodeChannelJoinRefused({
      channel_pubkey: CHANNEL, reason: "made_up" as "ejected",
    })).ok).toBe(false);
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
    const refused = encodeChannelJoinRefused({ channel_pubkey: CHANNEL, reason: "ejected" });
    expect(decodeChannelJoinAccepted(refused).ok).toBe(false);
    expect(decodeChannelRekey(refused).ok).toBe(false);
    expect(decodeChannelJoinRequest(refused).ok).toBe(false);
  });
});
