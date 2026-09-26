/**
 * M16 045-NOTICEBELL Parts B/C — channel notices are signed records and a ring, never a session.
 *
 * The admin writes a sealed notice (channel-signed, sealed to the member, under a slot only the two
 * can compute); the member's daemon reads, strictly decodes, verifies, applies and tells its agent
 * once. Real crypto throughout; the only fake is the relay's slot map.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, generateGroupKey, wrapGroupKeyFor, sealToRecipient } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  channelNoticeSlot, decodeChannelNotice, encodeChannelNotice, signChannelNotice, encodeNoticeEjectBody, encodeNoticePassBody,
  encodeChannelPosterPass, signChannelPosterPass, encodeChannelInfo, signChannelInfo,
} from "@cello-protocol/protocol-types";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelPosterPassStore } from "../channel-poster-pass-store.js";
import {
  ChannelNoticeSeenStore, createChannelNoticeReader, writeChannelNotice, type NoticeRelays,
} from "../channel-notices.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const MEMBER_ID = "agent-member-1";
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let dir: string;
let db: DaemonDatabase;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-045-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

type InfoFor = (channel: InMemoryKeyProvider, admin: InMemoryKeyProvider, member: InMemoryKeyProvider) => Promise<Uint8Array>;

async function harness(opts: { subscribed?: boolean; revoked?: boolean; info?: InfoFor } = {}) {
  const channel = generateKeypair() as InMemoryKeyProvider;
  const admin = generateKeypair() as InMemoryKeyProvider;
  const member = generateKeypair() as InMemoryKeyProvider;
  const channelHex = hex(await channel.getPublicKey());
  const memberHex = hex(await member.getPublicKey());
  const logs: Array<{ event: string; ctx?: Record<string, unknown> }> = [];
  const logger: Logger = {
    debug() {}, info: (event, ctx) => { logs.push({ event, ctx }); },
    warn: (event, ctx) => { logs.push({ event, ctx }); }, error: (event, ctx) => { logs.push({ event, ctx }); },
  };
  const held = new Map<string, Uint8Array>();
  let fetches = 0;
  // The relay's rule, in miniature: one record per slot, replaced only by a newer issued_at.
  const relays: NoticeRelays = {
    deposit: (_r, record) => {
      const d = decodeChannelNotice(record);
      if (!d.ok) return Promise.resolve(0);
      const prior = held.get(hex(d.notice.slot));
      const priorAt = prior ? (decodeChannelNotice(prior) as { ok: true; notice: { issued_at: number } }).notice.issued_at : 0;
      if (d.notice.issued_at <= priorAt) return Promise.resolve(0);
      held.set(hex(d.notice.slot), record);
      return Promise.resolve(1);
    },
    fetch: (_r, slot) => { fetches += 1; const r = held.get(hex(slot)); return Promise.resolve(r ? [r] : []); },
  };
  const subs = new ChannelSubscriptionStore(db, logger);
  const passes = new ChannelPosterPassStore(db, logger);
  if (opts.subscribed !== false) {
    subs.upsert({ agent_id: MEMBER_ID, channel_pubkey: channelHex, admin_pubkey: hex(await admin.getPublicKey()), access: "invite_only", relays: [RELAY_A] });
  }
  const info = opts.info ? await opts.info(channel, admin, member) : null;
  const ended: Array<{ ch: string; reason: string }> = [];
  const removed: string[] = [];
  const reader = createChannelNoticeReader({
    logger, subscriptions: subs, posterPasses: passes, seen: new ChannelNoticeSeenStore(db), relays,
    keyProviderFor: (id) => (id === MEMBER_ID ? member : null),
    fetchInfo: () => Promise.resolve(info),
    channelRevoked: () => Promise.resolve(opts.revoked === true),
    onMembershipEnded: (_id, ch, reason) => { ended.push({ ch, reason }); },
    onPosterRemoved: (_id, ch) => { removed.push(ch); },
  });

  /** Write a notice the way the admin does. */
  async function write(type: "pass" | "eject" | "group_key", body: Uint8Array, issuedAt = 1000): Promise<boolean> {
    return writeChannelNotice({ relays, logger, now: () => issuedAt }, channel, [RELAY_A], memberHex, type, body);
  }
  const sharedCache = await channel.staticSharedSecret(await member.getPublicKey());
  /** Put raw bytes at a slot, bypassing the admin path — for forged and replayed records. */
  function putRaw(type: "pass" | "eject" | "group_key", record: Uint8Array): void {
    held.set(hex(channelNoticeSlot(sharedCache!, type)), record);
  }
  return {
    channel, admin, member, channelHex, memberHex, subs, passes, reader, ended, removed, logs, write, putRaw,
    fetches: () => fetches, slot: (t: "pass" | "eject" | "group_key") => channelNoticeSlot(sharedCache!, t),
  };
}

describe("045-NOTICEBELL — the member reads its notices; no session anywhere", () => {
  it("1. an eject notice marks the subscription ejected and rings the agent ONCE; a repeat is silent", async () => {
    const h = await harness();
    await h.write("eject", encodeNoticeEjectBody(await h.channel.getPublicKey()));
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.subs.get(MEMBER_ID, h.channelHex)?.status).toBe("ejected");
    expect(h.ended).toEqual([{ ch: h.channelHex, reason: "ejected" }]);
    // Re-subscribe to prove the repeat is dropped by issued_at, not by status.
    h.subs.upsert({ agent_id: MEMBER_ID, channel_pubkey: h.channelHex, admin_pubkey: "aa".repeat(32), access: "invite_only", relays: [RELAY_A] });
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.ended).toHaveLength(1);
  });

  it("2. a group_key notice adds the new generation and rings nobody", async () => {
    const h = await harness();
    const gk = generateGroupKey(2);
    const bundle = await wrapGroupKeyFor(gk, await h.channel.getPublicKey(), await h.member.getPublicKey(), h.admin);
    await h.write("group_key", bundle);
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.subs.keysFor(MEMBER_ID, h.channelHex).map((k) => k.generation)).toEqual([2]);
    expect(h.ended).toEqual([]);
  });

  it("3. a pass notice stores the pass and the member list", async () => {
    const h = await harness();
    const pass = await signChannelPosterPass(h.channel, { poster_pubkey: await h.member.getPublicKey(), issued_at: 500, expires_at: 9_000_000_000_000 });
    const other = new Uint8Array(32).fill(4);
    await h.write("pass", encodeNoticePassBody(encodeChannelPosterPass(pass), [other]));
    await h.reader.checkNotices(MEMBER_ID);
    const held = h.passes.get(MEMBER_ID, h.channelHex);
    expect(held?.issued_at).toBe(500);
    expect(held?.members).toEqual([hex(other)]);
  });

  it("4. non-member guard: a channel this agent does not follow is never fetched and rings nothing", async () => {
    const h = await harness({ subscribed: false });
    await h.write("eject", encodeNoticeEjectBody(await h.channel.getPublicKey()));
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.fetches()).toBe(0);
    expect(h.ended).toEqual([]);
  });

  it("5. a record under the member's slot signed by ANOTHER key is rejected, logged, and applies nothing", async () => {
    const h = await harness();
    const forger = generateKeypair() as InMemoryKeyProvider;
    const good = await signChannelNotice(forger, {
      slot: h.slot("eject"), type: "eject", issued_at: 1000,
      sealed: sealToRecipient(await h.member.getPublicKey(), encodeNoticeEjectBody(await h.channel.getPublicKey())),
    });
    // Claim the victim channel while keeping the forger's signature.
    h.putRaw("eject", encodeChannelNotice({ ...good, channel_pubkey: await h.channel.getPublicKey() }));
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.subs.get(MEMBER_ID, h.channelHex)?.status).toBe("active");
    expect(h.ended).toEqual([]);
    expect(h.logs.some((l) => l.event === "channel.notice.rejected" && l.ctx?.["reason"] === "signature_invalid")).toBe(true);
  });

  it("6. nagging guard: an OLDER genuine notice after a newer one is dropped silently", async () => {
    const h = await harness();
    const gk3 = generateGroupKey(3);
    await h.write("group_key", await wrapGroupKeyFor(gk3, await h.channel.getPublicKey(), await h.member.getPublicKey(), h.admin), 2000);
    await h.reader.checkNotices(MEMBER_ID);
    const gk2 = generateGroupKey(2);
    await h.write("group_key", await wrapGroupKeyFor(gk2, await h.channel.getPublicKey(), await h.member.getPublicKey(), h.admin), 1500);
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.subs.keysFor(MEMBER_ID, h.channelHex).map((k) => k.generation)).toEqual([3]);
  });

  it("7. a channel the directory reports revoked is marked closed and rings channel_closed once", async () => {
    const h = await harness({ revoked: true });
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.subs.get(MEMBER_ID, h.channelHex)?.status).toBe("closed");
    expect(h.ended).toEqual([{ ch: h.channelHex, reason: "channel_closed" }]);
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.ended).toHaveLength(1);
  });

  it("8. poster removed: the channel's own info record revoking this poster drops the pass and rings once", async () => {
    const h = await harness({
      info: async (channel, admin, member) => encodeChannelInfo(await signChannelInfo(channel, {
        access: "invite_only", admin_pubkey: await admin.getPublicKey(), relays: [RELAY_A], guidance: "g",
        retention_seconds: 3600, updated_at: 3000,
        ext: { posting: "listed", revoked: [{ poster_pubkey: await member.getPublicKey(), revoked_at: 600 }] },
      })),
    });
    // A pass issued BEFORE the revocation, held by the member.
    const pass = await signChannelPosterPass(h.channel, { poster_pubkey: await h.member.getPublicKey(), issued_at: 500, expires_at: 9_000_000_000_000 });
    h.passes.put(MEMBER_ID, h.channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: 500, expires_at: 9_000_000_000_000, members: [] });
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.passes.get(MEMBER_ID, h.channelHex)).toBeNull();
    expect(h.removed).toEqual([h.channelHex]);
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.removed).toHaveLength(1);
  });

  it("9. a pass issued AFTER the revocation is kept, and nobody is told", async () => {
    const h = await harness({
      info: async (channel, admin, member) => encodeChannelInfo(await signChannelInfo(channel, {
        access: "invite_only", admin_pubkey: await admin.getPublicKey(), relays: [RELAY_A], guidance: "g",
        retention_seconds: 3600, updated_at: 3000,
        ext: { posting: "listed", revoked: [{ poster_pubkey: await member.getPublicKey(), revoked_at: 600 }] },
      })),
    });
    const pass = await signChannelPosterPass(h.channel, { poster_pubkey: await h.member.getPublicKey(), issued_at: 700, expires_at: 9_000_000_000_000 });
    h.passes.put(MEMBER_ID, h.channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: 700, expires_at: 9_000_000_000_000, members: [] });
    await h.reader.checkNotices(MEMBER_ID);
    expect(h.passes.get(MEMBER_ID, h.channelHex)?.issued_at).toBe(700);
    expect(h.removed).toEqual([]);
  });
});
