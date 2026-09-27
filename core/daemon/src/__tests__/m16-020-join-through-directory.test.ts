/**
 * M16 020-CHANADMIN / 046-JOINBELL — joining somebody else's channel, END TO END, with no session.
 *
 * ⚠️ **THIS IS THE TEST THE ORDER ASKED FOR, AND THE FIRST ATTEMPT WAS AT THE WRONG LAYER.** The
 * other 020 tests inject a fake at or above `createProfileAdminPubkey`, which means the seam this
 * order actually ADDS — the join path's agent ID resolved to an agent name, and that name resolved
 * to a directory connection — is never executed. Break it and everything stays green while every
 * remote join is refused, which is precisely how the code behaved BEFORE the order: it looks like
 * nothing changed rather than like something broke.
 *
 * So this drives `wireChannelMembership` itself. The only fakes are the things outside the daemon:
 * the directory's answer, and the session the frame arrives on.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, sealToRecipient, verify, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  signBroadcastArtifact, decodeChannelNotice, channelNoticeSlot, signChannelNotice, encodeChannelNotice,
  signChannelInfo, encodeChannelInfo, decodeChannelJoinSlotRecord, signChannelJoinAnswer, encodeChannelJoinAnswer,
  buildChannelJoinListTbs,
} from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelConfigStore } from "../channel-config-store.js";
import { ChannelLogStore } from "../channel-log-store.js";
import {
  wireChannelMembership, RELAY_RECORD_TICK_MS, NOTICE_BACKSTOP_TICK_MS, type ChannelMembershipWiringDeps,
} from "../channel-membership-wiring.js";
import { ChannelNoticeSeenStore } from "../channel-notices.js";
import { JOIN_THROTTLE_GUIDANCE, ensureCurrentGroupKey } from "../channel-join-exchange.js";
import type { SignalingLike } from "../channel-admin-lookup.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X";
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/** The subscriber's own agent, as the daemon knows it: a display NAME and a separate stable ID. */
const SUB_NAME = "Alice's Agent";
const SUB_ID = "agent-alice-1";

let dir: string;
let db: DaemonDatabase;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-020e2e-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

/**
 * M16 046-JOINBELL — TWO daemons' wirings, the joiner's and the admin's, joined only by what sits
 * between two machines: a fake relay pair (notice slots, join slots, info records) and a fake
 * directory (the channel lookup with its relay record, the relay-record publish, the join ring).
 * There is no session layer in either wiring any more, so "no session" is structural; what these
 * prove is that the join COMPLETES without one, and that each stranger guard holds.
 */
const ADMIN_NAME = "Publisher's Agent";
const ADMIN_ID = "agent-admin-1";
const CHANNEL_NAME = "test-channel";

type Notify = { event: string; agentId: string; channel: string; outcome?: string; reason?: string; subscriber?: string };

async function joinWorld(opts: { access: "open" | "invite_only" | "public"; retentionSeconds?: number } = { access: "open" }) {
  const joinerKp = generateKeypair() as InMemoryKeyProvider;
  const channelKp = generateKeypair() as InMemoryKeyProvider;
  const adminKp = generateKeypair() as InMemoryKeyProvider;
  const joinerHex = hex(await joinerKp.getPublicKey());
  const channelHex = hex(await channelKp.getPublicKey());
  const adminHex = hex(await adminKp.getPublicKey());
  const retention = opts.retentionSeconds ?? 7 * 24 * 3600;

  // ── Between the machines ─────────────────────────────────────────────────────────────────────
  const noticeSlots = new Map<string, Uint8Array>();
  const joinSlots = new Map<string, Uint8Array>();
  const info = encodeChannelInfo(await signChannelInfo(channelKp, {
    access: opts.access, admin_pubkey: await adminKp.getPublicKey(), relays: [RELAY_A, RELAY_B],
    guidance: "release notes", retention_seconds: retention, updated_at: 1, ext: null,
  }));
  let relayRecord: Uint8Array | undefined;
  let revoked = false;
  let ringRefusal: string | null = null;
  // The admin's directory stream is down: the directory acks the ring but reaches nobody.
  let adminOffline = false;
  let relayJoinRefusal: string | null = null;
  const rings: string[] = [];
  // 047: the joiner's directory stream is down — the admin's ring about its answer reaches nobody.
  let joinerOffline = false;
  let joinRingCount = 0;
  let joinLists = 0;

  // ── The two daemons' notify recorders (start empty) ──────────────────────────────────────────
  const notified: Notify[] = [];
  const notify = {
    channelPosts() {},
    channelJoinAnswer: (agentId: string, channel: string, outcome: string, reason?: string) => { notified.push({ event: "answer", agentId, channel, outcome, ...(reason ? { reason } : {}) }); },
    channelJoinRequest: (agentId: string, channel: string, subscriber: string) => { notified.push({ event: "request", agentId, channel, subscriber }); },
    channelMembershipEnded() {}, channelPosterRemoved() {},
  };

  const relayHalves = (wiringRef: () => ReturnType<typeof wireChannelMembership> | null) => ({
    depositNotice: (_r: string[], record: Uint8Array) => {
      const d = decodeChannelNotice(record);
      if (!d.ok) return Promise.resolve(0);
      noticeSlots.set(hex(d.notice.slot), record);
      return Promise.resolve(2);
    },
    fetchNotices: (_r: string[], slot: Uint8Array) => Promise.resolve(noticeSlots.has(hex(slot)) ? [noticeSlots.get(hex(slot))!] : []),
    depositJoin: (_r: string[], record: Uint8Array) => {
      if (relayJoinRefusal) return Promise.resolve({ accepted: 0, refusals: [relayJoinRefusal, relayJoinRefusal] });
      const d = decodeChannelJoinSlotRecord(record);
      if (!d.ok) return Promise.resolve({ accepted: 0, refusals: ["bad_record"] });
      joinSlots.set(hex(d.record.slot), record);
      return Promise.resolve({ accepted: 2, refusals: [] });
    },
    fetchJoins: (_r: string[], slot: Uint8Array) => Promise.resolve(joinSlots.has(hex(slot)) ? [joinSlots.get(hex(slot))!] : []),
    // 047: the relay serves the channel's waiting requests only to a signature by the CHANNEL key
    // over its fresh nonce — anything else lists nothing.
    listJoins: async (_r: string[], ch: string, sign: (tbs: Uint8Array) => Promise<Uint8Array>) => {
      joinLists += 1;
      const nonce = new Uint8Array(32).map(() => Math.floor(Math.random() * 256));
      const tbs = buildChannelJoinListTbs(new Uint8Array(Buffer.from(ch, "hex")), nonce);
      if (!verify(new Uint8Array(Buffer.from(ch, "hex")), tbs, await sign(tbs))) return [];
      return [...joinSlots.values()].filter((r) => { const d = decodeChannelJoinSlotRecord(r); return d.ok && hex(d.record.channel_pubkey) === ch; });
    },
    // The admin rings the joiner: the joiner's daemon reads its notices, as its wake does.
    ringMembers: (_agent: string, _ch: string, members: string[]) => {
      rings.push(...members);
      if (members.includes(joinerHex) && !joinerOffline) void wiringRef()?.checkNotices(SUB_ID);
      return Promise.resolve(true);
    },
    isAgentOnline: () => true,
  });

  // ── The admin's daemon ───────────────────────────────────────────────────────────────────────
  // Its own file per world; left open (the tmp dir is removed after each test) because the posting
  // admin's lease timer, which `stop()` does not own, may still tick against it.
  const adminDb = openTestDb(join(dir, `admin-${channelHex.slice(0, 8)}.db`));
  const adminMembers = new ChannelMembershipStore(adminDb, silent);
  adminMembers.putSettings(channelHex, {
    access: opts.access, members_visible: false, guidance: "release notes",
    retention_seconds: retention, relays: [RELAY_A, RELAY_B], admin_pubkey: adminHex,
  });
  const adminInbound = new Set<(f: Record<string, unknown>) => void>();
  const adminSignaling: SignalingLike = {
    registerInboundHandler(cb) { adminInbound.add(cb); return () => adminInbound.delete(cb); },
    sendRaw(frame: unknown) {
      const f = frame as Record<string, unknown>;
      if (f["type"] === "channel_relay_record_set") {
        relayRecord = f["record"] as Uint8Array;
        queueMicrotask(() => { for (const cb of adminInbound) cb({ type: "channel_relay_record_ack", channel_pubkey: f["channel_pubkey"] }); });
      }
      return Promise.resolve({ ok: true as const });
    },
  };
  const adminHandlers = new Map<string, Handler>();
  let joinerWiring: ReturnType<typeof wireChannelMembership> | null = null;
  const adminWiring = wireChannelMembership({
    handlers: adminHandlers, logger: silent, getDb: () => adminDb,
    loadedAgents: [
      { name: ADMIN_NAME, pubkey: adminHex, keyProvider: adminKp },
      { name: CHANNEL_NAME, pubkey: channelHex, keyProvider: channelKp },
    ],
    keyProviders: new Map<string, InMemoryKeyProvider>([[ADMIN_NAME, adminKp], [CHANNEL_NAME, channelKp]]),
    resolveAgentId: (n) => (n === ADMIN_NAME ? ADMIN_ID : `id-of-${n}`),
    resolveCurrentAgent: () => ADMIN_NAME,
    signalingFor: (n) => (n === ADMIN_NAME ? adminSignaling : null),
    notify, collectNow: () => {}, isChannelAgent: (n) => n === CHANNEL_NAME,
    channelLastSeq: () => null, fetchChannelInfo: () => Promise.resolve(info),
    pruneAllPosts: () => Promise.resolve({ pruned: 0, relays: [] }),
    noticeTransport: () => relayHalves(() => joinerWiring),
  } as ChannelMembershipWiringDeps);

  // ── The joiner's daemon ──────────────────────────────────────────────────────────────────────
  const joinerInbound = new Set<(f: Record<string, unknown>) => void>();
  const joinerSignaling: SignalingLike = {
    registerInboundHandler(cb) { joinerInbound.add(cb); return () => joinerInbound.delete(cb); },
    sendRaw(frame: unknown) {
      const f = frame as Record<string, unknown>;
      const ch = f["channel_pubkey"] as Uint8Array;
      const reply = (r: Record<string, unknown>): void => { queueMicrotask(() => { for (const cb of joinerInbound) cb({ channel_pubkey: ch, ...r }); }); };
      if (f["type"] === "channel_admin_query") {
        if (revoked) reply({ type: "channel_admin_result", registered: false, channel: false, revoked: true, admin_pubkey: "" });
        else reply({ type: "channel_admin_result", registered: true, channel: true, admin_pubkey: adminHex, ...(relayRecord ? { relay_record: relayRecord } : {}) });
      }
      if (f["type"] === "channel_join_ring") {
        joinRingCount += 1;
        if (ringRefusal) { reply({ type: "channel_join_ring_error", reason: ringRefusal }); }
        else {
          // The directory rings the admin, naming the joiner it AUTHENTICATED — then acks.
          if (!adminOffline) void adminWiring.onJoinBell(hex(ch), joinerHex);
          reply({ type: "channel_join_ring_ack", delivered: true });
        }
      }
      return Promise.resolve({ ok: true as const });
    },
  };
  const joinerHandlers = new Map<string, Handler>();
  joinerWiring = wireChannelMembership({
    handlers: joinerHandlers, logger: silent, getDb: () => db,
    loadedAgents: [{ name: SUB_NAME, pubkey: joinerHex, keyProvider: joinerKp }],
    keyProviders: new Map([[SUB_NAME, joinerKp]]),
    resolveAgentId: (n) => (n === SUB_NAME ? SUB_ID : `id-of-${n}`),
    resolveCurrentAgent: () => SUB_NAME,
    signalingFor: (n) => (n === SUB_NAME ? joinerSignaling : null),
    notify, collectNow: () => {}, isChannelAgent: () => false,
    channelLastSeq: () => null, fetchChannelInfo: () => Promise.resolve(info),
    pruneAllPosts: () => Promise.resolve({ pruned: 0, relays: [] }),
    noticeTransport: () => relayHalves(() => joinerWiring),
  } as ChannelMembershipWiringDeps);

  const publishRelayRecord = async (): Promise<void> => {
    // The admin publishes on its relay-record tick; tests advance that tick rather than reach inside.
    await vi.advanceTimersByTimeAsync(RELAY_RECORD_TICK_MS);
  };
  const joinAs = (params: Record<string, unknown> = {}) =>
    joinerHandlers.get("cello_channel_join")!({ channel: channelHex, note: "hi, it is Alice", ...params }, "c") as Promise<Record<string, unknown>>;
  const slotOfAnswer = async (): Promise<string> =>
    hex(channelNoticeSlot((await channelKp.staticSharedSecret(new Uint8Array(Buffer.from(joinerHex, "hex"))))!, "join_answer"));

  return {
    joinerKp, channelKp, adminKp, joinerHex, channelHex, adminHex, adminMembers, adminHandlers, joinerHandlers,
    adminWiring, joinerWiring, notified, rings, noticeSlots, joinSlots, publishRelayRecord, joinAs, slotOfAnswer,
    subs: new ChannelSubscriptionStore(db, silent), adminSubs: new ChannelSubscriptionStore(adminDb, silent),
    setRevoked: (v: boolean) => { revoked = v; },
    setRingRefusal: (r: string | null) => { ringRefusal = r; },
    setAdminOffline: (v: boolean) => { adminOffline = v; },
    setRelayJoinRefusal: (r: string | null) => { relayJoinRefusal = r; },
    setJoinerOffline: (v: boolean) => { joinerOffline = v; },
    joinRings: () => joinRingCount,
    joinLists: () => joinLists,
    close: () => { joinerWiring?.stop(); adminWiring.stop(); },
  };
}

/** Let queued microtasks and fire-and-forget promises settle under fake timers. */
const settle = async (): Promise<void> => { for (let i = 0; i < 20; i++) await vi.advanceTimersByTimeAsync(5); };

describe("M16 046-JOINBELL — joining is records plus a ring, never a session", () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ["setInterval", "setTimeout", "Date"] }); vi.setSystemTime(1_800_000_000_000); });
  afterEach(() => { vi.useRealTimers(); });

  it("1. an OPEN channel: the joiner is admitted with the key, told 'admitted', and the admin's agent is not alerted", async () => {
    const w = await joinWorld({ access: "open" });
    await w.publishRelayRecord();
    const res = await w.joinAs();
    expect(res).toMatchObject({ ok: true, state: "requested", rung: true });
    await settle();

    const sub = w.subs.get(SUB_ID, w.channelHex);
    expect(sub?.access).toBe("open");
    expect(sub?.relays).toEqual([RELAY_A, RELAY_B]);
    expect(sub?.guidance).toBe("release notes");
    expect(w.subs.keysFor(SUB_ID, w.channelHex).map((k) => k.generation)).toEqual([1]);
    expect(w.notified.filter((n) => n.event === "answer")).toEqual([{ event: "answer", agentId: SUB_ID, channel: w.channelHex, outcome: "admitted" }]);
    expect(w.notified.filter((n) => n.event === "request")).toEqual([]);
    expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBe("active");
    w.close();
  });

  it("2. INVITE-ONLY: pending, the admin's agent is alerted ONCE (a repeat ring is silent), and approve admits", async () => {
    const w = await joinWorld({ access: "invite_only" });
    await w.publishRelayRecord();
    await w.joinAs();
    await settle();
    expect(w.notified.filter((n) => n.event === "request")).toEqual([{ event: "request", agentId: ADMIN_ID, channel: w.channelHex, subscriber: w.joinerHex }]);
    expect(w.notified.filter((n) => n.event === "answer").map((n) => n.outcome)).toEqual(["pending"]);

    // The same record rung again — the nagging guard.
    await w.adminWiring.onJoinBell(w.channelHex, w.joinerHex);
    await settle();
    expect(w.notified.filter((n) => n.event === "request")).toHaveLength(1);

    const approved = await w.adminHandlers.get("cello_channel_approve")!({ channel: w.channelHex, subscriber: w.joinerHex }, "c");
    expect(approved).toEqual({ ok: true, channel: w.channelHex });
    await settle();
    expect(w.subs.get(SUB_ID, w.channelHex)?.status).toBe("active");
    expect(w.notified.filter((n) => n.event === "answer").map((n) => n.outcome)).toEqual(["pending", "admitted"]);
    w.close();
  });

  it("3. a FORGED answer (not signed by the channel key) is dropped; nothing is stored", async () => {
    const w = await joinWorld({ access: "invite_only" });
    await w.publishRelayRecord();
    await w.joinAs();
    await settle();
    // A forger writes an 'accepted' answer into the joiner's answer slot, naming the real channel.
    const forger = generateKeypair() as InMemoryKeyProvider;
    const slot = new Uint8Array(Buffer.from(await w.slotOfAnswer(), "hex"));
    const answer = await signChannelJoinAnswer(forger, { outcome: "accepted", reason: null, key_bundle: new Uint8Array(40).fill(1), signed_at: Date.now() + 10 });
    const notice = await signChannelNotice(forger, {
      slot, type: "join_answer", issued_at: Date.now() + 10,
      sealed: sealToRecipient(await w.joinerKp.getPublicKey(), encodeChannelJoinAnswer({ ...answer, channel_pubkey: new Uint8Array(Buffer.from(w.channelHex, "hex")) })),
    });
    w.noticeSlots.set(hex(slot), encodeChannelNotice({ ...notice, channel_pubkey: new Uint8Array(Buffer.from(w.channelHex, "hex")) }));
    await w.joinerWiring!.checkNotices(SUB_ID);
    expect(w.subs.get(SUB_ID, w.channelHex)).toBeNull();
    expect(w.notified.filter((n) => n.outcome === "admitted")).toEqual([]);
    w.close();
  });

  it("4. a genuine answer for a channel this agent never asked to join is ignored", async () => {
    const w = await joinWorld({ access: "open" });
    // The admin writes an acceptance nobody requested (no join, so no outstanding request).
    const slot = new Uint8Array(Buffer.from(await w.slotOfAnswer(), "hex"));
    const answer = await signChannelJoinAnswer(w.channelKp, { outcome: "accepted", reason: null, key_bundle: null, signed_at: Date.now() });
    const notice = await signChannelNotice(w.channelKp, { slot, type: "join_answer", issued_at: Date.now(), sealed: sealToRecipient(await w.joinerKp.getPublicKey(), encodeChannelJoinAnswer(answer)) });
    w.noticeSlots.set(hex(slot), encodeChannelNotice(notice));
    await w.joinerWiring!.checkNotices(SUB_ID);
    expect(w.subs.get(SUB_ID, w.channelHex)).toBeNull();
    w.close();
  });

  it("5. a replayed acceptance older than the latest ejection this agent holds is dropped", async () => {
    // PUBLIC, so the replayed acceptance needs no key and would otherwise be applied as it stands.
    const w = await joinWorld({ access: "public" });
    await w.publishRelayRecord();
    const oldAnswer = await signChannelJoinAnswer(w.channelKp, { outcome: "accepted", reason: null, key_bundle: null, signed_at: Date.now() - 60_000 });
    // This agent holds an ejection from the channel, newer than that answer.
    new ChannelNoticeSeenStore(db).set(SUB_ID, w.channelHex, "eject", Date.now() - 1_000);
    w.setRingRefusal("rate_limited"); // keep the admin out of it: only the replay is in the slot
    await w.joinAs();
    w.setRingRefusal(null);
    const slot = new Uint8Array(Buffer.from(await w.slotOfAnswer(), "hex"));
    const notice = await signChannelNotice(w.channelKp, { slot, type: "join_answer", issued_at: Date.now(), sealed: sealToRecipient(await w.joinerKp.getPublicKey(), encodeChannelJoinAnswer(oldAnswer)) });
    w.noticeSlots.set(hex(slot), encodeChannelNotice(notice));
    await w.joinerWiring!.checkNotices(SUB_ID);
    expect(w.subs.get(SUB_ID, w.channelHex)).toBeNull();
    // Control: with no ejection held, the very same answer IS applied — so the ejection is what refused it.
    new ChannelNoticeSeenStore(db).set(SUB_ID, w.channelHex, "eject", 0);
    await w.joinerWiring!.checkNotices(SUB_ID);
    expect(w.subs.get(SUB_ID, w.channelHex)?.access).toBe("public");
    w.close();
  });

  it("6. WITHDRAW: leaving a pending request drops it from the admin's list, and the admin's agent is not alerted again", async () => {
    const w = await joinWorld({ access: "invite_only" });
    await w.publishRelayRecord();
    await w.joinAs();
    await settle();
    expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBe("pending");
    await vi.advanceTimersByTimeAsync(10);
    const left = await w.joinerHandlers.get("cello_channel_leave")!({ channel: w.channelHex }, "c");
    expect(left).toMatchObject({ ok: true, withdrawn: true });
    // No manual ring: the withdrawal rings the admin itself.
    await settle();
    expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBeNull();
    expect(w.notified.filter((n) => n.event === "request")).toHaveLength(1);
    w.close();
  });

  it("7. LAPSE: after the channel's retention the joiner is told 'expired' and the admin's pending list drops it", async () => {
    const w = await joinWorld({ access: "invite_only", retentionSeconds: 60 });
    await w.publishRelayRecord();
    await w.joinAs();
    await settle();
    expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBe("pending");
    vi.setSystemTime(Date.now() + 61_000);
    await w.joinerWiring!.checkNotices(SUB_ID);
    expect(w.notified.filter((n) => n.event === "answer").map((n) => n.outcome)).toEqual(["pending", "expired"]);
    await vi.advanceTimersByTimeAsync(NOTICE_BACKSTOP_TICK_MS);
    expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBeNull();
    w.close();
  });

  it("8. a guard refusal is TOLD with the guidance — the directory's rate limit and the relay's slot cap", async () => {
    const w = await joinWorld({ access: "open" });
    await w.publishRelayRecord();
    w.setRingRefusal("rate_limited");
    expect(await w.joinAs()).toEqual({ ok: false, reason: "rate_limited", guidance: JOIN_THROTTLE_GUIDANCE });
    w.setRingRefusal(null);
    w.setRelayJoinRefusal("join_slot_cap");
    expect(await w.joinAs()).toEqual({ ok: false, reason: "join_slot_cap", guidance: JOIN_THROTTLE_GUIDANCE });
    w.close();
  });

  it("10. a PUBLIC channel admits with NO key — an active subscription with the relays, nothing to unwrap", async () => {
    const w = await joinWorld({ access: "public" });
    await w.publishRelayRecord();
    await w.joinAs();
    await settle();
    expect(w.subs.get(SUB_ID, w.channelHex)?.access).toBe("public");
    expect(w.subs.keysFor(SUB_ID, w.channelHex)).toEqual([]);
    w.close();
  });

  it("11. already_member and ejected are refused BY NAME, and an ejected member stays out", async () => {
    for (const status of ["active", "ejected"] as const) {
      const w = await joinWorld({ access: "open" });
      await w.publishRelayRecord();
      w.adminMembers.admit(w.channelHex, w.joinerHex, status, 1000);
      await w.joinAs();
      await settle();
      expect(w.notified.filter((n) => n.event === "answer")).toEqual([{
        event: "answer", agentId: SUB_ID, channel: w.channelHex, outcome: "refused", reason: status === "active" ? "already_member" : "ejected",
      }]);
      expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBe(status);
      w.close();
    }
  });

  it("12. a member admitted AFTER a post receives the very key that post was encrypted with (028)", async () => {
    const w = await joinWorld({ access: "open" });
    const minted = ensureCurrentGroupKey({ members: w.adminMembers, subscriptions: w.adminSubs, now: () => Date.now() }, ADMIN_ID, w.channelHex);
    await w.publishRelayRecord();
    await w.joinAs();
    await settle();
    const keys = w.subs.keysFor(SUB_ID, w.channelHex);
    expect(keys.map((k) => k.generation)).toEqual([minted!.generation]);
    expect(Buffer.from(keys[0]!.key).equals(Buffer.from(minted!.key))).toBe(true);
    w.close();
  });

  it("13. REFUSING is not ejecting: it cannot remove an existing member", async () => {
    const w = await joinWorld({ access: "invite_only" });
    w.adminMembers.admit(w.channelHex, w.joinerHex, "active", 1000);
    const res = await w.adminHandlers.get("cello_channel_refuse")!({ channel: w.channelHex, subscriber: w.joinerHex }, "c") as Record<string, unknown>;
    expect(res.ok).toBe(false);
    expect(String(res.reason)).toContain("not_a_pending_request");
    expect(w.adminMembers.statusOf(w.channelHex, w.joinerHex)).toBe("active");
    w.close();
  });

  it("14. 047 perfect bad sync: admin offline at the ring, joiner offline at the answer — each side's reconnect completes it, one ring total", async () => {
    const w = await joinWorld({ access: "invite_only" });
    await w.publishRelayRecord();
    w.setAdminOffline(true);
    await w.joinAs();
    await settle();
    // The joiner rings ONCE: a backstop tick sends no second ring (the 046 re-ring is gone).
    await vi.advanceTimersByTimeAsync(NOTICE_BACKSTOP_TICK_MS);
    await settle();
    expect(w.joinRings()).toBe(1);
    expect(w.notified.filter((n) => n.event === "request")).toEqual([]);
    // The admin comes back: its reconnect lists the channel's waiting requests and is alerted at once.
    w.setAdminOffline(false);
    w.setJoinerOffline(true);
    w.adminWiring.onReconnect(ADMIN_NAME);
    await settle();
    expect(w.joinLists()).toBe(1);
    expect(w.notified.filter((n) => n.event === "request")).toEqual([{ event: "request", agentId: ADMIN_ID, channel: w.channelHex, subscriber: w.joinerHex }]);
    const approved = (await w.adminHandlers.get("cello_channel_approve")!({ channel: w.channelHex, subscriber: w.joinerHex }, "c")) as Record<string, unknown>;
    expect(approved["ok"]).toBe(true);
    await settle();
    expect(w.subs.get(SUB_ID, w.channelHex)?.status ?? null).toBeNull();
    // The joiner comes back: the daemon's reconnect hook runs checkNotices, which reads its answer slot.
    w.setJoinerOffline(false);
    void w.joinerWiring!.checkNotices(SUB_ID);
    await settle();
    expect(w.subs.get(SUB_ID, w.channelHex)?.status).toBe("active");
    expect(w.notified.filter((n) => n.event === "answer").map((n) => n.outcome)).toContain("admitted");
    expect(w.joinRings()).toBe(1);
    w.close();
  });

  it("15. 047 a reconnect of an agent that administers no channel lists nothing", async () => {
    const w = await joinWorld({ access: "open" });
    w.joinerWiring!.onReconnect(SUB_NAME);
    await settle();
    expect(w.joinLists()).toBe(0);
    w.close();
  });

  it("9. a deleted channel is refused channel_deleted, and a channel with no relay record no_relays — nothing is written", async () => {
    const w = await joinWorld({ access: "open" });
    expect(await w.joinAs()).toMatchObject({ ok: false, reason: "no_relays" });
    await w.publishRelayRecord();
    w.setRevoked(true);
    expect(await w.joinAs()).toMatchObject({ ok: false, reason: "channel_deleted" });
    expect(w.joinSlots.size).toBe(0);
    w.close();
  });
});

// ─── M16 034-LIFECYCLE — the ADMIN side: eject tells the member, and a channel can be deleted ─────
//
// A daemon that HOLDS a channel and its admin agent. The only fakes are outside the daemon: the
// sessions a frame rides, the session-opener, the relay prune, and the retire path.

async function adminHarness() {
  const adminKp = generateKeypair() as InMemoryKeyProvider;
  const channelKp = generateKeypair() as InMemoryKeyProvider;
  const adminHex = hex(await adminKp.getPublicKey());
  const channelHex = hex(await channelKp.getPublicKey());

  const handlers = new Map<string, Handler>();

  // What the wiring's own stores read — configured on the SAME db, so its internal stores see it.
  const members = new ChannelMembershipStore(db, silent);
  members.putSettings(channelHex, {
    access: "invite_only", members_visible: false, guidance: "release notes",
    retention_seconds: 7 * 24 * 3600, relays: [RELAY_A, RELAY_B], admin_pubkey: adminHex,
  });

  // Recorders — start empty, so a test cannot pass on a value that was never produced.
  const prunedChannels: string[] = [];
  const removedAgents: string[] = [];
  const closedSessions: Array<{ session_id: string; agent: string }> = [];
  // 040-CLEANUP Part A: a capturing logger, so a test can prove the re-key logged an unreached
  // member with the send error as the reason (not just that the array named them).
  const logs: Array<{ level: string; event: string; ctx?: Record<string, unknown> }> = [];
  const capLogger: Logger = {
    debug: (event, ctx) => { logs.push({ level: "debug", event, ctx }); },
    info: (event, ctx) => { logs.push({ level: "info", event, ctx }); },
    warn: (event, ctx) => { logs.push({ level: "warn", event, ctx }); },
    error: (event, ctx) => { logs.push({ level: "error", event, ctx }); },
  };
  // Configurable: whether the fake retire path succeeds.
  let removeAgentResult: { ok: boolean; reason?: string } = { ok: true };
  // Configurable: the admin's directory connection. Null by default (this daemon administers the
  // channel from its own settings, so no directory round trip is needed). B3 sets one that answers
  // `revoked` to prove a deleted channel's `info` now asks the directory.
  let signaling: SignalingLike | null = null;

  // 045-NOTICEBELL: every notice record deposited (decoded), every ring, and which slots the relays refuse.
  const notices: Array<{ type: string; slot: string; record: Uint8Array }> = [];
  const rings: Array<{ agent: string; channel: string; members: string[]; afterRetire: boolean }> = [];
  let refusedSlots = new Set<string>();
  let ringOk = true;

  // A fake retire path — the real cello_remove_agent lives in agent-handlers; here we only prove
  // delete REACHES it with the channel's name.
  handlers.set("cello_remove_agent", (params) => {
    removedAgents.push(String(params?.["name"] ?? ""));
    return Promise.resolve(removeAgentResult);
  });
  // A fake close path — the real one lives in close-session-handler; here we only prove notifyRefused
  // closes a session it OPENED and leaves an existing one alone.
  handlers.set("cello_close_session", (params) => {
    closedSessions.push({ session_id: String(params?.["session_id"] ?? ""), agent: String(params?.["agent"] ?? "") });
    return Promise.resolve({ ok: true });
  });

  wireChannelMembership({
    handlers,
    logger: capLogger,
    getDb: () => db,
    loadedAgents: [
      { name: ADMIN_NAME, pubkey: adminHex, keyProvider: adminKp },
      { name: CHANNEL_NAME, pubkey: channelHex, keyProvider: channelKp },
    ],
    keyProviders: new Map<string, InMemoryKeyProvider>([[ADMIN_NAME, adminKp], [CHANNEL_NAME, channelKp]]),
    resolveAgentId: (agentName) => (agentName === ADMIN_NAME ? ADMIN_ID : `id-of-${agentName}`),
    resolveCurrentAgent: () => ADMIN_NAME,
    signalingFor: (agentName) => (agentName === ADMIN_NAME ? signaling : null),
    notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    pruneAllPosts: (agentName, chHex) => {
      prunedChannels.push(chHex);
      return Promise.resolve({ pruned: 3, relays: [{ relay: RELAY_A, ok: true }, { relay: RELAY_B, ok: true }] });
    },
    // 041-HELPTRUTH: the two deps `cello_channels` reads. This channel identity is CHANNEL_NAME, and
    // its log is empty here (the post count on an admin row is null).
    isChannelAgent: (name) => name === CHANNEL_NAME,
    channelLastSeq: () => null,
    fetchChannelInfo: () => Promise.resolve(null),
    noticeTransport: () => ({
      depositNotice: (_relays, record) => {
        const d = decodeChannelNotice(record);
        if (!d.ok) throw new Error(d.reason);
        if (refusedSlots.has(hex(d.notice.slot))) return Promise.resolve(0);
        notices.push({ type: d.notice.type, slot: hex(d.notice.slot), record });
        return Promise.resolve(2);
      },
      fetchNotices: () => Promise.resolve([]),
      depositJoin: () => Promise.resolve({ accepted: 0, refusals: [] }),
      fetchJoins: () => Promise.resolve([]),
      ringMembers: (agent, channel, ringed) => {
        // Whether the retire (the directory revocation) had already run when this ring went out.
        rings.push({ agent, channel, members: ringed, afterRetire: removedAgents.length > 0 });
        return Promise.resolve(ringOk);
      },
      isAgentOnline: () => true,
    }),
  });

  /** The slot a notice of `type` for `memberHex` lives under — computed the way the member does. */
  const slotFor = async (memberHex: string, type: "pass" | "eject" | "group_key"): Promise<string> =>
    hex(channelNoticeSlot((await channelKp.staticSharedSecret(new Uint8Array(Buffer.from(memberHex, "hex"))))!, type));

  return {
    handlers, members, adminKp, channelKp, adminHex, channelHex,
    prunedChannels, removedAgents, closedSessions, logs, notices, rings, slotFor,
    setRefusedSlots: (slots: string[]) => { refusedSlots = new Set(slots); },
    setRingOk: (ok: boolean) => { ringOk = ok; },
    setRemoveAgentResult: (r: typeof removeAgentResult) => { removeAgentResult = r; },
    setSignaling: (s: SignalingLike | null) => { signaling = s; },
    subs: new ChannelSubscriptionStore(db, silent),
  };
}

describe("M16 034-LIFECYCLE — admin side: eject tells the member, delete removes the channel", () => {
  it("1. eject writes the ejected member a sealed eject notice and rings them — no session", async () => {
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);

    const res = (await h.handlers.get("cello_channel_eject")!(
      { channel: h.channelHex, subscriber: memberHex }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.member_notified, "the eject notice reached the relays").toBe(true);
    expect(h.notices.map((n) => ({ type: n.type, slot: n.slot }))).toEqual([{ type: "eject", slot: await h.slotFor(memberHex, "eject") }]);
    expect(h.rings).toEqual([{ agent: ADMIN_NAME, channel: h.channelHex, members: [memberHex], afterRetire: false }]);
  });

  it("2. eject when no relay takes the notice → ok, member_notified false, and the ejection still holds", async () => {
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setRefusedSlots([await h.slotFor(memberHex, "eject")]);

    const res = (await h.handlers.get("cello_channel_eject")!(
      { channel: h.channelHex, subscriber: memberHex }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.member_notified).toBe(false);
    expect(h.members.statusOf(h.channelHex, memberHex)).toBe("ejected");
  });

  it("040-CLEANUP Part A (045): a remaining member whose new-key notice no relay takes is named in unreached; the others still get theirs", async () => {
    const h = await adminHarness();
    const mk = async () => hex(await (generateKeypair() as InMemoryKeyProvider).getPublicKey());
    const ejectHex = await mk();
    const m1 = await mk();
    const m2 = await mk();
    const m3 = await mk();
    for (const m of [ejectHex, m1, m2, m3]) h.members.admit(h.channelHex, m, "active", 1000);
    h.setRefusedSlots([await h.slotFor(m2, "group_key")]);

    const res = (await h.handlers.get("cello_channel_eject")!(
      { channel: h.channelHex, subscriber: ejectHex }, "conn-1",
    )) as { ok: boolean; delivered: number; unreached: string[] };

    expect(res.ok).toBe(true);
    expect(res.delivered).toBe(2);
    expect(res.unreached).toEqual([m2]);
    const keySlots = h.notices.filter((n) => n.type === "group_key").map((n) => n.slot).sort();
    expect(keySlots).toEqual([await h.slotFor(m1, "group_key"), await h.slotFor(m3, "group_key")].sort());
    // One ring: the ejected member and every remaining member that has a new key to read.
    expect(h.rings).toHaveLength(1);
    expect([...h.rings[0]!.members].sort()).toEqual([ejectHex, m1, m3].sort());
  });

  it("4. cello_channels lists an ejected subscription with status ejected, hides left, and shows unread", async () => {
    const h = await adminHarness();
    const active = "cc".repeat(32);
    const ejected = "dd".repeat(32);
    const left = "ff".repeat(32);
    for (const ch of [active, ejected, left]) {
      h.subs.upsert({ agent_id: ADMIN_ID, channel_pubkey: ch, admin_pubkey: h.adminHex, access: "open", relays: [RELAY_A] });
    }
    h.subs.setDeliveredThrough(ADMIN_ID, ejected, 5); // 5 unread on the ejected one — still computed
    h.subs.markEjected(ADMIN_ID, ejected);
    h.subs.markLeft(ADMIN_ID, left);

    const res = (await h.handlers.get("cello_channels")!({}, "conn-1")) as {
      ok: boolean; channels: Array<{ channel: string; status: string; unread: number }>;
    };
    expect(res.ok).toBe(true);
    const byChannel = new Map(res.channels.map((c) => [c.channel, c]));
    expect(byChannel.get(active)?.status).toBe("active");
    expect(byChannel.get(ejected)?.status).toBe("ejected");
    expect(byChannel.get(ejected)?.unread, "unread is still computed for an ejected channel").toBe(5);
    expect(byChannel.has(left), "a channel the operator LEFT stays hidden").toBe(false);
  });

  it("5. delete prunes, retires (revokes at the directory), THEN rings active AND pending members — no session", async () => {
    const h = await adminHarness();
    const activeKp = generateKeypair() as InMemoryKeyProvider;
    const pendingKp = generateKeypair() as InMemoryKeyProvider;
    const activeHex = hex(await activeKp.getPublicKey());
    const pendingHex = hex(await pendingKp.getPublicKey());
    h.members.admit(h.channelHex, activeHex, "active", 1000);
    h.members.admit(h.channelHex, pendingHex, "pending", 1000);

    const res = (await h.handlers.get("cello_channel_delete")!(
      { channel: h.channelHex }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.members_notified).toBe(2);
    expect(res.members_unreached).toEqual([]);
    // The ring goes out only after the revocation, so a rung member's first check reads "deleted".
    expect(h.rings).toEqual([{ agent: ADMIN_NAME, channel: h.channelHex, members: [activeHex, pendingHex], afterRetire: true }]);
    expect(h.prunedChannels).toEqual([h.channelHex]);
    expect(res.relays).toEqual([{ relay: RELAY_A, ok: true }, { relay: RELAY_B, ok: true }]);
    expect(h.removedAgents).toEqual([CHANNEL_NAME]);
    expect(res.retired).toBe(true);
  });

  it("6. delete of a channel this daemon does not administer is refused — nothing sent, nothing pruned, nothing retired", async () => {
    const h = await adminHarness();
    const notOurs = "ab".repeat(32); // a channel key this daemon does not hold

    const res = (await h.handlers.get("cello_channel_delete")!(
      { channel: notOurs }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("channel_not_local");
    expect(h.prunedChannels, "nothing was pruned").toEqual([]);
    expect(h.removedAgents, "no identity was retired").toEqual([]);
  });

  it("045: six notices to one member leave ZERO sessions between admin and member", async () => {
    const h = await adminHarness();
    const memberHex = hex(await (generateKeypair() as InMemoryKeyProvider).getPublicKey());
    const otherHex = hex(await (generateKeypair() as InMemoryKeyProvider).getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.members.admit(h.channelHex, otherHex, "active", 1000);
    const call = (verb: string, params: Record<string, unknown>) => h.handlers.get(verb)!({ channel: h.channelHex, ...params }, "conn-1");

    await call("cello_channel_posting", { posting: "listed" });
    await call("cello_channel_poster_add", { poster: memberHex });      // 1. pass
    await call("cello_channel_poster_remove", { poster: memberHex });   // 2. poster removed
    await call("cello_channel_poster_add", { poster: memberHex });      // 3. pass again
    await call("cello_channel_eject", { subscriber: otherHex });        // 4. new group key
    await call("cello_channel_eject", { subscriber: memberHex });       // 5. ejected
    h.members.admit(h.channelHex, memberHex, "pending", 2000);
    await call("cello_channel_delete", {});                             // 6. channel deleted

    const rungForMember = h.rings.filter((r) => r.members.includes(memberHex)).length;
    expect(rungForMember).toBe(6);
    expect(h.closedSessions).toEqual([]);
  });

  it("review MEDIUM: delete reports retired:false with a reason and guidance when the retire fails", async () => {
    // The notices and prune already ran, so delete is ok:true — but the channel identity is still
    // loaded, and an operator must be told that and how to finish. A silent ok:true hid it.
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setRemoveAgentResult({ ok: false, reason: "agent_not_found" });

    const res = (await h.handlers.get("cello_channel_delete")!(
      { channel: h.channelHex }, "conn-1",
    )) as Record<string, unknown>;

    // The members were still told and the relays still pruned — delete's first two steps succeeded.
    expect(res.ok).toBe(true);
    expect(res.members_notified).toBe(1);
    expect(h.prunedChannels).toEqual([h.channelHex]);
    // But the retire failed, and the answer says so, with the reason and operator guidance.
    expect(res.retired).toBe(false);
    expect(res.retire_reason).toBe("agent_not_found");
    expect(typeof res.guidance).toBe("string");
    expect(String(res.guidance)).toContain(CHANNEL_NAME);
  });

  // ─── M16 039-NEWCHANFIX Part B — a deleted channel is forgotten by the admin's OWN daemon ──────
  //
  // A delete used to leave the channel's local settings and config rows behind, so `channel info` on
  // the admin's own daemon still answered admin/access/relays/description from them without ever
  // asking the directory — the channel read as live after it was deleted. After a SUCCESSFUL retire
  // the delete now forgets those rows; the post log (the admin's own record) survives.

  it("B1. after delete with a successful retire, settings and config are gone but the post log survives (039-NEWCHANFIX Part B)", async () => {
    const h = await adminHarness();
    const config = new ChannelConfigStore(db, silent);

    // A post in the admin's own log — the durable record a delete must NOT touch (MUST NOT CHANGE 4).
    const log = new ChannelLogStore(db, silent);
    log.ensureChannel(h.channelHex);
    const { seq } = log.nextPosition(h.channelHex);
    const post = await signBroadcastArtifact(h.channelKp, h.adminKp, {
      seq, published_at: 1000, title: "kept", body: new TextEncoder().encode("body"), supersedes: null, ext: null,
    });
    log.append(h.channelHex, post);

    // Present before the delete.
    expect(h.members.settings(h.channelHex), "settings present before delete").not.toBeNull();
    expect(config.get(h.channelHex), "config present before delete").not.toBeNull();

    const res = (await h.handlers.get("cello_channel_delete")!({ channel: h.channelHex }, "conn-1")) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect(res.retired, "the retire succeeded, so the local rows are forgotten").toBe(true);

    // The admin's local rows are gone — info/join now ask the directory like any other daemon.
    expect(h.members.settings(h.channelHex), "settings row removed").toBeNull();
    expect(config.get(h.channelHex), "config row removed").toBeNull();
    // But the post log survives.
    expect(log.readRange(h.channelHex, seq, seq), "the admin's post log is kept").toHaveLength(1);
  });

  it("B2. a FAILED retire forgets nothing — the local rows remain (039-NEWCHANFIX Part B)", async () => {
    const h = await adminHarness();
    const config = new ChannelConfigStore(db, silent);
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setRemoveAgentResult({ ok: false, reason: "agent_not_found" });

    const res = (await h.handlers.get("cello_channel_delete")!({ channel: h.channelHex }, "conn-1")) as Record<string, unknown>;
    expect(res.retired).toBe(false);

    // The channel identity is still loaded, so the rows must stay — the guidance to finish by hand
    // still needs them, and a still-loaded channel must still resolve locally.
    expect(h.members.settings(h.channelHex), "settings row kept on a failed retire").not.toBeNull();
    expect(config.get(h.channelHex), "config row kept on a failed retire").not.toBeNull();
    expect(h.members.statusOf(h.channelHex, memberHex), "member row kept on a failed retire").toBe("active");
  });

  it("B3. info on a deleted channel asks the directory and reports channel_deleted (039-NEWCHANFIX Part B)", async () => {
    const h = await adminHarness();

    // A directory connection that answers this channel is revoked, recording each query.
    const inbound = new Set<(f: Record<string, unknown>) => void>();
    const asked: string[] = [];
    const signaling: SignalingLike = {
      registerInboundHandler(cb) { inbound.add(cb); return () => inbound.delete(cb); },
      sendRaw(frame: unknown) {
        const sent = frame as Record<string, unknown>;
        const askedHex = Buffer.from(sent["channel_pubkey"] as Uint8Array).toString("hex");
        asked.push(askedHex);
        queueMicrotask(() => {
          for (const cb of inbound) {
            cb({
              type: "channel_admin_result",
              channel_pubkey: new Uint8Array(Buffer.from(askedHex, "hex")),
              registered: false, channel: false, revoked: true,
            });
          }
        });
        return Promise.resolve({ ok: true as const });
      },
    };
    h.setSignaling(signaling);

    // Delete with a successful retire — this forgets the local settings and config rows.
    const del = (await h.handlers.get("cello_channel_delete")!({ channel: h.channelHex }, "conn-1")) as Record<string, unknown>;
    expect(del.retired).toBe(true);

    // With the rows gone, `info` can no longer answer locally — it asks the directory, which says
    // the channel is revoked, and that surfaces as channel_deleted.
    const info = (await h.handlers.get("cello_channel_info")!({ channel: h.channelHex }, "conn-1")) as Record<string, unknown>;
    expect(info.ok).toBe(false);
    expect(info.reason).toBe("channel_deleted");
    // The directory was asked exactly once, for this channel — the local short-circuit is gone.
    expect(asked, "info reached the directory once for the deleted channel").toEqual([h.channelHex]);
  });
});

// ─── M16 041-HELPTRUTH Parts A & B — `cello channels` lists what you follow AND what you run ─────
//
// Part A: with neither `--agent` nor a selected agent, `cello_channels` lists every OPERATOR agent's
// channels, grouped, instead of refusing `no_current_agent`. A channel identity is not an operator
// agent (033-CHANNELVIEW), so it is left out. Part B: an agent's list also carries a row for each
// channel it ADMINISTERS on this daemon (the config store's rows whose admin is this agent), with
// role "admin" and the channel's name/access/relays/last-published seq; followed channels are "member".

/** A daemon holding two operator agents plus one channel identity, driving `cello_channels` only. */
async function listHarness(): Promise<{
  handlers: Map<string, Handler>;
  a1Hex: string; a2Hex: string; chHex: string;
  subs: ChannelSubscriptionStore; config: ChannelConfigStore;
  setCurrent: (n: string | null) => void; setLastSeq: (channelHex: string, seq: number) => void;
}> {
  const a1kp = generateKeypair() as InMemoryKeyProvider;
  const a2kp = generateKeypair() as InMemoryKeyProvider;
  const chKp = generateKeypair() as InMemoryKeyProvider;
  const a1Hex = hex(await a1kp.getPublicKey());
  const a2Hex = hex(await a2kp.getPublicKey());
  const chHex = hex(await chKp.getPublicKey());
  const handlers = new Map<string, Handler>();
  let current: string | null = null;
  const lastSeq = new Map<string, number>();

  wireChannelMembership({
    handlers, logger: silent, getDb: () => db,
    loadedAgents: [
      { name: "Agent One", pubkey: a1Hex, keyProvider: a1kp },
      { name: "Agent Two", pubkey: a2Hex, keyProvider: a2kp },
      { name: "test-channel", pubkey: chHex, keyProvider: chKp },
    ],
    keyProviders: new Map<string, InMemoryKeyProvider>([["Agent One", a1kp], ["Agent Two", a2kp], ["test-channel", chKp]]),
    resolveAgentId: (agentName) => `id-of-${agentName}`,
    // Null when nothing is selected and nothing was named — the exact case Part A answers.
    resolveCurrentAgent: (_c, explicit) => explicit ?? current,
    signalingFor: () => null,
    notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    pruneAllPosts: () => Promise.resolve({ pruned: 0, relays: [] }),
    // 041 Part A: a channel identity is not an operator agent, so it is not one of the grouped rows.
    isChannelAgent: (name) => name === "test-channel",
    // 041 Part B: the last published seq for a channel this agent administers.
    channelLastSeq: (channelHex) => lastSeq.get(channelHex) ?? null,
  });

  return {
    handlers, a1Hex, a2Hex, chHex,
    subs: new ChannelSubscriptionStore(db, silent),
    config: new ChannelConfigStore(db, silent),
    setCurrent: (n) => { current = n; },
    setLastSeq: (channelHex, seq) => { lastSeq.set(channelHex, seq); },
  };
}

describe("M16 041-HELPTRUTH Part A — no agent lists every operator agent's channels, grouped", () => {
  it("with neither --agent nor a current agent, returns each operator agent's rows, and never a channel identity", async () => {
    const h = await listHarness();
    const ch1 = "1a".repeat(32);
    const ch2 = "2b".repeat(32);
    h.subs.upsert({ agent_id: "id-of-Agent One", channel_pubkey: ch1, admin_pubkey: "aa".repeat(32), access: "public", relays: [RELAY_A] });
    h.subs.upsert({ agent_id: "id-of-Agent Two", channel_pubkey: ch2, admin_pubkey: "bb".repeat(32), access: "open", relays: [RELAY_A] });
    h.setCurrent(null);

    const res = (await h.handlers.get("cello_channels")!({}, "conn-1")) as {
      ok: boolean; reason?: string; agents?: Array<{ agent: string; channels: Array<{ channel: string }> }>;
    };

    expect(res.ok, `no-agent listing must succeed, got ${res.reason ?? "ok"}`).toBe(true);
    expect(res.agents, "the answer is grouped by agent, not a flat channel list").toBeDefined();
    const byAgent = new Map(res.agents!.map((a) => [a.agent, a.channels.map((c) => c.channel)]));
    // Both operator agents appear; the channel identity does not.
    expect([...byAgent.keys()].sort()).toEqual(["Agent One", "Agent Two"]);
    expect(byAgent.get("Agent One")).toContain(ch1);
    expect(byAgent.get("Agent Two")).toContain(ch2);
  });

  it("review LOW: an explicit --agent that names no operator agent answers agent_unknown, not an empty list", async () => {
    const h = await listHarness();
    const res = (await h.handlers.get("cello_channels")!({ agent: "Bogus" }, "conn-1")) as {
      ok: boolean; reason?: string; guidance?: string; channels?: unknown[];
    };
    expect(res.ok, "an unknown --agent is an error, not an empty success").toBe(false);
    expect(res.reason).toBe("agent_unknown");
    expect(res.guidance).toContain("Bogus");
    expect(res.channels).toBeUndefined();

    // A REAL agent named explicitly still lists (ok: true), so the guard does not reject valid names.
    const ok = (await h.handlers.get("cello_channels")!({ agent: "Agent One" }, "conn-1")) as { ok: boolean };
    expect(ok.ok).toBe(true);
  });
});

describe("M16 041-HELPTRUTH Part B — the list also carries the channels you RUN", () => {
  it("a settings row under an ordinary agent's key, or a channel no longer held, is not listed", async () => {
    const h = await listHarness();
    const row = (admin: string) => ({
      access: "public" as const, relays: [RELAY_A, RELAY_B], guidance: "", retention_seconds: 3600,
      members_visible: false, admin_pubkey: admin,
    });
    h.config.set(h.chHex, row(h.a1Hex), Date.now());
    h.config.set(h.a1Hex, row(h.a1Hex), Date.now()); // the agent's OWN key, as a pre-fix setup left
    h.config.set("5e".repeat(32), row(h.a1Hex), Date.now()); // a deleted channel: no key held
    h.setCurrent("Agent One");
    const res = (await h.handlers.get("cello_channels")!({}, "conn-1")) as { channels: Array<Record<string, unknown>> };
    expect(res.channels.filter((c) => c.role === "admin").map((c) => c.channel)).toEqual([h.chHex]);
  });

  it("an agent that administers one channel and follows one subscription gets two rows, one per role", async () => {
    const h = await listHarness();
    const followed = "3c".repeat(32);
    // Agent One follows one channel...
    h.subs.upsert({ agent_id: "id-of-Agent One", channel_pubkey: followed, admin_pubkey: "aa".repeat(32), access: "public", relays: [RELAY_A] });
    // ...and administers the test-channel: a config row whose admin is Agent One's key.
    h.config.set(h.chHex, {
      access: "invite_only", relays: [RELAY_A, RELAY_B], guidance: "release notes",
      retention_seconds: 7 * 24 * 3600, members_visible: false, admin_pubkey: h.a1Hex,
    }, Date.now());
    h.setLastSeq(h.chHex, 7);
    h.setCurrent("Agent One");

    const res = (await h.handlers.get("cello_channels")!({}, "conn-1")) as {
      ok: boolean; channels: Array<Record<string, unknown>>;
    };
    expect(res.ok).toBe(true);

    // The followed channel is a member row.
    const member = res.channels.find((c) => c.role === "member" && c.channel === followed);
    expect(member, "the followed channel is listed as a member row").toBeDefined();

    // The administered channel is an admin row, with the channel's name, access, relays and last seq.
    const admin = res.channels.find((c) => c.role === "admin" && c.channel === h.chHex);
    expect(admin, "the administered channel is listed as an admin row").toBeDefined();
    expect(admin!.name, "the admin row carries the channel identity's display name").toBe("test-channel");
    expect(admin!.access).toBe("invite_only");
    expect(admin!.relays).toEqual([RELAY_A, RELAY_B]);
    expect(admin!.posts, "the admin row carries the last published seq").toBe(7);
  });
});
