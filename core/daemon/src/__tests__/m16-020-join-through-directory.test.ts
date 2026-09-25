/**
 * M16 020-CHANADMIN tests 13 and 14 — joining somebody else's channel, END TO END.
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
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, generateGroupKey, wrapGroupKeyFor, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import { encodeChannelJoinAccepted, decodeChannelJoinRefused } from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { wireChannelMembership, type ChannelMembershipWiringDeps } from "../channel-membership-wiring.js";
import type { SignalingLike } from "../channel-admin-lookup.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";
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
 * A daemon holding ONE agent — the subscriber. The channel and its admin belong to somebody else
 * entirely, which is the whole point: before 020 this daemon had no way to learn who administers a
 * channel it does not publish, so the join was refused however genuine it was.
 */
async function harness(opts: {
  /**
   * Whether the directory knows this channel. `false` is the "not a channel" answer — a settled
   * negative, not an outage.
   */
  registered: boolean;
}) {
  const subscriberKp = generateKeypair() as InMemoryKeyProvider;
  const channelKp = generateKeypair() as InMemoryKeyProvider;
  const adminKp = generateKeypair() as InMemoryKeyProvider;
  const strangerKp = generateKeypair() as InMemoryKeyProvider;
  const subscriberHex = hex(await subscriberKp.getPublicKey());
  const channelHex = hex(await channelKp.getPublicKey());
  const adminHex = hex(await adminKp.getPublicKey());
  const strangerHex = hex(await strangerKp.getPublicKey());

  const asked: string[] = [];
  /**
   * A directory connection for the subscriber. It answers `channel_admin_query` the way a rolled
   * directory does, echoing the channel it was asked about.
   */
  const signaling: SignalingLike = {
    registerInboundHandler(h) {
      handlers.add(h);
      return () => handlers.delete(h);
    },
    async sendRaw(frame: unknown) {
      const sent = frame as Record<string, unknown>;
      const askedHex = Buffer.from(sent["channel_pubkey"] as Uint8Array).toString("hex");
      asked.push(askedHex);
      // Registered only for THIS harness's channel, and only when asked for.
      const known = opts.registered && askedHex === channelHex;
      queueMicrotask(() => {
        for (const h of handlers) {
          h({
            type: "channel_admin_result",
            channel_pubkey: new Uint8Array(Buffer.from(askedHex, "hex")),
            registered: known,
            channel: known,
            admin_pubkey: known ? adminHex : "",
          });
        }
      });
      return { ok: true as const };
    },
  };
  const handlers = new Set<(f: Record<string, unknown>) => void>();

  let onJoinFrame: ChannelMembershipWiringDeps["setOnChannelJoinFrame"] extends (cb: infer C) => void ? C : never;
  const signalingAskedFor: string[] = [];

  wireChannelMembership({
    handlers: new Map(),
    logger: silent,
    getDb: () => db,
    sendInSession: () => Promise.resolve(),
    setOnChannelJoinFrame: (cb) => { onJoinFrame = cb; },
    loadedAgents: [{ name: SUB_NAME, pubkey: subscriberHex, keyProvider: subscriberKp }],
    keyProviders: new Map([[SUB_NAME, subscriberKp as unknown as InMemoryKeyProvider]]),
    // ⚠️ The ID is NOT the name, deliberately. The join path carries the ID and `signalingFor` is
    // keyed by the name; a seam that confused them would find no connection and refuse everything.
    resolveAgentId: (agentName) => (agentName === SUB_NAME ? SUB_ID : `id-of-${agentName}`),
    resolveCurrentAgent: () => SUB_NAME,
    activeSessionsFor: () => [],
    signalingFor: (agentName) => {
      signalingAskedFor.push(agentName);
      return agentName === SUB_NAME ? signaling : null;
    },
    notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
  });

  /** A genuine acceptance, wrapped to the subscriber's real key — no shortcuts through the crypto. */
  async function acceptanceFrame(): Promise<Uint8Array> {
    const groupKey = generateGroupKey(1);
    const bundle = await wrapGroupKeyFor(
      groupKey,
      new Uint8Array(Buffer.from(channelHex, "hex")),
      new Uint8Array(Buffer.from(subscriberHex, "hex")),
      adminKp,
    );
    return encodeChannelJoinAccepted({
      channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
      access: "invite_only",
      relays: [RELAY_A, RELAY_B],
      guidance: "release notes",
      retention_seconds: 7 * 24 * 3600,
      members_visible: false,
      key_bundle: bundle,
    });
  }

  return {
    onJoinFrame: onJoinFrame!, acceptanceFrame, asked, signalingAskedFor,
    channelHex, adminHex, subscriberHex, strangerHex,
    subs: new ChannelSubscriptionStore(db, silent),
  };
}

/** The hook is synchronous by contract; the work it queues is not. Let it settle. */
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

describe("M16 020 — joining a channel this daemon does not administer", () => {
  it("13. the directory names the admin, that admin answers, and the join COMPLETES", async () => {
    const h2 = await harness({ registered: true });
    const frame = await h2.acceptanceFrame();

    const verdict = h2.onJoinFrame(SUB_NAME, "session-1", frame, h2.adminHex, "corr-1");
    expect(verdict.consumed, "a join frame is never transcript content").toBe(true);
    await settle();

    /**
     * ⚠️ **THE SUBSCRIPTION IS THE PROOF.** Before 020 this row was never written for a channel
     * published elsewhere: the admin could not be resolved, so the join was refused however genuine
     * it was. Nobody could follow anybody else's channel — or their own, from a second device.
     */
    const sub = h2.subs.get(SUB_ID, h2.channelHex);
    expect(sub, "the subscription exists").not.toBeNull();
    expect(sub?.admin_pubkey).toBe(h2.adminHex);
    expect(sub?.relays).toEqual([RELAY_A, RELAY_B]);
    expect(h2.subs.keysFor(SUB_ID, h2.channelHex).map((k) => k.generation)).toEqual([1]);

    // And the seam actually ran: the lookup went out on the SUBSCRIBER'S connection, found by
    // resolving its agent ID back to the name the daemon keys connections by.
    expect(h2.asked).toEqual([h2.channelHex]);
    expect(h2.signalingAskedFor).toContain(SUB_NAME);
  });

  it("14. the directory names one admin and somebody ELSE answers — refused, and nothing is stored", async () => {
    /**
     * ⚠️ **THE HOLE THE CHECK EXISTS TO CLOSE.** The session proves who the counterparty is and says
     * nothing about their authority. Without this, any agent that can open a session with you hands
     * you a key bundle and a relay pair and becomes your channel — and every post you then read is
     * theirs, signed by a channel key you never verified against anything.
     *
     * The acceptance here is cryptographically perfect. The only thing wrong with it is who sent it.
     */
    const h2 = await harness({ registered: true });
    const frame = await h2.acceptanceFrame();

    h2.onJoinFrame(SUB_NAME, "session-1", frame, h2.strangerHex, "corr-1");
    await settle();

    expect(h2.subs.get(SUB_ID, h2.channelHex), "no subscription was created").toBeNull();
    expect(h2.subs.keysFor(SUB_ID, h2.channelHex), "and no key was kept").toEqual([]);
  });

  it("21. the refusal NAMES the cause, so admin_unresolved is not a dead end", async () => {
    /**
     * ⚠️ **`admin_unresolved` IS AN EXIT-POINT LABEL.** A dead signaling stream, a ten-second
     * timeout against a directory that has not been rolled, a channel nobody has registered and a
     * database fault all arrive at that one word. The cause used to survive only in a log line one
     * step upstream — which is not where anyone looks when a join is refused.
     *
     * This drives the exchange directly, because the refusal is what carries the detail and the
     * wiring test above can only see that nothing was stored.
     */
    const { createChannelJoinExchange } = await import("../channel-join-exchange.js");
    const h2 = await harness({ registered: false });
    const frame = await h2.acceptanceFrame();

    const exchange = createChannelJoinExchange({
      logger: silent,
      members: new (await import("../channel-membership-store.js")).ChannelMembershipStore(db, silent),
      subscriptions: h2.subs,
      sendInSession: () => Promise.resolve(),
      localChannelAdmin: () => null,
      profileAdminPubkey: () => Promise.resolve({ ok: false as const, reason: "signaling_unavailable" }),
      keyProviderFor: () => null,
      raiseNotice: () => {},
    });

    const result = await exchange.onSubscriberFrame(SUB_ID, "session-1", h2.adminHex, frame);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("admin_unresolved");
      expect(result.detail, "the cause travels with the refusal").toBe("signaling_unavailable");
    }
  });

  it("14b. a directory that answers 'not a channel' refuses the join too", async () => {
    // Nothing to check the answerer against, so there is no admission to make.
    const h2 = await harness({ registered: false });
    const frame = await h2.acceptanceFrame();

    h2.onJoinFrame(SUB_NAME, "session-1", frame, h2.adminHex, "corr-1");
    await settle();

    expect(h2.subs.get(SUB_ID, h2.channelHex)).toBeNull();
  });
});

// ─── M16 034-LIFECYCLE — the ADMIN side: eject tells the member, and a channel can be deleted ─────
//
// A daemon that HOLDS a channel and its admin agent. The only fakes are outside the daemon: the
// sessions a frame rides, the session-opener, the relay prune, and the retire path.

const ADMIN_NAME = "Publisher's Agent";
const ADMIN_ID = "agent-admin-1";
const CHANNEL_NAME = "test-channel";

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
  const sent: Array<{ agentName: string; sessionId: string; content: Uint8Array }> = [];
  const openedSessionsFor: string[] = [];
  const prunedChannels: string[] = [];
  const removedAgents: string[] = [];
  // Configurable: which member pubkeys this daemon holds an OPEN session with.
  let openSessions: Array<{ sessionId: string; counterpartyPubkeyHex: string }> = [];
  // Configurable: whether openSessionFor succeeds, and the session it yields.
  let openSessionForResult: { ok: boolean; sessionId?: string; reason?: string } = { ok: false, reason: "offline" };

  // A fake retire path — the real cello_remove_agent lives in agent-handlers; here we only prove
  // delete REACHES it with the channel's name.
  handlers.set("cello_remove_agent", (params) => {
    removedAgents.push(String(params?.["name"] ?? ""));
    return Promise.resolve({ ok: true });
  });

  wireChannelMembership({
    handlers,
    logger: silent,
    getDb: () => db,
    sendInSession: (agentName, sessionId, content) => { sent.push({ agentName, sessionId, content }); return Promise.resolve(); },
    setOnChannelJoinFrame: () => {},
    loadedAgents: [
      { name: ADMIN_NAME, pubkey: adminHex, keyProvider: adminKp },
      { name: CHANNEL_NAME, pubkey: channelHex, keyProvider: channelKp },
    ],
    keyProviders: new Map<string, InMemoryKeyProvider>([[ADMIN_NAME, adminKp], [CHANNEL_NAME, channelKp]]),
    resolveAgentId: (agentName) => (agentName === ADMIN_NAME ? ADMIN_ID : `id-of-${agentName}`),
    resolveCurrentAgent: () => ADMIN_NAME,
    activeSessionsFor: (agentName) => (agentName === ADMIN_NAME ? openSessions : []),
    signalingFor: () => null,
    openSessionFor: (agentName, opts) => {
      openedSessionsFor.push(opts.targetPubkey);
      return Promise.resolve(openSessionForResult);
    },
    notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    pruneAllPosts: (agentName, chHex) => {
      prunedChannels.push(chHex);
      return Promise.resolve({ pruned: 3, relays: [{ relay: RELAY_A, ok: true }, { relay: RELAY_B, ok: true }] });
    },
  });

  return {
    handlers, members, adminKp, channelKp, adminHex, channelHex, sent, openedSessionsFor,
    prunedChannels, removedAgents,
    setOpenSessions: (s: typeof openSessions) => { openSessions = s; },
    setOpenSessionForResult: (r: typeof openSessionForResult) => { openSessionForResult = r; },
    subs: new ChannelSubscriptionStore(db, silent),
  };
}

describe("M16 034-LIFECYCLE — admin side: eject tells the member, delete removes the channel", () => {
  it("1. eject sends the ejected member a refused(ejected) frame on the open session", async () => {
    const h = await adminHarness();
    // A single active member, so the re-key loop is empty and the only send is the notice.
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setOpenSessions([{ sessionId: "s-member", counterpartyPubkeyHex: memberHex }]);

    const res = (await h.handlers.get("cello_channel_eject")!(
      { channel: h.channelHex, subscriber: memberHex }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.member_notified, "the ejected member was told").toBe(true);
    // The frame reached the member's session, and it is a refusal naming `ejected`.
    const notice = h.sent.find((s) => s.sessionId === "s-member");
    expect(notice, "a frame was sent on the member's session").toBeDefined();
    const decoded = decodeChannelJoinRefused(notice!.content);
    expect(decoded.ok && decoded.frame.reason).toBe("ejected");
  });

  it("2. eject with the member unreachable → ok, member_notified false, and the ejection still holds", async () => {
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    // No open session, and opening one fails: the member is offline.
    h.setOpenSessions([]);
    h.setOpenSessionForResult({ ok: false, reason: "offline" });

    const res = (await h.handlers.get("cello_channel_eject")!(
      { channel: h.channelHex, subscriber: memberHex }, "conn-1",
    )) as Record<string, unknown>;

    // The eject itself succeeds — the member is out at the relay from the next post regardless.
    expect(res.ok).toBe(true);
    expect(res.member_notified, "could not reach them to tell them").toBe(false);
    // And it is not on the open session (there was none) — nothing was sent.
    expect(h.sent).toHaveLength(0);
    // The store recorded the ejection.
    expect(h.members.statusOf(h.channelHex, memberHex)).toBe("ejected");
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

  it("5. delete notifies active AND pending members, prunes both relays, and retires the channel identity", async () => {
    const h = await adminHarness();
    const activeKp = generateKeypair() as InMemoryKeyProvider;
    const pendingKp = generateKeypair() as InMemoryKeyProvider;
    const activeHex = hex(await activeKp.getPublicKey());
    const pendingHex = hex(await pendingKp.getPublicKey());
    h.members.admit(h.channelHex, activeHex, "active", 1000);
    h.members.admit(h.channelHex, pendingHex, "pending", 1000);
    // Reachable through openSessionFor (no pre-existing session needed).
    h.setOpenSessions([]);
    h.setOpenSessionForResult({ ok: true, sessionId: "s-opened" });

    const res = (await h.handlers.get("cello_channel_delete")!(
      { channel: h.channelHex }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(true);
    // (a) both members were told the channel is gone.
    expect(res.members_notified).toBe(2);
    expect(res.members_unreached).toEqual([]);
    const closedReasons = h.sent.map((s) => decodeChannelJoinRefused(s.content)).filter((d) => d.ok).map((d) => (d.ok ? d.frame.reason : ""));
    expect(closedReasons).toEqual(["channel_closed", "channel_closed"]);
    // (b) the whole channel was pruned on both relays.
    expect(h.prunedChannels).toEqual([h.channelHex]);
    expect(res.relays).toEqual([{ relay: RELAY_A, ok: true }, { relay: RELAY_B, ok: true }]);
    // (c) the channel identity was retired through the existing remove path, by NAME.
    expect(h.removedAgents).toEqual([CHANNEL_NAME]);
  });

  it("6. delete of a channel this daemon does not administer is refused — nothing sent, nothing pruned, nothing retired", async () => {
    const h = await adminHarness();
    const notOurs = "ab".repeat(32); // a channel key this daemon does not hold

    const res = (await h.handlers.get("cello_channel_delete")!(
      { channel: notOurs }, "conn-1",
    )) as Record<string, unknown>;

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("channel_not_local");
    expect(h.sent, "no member was told").toHaveLength(0);
    expect(h.prunedChannels, "nothing was pruned").toEqual([]);
    expect(h.removedAgents, "no identity was retired").toEqual([]);
  });
});
