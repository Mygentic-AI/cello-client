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
import { encodeChannelJoinAccepted, decodeChannelMembershipEnded, signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelConfigStore } from "../channel-config-store.js";
import { ChannelLogStore } from "../channel-log-store.js";
import { wireChannelMembership, type ChannelMembershipWiringDeps } from "../channel-membership-wiring.js";
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
  // 040-CLEANUP Part A: session ids whose send THROWS — so a re-key delivery can fail mid-loop.
  let sendThrowSessions = new Set<string>();
  // Configurable: which member pubkeys this daemon holds an OPEN session with.
  let openSessions: Array<{ sessionId: string; counterpartyPubkeyHex: string }> = [];
  // Configurable: whether openSessionFor succeeds, and the session it yields.
  let openSessionForResult: { ok: boolean; sessionId?: string; reason?: string } = { ok: false, reason: "offline" };
  // Configurable: whether the fake retire path succeeds.
  let removeAgentResult: { ok: boolean; reason?: string } = { ok: true };
  // Configurable: the admin's directory connection. Null by default (this daemon administers the
  // channel from its own settings, so no directory round trip is needed). B3 sets one that answers
  // `revoked` to prove a deleted channel's `info` now asks the directory.
  let signaling: SignalingLike | null = null;

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
    sendInSession: (agentName, sessionId, content) => {
      if (sendThrowSessions.has(sessionId)) return Promise.reject(new Error("relay_send_failed"));
      sent.push({ agentName, sessionId, content });
      return Promise.resolve();
    },
    setOnChannelJoinFrame: () => {},
    loadedAgents: [
      { name: ADMIN_NAME, pubkey: adminHex, keyProvider: adminKp },
      { name: CHANNEL_NAME, pubkey: channelHex, keyProvider: channelKp },
    ],
    keyProviders: new Map<string, InMemoryKeyProvider>([[ADMIN_NAME, adminKp], [CHANNEL_NAME, channelKp]]),
    resolveAgentId: (agentName) => (agentName === ADMIN_NAME ? ADMIN_ID : `id-of-${agentName}`),
    resolveCurrentAgent: () => ADMIN_NAME,
    activeSessionsFor: (agentName) => (agentName === ADMIN_NAME ? openSessions : []),
    signalingFor: (agentName) => (agentName === ADMIN_NAME ? signaling : null),
    openSessionFor: (agentName, opts) => {
      openedSessionsFor.push(opts.targetPubkey);
      return Promise.resolve(openSessionForResult);
    },
    notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    pruneAllPosts: (agentName, chHex) => {
      prunedChannels.push(chHex);
      return Promise.resolve({ pruned: 3, relays: [{ relay: RELAY_A, ok: true }, { relay: RELAY_B, ok: true }] });
    },
    // 041-HELPTRUTH: the two deps `cello_channels` reads. This channel identity is CHANNEL_NAME, and
    // its log is empty here (the post count on an admin row is null).
    isChannelAgent: (name) => name === CHANNEL_NAME,
    channelLastSeq: () => null,
  });

  return {
    handlers, members, adminKp, channelKp, adminHex, channelHex, sent, openedSessionsFor,
    prunedChannels, removedAgents, closedSessions, logs,
    setSendThrows: (ids: string[]) => { sendThrowSessions = new Set(ids); },
    setOpenSessions: (s: typeof openSessions) => { openSessions = s; },
    setOpenSessionForResult: (r: typeof openSessionForResult) => { openSessionForResult = r; },
    setRemoveAgentResult: (r: typeof removeAgentResult) => { removeAgentResult = r; },
    setSignaling: (s: SignalingLike | null) => { signaling = s; },
    subs: new ChannelSubscriptionStore(db, silent),
  };
}

describe("M16 034-LIFECYCLE — admin side: eject tells the member, delete removes the channel", () => {
  it("1. eject sends the ejected member a membership_ended(ejected) frame on the open session", async () => {
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
    // 038-RETESTFIX Part E: the frame reached the member's session, and it is a MEMBERSHIP-ENDED
    // frame naming `ejected` — its own type now, not a join refusal.
    const notice = h.sent.find((s) => s.sessionId === "s-member");
    expect(notice, "a frame was sent on the member's session").toBeDefined();
    const decoded = decodeChannelMembershipEnded(notice!.content);
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

  it("040-CLEANUP Part A: a remaining member whose re-key send THROWS is named in unreached, and the others are still re-keyed", async () => {
    // Three remaining members after an eject; the middle one's send throws. Before the fix the throw
    // ended the loop, so the third member never got the new key and never appeared in `unreached` —
    // the ejection re-keyed only the members ahead of the failure and silently skipped the rest.
    const h = await adminHarness();
    const mk = async () => hex(await (generateKeypair() as InMemoryKeyProvider).getPublicKey());
    const ejectHex = await mk();
    const m1 = await mk();
    const m2 = await mk();
    const m3 = await mk();
    // The ejected member plus three remaining, all active with an open session each.
    for (const m of [ejectHex, m1, m2, m3]) h.members.admit(h.channelHex, m, "active", 1000);
    h.setOpenSessions([
      { sessionId: "s-eject", counterpartyPubkeyHex: ejectHex },
      { sessionId: "s-m1", counterpartyPubkeyHex: m1 },
      { sessionId: "s-m2", counterpartyPubkeyHex: m2 },
      { sessionId: "s-m3", counterpartyPubkeyHex: m3 },
    ]);
    // The middle member's re-key send fails.
    h.setSendThrows(["s-m2"]);

    const res = (await h.handlers.get("cello_channel_eject")!(
      { channel: h.channelHex, subscriber: ejectHex }, "conn-1",
    )) as { ok: boolean; delivered: number; unreached: string[] };

    // The eject succeeds, and the loop did NOT abort on the throw.
    expect(res.ok).toBe(true);
    // The two reachable members got the re-key; the throwing one did not.
    expect(res.delivered).toBe(2);
    expect(res.unreached).toEqual([m2]);
    expect(h.sent.some((s) => s.sessionId === "s-m1"), "m1 was re-keyed").toBe(true);
    expect(h.sent.some((s) => s.sessionId === "s-m3"), "m3 was re-keyed even though m2 failed first").toBe(true);
    expect(h.sent.some((s) => s.sessionId === "s-m2"), "m2's re-key threw, so nothing was sent on it").toBe(false);
    // The log names the unreached member WITH the send error as the reason.
    const logged = h.logs.find((l) => l.event === "channel.rekey.member_unreached" && l.ctx?.["member_pubkey"] === m2);
    expect(logged, "an unreached-member log line was written for m2").toBeDefined();
    expect(logged!.ctx?.["reason"]).toBe("relay_send_failed");
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
    // 038-RETESTFIX Part E: deletion is a MEMBERSHIP-ENDED frame now, not a join refusal.
    const closedReasons = h.sent.map((s) => decodeChannelMembershipEnded(s.content)).filter((d) => d.ok).map((d) => (d.ok ? d.frame.reason : ""));
    expect(closedReasons).toEqual(["channel_closed", "channel_closed"]);
    // (b) the whole channel was pruned on both relays.
    expect(h.prunedChannels).toEqual([h.channelHex]);
    expect(res.relays).toEqual([{ relay: RELAY_A, ok: true }, { relay: RELAY_B, ok: true }]);
    // (c) the channel identity was retired through the existing remove path, by NAME.
    expect(h.removedAgents).toEqual([CHANNEL_NAME]);
    // (d) a successful retire is reported as retired: true.
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
    expect(h.sent, "no member was told").toHaveLength(0);
    expect(h.prunedChannels, "nothing was pruned").toEqual([]);
    expect(h.removedAgents, "no identity was retired").toEqual([]);
  });

  it("review MEDIUM: a notice that OPENED a session seals it closed afterwards", async () => {
    // notifyRefused opens a session when none is held. An opened-and-never-closed session counts
    // against the relay's per-pair cap of 5. The session it opened is closed through the same
    // (sealing) cello_close_session path.
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setOpenSessions([]); // none open → notifyRefused opens one
    h.setOpenSessionForResult({ ok: true, sessionId: "s-opened" });

    await h.handlers.get("cello_channel_eject")!({ channel: h.channelHex, subscriber: memberHex }, "conn-1");

    // The session it opened is sealed closed; the close rides the standard handler with the agent.
    expect(h.closedSessions).toEqual([{ session_id: "s-opened", agent: ADMIN_NAME }]);
  });

  it("review MEDIUM: a notice riding an EXISTING session leaves it open", async () => {
    // A session the operator already held is theirs — the notice rides it and it is NOT closed.
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setOpenSessions([{ sessionId: "s-existing", counterpartyPubkeyHex: memberHex }]);

    await h.handlers.get("cello_channel_eject")!({ channel: h.channelHex, subscriber: memberHex }, "conn-1");

    // Rode the existing session (frame sent on it), and closed nothing — openSessionFor untouched.
    expect(h.sent.some((s) => s.sessionId === "s-existing")).toBe(true);
    expect(h.openedSessionsFor, "no session was opened").toEqual([]);
    expect(h.closedSessions, "the operator's own session is left open").toEqual([]);
  });

  it("review MEDIUM: delete reports retired:false with a reason and guidance when the retire fails", async () => {
    // The notices and prune already ran, so delete is ok:true — but the channel identity is still
    // loaded, and an operator must be told that and how to finish. A silent ok:true hid it.
    const h = await adminHarness();
    const memberKp = generateKeypair() as InMemoryKeyProvider;
    const memberHex = hex(await memberKp.getPublicKey());
    h.members.admit(h.channelHex, memberHex, "active", 1000);
    h.setOpenSessions([{ sessionId: "s-member", counterpartyPubkeyHex: memberHex }]);
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

    h.setOpenSessions([]);
    h.setOpenSessionForResult({ ok: true, sessionId: "s-opened" });
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
    h.setOpenSessions([{ sessionId: "s-member", counterpartyPubkeyHex: memberHex }]);
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
    h.setOpenSessions([]);
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
    sendInSession: () => Promise.resolve(),
    setOnChannelJoinFrame: () => {},
    loadedAgents: [
      { name: "Agent One", pubkey: a1Hex, keyProvider: a1kp },
      { name: "Agent Two", pubkey: a2Hex, keyProvider: a2kp },
      { name: "test-channel", pubkey: chHex, keyProvider: chKp },
    ],
    keyProviders: new Map<string, InMemoryKeyProvider>([["Agent One", a1kp], ["Agent Two", a2kp], ["test-channel", chKp]]),
    resolveAgentId: (agentName) => `id-of-${agentName}`,
    // Null when nothing is selected and nothing was named — the exact case Part A answers.
    resolveCurrentAgent: (_c, explicit) => explicit ?? current,
    activeSessionsFor: () => [],
    signalingFor: () => null,
    openSessionFor: () => Promise.resolve({ ok: false }),
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
