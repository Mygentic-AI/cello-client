/**
 * M16 019-MEMBERSHIP Part B — the join exchange, both sides. Tests 6–11 of the order.
 *
 * A channel never converses; its ADMIN is an ordinary agent, so a join happens inside a normal
 * sealed session with that admin. The two checks this file exists for:
 *
 *   ADMIN side       the session counterparty must BE the subscriber it is admitting — nobody
 *                    joins on somebody else's behalf.
 *   SUBSCRIBER side  the agent that answered must be the admin named in the channel's DIRECTORY
 *                    PROFILE — not merely whoever replied in this session.
 *
 * Drop the second and the immutable admin key protects nobody: any agent that can get a session
 * with you can hand you a key bundle and a relay pair and become your channel.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateKeypair, generateGroupKey, wrapGroupKeyFor, type InMemoryKeyProvider,
} from "@cello-protocol/crypto";
import {
  encodeChannelJoinRequest, decodeChannelJoinAccepted, decodeChannelJoinRefused,
  encodeChannelJoinAccepted, encodeChannelJoinRefused, encodeChannelMembershipEnded,
  isChannelJoinFrame, channelJoinFrameType,
  JOIN_ACCEPTED_TYPE, JOIN_REQUEST_TYPE,
} from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import {
  createChannelJoinExchange, ensureCurrentGroupKey, type ChannelJoinExchange,
} from "../channel-join-exchange.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X";
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let dir: string;
let db: DaemonDatabase;

interface Fixture {
  exchange: ChannelJoinExchange;
  members: ChannelMembershipStore;
  subs: ChannelSubscriptionStore;
  channelKp: InMemoryKeyProvider;
  adminKp: InMemoryKeyProvider;
  subscriberKp: InMemoryKeyProvider;
  channelHex: string;
  adminHex: string;
  subscriberHex: string;
  /** Everything the exchange asked a session to send, in order. */
  sent: Array<{ sessionId: string; content: Uint8Array }>;
  /** What the directory profile says the channel's admin is. */
  profileAdmin: Map<string, string>;
  notices: Array<{ event: string; channel: string; subscriber: string }>;
  /** M16 032-NOTICES: every onJoinAnswer the subscriber half fired, in order. */
  joinAnswers: Array<{ agentId: string; channelHex: string; outcome: string; reason?: string }>;
  /** 038-RETESTFIX Part B: every collectNow the subscriber half fired, in order (agent ids). */
  collectNowCalls: string[];
  /** 038-RETESTFIX Part E: every onMembershipEnded the subscriber half fired, in order. */
  membershipEnded: Array<{ agentId: string; channelHex: string; reason: string }>;
}

async function fixture(access: "open" | "invite_only" | "public" = "open"): Promise<Fixture> {
  const channelKp = generateKeypair();
  const adminKp = generateKeypair();
  const subscriberKp = generateKeypair();
  const channelHex = hex(await channelKp.getPublicKey());
  const adminHex = hex(await adminKp.getPublicKey());
  const subscriberHex = hex(await subscriberKp.getPublicKey());

  const members = new ChannelMembershipStore(db, silent);
  members.putSettings(channelHex, {
    access, members_visible: false, guidance: "release notes",
    retention_seconds: 7 * 24 * 3600, relays: [RELAY_A, RELAY_B], admin_pubkey: adminHex,
  });
  const subs = new ChannelSubscriptionStore(db, silent);

  const sent: Array<{ sessionId: string; content: Uint8Array }> = [];
  const profileAdmin = new Map<string, string>([[channelHex, adminHex]]);
  const notices: Array<{ event: string; channel: string; subscriber: string }> = [];
  const joinAnswers: Array<{ agentId: string; channelHex: string; outcome: string; reason?: string }> = [];
  const collectNowCalls: string[] = [];
  const membershipEnded: Array<{ agentId: string; channelHex: string; reason: string }> = [];

  const exchange = createChannelJoinExchange({
    logger: silent,
    members,
    subscriptions: subs,
    sendInSession: (sessionId, content) => { sent.push({ sessionId, content }); return Promise.resolve(); },
    // Which channels THIS daemon administers, and with which agent key.
    localChannelAdmin: (chHex) => (chHex === channelHex
      ? { agentId: "admin-1", adminPubkeyHex: adminHex, channelKeyProvider: channelKp, adminKeyProvider: adminKp }
      : null),
    // The channel's admin AS THE DIRECTORY REPORTS IT — the subscriber's only trustworthy source.
    profileAdminPubkey: (chHex) => {
      const found = profileAdmin.get(chHex);
      // M16 021 item 21: the seam carries WHY there is no admin, not just that there is none.
      return Promise.resolve(found !== undefined
        ? { ok: true as const, adminPubkeyHex: found }
        : { ok: false as const, reason: "not_a_channel" });
    },
    keyProviderFor: () => subscriberKp,
    raiseNotice: (event, channel, subscriber) => { notices.push({ event, channel, subscriber }); },
    onJoinAnswer: (agentId, chHex, outcome, reason) => { joinAnswers.push({ agentId, channelHex: chHex, outcome, reason }); },
    onMembershipEnded: (agentId, chHex, reason) => { membershipEnded.push({ agentId, channelHex: chHex, reason }); },
    collectNow: (agentId) => { collectNowCalls.push(agentId); },
    now: () => 1_800_000_000_000,
  });

  return {
    exchange, members, subs, channelKp, adminKp, subscriberKp,
    channelHex, adminHex, subscriberHex, sent, profileAdmin, notices, joinAnswers, collectNowCalls, membershipEnded,
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-019j-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("M16 019 Part B — the join exchange", () => {
  it("6. an OPEN channel auto-admits, and the acceptance carries key, relays, guidance and retention", async () => {
    const f = await fixture("open");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "I follow Andre's work",
    });

    const handled = await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    expect(handled.consumed).toBe(true);
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBe("active");

    expect(f.sent).toHaveLength(1);
    const accepted = decodeChannelJoinAccepted(f.sent[0].content);
    expect(accepted.ok, accepted.ok ? "" : accepted.reason).toBe(true);
    if (!accepted.ok) return;
    // Everything needed to start reading arrives in ONE frame. Without the relays the subscriber
    // knows the channel's name and can fetch nothing.
    expect(accepted.frame.relays).toEqual([RELAY_A, RELAY_B]);
    expect(accepted.frame.guidance).toBe("release notes");
    expect(accepted.frame.retention_seconds).toBe(7 * 24 * 3600);
    expect(accepted.frame.key_bundle.length).toBeGreaterThan(0);

    // And the subscriber, receiving it, ends up able to read: the key is stored against the channel.
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    expect(result.ok, result.ok ? "" : result.reason).toBe(true);
    const sub = f.subs.get("agent-2", f.channelHex);
    expect(sub?.relays).toEqual([RELAY_A, RELAY_B]);
    expect(f.subs.keysFor("agent-2", f.channelHex)).toHaveLength(1);
  });

  it("038 Part B — a stored acceptance triggers an immediate collect for that agent, no wake needed", async () => {
    // Live evidence (F35): Miss_Chelly joined test-public, delivered_through stayed 0, and the four
    // existing posts arrived only when a NEW post rang the wake. A subscription that becomes active
    // must collect at once. The recorder starts EMPTY, so a green assertion proves the acceptance —
    // and only the acceptance — drove the collect; nothing here rings a wake.
    const f = await fixture("open");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "collect me in",
    });
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    // Nothing collected until the subscriber actually stores the acceptance.
    expect(f.collectNowCalls).toEqual([]);

    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    expect(result.ok, result.ok ? "" : result.reason).toBe(true);
    // The acceptance stored → collect fired once, for THIS agent id, with no wake.
    expect(f.collectNowCalls).toEqual(["agent-2"]);
  });

  it("038 Part B — a public admission also triggers an immediate collect", async () => {
    const f = await fixture("public");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "public collect",
    });
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    expect(f.collectNowCalls).toEqual([]);
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    expect(result.ok, result.ok ? "" : result.reason).toBe(true);
    expect(f.collectNowCalls).toEqual(["agent-2"]);
  });

  it("7. an INVITE-ONLY channel replies pending_approval, and approval delivers the key", async () => {
    const f = await fixture("invite_only");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "please",
    });

    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    // ⚠️ PENDING, NOT ADMITTED. Invite-only admission is the admin AGENT's decision — there is no
    // auto-approve heuristic, and a pending member holds no key.
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBe("pending");
    const refused = decodeChannelJoinRefused(f.sent[0].content);
    expect(refused.ok && refused.frame.reason).toBe("pending_approval");
    expect(f.notices.map((n) => n.event)).toContain("channel.join.pending");

    // The admin then approves, and THAT is what sends the key.
    const approved = await f.exchange.approve(f.channelHex, f.subscriberHex, "s1");
    expect(approved.ok, approved.ok ? "" : approved.reason).toBe(true);
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBe("active");
    const accepted = decodeChannelJoinAccepted(f.sent[1].content);
    expect(accepted.ok && accepted.frame.key_bundle.length).toBeGreaterThan(0);
  });

  it("8. a counterparty that is NOT the subscriber_pubkey is refused — nobody joins for another", async () => {
    const f = await fixture("open");
    const impostor = generateKeypair();
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      // The frame names the real subscriber...
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "let me in as them",
    });

    // ...but the SESSION is with somebody else. Admitting this would let anyone enrol a third party
    // and, worse, receive that third party's key bundle themselves.
    const handled = await f.exchange.onAdminFrame("s1", hex(await impostor.getPublicKey()), request);
    expect(handled.consumed).toBe(true);
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBeNull();
    const refused = decodeChannelJoinRefused(f.sent[0].content);
    expect(refused.ok && refused.frame.reason).toBe("not_admin_of_channel");
  });

  it("9. an acceptance from an agent that is NOT the profile's admin is refused BY THE SUBSCRIBER", async () => {
    const f = await fixture("open");
    const attacker = generateKeypair();

    /**
     * ⚠️ **THE BUNDLE IS GENUINELY WRAPPED FOR THIS SUBSCRIBER, by the attacker.** An earlier
     * version of this test used random bytes, and it went red when the admin check was removed —
     * but for the WRONG REASON: the unwrap failed on its own, so the test proved nothing about the
     * check it is named for. Wrapping it properly leaves the admin check as the only thing that can
     * refuse it, which is what the revert test has to isolate.
     */
    const attackerKey = generateGroupKey(1);
    const realBundle = await wrapGroupKeyFor(
      attackerKey, await f.channelKp.getPublicKey(), await f.subscriberKp.getPublicKey(), attacker,
    );
    const bundleBytes = encodeChannelJoinAccepted({
      channel_pubkey: await f.channelKp.getPublicKey(),
      key_bundle: realBundle,
      guidance: "come to my relay", retention_seconds: 3600,
      access: "open", relays: ["/dns4/attacker.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83"], members_visible: false,
    });

    /**
     * ⚠️ **THE CHECK THE WHOLE IMMUTABLE-ADMIN DESIGN RESTS ON.** The session proves who the
     * counterparty is; it does not prove they are this channel's admin. Without comparing against
     * the DIRECTORY PROFILE, any agent that can open a session with you hands you a key bundle and
     * a relay pair and becomes your channel — you would read their posts believing them to be
     * somebody else's.
     */
    const result = await f.exchange.onSubscriberFrame(
      "agent-2", "s1", hex(await attacker.getPublicKey()), bundleBytes,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("not_admin_of_channel");
    // Nothing was stored: no subscription, no key, no relays.
    expect(f.subs.get("agent-2", f.channelHex)).toBeNull();
    expect(f.subs.keysFor("agent-2", f.channelHex)).toEqual([]);
  });

  it("036-PUBLICSUB test 3: a PUBLIC channel ADMITS the join — accepted frame, empty bundle, the relays, NO key stored", async () => {
    const f = await fixture("public");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });

    const handled = await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    expect(handled.consumed).toBe(true);
    // ⚠️ Admitted, not refused (Andre's Option B). The member is recorded `active` because that is
    // what feeds reader counts and wakes — a public reader is still a reader.
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBe("active");

    expect(f.sent).toHaveLength(1);
    const accepted = decodeChannelJoinAccepted(f.sent[0].content);
    expect(accepted.ok, accepted.ok ? "" : accepted.reason).toBe(true);
    if (!accepted.ok) return;
    expect(accepted.frame.access).toBe("public");
    // Public posts are not encrypted, so the acceptance carries NO key — the bundle is empty.
    expect(accepted.frame.key_bundle.length).toBe(0);
    // The relays still travel: without them the reader knows the channel's name and can fetch nothing.
    expect(accepted.frame.relays).toEqual([RELAY_A, RELAY_B]);
    expect(accepted.frame.guidance).toBe("release notes");

    // ⚠️ ZERO KEYS were minted or stored under the admin's own id — a public channel has none, and
    // minting one would be a key nobody uses that ejection could never bite.
    expect(f.subs.keysFor("admin-1", f.channelHex)).toEqual([]);
  });

  it("036-PUBLICSUB test 4: receiving a PUBLIC acceptance creates an active subscription with the relays and NO key, and rings admitted", async () => {
    const f = await fixture("public");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });
    // The admin admits (test 3), then the subscriber receives that very frame.
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    expect(result.ok, result.ok ? "" : result.reason).toBe(true);

    const sub = f.subs.get("agent-2", f.channelHex);
    expect(sub?.status).toBe("active");
    expect(sub?.access).toBe("public");
    expect(sub?.relays).toEqual([RELAY_A, RELAY_B]);
    // ⚠️ NO key was unwrapped or stored — a public acceptance carries none, and calling addKey would
    // store a phantom key. This is the assertion the revert test reddens.
    expect(f.subs.keysFor("agent-2", f.channelHex)).toEqual([]);
    // 032's doorbell: the reader is IN, so onJoinAnswer fires `admitted`, no reason.
    expect(f.joinAnswers).toEqual([{ agentId: "agent-2", channelHex: f.channelHex, outcome: "admitted", reason: undefined }]);
  });

  it("036-PUBLICSUB (security): a PUBLIC acceptance from a NON-admin peer is refused and stores nothing", async () => {
    // ⚠️ **THE ADMIN CHECK STAYS ON THE PUBLIC BRANCH.** The session proves who the peer is, not that
    // they administer the channel. Without comparing the sender against the directory's admin, any
    // agent that can open a session hands you a relay pair and becomes your channel — even a public
    // one, where the reader would fetch a stranger's posts believing them the real channel's.
    const f = await fixture("public");
    const attacker = generateKeypair();
    const attackerHex = hex(await attacker.getPublicKey());
    const publicAccept = encodeChannelJoinAccepted({
      channel_pubkey: await f.channelKp.getPublicKey(),
      key_bundle: new Uint8Array(0), guidance: "read my relay instead", retention_seconds: 3600,
      access: "public", relays: [RELAY_A], members_visible: true,
    });

    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", attackerHex, publicAccept);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("not_admin_of_channel");
    // Nothing stored: no subscription created off a stranger's public acceptance.
    expect(f.subs.get("agent-2", f.channelHex)).toBeNull();
  });

  it("11. already_member and ejected are refused by NAME, and an ejected member stays out", async () => {
    const f = await fixture("invite_only");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });

    f.members.admit(f.channelHex, f.subscriberHex, "active", 1000);
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    expect(decodeChannelJoinRefused(f.sent[0].content).ok
      && decodeChannelJoinRefused(f.sent[0].content).frame.reason).toBe("already_member");

    // ⚠️ AND AN EJECTED MEMBER CANNOT SIMPLY ASK AGAIN. Re-admitting them would undo the ejection
    // the moment they retried, which is what keeping the ejected row is for.
    f.members.eject(f.channelHex, f.subscriberHex);
    await f.exchange.onAdminFrame("s2", f.subscriberHex, request);
    const second = decodeChannelJoinRefused(f.sent[1].content);
    expect(second.ok && second.frame.reason).toBe("ejected");
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBe("ejected");
  });

  it("6b. an ACCEPTANCE is routed to the subscriber, not swallowed by the admin half", async () => {
    const f = await fixture("open");

    /**
     * ⚠️ **THE BUG THIS PINS MADE JOINING IMPOSSIBLE, and every unit test above missed it** because
     * they call the two halves by hand. The wiring tried the admin half first and fell through on
     * `consumed: false` — but `onAdminFrame` answers `consumed: true` for ANY join frame it cannot
     * read as a request. So an acceptance arriving at a subscriber was absorbed there: the daemon
     * appended a leaf, logged it as received, and discarded it. No subscription, no key, and not one
     * line saying anything had gone wrong. Every re-key after an ejection went the same way.
     *
     * The classifier is what a caller must route on, so the assertion is on IT.
     */
    const accepted = encodeChannelJoinAccepted({
      channel_pubkey: await f.channelKp.getPublicKey(),
      key_bundle: new Uint8Array(Buffer.alloc(120, 0x33)),
      guidance: "g", retention_seconds: 3600, access: "open",
      relays: [RELAY_A], members_visible: false,
    });
    expect(channelJoinFrameType(accepted)).toBe(JOIN_ACCEPTED_TYPE);
    expect(channelJoinFrameType(accepted)).not.toBe(JOIN_REQUEST_TYPE);

    // And the admin half still claims it, which is exactly why routing cannot be "try admin first".
    const swallowed = await f.exchange.onAdminFrame("s1", f.subscriberHex, accepted);
    expect(swallowed.consumed, "the admin half consumes what it cannot read — hence route by type").toBe(true);
  });

  it("6c. guidance and retention are STORED, not just decoded off the frame", async () => {
    const f = await fixture("open");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);

    // ⚠️ Both were validated on the frame and then dropped. A subscriber that does not keep them has
    // no idea what the channel is for or how long its posts last — and no other way to learn either.
    const row = f.subs.get("agent-2", f.channelHex);
    expect(row?.guidance).toBe("release notes");
    expect(row?.retention_seconds).toBe(7 * 24 * 3600);
  });

  it("6d. rejoining after LEAVING makes the subscription active again", async () => {
    const f = await fixture("open");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    f.subs.markLeft("agent-2", f.channelHex);
    expect(f.subs.active()).toEqual([]);

    // ⚠️ `status` was missing from the upsert's update list, so a rejoin stored a fresh key, answered
    // ok, and left the row `left` — the collector never fetched, and the operator saw a channel they
    // had just rejoined produce nothing, for ever.
    await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    expect(f.subs.get("agent-2", f.channelHex)?.status).toBe("active");
    expect(f.subs.active().map((s) => s.channel_pubkey)).toEqual([f.channelHex]);
  });

  it("11b. REFUSING is not ejecting: it cannot remove an existing member", async () => {
    const f = await fixture("invite_only");
    f.members.admit(f.channelHex, f.subscriberHex, "active", 1000);

    const result = await f.exchange.refuse(f.channelHex, f.subscriberHex, "s1");
    /**
     * ⚠️ This used to answer `ok: true`, mark the member `ejected`, and change nothing else — so
     * they kept the current group key AND the current fetch key and read on indefinitely while the
     * table said they were gone. An eject re-keys the channel; a refusal has nothing to re-key,
     * because a refused party was never in.
     */
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("not_a_pending_request");
    expect(f.members.statusOf(f.channelHex, f.subscriberHex), "still a member").toBe("active");
  });

  it("5. a member admitted AFTER a post receives the key that post was encrypted with", async () => {
    const f = await fixture("open");

    /**
     * ⚠️ **028-GROUPPUB: PUBLISH AND ADMIT MUST REACH THE SAME STORED KEY.** The publisher mints (or
     * reuses) the channel's current group key through `ensureCurrentGroupKey` before anyone has
     * joined — the admin's agent id in this fixture's `localChannelAdmin` is "admin-1". A member who
     * joins afterwards must be handed that SAME key, or the pre-join post is permanently unreadable
     * to the first member. If the two paths minted separately, the bytes below would differ.
     */
    const minted = ensureCurrentGroupKey(
      { members: f.members, subscriptions: f.subs, now: () => 1_800_000_000_000 },
      "admin-1", f.channelHex,
    );
    expect(minted, "the publish path must mint a key for a non-public channel").toBeDefined();
    if (!minted) return;
    expect(minted.generation).toBe(1);

    // Then a member joins the ordinary way — the same admit path tests 6/6c use.
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });
    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, f.sent[0].content);
    expect(result.ok, result.ok ? "" : result.reason).toBe(true);

    // The key the new member unwrapped from the acceptance IS the one the pre-join post used.
    const memberKeys = f.subs.keysFor("agent-2", f.channelHex);
    expect(memberKeys).toHaveLength(1);
    expect(memberKeys[0].generation).toBe(minted.generation);
    expect(Buffer.from(memberKeys[0].key).equals(Buffer.from(minted.key)), "same key bytes").toBe(true);
  });

  it("3. join outcomes reach onJoinAnswer — admitted / pending / refused+reason — and a pending request reaches the admin notice", async () => {
    // (a) ADMIN side: an invite-only request lands pending and fires the admin's notice ONCE, named
    // with the counterparty. The wiring turns that notice into the channel_join_request doorbell.
    const fa = await fixture("invite_only");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await fa.channelKp.getPublicKey(),
      subscriber_pubkey: await fa.subscriberKp.getPublicKey(),
      note: "",
    });
    await fa.exchange.onAdminFrame("s1", fa.subscriberHex, request);
    const pendingNotices = fa.notices.filter((n) => n.event === "channel.join.pending");
    expect(pendingNotices).toHaveLength(1);
    expect(pendingNotices[0].subscriber).toBe(fa.subscriberHex);
    // A REPEAT of the same request is answered pending_approval again but must NOT ring the admin a
    // second time — otherwise a subscriber could page an admin on every retry (032 review F2).
    await fa.exchange.onAdminFrame("s1", fa.subscriberHex, request);
    expect(fa.notices.filter((n) => n.event === "channel.join.pending"), "a repeat request re-rang the admin").toHaveLength(1);

    // (b) SUBSCRIBER side, ADMITTED: an acceptance stored → onJoinAnswer "admitted", no reason.
    const fo = await fixture("open");
    const req2 = encodeChannelJoinRequest({
      channel_pubkey: await fo.channelKp.getPublicKey(),
      subscriber_pubkey: await fo.subscriberKp.getPublicKey(),
      note: "",
    });
    await fo.exchange.onAdminFrame("s1", fo.subscriberHex, req2);
    const admitted = await fo.exchange.onSubscriberFrame("agent-2", "s1", fo.adminHex, fo.sent[0].content);
    expect(admitted.ok, admitted.ok ? "" : admitted.reason).toBe(true);
    expect(fo.joinAnswers).toEqual([{ agentId: "agent-2", channelHex: fo.channelHex, outcome: "admitted", reason: undefined }]);

    // (c) SUBSCRIBER side, PENDING: a refused frame carrying pending_approval → onJoinAnswer "pending".
    const fp = await fixture("invite_only");
    const pendingFrame = encodeChannelJoinRefused({ channel_pubkey: await fp.channelKp.getPublicKey(), reason: "pending_approval" });
    await fp.exchange.onSubscriberFrame("agent-2", "s1", fp.adminHex, pendingFrame);
    expect(fp.joinAnswers).toEqual([{ agentId: "agent-2", channelHex: fp.channelHex, outcome: "pending", reason: undefined }]);

    // (d) SUBSCRIBER side, REFUSED: any other refusal → onJoinAnswer "refused" + the reason word.
    // 038-RETESTFIX Part E: `ejected` is no longer a refusal — a plain refusal reason is used here.
    const fr = await fixture("invite_only");
    const refusedFrame = encodeChannelJoinRefused({ channel_pubkey: await fr.channelKp.getPublicKey(), reason: "refused_by_admin" });
    await fr.exchange.onSubscriberFrame("agent-2", "s1", fr.adminHex, refusedFrame);
    expect(fr.joinAnswers).toEqual([{ agentId: "agent-2", channelHex: fr.channelHex, outcome: "refused", reason: "refused_by_admin" }]);
  });

  it("034-LIFECYCLE test 3 (038 Part E): a membership-ended(ejected) frame marks a subscribed channel `ejected` and fires onMembershipEnded", async () => {
    const f = await fixture("invite_only");
    // The member is genuinely subscribed — this is the state an eject arrives into.
    f.subs.upsert({
      agent_id: "agent-2", channel_pubkey: f.channelHex, admin_pubkey: f.adminHex,
      access: "invite_only", relays: [RELAY_A, RELAY_B],
    });
    f.subs.addKey("agent-2", f.channelHex, { generation: 1, key: new Uint8Array(32) }, 1000);
    expect(f.subs.get("agent-2", f.channelHex)?.status).toBe("active");

    // 038-RETESTFIX Part E: removal is its OWN frame now, not a join refusal.
    const ejected = encodeChannelMembershipEnded({ channel_pubkey: await f.channelKp.getPublicKey(), reason: "ejected" });
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, ejected);
    expect(result.ok).toBe(false);

    // ⚠️ THE SUBSCRIPTION IS MARKED, so it stops looking like a normal one forever — the live defect.
    expect(f.subs.get("agent-2", f.channelHex)?.status).toBe("ejected");
    // And the membership-ended doorbell fires so the operator learns of it — NOT a join answer.
    expect(f.membershipEnded).toEqual([{ agentId: "agent-2", channelHex: f.channelHex, reason: "ejected" }]);
    expect(f.joinAnswers, "removal is not a join answer").toEqual([]);
    // The kept key is untouched: earlier posts stay readable.
    expect(f.subs.keysFor("agent-2", f.channelHex)).toHaveLength(1);
  });

  it("034-LIFECYCLE test 7 (038 Part E): a membership-ended(channel_closed) frame marks a subscribed channel `closed` and fires onMembershipEnded", async () => {
    const f = await fixture("invite_only");
    f.subs.upsert({
      agent_id: "agent-2", channel_pubkey: f.channelHex, admin_pubkey: f.adminHex,
      access: "invite_only", relays: [RELAY_A, RELAY_B],
    });
    f.subs.addKey("agent-2", f.channelHex, { generation: 1, key: new Uint8Array(32) }, 1000);

    const closed = encodeChannelMembershipEnded({ channel_pubkey: await f.channelKp.getPublicKey(), reason: "channel_closed" });
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, closed);
    expect(result.ok).toBe(false);

    // `closed`, NOT `ejected`: the whole channel is gone, and the doorbell renders differently for it.
    expect(f.subs.get("agent-2", f.channelHex)?.status).toBe("closed");
    expect(f.membershipEnded).toEqual([{ agentId: "agent-2", channelHex: f.channelHex, reason: "channel_closed" }]);
    expect(f.subs.keysFor("agent-2", f.channelHex)).toHaveLength(1);
  });

  it("034-LIFECYCLE (review HIGH): a membership-ended frame from a NON-admin peer changes nothing", async () => {
    // A membership-ended(ejected)/(channel_closed) removes a member's subscription — a privileged act.
    // The session proves who the peer IS, not that they administer the channel. Without checking the
    // sender against the subscription's stored admin, any peer that can open a session could mark you
    // ejected or your channel deleted. This pins the check the accept/rekey branch already makes.
    const f = await fixture("invite_only");
    f.subs.upsert({
      agent_id: "agent-2", channel_pubkey: f.channelHex, admin_pubkey: f.adminHex,
      access: "invite_only", relays: [RELAY_A, RELAY_B],
    });
    const stranger = generateKeypair();
    const strangerHex = hex(await stranger.getPublicKey());

    for (const reason of ["ejected", "channel_closed"] as const) {
      const frame = encodeChannelMembershipEnded({ channel_pubkey: await f.channelKp.getPublicKey(), reason });
      const res = await f.exchange.onSubscriberFrame("agent-2", "s1", strangerHex, frame);
      expect(res.ok).toBe(false);
      // The status is untouched, and no removal doorbell fired — a stranger cannot remove you.
      expect(f.subs.get("agent-2", f.channelHex)?.status, `${reason} from a stranger`).toBe("active");
    }
    expect(f.membershipEnded, "no removal doorbell fired for a non-admin sender").toEqual([]);

    // And from the ACTUAL admin, the same frame still marks it.
    const ejected = encodeChannelMembershipEnded({ channel_pubkey: await f.channelKp.getPublicKey(), reason: "ejected" });
    await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, ejected);
    expect(f.subs.get("agent-2", f.channelHex)?.status).toBe("ejected");
  });

  it("034-LIFECYCLE: a membership-ended(ejected) for a channel NOT subscribed does not throw and marks nothing", async () => {
    // The member never joined. Marking must be guarded on the subscription existing — a bare
    // markEjected would throw subscription_unknown and take the handler down.
    const f = await fixture("invite_only");
    const ejected = encodeChannelMembershipEnded({ channel_pubkey: await f.channelKp.getPublicKey(), reason: "ejected" });
    const result = await f.exchange.onSubscriberFrame("agent-2", "s1", f.adminHex, ejected);
    expect(result.ok).toBe(false);
    expect(f.subs.get("agent-2", f.channelHex)).toBeNull();
    // Nothing to mark, but the operator is still told the membership ended.
    expect(f.membershipEnded).toEqual([{ agentId: "agent-2", channelHex: f.channelHex, reason: "ejected" }]);
  });

  it("a frame that is not a join frame is NOT consumed — it is somebody talking", async () => {
    const f = await fixture("open");
    const message = new TextEncoder().encode("hello, are you there?");
    expect(isChannelJoinFrame(message)).toBe(false);
    // Consuming it would make a person's message vanish instead of reaching the operator.
    const handled = await f.exchange.onAdminFrame("s1", f.subscriberHex, message);
    expect(handled.consumed).toBe(false);
    expect(f.sent).toEqual([]);
  });
});
