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
  encodeChannelJoinAccepted, isChannelJoinFrame,
} from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { createChannelJoinExchange, type ChannelJoinExchange } from "../channel-join-exchange.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";
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
    retention_seconds: 7 * 24 * 3600, relays: [RELAY_A, RELAY_B],
  });
  const subs = new ChannelSubscriptionStore(db, silent);

  const sent: Array<{ sessionId: string; content: Uint8Array }> = [];
  const profileAdmin = new Map<string, string>([[channelHex, adminHex]]);
  const notices: Array<{ event: string; channel: string; subscriber: string }> = [];

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
    profileAdminPubkey: (chHex) => Promise.resolve(profileAdmin.get(chHex) ?? null),
    keyProviderFor: () => subscriberKp,
    raiseNotice: (event, channel, subscriber) => { notices.push({ event, channel, subscriber }); },
    now: () => 1_800_000_000_000,
  });

  return {
    exchange, members, subs, channelKp, adminKp, subscriberKp,
    channelHex, adminHex, subscriberHex, sent, profileAdmin, notices,
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
      access: "open", relays: ["/dns4/attacker.example/tcp/443/tls/ws"], members_visible: false,
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

  it("10. a PUBLIC channel refuses the join — there is nothing to join", async () => {
    const f = await fixture("public");
    const request = encodeChannelJoinRequest({
      channel_pubkey: await f.channelKp.getPublicKey(),
      subscriber_pubkey: await f.subscriberKp.getPublicKey(),
      note: "",
    });

    await f.exchange.onAdminFrame("s1", f.subscriberHex, request);
    const refused = decodeChannelJoinRefused(f.sent[0].content);
    // A public channel has no keys and no membership: anyone may read it. Admitting somebody would
    // record a membership that means nothing and promise a key that does not exist.
    expect(refused.ok && refused.frame.reason).toBe("channel_is_public");
    expect(f.members.statusOf(f.channelHex, f.subscriberHex)).toBeNull();
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
