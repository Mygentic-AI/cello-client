/**
 * M16 022-SUBSCRIBE — the verbs that make the other eleven mean anything.
 *
 * ⚠️ **NOTHING IN PRODUCTION SENT A JOIN REQUEST BEFORE THIS.** `encodeChannelJoinRequest` was
 * written, exported, and called only by tests, and no verb read a post back out. So fifteen orders
 * built a feature a person could publish to and not subscribe to — every order's tests green,
 * because each tested its own layer and none asked whether an operator could do the thing.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join as pathJoin } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelInboxStore } from "../channel-inbox-store.js";
import { createChannelSubscribe } from "../channel-subscribe.js";
import { decodeChannelJoinRequest, signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { generateKeypair } from "@cello-protocol/crypto";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const AGENT = "agent-1";
const AGENT_NAME = "Alice";
const AGENT_PUBKEY = "a1".repeat(32);
const CHANNEL = "c1".repeat(32);
const ADMIN = "ad".repeat(32);
const RELAY = "/dns4/relay-a.example/tcp/443/tls/ws";

let dir: string;
let db: DaemonDatabase;
let subs: ChannelSubscriptionStore;
const channelKp = generateKeypair();
const adminKp = generateKeypair();
let inbox: ChannelInboxStore;

beforeEach(() => {
  dir = mkdtempSync(pathJoin(tmpdir(), "cello-m16-022-"));
  db = openTestDb(pathJoin(dir, "sessions.db"));
  subs = new ChannelSubscriptionStore(db, silent);
  inbox = new ChannelInboxStore(db, silent);
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function build(over: Partial<Parameters<typeof createChannelSubscribe>[0]> = {}) {
  const sent: Array<{ sessionId: string; content: Uint8Array }> = [];
  const api = createChannelSubscribe({
    logger: silent,
    subscriptions: subs,
    inbox,
    lookupAdmin: () => Promise.resolve({ kind: "admin" as const, adminPubkeyHex: ADMIN }),
    sessionWith: () => Promise.resolve({ ok: true as const, sessionId: "session-1" }),
    sendInSession: (_a, sessionId, content) => { sent.push({ sessionId, content }); return Promise.resolve(); },
    agentPubkey: () => AGENT_PUBKEY,
    decrypt: (_a, _c, _s, body) => Promise.resolve(body),
    ...over,
  });
  return { api, sent };
}

/** A subscription as the join acceptance would have created it — relays included. */
function subscribe(deliveredThrough = 0) {
  subs.upsert({ agent_id: AGENT, channel_pubkey: CHANNEL, admin_pubkey: ADMIN, access: "open", relays: [RELAY] });
  if (deliveredThrough > 0) subs.setDeliveredThrough(AGENT, CHANNEL, deliveredThrough);
}

/** A collected post, stored the way the collector stores one. Title is clear; body is the sealed part. */
async function storePost(seq: number, title: string, body: string) {
  const post = await signBroadcastArtifact(channelKp, adminKp, {
    seq, published_at: 1_800_000_000_000 + seq, title,
    body: new Uint8Array(Buffer.from(body, "utf8")), supersedes: null, ext: null,
  });
  inbox.store(AGENT, CHANNEL, post, { fromRelay: RELAY, collectedAt: 1_800_000_000_000 });
}

describe("M16 022 — info", () => {
  it("1. says who administers a channel, from the directory alone", async () => {
    const { api } = build();
    const r = await api.info(AGENT, CHANNEL);
    expect(r).toEqual({ ok: true, channelHex: CHANNEL, adminPubkeyHex: ADMIN });
  });

  it("2. a pubkey that is not a channel is a settled NO, not an outage", async () => {
    const { api } = build({ lookupAdmin: () => Promise.resolve({ kind: "not_a_channel" as const }) });
    const r = await api.info(AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("not_a_channel");
  });

  it("3. an unreachable directory is UNAVAILABLE and carries why", async () => {
    // ⚠️ The distinction the whole of M16 turns on: "it is not a channel" is an answer a caller acts
    // on; "I could not find out" is not, and collapsing them makes an outage look like a verdict.
    const { api } = build({ lookupAdmin: () => Promise.resolve({ kind: "unavailable" as const, reason: "timeout" }) });
    const r = await api.info(AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) { expect(r.reason).toBe("unavailable"); expect(r.detail).toBe("timeout"); }
  });
});

describe("M16 022 — join", () => {
  it("4. sends a join request to the ADMIN the directory named, and NO RELAY is involved", async () => {
    /**
     * ⚠️ **THE VERB THAT DID NOT EXIST.** And it takes one argument: relays are the publisher's
     * choice and arrive on the acceptance, so a subscriber never sees or types one.
     */
    const { api, sent } = build();
    const r = await api.join(AGENT_NAME, AGENT, CHANNEL);
    expect(r).toEqual({ ok: true, channelHex: CHANNEL, state: "requested" });

    expect(sent).toHaveLength(1);
    const decoded = decodeChannelJoinRequest(sent[0].content);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(Buffer.from(decoded.frame.channel_pubkey).toString("hex")).toBe(CHANNEL);
      expect(Buffer.from(decoded.frame.subscriber_pubkey).toString("hex")).toBe(AGENT_PUBKEY);
    }
  });

  it("5. IT DOES NOT RECORD A SUBSCRIPTION — asking is not being admitted", async () => {
    /**
     * ⚠️ The answer arrives later as a join frame and the EXCHANGE decides, after running the admin
     * check 020 built. A verb that wrote a subscription on send would make an unanswered request —
     * or a refused one — look like membership, and would hand the operator a channel they cannot
     * read.
     */
    const { api, sent } = build();
    await api.join(AGENT_NAME, AGENT, CHANNEL);
    // Paired with the send, so this cannot pass for an implementation that simply failed earlier.
    expect(sent, "the request really went out").toHaveLength(1);
    expect(subs.get(AGENT, CHANNEL)).toBeNull();
  });

  it("6. a channel the directory does not know is refused before any session is opened", async () => {
    const sessionWith = vi.fn(() => Promise.resolve({ ok: true as const, sessionId: "session-1" }));
    const { api } = build({ lookupAdmin: () => Promise.resolve({ kind: "not_a_channel" as const }), sessionWith });
    const r = await api.join(AGENT_NAME, AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    expect(sessionWith, "no session is opened for a channel that does not exist").not.toHaveBeenCalled();
  });

  it("7. no session with the admin is a named refusal, not a throw", async () => {
    const { api } = build({
      sessionWith: () => Promise.resolve({ ok: false as const, reason: "invalid_target_pubkey" }),
    });
    const r = await api.join(AGENT_NAME, AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("no_session");
      /**
       * ⚠️ **THE REAL CAUSE TRAVELS, and the first version threw it away.** It said "could not open
       * a session with the admin" for everything — including a field name wrong in the caller,
       * which is what actually shipped. That message points an operator at the counterparty and the
       * network for a bug in their own daemon.
       */
      expect(r.detail).toBe("invalid_target_pubkey");
    }
  });
});

describe("M16 022 — read", () => {
  it("8. returns posts after the read position and advances it", async () => {
    subscribe(2);
    await storePost(1, "first", "one");
    await storePost(2, "second", "two");

    const { api } = build();
    const r = await api.read(AGENT, CHANNEL);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.posts.map((p) => p.title)).toEqual(["first", "second"]);
      expect(r.through).toBe(2);
    }
    expect(subs.get(AGENT, CHANNEL)?.processed_through).toBe(2);
  });

  it("9. a second read returns nothing new", async () => {
    subscribe(1);
    await storePost(1, "only", "one");
    const { api } = build();
    await api.read(AGENT, CHANNEL);
    const again = await api.read(AGENT, CHANNEL);
    expect(again.ok && again.posts).toEqual([]);
  });

  it("10. it NEVER reads past what the collector has fetched", async () => {
    /**
     * ⚠️ **TWO POSITIONS, AND THIS VERB OWNS ONLY ONE.** `delivered_through` is the collector's
     * edge; `processed_through` is what a person has seen. Reading past the first would advance the
     * second over posts that have not been collected, and those posts would never be shown again.
     */
    subscribe(1);
    await storePost(1, "fetched", "yes");
    await storePost(2, "not fetched yet", "no");

    const { api } = build();
    const r = await api.read(AGENT, CHANNEL);
    expect(r.ok && r.posts.map((p) => p.seq)).toEqual([1]);
    expect(subs.get(AGENT, CHANNEL)?.processed_through).toBe(1);
  });

  it("11. --all re-reads from the start WITHOUT moving the position", async () => {
    /**
     * ⚠️ The position must be BEHIND the collector's edge for this to prove anything. With both at
     * the same number, an implementation that advanced on `--all` would set it to the value it
     * already had and the test would pass regardless.
     */
    subscribe(2);
    await storePost(1, "first", "one");
    await storePost(2, "second", "two");
    subs.advanceProcessed(AGENT, CHANNEL, 1);

    const { api } = build();
    const all = await api.read(AGENT, CHANNEL, true);
    expect(all.ok && all.posts).toHaveLength(2);
    // Reviewing history is not seeing something new.
    expect(subs.get(AGENT, CHANNEL)?.processed_through, "unchanged, and still behind").toBe(1);
  });

  it("12. A POST THAT WILL NOT DECRYPT IS NAMED, NOT SKIPPED", async () => {
    /**
     * ⚠️ `unknown_generation` means a re-key this subscriber never received — usually an ejection.
     * Skipping it silently makes being ejected indistinguishable from a channel that went quiet,
     * which is the one reading of it the operator must not be left with.
     */
    subscribe(2);
    await storePost(1, "readable", "yes");
    await storePost(2, "sealed", "no");
    const { api } = build({
      decrypt: (_a, _c, seq, body) => Promise.resolve(seq === 2 ? null : body),
    });

    const r = await api.read(AGENT, CHANNEL);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.posts.map((p) => p.seq)).toEqual([1]);
      expect(r.undecryptable, "the operator is told which posts could not be opened").toEqual([2]);
    }
    /**
     * ⚠️ **AND THE POSITION STOPS BELOW IT.** Naming the post and then advancing past it is
     * "announced once, then skipped for ever": receive the missing key later and those posts are
     * behind the read position, never to be shown. The next read must retry them.
     */
    expect(subs.get(AGENT, CHANNEL)?.processed_through, "stops below the sealed post").toBe(1);
  });

  it("13. reading a channel this agent does not follow is a named refusal", async () => {
    const { api } = build();
    const r = await api.read(AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("not_subscribed");
  });
});
