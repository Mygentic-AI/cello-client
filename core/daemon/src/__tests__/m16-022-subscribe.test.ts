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
import { decodeChannelJoinRequest, signBroadcastArtifact, signChannelInfo, encodeChannelInfo } from "@cello-protocol/protocol-types";
import { generateKeypair } from "@cello-protocol/crypto";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const AGENT = "agent-1";
const AGENT_NAME = "Alice";
const AGENT_PUBKEY = "a1".repeat(32);
const CHANNEL = "c1".repeat(32);
const ADMIN = "ad".repeat(32);
const RELAY = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";

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
    // Default: this daemon administers NO channel. Overridden per-test to prove the administered case.
    channelConfig: () => null,
    sessionWith: () => Promise.resolve({ ok: true as const, sessionId: "session-1" }),
    sendInSession: (_a, sessionId, content) => { sent.push({ sessionId, content }); return Promise.resolve(); },
    agentPubkey: () => AGENT_PUBKEY,
    decrypt: (_a, _c, _s, body) => Promise.resolve(body),
    // 041 Part C: by default no relay holds an info record — the stored description is used.
    fetchInfo: () => Promise.resolve(null),
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
  it("1. a channel this daemon neither administers nor follows carries only the admin + a detail", async () => {
    // 035-INFOCLI item 1: the directory names just the admin, so `info` says how to learn the rest
    // rather than inventing an access/description/relays it cannot know.
    const { api } = build();
    const r = await api.info(AGENT, CHANNEL);
    expect(r).toEqual({
      ok: true, channelHex: CHANNEL, adminPubkeyHex: ADMIN,
      detail: "Join the channel to see its description and relays.",
    });
  });

  it("1a. 035 item 1 — a channel this daemon ADMINISTERS carries access, guidance, relays from config", async () => {
    const { api } = build({
      channelConfig: () => ({ access: "invite_only", guidance: "the release channel", relays: [RELAY, "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X"] }),
    });
    const r = await api.info(AGENT, CHANNEL);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.access).toBe("invite_only");
      expect(r.guidance).toBe("the release channel");
      expect(r.relays).toEqual([RELAY, "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X"]);
      // Administering the channel is not following it, so no member status is reported.
      expect(r.status).toBeUndefined();
      expect(r.detail).toBeUndefined();
    }
  });

  it("1b. 035 item 1 — a channel this daemon FOLLOWS carries access, guidance, relays AND status", async () => {
    // The subscription the acceptance created (guidance included), and this daemon administers nothing.
    subs.upsert({ agent_id: AGENT, channel_pubkey: CHANNEL, admin_pubkey: ADMIN, access: "open", relays: [RELAY], guidance: "what it is for" });
    const { api } = build();
    const r = await api.info(AGENT, CHANNEL);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.access).toBe("open");
      expect(r.guidance).toBe("what it is for");
      expect(r.relays).toEqual([RELAY]);
      expect(r.status).toBe("active");
      expect(r.detail).toBeUndefined();
    }
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

  it("038 Part D — info on a revoked channel says it was deleted", async () => {
    // Live evidence (F38): after `cello channel delete`, `channel info` still returned admin, access
    // and relays, so a newcomer would try to join. When the directory answers revoked, info says so.
    const { api } = build({ lookupAdmin: () => Promise.resolve({ kind: "revoked" as const }) });
    const r = await api.info(AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("channel_deleted");
      expect(r.guidance).toBe("This channel was deleted by its admin.");
    }
  });

  it("038 Part D — info reports a local subscription's `closed` status even before the fleet is rolled", async () => {
    // The member received the channel_closed notice, so its subscription is marked closed. Even if
    // the directory has not yet been rolled (still answers `admin`), info reports the channel deleted
    // and carries the closed status.
    subs.upsert({ agent_id: AGENT, channel_pubkey: CHANNEL, admin_pubkey: ADMIN, access: "open", relays: [RELAY] });
    subs.markClosed(AGENT, CHANNEL);
    const { api } = build(); // lookupAdmin defaults to { kind: "admin" }
    const r = await api.info(AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("channel_deleted");
      expect(r.status).toBe("closed");
    }
  });
});

// ─── M16 041-HELPTRUTH Part C — a member's `channel info` shows the CURRENT description ──────────
//
// The info-set help promises "existing members see the new text the next time they run 'channel
// info'", but a member's `info` answered from the subscription row whose description was frozen at
// admission. Now a member asks its relays for the signed info record, verifies it against the
// channel key, and prefers it — falling back to the stored text (never an unverified one) when no
// relay answers or the record does not verify, marking the source so the reader knows which it got.
describe("M16 041-HELPTRUTH Part C — a member's info refreshes the description from the relays", () => {
  /** A signed info record for `channel`, from `signer` (the channel key for a genuine one). */
  async function signedInfo(signer: typeof channelKp, channelHex: string, guidance: string): Promise<Uint8Array> {
    const info = await signChannelInfo(signer, {
      access: "open",
      admin_pubkey: await adminKp.getPublicKey(),
      relays: [RELAY],
      guidance,
      retention_seconds: 7 * 24 * 3600,
      updated_at: 1_800_000_000_000,
      ext: null,
    });
    return encodeChannelInfo(info);
  }

  it("C1. a relay serves a newer signed record → the new text is shown and the stored row is updated", async () => {
    const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
    subs.upsert({ agent_id: AGENT, channel_pubkey: channelHex, admin_pubkey: ADMIN, access: "open", relays: [RELAY], guidance: "old stored text" });
    const record = await signedInfo(channelKp, channelHex, "the current description");
    const { api } = build({ fetchInfo: () => Promise.resolve(record) });

    const r = await api.info(AGENT, channelHex);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.guidance, "the fresh, verified description is shown").toBe("the current description");
      expect(r.description_source).toBe("relay");
    }
    // And the fresh text was written back to the subscription row.
    expect(subs.get(AGENT, channelHex)?.guidance, "the stored description was refreshed").toBe("the current description");
  });

  it("C2. a record signed by ANOTHER key is refused → the stored text is shown, source stored", async () => {
    const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
    subs.upsert({ agent_id: AGENT, channel_pubkey: channelHex, admin_pubkey: ADMIN, access: "open", relays: [RELAY], guidance: "old stored text" });
    // Signed by the ADMIN key, not the channel key — it verifies against its own (admin) pubkey, so
    // the channel-pubkey match fails and the record is refused. An unverified description is NEVER shown.
    const forged = await signedInfo(adminKp, channelHex, "a description the channel never signed");
    const { api } = build({ fetchInfo: () => Promise.resolve(forged) });

    const r = await api.info(AGENT, channelHex);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.guidance, "the unverified relay record is ignored").toBe("old stored text");
      expect(r.description_source).toBe("stored");
    }
    expect(subs.get(AGENT, channelHex)?.guidance, "the stored description is untouched").toBe("old stored text");
  });

  it("C3. no relay answers → the stored text is shown, source stored", async () => {
    const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
    subs.upsert({ agent_id: AGENT, channel_pubkey: channelHex, admin_pubkey: ADMIN, access: "open", relays: [RELAY], guidance: "old stored text" });
    const { api } = build({ fetchInfo: () => Promise.resolve(null) });

    const r = await api.info(AGENT, channelHex);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.guidance).toBe("old stored text");
      expect(r.description_source).toBe("stored");
    }
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

  it("038 Part D — a join to a revoked channel is refused BEFORE any session is opened", async () => {
    const sessionWith = vi.fn(() => Promise.resolve({ ok: true as const, sessionId: "session-1" }));
    const { api, sent } = build({ lookupAdmin: () => Promise.resolve({ kind: "revoked" as const }), sessionWith });
    const r = await api.join(AGENT_NAME, AGENT, CHANNEL);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("channel_deleted");
      expect(r.guidance).toBe("This channel was deleted by its admin.");
    }
    // No session opened, nothing sent — the refusal comes from the directory answer alone.
    expect(sessionWith, "no session is opened for a deleted channel").not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
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

  it("036-PUBLICSUB test 5: read on a PUBLIC subscription returns posts as plaintext WITHOUT attempting decryption", async () => {
    /**
     * ⚠️ A public channel's posts are stored in clear (028) — there is no key. The read path must
     * return the body as plaintext directly; routing a public body through decryptBody finds no key
     * for it and reports it `undecryptable`, so a public reader would see nothing. The decrypt seam
     * is stubbed to RETURN NULL here so the test reddens the moment the code touches it.
     */
    subs.upsert({ agent_id: AGENT, channel_pubkey: CHANNEL, admin_pubkey: ADMIN, access: "public", relays: [RELAY] });
    subs.setDeliveredThrough(AGENT, CHANNEL, 1);
    await storePost(1, "bulletin", "the morning news");

    const decrypt = vi.fn((): Promise<Uint8Array | null> => Promise.resolve(null));
    const { api } = build({ decrypt });
    const r = await api.read(AGENT, CHANNEL);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.posts.map((p) => p.body)).toEqual(["the morning news"]);
      expect(r.undecryptable, "a public post is never undecryptable — there is nothing to decrypt").toEqual([]);
    }
    // ⚠️ The decrypt seam was NEVER reached: a public read does not decrypt.
    expect(decrypt, "public read must not call decryptBody").not.toHaveBeenCalled();
    expect(subs.get(AGENT, CHANNEL)?.processed_through).toBe(1);
  });
});
