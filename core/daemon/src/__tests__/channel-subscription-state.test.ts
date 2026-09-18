/**
 * M16 019-MEMBERSHIP Part D — subscription state.
 *
 * What a subscriber holds for a channel it follows: the admin it verified, the relay pair, the group
 * keys for every generation, and TWO positions — how far the daemon has fetched, and how far the
 * agent has read. Tests 16–20 of the order, written before the implementation.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const CHANNEL = "aa".repeat(32);
const ADMIN = "bb".repeat(32);
const AGENT = "agent-1";
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";

let dir: string;
let db: DaemonDatabase;
let subs: ChannelSubscriptionStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-019d-"));
  db = openTestDb(join(dir, "sessions.db"));
  subs = new ChannelSubscriptionStore(db, silent);
  subs.upsert({
    agent_id: AGENT, channel_pubkey: CHANNEL, admin_pubkey: ADMIN,
    access: "invite_only", relays: [RELAY_A, RELAY_B],
  });
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("M16 019 Part D — subscription state", () => {
  it("16. a subscription reads back with its relays, admin and access", () => {
    const got = subs.get(AGENT, CHANNEL);
    expect(got).not.toBeNull();
    if (!got) return;
    expect(got.admin_pubkey).toBe(ADMIN);
    expect(got.access).toBe("invite_only");
    // The relay pair is what the collector fetches from. A subscription without it is a channel the
    // subscriber knows the name of and cannot read.
    expect(got.relays).toEqual([RELAY_A, RELAY_B]);
    expect(got.status).toBe("active");
    expect(got.delivered_through).toBe(0);
    expect(got.processed_through).toBe(0);
  });

  it("17. both positions advance MONOTONICALLY, and a regression throws", () => {
    subs.setDeliveredThrough(AGENT, CHANNEL, 5);
    subs.advanceProcessed(AGENT, CHANNEL, 3);
    expect(subs.get(AGENT, CHANNEL)?.delivered_through).toBe(5);
    expect(subs.get(AGENT, CHANNEL)?.processed_through).toBe(3);

    /**
     * ⚠️ **A LOWER VALUE THROWS RATHER THAN BEING IGNORED.** Silently refusing would leave a caller
     * that computed a wrong position believing it had been applied — and the position an agent has
     * READ is not recoverable from anywhere else. Moving it backwards re-delivers messages the
     * operator already saw; a caller that tries must hear about it.
     */
    expect(() => { subs.advanceProcessed(AGENT, CHANNEL, 2); }).toThrow(/position_regression/);
    expect(subs.get(AGENT, CHANNEL)?.processed_through, "unchanged by the refusal").toBe(3);

    // Equal is not a regression: re-reading the same position is a no-op, not an error.
    subs.advanceProcessed(AGENT, CHANNEL, 3);
    expect(subs.get(AGENT, CHANNEL)?.processed_through).toBe(3);

    // ⚠️ AND THE TWO NEVER TOUCH. A read must not move the fetch position, or the collector would
    // skip everything between them on its next pass.
    expect(subs.get(AGENT, CHANNEL)?.delivered_through).toBe(5);
  });

  it("18. keysFor returns EVERY generation, newest first", () => {
    subs.addKey(AGENT, CHANNEL, { generation: 1, key: new Uint8Array(Buffer.alloc(32, 0x11)) }, 1000);
    subs.addKey(AGENT, CHANNEL, { generation: 3, key: new Uint8Array(Buffer.alloc(32, 0x33)) }, 3000);
    subs.addKey(AGENT, CHANNEL, { generation: 2, key: new Uint8Array(Buffer.alloc(32, 0x22)) }, 2000);

    const keys = subs.keysFor(AGENT, CHANNEL);
    /**
     * ⚠️ **OLD GENERATIONS ARE NEVER DELETED.** A re-key does not make yesterday's posts
     * unreadable — they are still encrypted under the old key and still in the relay's queue.
     * Dropping the old key would silently turn the channel's own history into `unknown_generation`.
     * Newest first because that is what almost every body needs.
     */
    expect(keys.map((k) => k.generation)).toEqual([3, 2, 1]);
    expect(keys[0].key[0]).toBe(0x33);

    // Re-adding a generation is idempotent, not a duplicate: a re-key can be delivered twice.
    subs.addKey(AGENT, CHANNEL, { generation: 3, key: new Uint8Array(Buffer.alloc(32, 0x33)) }, 3500);
    expect(subs.keysFor(AGENT, CHANNEL).map((k) => k.generation)).toEqual([3, 2, 1]);
  });

  it("19. markLeft stops collection, and markEjected is a DIFFERENT state", () => {
    expect(subs.active().map((s) => s.channel_pubkey)).toEqual([CHANNEL]);

    subs.markLeft(AGENT, CHANNEL);
    // ⚠️ The collector reads `active()`. Leaving is LOCAL: nothing is sent, nothing is asked of the
    // publisher, and the daemon simply stops fetching.
    expect(subs.active()).toEqual([]);
    expect(subs.get(AGENT, CHANNEL)?.status).toBe("left");

    // Ejected is not the same thing and must not be written over by it: one is the subscriber's own
    // decision and can be undone by rejoining, the other is the publisher's and cannot.
    subs.upsert({
      agent_id: AGENT, channel_pubkey: CHANNEL, admin_pubkey: ADMIN,
      access: "invite_only", relays: [RELAY_A, RELAY_B],
    });
    subs.markEjected(AGENT, CHANNEL);
    expect(subs.get(AGENT, CHANNEL)?.status).toBe("ejected");
    expect(subs.active()).toEqual([]);
  });

  it("21c. the gate's lookup takes an agent ID — a NAME matches nothing, and nothing reads as allow", () => {
    /**
     * ⚠️ **THE DEFECT THIS PINS WAS INVISIBLE FROM BOTH SIDES.** The inbound path hands the gate
     * `localAgent.name`; this store queries `agent_id`. Passing the name matched no row, a missing
     * row means "not a channel", and "not a channel" is ALLOW — so the refusal never fired and
     * nothing anywhere said so. Test 21 could not see it: its harness replaces this lookup with a
     * name-keyed stub, so it proves the refusal BRANCH works and nothing about whether it is reached.
     *
     * The subscription above is stored under the id `agent-1`. A daemon that passed a display name
     * would ask a question this store cannot answer yes to.
     */
    expect(subs.isSubscribedChannel(AGENT, CHANNEL), "by id — the column that is queried").toBe(true);
    expect(subs.isSubscribedChannel("Alice's Agent", CHANNEL), "a display name finds nothing").toBe(false);
  });

  it("20. isSubscribedChannel answers for the channel KEY, per agent", () => {
    // The inbound-session gate asks this of a sender's pubkey: a channel never opens a session, so
    // one arriving FROM a channel this agent subscribes to is a signal worth refusing on.
    expect(subs.isSubscribedChannel(AGENT, CHANNEL)).toBe(true);
    expect(subs.isSubscribedChannel(AGENT, "cc".repeat(32))).toBe(false);
    // Another agent on this daemon has not subscribed, so for THEM it is an ordinary pubkey.
    expect(subs.isSubscribedChannel("agent-2", CHANNEL)).toBe(false);

    // Still true after leaving: the sender is still a channel, and a session from one is still
    // suspicious. Answering false here would reopen the hole the moment somebody unsubscribed.
    subs.markLeft(AGENT, CHANNEL);
    expect(subs.isSubscribedChannel(AGENT, CHANNEL)).toBe(true);
  });

  it("20c. subscribing to a channel writes NO contact — a subscription is not a relationship", () => {
    /**
     * ⚠️ Order test 20. A channel is somebody you READ, not somebody you know: it never converses,
     * so a contact row for one would put an identity in `cello_contacts` that can never hold a
     * session, and every trust surface that walks contacts would have to learn to skip it. The two
     * live in different tables and nothing bridges them — this is what pins that.
     */
    db.exec(`CREATE TABLE IF NOT EXISTS contacts (
      agent_name TEXT NOT NULL, pubkey TEXT NOT NULL, added_at INTEGER NOT NULL,
      PRIMARY KEY (agent_name, pubkey))`);

    subs.upsert({
      agent_id: AGENT, channel_pubkey: "ee".repeat(32), admin_pubkey: ADMIN,
      access: "open", relays: [RELAY_A],
    });
    subs.addKey(AGENT, "ee".repeat(32), { generation: 1, key: new Uint8Array(32) }, 1000);

    const rows = db.prepare(`SELECT COUNT(*) AS n FROM contacts`).get() as { n: number | bigint };
    expect(Number(rows.n), "no contact was created by subscribing").toBe(0);
  });

  it("20b. a moniker is a LOCAL label and never changes the identity", () => {
    subs.setMoniker(AGENT, CHANNEL, "Release notes");
    expect(subs.get(AGENT, CHANNEL)?.moniker).toBe("Release notes");
    // The pubkey is the identity and is untouched by naming it.
    expect(subs.get(AGENT, CHANNEL)?.channel_pubkey).toBe(CHANNEL);
  });
});
