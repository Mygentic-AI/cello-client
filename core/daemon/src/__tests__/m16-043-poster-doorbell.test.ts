/**
 * M16 043-POSTERS Part F — a poster's post rings the members, through the ADMIN's daemon.
 *
 * The admin's collector reads its channel's poster lanes on the existing collection schedule (the
 * ticker's pass), as a reader; a new poster post rings the members through the same wake an admin
 * post uses — a `channel_wake_request` naming every active member — and only once per new post.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, generateGroupKey } from "@cello-protocol/crypto";
import {
  decodeBroadcastArtifact, encodeChannelPosterPass, encodeRelayPostReceipt, signChannelPosterPass, signRelayPostReceipt,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelInboxStore } from "../channel-inbox-store.js";
import { ChannelPosterPassStore } from "../channel-poster-pass-store.js";
import { ChannelLanePositionStore } from "../channel-lane-position-store.js";
import { ChannelPosterPublisher } from "../channel-poster-publisher.js";
import { ChannelCollector } from "../channel-collector.js";
import { createChannelCollectTicker } from "../channel-collect-tick.js";
import { createChannelWakeSender } from "../channel-wake-sender.js";
import { createPosterDoorbell } from "../channel-poster-doorbell.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const NOW = 1_800_000_000_000;
const DAY = 86_400_000;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let dir: string;
let db: DaemonDatabase;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-043f-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("043-POSTERS Part F — the doorbell for a poster's post", () => {
  it("F1. a poster post rings the members through the admin's daemon, once; a quiet pass rings nobody", async () => {
    const channel = generateKeypair();
    const admin = generateKeypair();
    const bob = generateKeypair();
    const channelHex = hex(await channel.getPublicKey());
    const adminHex = hex(await admin.getPublicKey());
    const gk = generateGroupKey(1);
    const relayKey = generateKeypair();
    const lanes = new Map<string, Map<number, { post_cbor: Uint8Array; receipt_cbor: Uint8Array }>>();

    // The poster (Bob's daemon) — a separate store set on the same test DB, keyed by its own agent id.
    const subs = new ChannelSubscriptionStore(db, silent);
    const passes = new ChannelPosterPassStore(db, silent);
    subs.upsert({ agent_id: "id-bob", channel_pubkey: channelHex, admin_pubkey: adminHex, access: "invite_only", relays: [RELAY] });
    subs.addKey("id-bob", channelHex, gk, NOW);
    const pass = await signChannelPosterPass(channel, { poster_pubkey: await bob.getPublicKey(), issued_at: NOW - DAY, expires_at: NOW + 6 * DAY });
    passes.put("id-bob", channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: pass.issued_at, expires_at: pass.expires_at });
    const poster = new ChannelPosterPublisher({
      logger: silent, log: new ChannelLogStore(db, silent), passes, subscriptions: subs,
      resolveAgentId: () => "id-bob", getAgentKey: () => bob,
      screenOutbound: () => Promise.resolve({ disposition: "allow" }), now: () => NOW,
      deposit: async (_r, req) => {
        const d = decodeBroadcastArtifact(req.post_cbor);
        if (!d.ok) return { ok: false, reason: "bad_post" };
        const lane = `${channelHex}/${hex(d.artifact.agent_pubkey)}`;
        const receipt_cbor = encodeRelayPostReceipt(await signRelayPostReceipt(relayKey, d.artifact, NOW));
        const q = lanes.get(lane) ?? new Map();
        q.set(d.artifact.seq, { post_cbor: req.post_cbor, receipt_cbor });
        lanes.set(lane, q);
        return { ok: true, receipt_cbor };
      },
    });

    // The admin's daemon: holds the group key under its own id, a collector, the wake, the ticker.
    subs.addKey("id-admin", channelHex, gk, NOW);
    const collector = new ChannelCollector({
      logger: silent, subscriptions: subs, inbox: new ChannelInboxStore(db, silent),
      lanePositions: new ChannelLanePositionStore(db, silent),
      fetch: (_r, req) => {
        const q = lanes.get(`${hex(req.channel_pubkey)}/${hex(req.lane_poster!)}`) ?? new Map();
        const seqs = [...q.keys()].sort((x, y) => x - y);
        return Promise.resolve({
          ok: true as const, posts: seqs.filter((s) => s >= req.since_seq).map((s) => ({ seq: s, ...q.get(s)! })),
          first_held_seq: seqs[0] ?? null, last_seq: seqs[seqs.length - 1] ?? null,
        });
      },
      lanes: () => Promise.resolve({
        ok: true as const,
        lanes: [...lanes.keys()].map((k) => ({ poster_pubkey: new Uint8Array(Buffer.from(k.split("/")[1]!, "hex")), last_seq: 1 })),
      }),
      fetchAuth: () => Promise.resolve(undefined),
      localAgentKeys: () => [], requestRepair: () => Promise.resolve(),
    });
    const frames: Array<Record<string, unknown>> = [];
    const members = [hex(await bob.getPublicKey()), "cd".repeat(32)];
    const sendWake = createChannelWakeSender({
      logger: silent, activeMembers: () => members,
      signalingFor: (name) => (name === "admin" ? { sendRaw: (f: unknown) => { frames.push(f as Record<string, unknown>); return Promise.resolve({ ok: true }); } } : null),
    });
    const ticker = createChannelCollectTicker({
      logger: silent, collector, subscriptions: subs, isAgentOnline: () => true,
      adminPass: createPosterDoorbell({
        logger: silent,
        collectPosterLanesAsAdmin: (id, ch, view) => collector.collectPosterLanesAsAdmin(id, ch, view),
        postingChannels: () => [channelHex],
        channelConfig: () => ({ access: "invite_only", relays: [RELAY], admin_pubkey: adminHex }),
        adminAgent: (h) => (h === adminHex ? { name: "admin", agentId: "id-admin" } : null),
        isAgentOnline: () => true,
        sendWake,
      }),
    });

    await ticker.collectAllDue(NOW);
    expect(frames.length).toBe(0); // nothing posted yet → no ring

    expect(await poster.publish("bob", channelHex, "hello", "from bob")).toMatchObject({ ok: true, seq: 1 });
    await ticker.collectAllDue(NOW + 1);
    expect(frames.length).toBe(1);
    expect(frames[0]!["type"]).toBe("channel_wake_request");
    expect(hex(frames[0]!["channel_pubkey"] as Uint8Array)).toBe(channelHex);
    expect((frames[0]!["agent_pubkeys"] as Uint8Array[]).map(hex)).toEqual(members);

    await ticker.collectAllDue(NOW + 2);
    expect(frames.length).toBe(1); // the same post does not ring twice
  });
});
