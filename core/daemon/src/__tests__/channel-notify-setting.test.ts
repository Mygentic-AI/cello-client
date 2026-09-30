/**
 * Per-channel push/pull. A subscriber can say a channel is noisy and should not ring its agent: the
 * daemon still fetches and stores every post and keeps the unread count, but sends no doorbell, so the
 * agent (or a cron job) pulls with `cello channel read`. The default is `push`, so nobody has to
 * discover a feature to keep the behaviour they had.
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
const CHANNEL_A = "aa".repeat(32);
const CHANNEL_B = "cc".repeat(32);
const ADMIN = "bb".repeat(32);
const AGENT = "agent-1";
const OTHER_AGENT = "agent-2";
const RELAYS = [
  "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83",
  "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X",
];

let dir: string;
let db: DaemonDatabase;
let subs: ChannelSubscriptionStore;

const join_ = (agent: string, channel: string) =>
  subs.upsert({ agent_id: agent, channel_pubkey: channel, admin_pubkey: ADMIN, access: "invite_only", relays: RELAYS });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-notify-"));
  db = openTestDb(join(dir, "sessions.db"));
  subs = new ChannelSubscriptionStore(db, silent);
  join_(AGENT, CHANNEL_A);
  join_(AGENT, CHANNEL_B);
  join_(OTHER_AGENT, CHANNEL_A);
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("channel notify setting", () => {
  it("a new subscription pushes by default", () => {
    expect(subs.get(AGENT, CHANNEL_A)?.notify).toBe("push");
    expect(subs.notifyFor(AGENT, CHANNEL_A)).toBe("push");
  });

  it("pull is stored, and read back, for that agent and that channel only", () => {
    subs.setNotify(AGENT, CHANNEL_A, "pull");
    expect(subs.notifyFor(AGENT, CHANNEL_A)).toBe("pull");
    expect(subs.notifyFor(AGENT, CHANNEL_B)).toBe("push");
    expect(subs.notifyFor(OTHER_AGENT, CHANNEL_A)).toBe("push");
  });

  it("can be switched back to push", () => {
    subs.setNotify(AGENT, CHANNEL_A, "pull");
    subs.setNotify(AGENT, CHANNEL_A, "push");
    expect(subs.notifyFor(AGENT, CHANNEL_A)).toBe("push");
  });

  it("rejoining a channel does not reset a pull the operator chose", () => {
    subs.setNotify(AGENT, CHANNEL_A, "pull");
    join_(AGENT, CHANNEL_A);
    expect(subs.notifyFor(AGENT, CHANNEL_A)).toBe("pull");
  });

  it("a channel this agent does not follow answers push, so nothing is silenced by accident", () => {
    expect(subs.notifyFor(AGENT, "dd".repeat(32))).toBe("push");
  });

  it("a daemon that ran channels before this setting existed keeps working and defaults to push", () => {
    db.exec("DROP TABLE channel_subscriptions");
    db.exec(`CREATE TABLE channel_subscriptions (
      agent_id TEXT NOT NULL, channel_pubkey TEXT NOT NULL, admin_pubkey TEXT NOT NULL, access TEXT NOT NULL,
      guidance TEXT NOT NULL DEFAULT '', guidance_updated_at INTEGER NOT NULL DEFAULT 0,
      retention_seconds INTEGER NOT NULL DEFAULT 604800, relays TEXT NOT NULL DEFAULT '[]',
      moniker TEXT NOT NULL DEFAULT '', delivered_through INTEGER NOT NULL DEFAULT 0,
      processed_through INTEGER NOT NULL DEFAULT 0, joined_at INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active', PRIMARY KEY (agent_id, channel_pubkey))`);
    db.prepare("INSERT INTO channel_subscriptions (agent_id, channel_pubkey, admin_pubkey, access, relays) VALUES (?,?,?,?,?)")
      .run(AGENT, CHANNEL_A, ADMIN, "invite_only", JSON.stringify(RELAYS));
    const upgraded = new ChannelSubscriptionStore(db, silent);
    expect(upgraded.get(AGENT, CHANNEL_A)?.notify).toBe("push");
    upgraded.setNotify(AGENT, CHANNEL_A, "pull");
    expect(upgraded.notifyFor(AGENT, CHANNEL_A)).toBe("pull");
  });
});
