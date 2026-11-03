/**
 * The relays moved from cello.mygentic.ai to celloprotocol.com, keeping their peer ids. Addresses
 * already stored on a Mac still name the old domain, which is expiring, so every dial to them fails.
 *
 * Real SQLCipher DB. No mocks.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { migrateRetiredRelayDomain, rewriteRetiredRelayAddrs } from "../retired-relay-domain.js";

const PEER = "12D3KooWFpvG5ksTBoiMCfyy3n126AtpFNYGXB14R2335DAf1BYt";
const OLD = `/dns4/relay-euw1.cello.mygentic.ai/tcp/443/tls/ws/p2p/${PEER}`;
const NEW = `/dns4/relay-euw1.celloprotocol.com/tcp/443/tls/ws/p2p/${PEER}`;
const OTHER = `/ip4/34.139.119.165/tcp/4001/ws/p2p/${PEER}`;

interface LogEvent { level: string; event: string; context?: Record<string, unknown> }
function capturing(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

describe("rewriteRetiredRelayAddrs", () => {
  it("moves the old domain to the new one and keeps the peer id", () => {
    expect(rewriteRetiredRelayAddrs([OLD])).toEqual([NEW]);
  });

  it("leaves addresses that are not on the retired domain untouched", () => {
    expect(rewriteRetiredRelayAddrs([NEW, OTHER])).toEqual([NEW, OTHER]);
  });

  it("does not match a host that merely ends in the same letters", () => {
    const lookalike = `/dns4/relay.notcello.mygentic.ai/tcp/443/tls/ws/p2p/${PEER}`;
    expect(rewriteRetiredRelayAddrs([lookalike])).toEqual([lookalike]);
  });

  it("does not rewrite the domain when it appears outside the host segment", () => {
    const elsewhere = `/ip4/1.2.3.4/tcp/443/sni/x.cello.mygentic.ai/p2p/${PEER}`;
    expect(rewriteRetiredRelayAddrs([elsewhere])).toEqual([elsewhere]);
  });
});

describe("migrateRetiredRelayDomain", () => {
  let dir: string;
  let db: DaemonDatabase;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "retired-relay-domain-"));
    db = openTestDb(join(dir, "sessions.db"));
    db.exec(`
      CREATE TABLE sessions (agent_id TEXT, session_id TEXT, status TEXT, relay_addrs TEXT, updated_at INTEGER);
      CREATE TABLE channel_config (channel_pubkey TEXT PRIMARY KEY, relays TEXT NOT NULL);
      CREATE TABLE channel_subscriptions (agent_id TEXT, channel_pubkey TEXT, relays TEXT NOT NULL DEFAULT '[]');
      CREATE TABLE channel_join_requests (agent_id TEXT, channel_pubkey TEXT, relays TEXT NOT NULL);
      CREATE TABLE channel_inbox (channel_pubkey TEXT, from_relay TEXT NOT NULL);
      CREATE TABLE transcript (session_id TEXT, blob BLOB);
    `);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const relaysIn = (sql: string): unknown => JSON.parse((db.prepare(sql).get() as { v: string }).v);

  it("rewrites every stored list a dial reads from", () => {
    const list = JSON.stringify([OLD, OTHER]);
    db.prepare("INSERT INTO sessions VALUES ('a', 's', 'seal_interrupted_pending', ?, 111)").run(list);
    db.prepare("INSERT INTO channel_config VALUES ('c', ?)").run(list);
    db.prepare("INSERT INTO channel_subscriptions VALUES ('a', 'c', ?)").run(list);
    db.prepare("INSERT INTO channel_join_requests VALUES ('a', 'c', ?)").run(list);

    migrateRetiredRelayDomain(db, capturing().logger);

    const expected = [NEW, OTHER];
    expect(relaysIn("SELECT relay_addrs v FROM sessions")).toEqual(expected);
    expect(relaysIn("SELECT relays v FROM channel_config")).toEqual(expected);
    expect(relaysIn("SELECT relays v FROM channel_subscriptions")).toEqual(expected);
    expect(relaysIn("SELECT relays v FROM channel_join_requests")).toEqual(expected);
  });

  it("rewrites sealed sessions too, because the mailbox pull and reservations read them", () => {
    db.prepare("INSERT INTO sessions VALUES ('a', 's', 'sealed', ?, 111)").run(JSON.stringify([OLD]));
    migrateRetiredRelayDomain(db, capturing().logger);
    expect(relaysIn("SELECT relay_addrs v FROM sessions")).toEqual([NEW]);
  });

  it("does not move updated_at, which decides which session's address is newest", () => {
    db.prepare("INSERT INTO sessions VALUES ('a', 's', 'sealed', ?, 111)").run(JSON.stringify([OLD]));
    migrateRetiredRelayDomain(db, capturing().logger);
    expect((db.prepare("SELECT updated_at u FROM sessions").get() as { u: number }).u).toBe(111);
  });

  it("leaves history alone: the transcript and where a post was collected from", () => {
    const said = Buffer.from(`we talked about ${OLD}`);
    db.prepare("INSERT INTO transcript VALUES ('s', ?)").run(said);
    db.prepare("INSERT INTO channel_inbox VALUES ('c', ?)").run(OLD);

    migrateRetiredRelayDomain(db, capturing().logger);

    const blob = (db.prepare("SELECT blob b FROM transcript").get() as { b: Uint8Array }).b;
    expect(Buffer.from(blob).equals(said)).toBe(true);
    expect((db.prepare("SELECT from_relay f FROM channel_inbox").get() as { f: string }).f).toBe(OLD);
  });

  it("leaves a malformed list as it found it, says so, and still fixes the good rows", () => {
    const { logger, events } = capturing();
    const broken = `not json ${OLD}`;
    db.prepare("INSERT INTO channel_config VALUES ('bad', ?)").run(broken);
    db.prepare("INSERT INTO channel_config VALUES ('good', ?)").run(JSON.stringify([OLD]));

    migrateRetiredRelayDomain(db, logger);

    expect((db.prepare("SELECT relays v FROM channel_config WHERE channel_pubkey = 'bad'").get() as { v: string }).v).toBe(broken);
    expect(relaysIn("SELECT relays v FROM channel_config WHERE channel_pubkey = 'good'")).toEqual([NEW]);
    const done = events.find((e) => e.event === "relay.domain.migration.completed");
    expect(done?.level).toBe("warn");
    expect(done?.context?.["malformed"]).toBe(1);
  });

  it("is safe to run on every start: a second run changes nothing and logs nothing", () => {
    db.prepare("INSERT INTO channel_config VALUES ('c', ?)").run(JSON.stringify([OLD]));
    migrateRetiredRelayDomain(db, capturing().logger);

    const second = capturing();
    migrateRetiredRelayDomain(db, second.logger);

    expect(second.events).toEqual([]);
    expect(relaysIn("SELECT relays v FROM channel_config")).toEqual([NEW]);
  });

  it("works on a database where a channel table does not exist yet", () => {
    db.exec("DROP TABLE channel_join_requests; DROP TABLE channel_subscriptions;");
    db.prepare("INSERT INTO channel_config VALUES ('c', ?)").run(JSON.stringify([OLD]));
    migrateRetiredRelayDomain(db, capturing().logger);
    expect(relaysIn("SELECT relays v FROM channel_config")).toEqual([NEW]);
  });

  it("keeps every row unchanged if the rewrite fails partway, then says so without stopping the daemon", () => {
    const { logger, events } = capturing();
    db.prepare("INSERT INTO channel_config VALUES ('c', ?)").run(JSON.stringify([OLD]));
    db.prepare("INSERT INTO channel_subscriptions VALUES ('a', 'c', ?)").run(JSON.stringify([OLD]));
    // channel_subscriptions is written after channel_config, so this fails with work already done.
    db.exec(`CREATE TRIGGER refuse BEFORE UPDATE ON channel_subscriptions BEGIN SELECT RAISE(ABORT, 'disk full'); END;`);

    expect(() => { migrateRetiredRelayDomain(db, logger); }).not.toThrow();

    expect(relaysIn("SELECT relays v FROM channel_config")).toEqual([OLD]);
    const failed = events.find((e) => e.event === "relay.domain.migration.failed");
    expect(failed?.level).toBe("error");
    expect(String(failed?.context?.["reason"])).toContain("disk full");
  });
});
