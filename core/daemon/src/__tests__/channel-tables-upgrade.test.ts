/**
 * M16 042-UPGRADE — the channel tables upgrade IN PLACE on a daemon that already has them.
 *
 * `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists, so every column added to
 * a channel table since its first commit never reached a daemon that created the table earlier. Live
 * on the Hermes box (daemon 0.0.252) this surfaced as `cello_channel_join` failing
 * `no such column: members_visible`. This suite recreates each table with its FIRST committed CREATE
 * SQL (inlined below, with the commit it came from), seeds one plausible row, then constructs the
 * store and exercises its main read AND write — all must succeed with no manual database step.
 *
 * Real SQLCipher DB. No mocks.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import { signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelConfigStore, CHANNEL_CONFIG_CREATE_SQL } from "../channel-config-store.js";
import { ChannelMembershipStore, CHANNEL_MEMBERS_CREATE_SQL } from "../channel-membership-store.js";
import { ChannelLogStore, CHANNEL_LOG_CREATE_SQL } from "../channel-log-store.js";
import { ChannelSubscriptionStore, CHANNEL_SUBSCRIPTION_CREATE_SQL } from "../channel-subscription-store.js";

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

// ─── FIRST committed CREATE SQL, inlined, so the guard below has a fixed baseline ───────────────

/** channel_config @798de4fb (018-PUBCOLLECT) — before members_visible, key_generation, admin_pubkey. */
const CHANNEL_CONFIG_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_config (
    channel_pubkey     TEXT    NOT NULL PRIMARY KEY,
    access             TEXT    NOT NULL,
    relays             TEXT    NOT NULL,
    guidance           TEXT    NOT NULL DEFAULT '',
    retention_seconds  INTEGER NOT NULL DEFAULT 604800,
    updated_at         INTEGER NOT NULL
  );
`;

/** channel_log @71f137a4 — the pre-posts epoch shape: no post_cbor; three NOT-NULL epoch columns. */
const CHANNEL_LOG_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_log (
    channel_pubkey   TEXT    NOT NULL,
    seq              INTEGER NOT NULL,
    epoch_index      INTEGER NOT NULL,
    leaf_hash        BLOB    NOT NULL,
    artifact_cbor    BLOB    NOT NULL,
    title            TEXT    NOT NULL,
    published_at     INTEGER NOT NULL,
    PRIMARY KEY (channel_pubkey, seq)
  );
  CREATE TABLE IF NOT EXISTS channel_epoch_state (
    channel_pubkey        TEXT    NOT NULL PRIMARY KEY,
    open_epoch_index      INTEGER NOT NULL,
    open_epoch_first_seq  INTEGER NOT NULL,
    open_epoch_opened_at  INTEGER NOT NULL,
    prev_epoch_root       BLOB,
    next_seq              INTEGER NOT NULL
  );
`;

/** channel_members @e38b2e0e (019-MEMBERSHIP) — unchanged since, so the guard passes trivially. */
const CHANNEL_MEMBERS_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_members (
    channel_pubkey     TEXT    NOT NULL,
    subscriber_pubkey  TEXT    NOT NULL,
    joined_at          INTEGER NOT NULL,
    status             TEXT    NOT NULL,
    PRIMARY KEY (channel_pubkey, subscriber_pubkey)
  );
`;

/** channel_subscriptions @a711d826 (018-PUBCOLLECT) — before guidance_updated_at. */
const CHANNEL_SUBSCRIPTIONS_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_subscriptions (
    agent_id           TEXT    NOT NULL,
    channel_pubkey     TEXT    NOT NULL,
    admin_pubkey       TEXT    NOT NULL,
    access             TEXT    NOT NULL,
    guidance           TEXT    NOT NULL DEFAULT '',
    retention_seconds  INTEGER NOT NULL DEFAULT 604800,
    relays             TEXT    NOT NULL DEFAULT '[]',
    moniker            TEXT    NOT NULL DEFAULT '',
    delivered_through  INTEGER NOT NULL DEFAULT 0,
    processed_through  INTEGER NOT NULL DEFAULT 0,
    joined_at          INTEGER NOT NULL DEFAULT 0,
    status             TEXT    NOT NULL DEFAULT 'active',
    PRIMARY KEY (agent_id, channel_pubkey)
  );
`;

let dir: string;
let db: DaemonDatabase;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-chan-upgrade-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

const CH = "aa".repeat(32);
const hasColumn = (table: string, col: string): boolean =>
  (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).some((c) => c.name === col);
const tableExists = (table: string): boolean =>
  (db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).get(table) as { name: string } | undefined) !== undefined;
const rowCount = (table: string): number =>
  Number((db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number | bigint }).n);

// ─── Part A — channel_config gains its three columns, whichever store opens first ───────────────

describe("042-UPGRADE Part A: channel_config gains members_visible, key_generation, admin_pubkey", () => {
  it("A1. ChannelConfigStore opened on a pre-columns table upgrades it, and reads the old row", () => {
    db.exec(CHANNEL_CONFIG_V1_SQL);
    db.prepare(
      `INSERT INTO channel_config (channel_pubkey, access, relays, guidance, retention_seconds, updated_at)
       VALUES (?, 'invite', '[]', 'an old channel', 604800, 111)`,
    ).run(CH);
    expect(hasColumn("channel_config", "members_visible")).toBe(false);

    const { logger } = capturing();
    const store = new ChannelConfigStore(db, logger);

    expect(hasColumn("channel_config", "members_visible")).toBe(true);
    expect(hasColumn("channel_config", "key_generation")).toBe(true);
    expect(hasColumn("channel_config", "admin_pubkey")).toBe(true);

    // READ the pre-existing row: the birthed columns default (members_visible false, admin '').
    const got = store.get(CH);
    expect(got).not.toBeNull();
    expect(got?.access).toBe("invite");
    expect(got?.members_visible).toBe(false);
    expect(got?.admin_pubkey).toBe("");

    // WRITE: set + get round-trips the new columns.
    store.set(CH, { access: "invite", relays: ["/relay/a"], guidance: "g", retention_seconds: 604800, members_visible: true, admin_pubkey: "bb".repeat(32) }, 222);
    const after = store.get(CH);
    expect(after?.members_visible).toBe(true);
    expect(after?.admin_pubkey).toBe("bb".repeat(32));
  });

  it("A2. ChannelMembershipStore opened FIRST on a pre-columns table also upgrades it, and settings + admit succeed", () => {
    db.exec(CHANNEL_CONFIG_V1_SQL);
    db.prepare(
      `INSERT INTO channel_config (channel_pubkey, access, relays, guidance, retention_seconds, updated_at)
       VALUES (?, 'invite', '[]', 'an old channel', 604800, 111)`,
    ).run(CH);

    const { logger } = capturing();
    // Membership store is the ONLY store constructed here — it must upgrade the shared table itself.
    const members = new ChannelMembershipStore(db, logger);

    expect(hasColumn("channel_config", "key_generation")).toBe(true);
    expect(hasColumn("channel_config", "admin_pubkey")).toBe(true);

    // READ: settings() selects key_generation + admin_pubkey — would throw "no such column" if unbuilt.
    const s = members.settings(CH);
    expect(s).not.toBeNull();
    expect(s?.key_generation).toBe(0);

    // WRITE: putSettings then admit a member.
    members.putSettings(CH, { access: "invite", members_visible: true, guidance: "g", retention_seconds: 604800, relays: ["/relay/a"], admin_pubkey: "bb".repeat(32) });
    members.admit(CH, "cc".repeat(32), "active", 333);
    expect(members.activeMembers(CH)).toEqual(["cc".repeat(32)]);
  });
});

// ─── Part B — a pre-posts channel_log is retired, not patched ───────────────────────────────────

describe("042-UPGRADE Part B: a pre-posts channel_log is retired and recreated", () => {
  it("B1. an epoch-shaped channel_log (no post_cbor) is renamed aside, its bytes kept, and the store then works", async () => {
    db.exec(CHANNEL_LOG_V1_SQL);
    db.prepare(
      `INSERT INTO channel_log (channel_pubkey, seq, epoch_index, leaf_hash, artifact_cbor, title, published_at)
       VALUES (?, 1, 0, ?, ?, 'old post', 999)`,
    ).run(CH, Buffer.from([1, 2, 3]), Buffer.from([4, 5, 6]));
    expect(hasColumn("channel_log", "post_cbor")).toBe(false);

    const { logger, events } = capturing();
    const store = new ChannelLogStore(db, logger);

    // The old bytes are kept under the retired name; the current table now has post_cbor.
    expect(tableExists("channel_log_epoch_retired")).toBe(true);
    expect(rowCount("channel_log_epoch_retired")).toBe(1);
    expect(hasColumn("channel_log", "post_cbor")).toBe(true);
    const retired = events.find((e) => e.event === "channel.log.legacy_retired");
    expect(retired?.context?.rows).toBe(1);

    // WRITE + READ against the recreated table: a real signed post appends and reads back.
    const kp = generateKeypair();
    const agent = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    store.ensureChannel(hex);
    const post = await signBroadcastArtifact(kp, agent, {
      seq: 1, published_at: 1_789_000_000_001, title: "new post",
      body: new Uint8Array([9, 9]), supersedes: null, ext: null,
    });
    store.append(hex, post);
    expect(store.head(hex)).toEqual({ first_seq: 1, last_seq: 1, pruned_through: 0 });
  });
});

// ─── Part C — channel_subscriptions gains guidance_updated_at (already wired at 2393f264) ───────

describe("042-UPGRADE Part C: channel_subscriptions gains guidance_updated_at", () => {
  it("C1. a pre-column subscriptions table is upgraded on open, and upsert + get round-trip", () => {
    db.exec(CHANNEL_SUBSCRIPTIONS_V1_SQL);
    db.prepare(
      `INSERT INTO channel_subscriptions (agent_id, channel_pubkey, admin_pubkey, access)
       VALUES ('agent-1', ?, ?, 'invite')`,
    ).run(CH, "bb".repeat(32));
    expect(hasColumn("channel_subscriptions", "guidance_updated_at")).toBe(false);

    const { logger } = capturing();
    const store = new ChannelSubscriptionStore(db, logger);
    expect(hasColumn("channel_subscriptions", "guidance_updated_at")).toBe(true);

    // READ the pre-existing row: the birthed column defaults to 0.
    const old = store.get("agent-1", CH);
    expect(old?.guidance_updated_at).toBe(0);

    // WRITE: upsert then get round-trips.
    store.upsert({ agent_id: "agent-2", channel_pubkey: CH, admin_pubkey: "bb".repeat(32), access: "invite", relays: ["/relay/a"] });
    const got = store.get("agent-2", CH);
    expect(got?.access).toBe("invite");
    expect(got?.relays).toEqual(["/relay/a"]);
  });
});

// ─── MUST NOT CHANGE ────────────────────────────────────────────────────────────────────────────

describe("042-UPGRADE: invariants that must not change", () => {
  it("I1. a fresh DB gets exactly today's schema, with no retired table", () => {
    const { logger } = capturing();
    new ChannelConfigStore(db, logger);
    new ChannelLogStore(db, logger);
    new ChannelSubscriptionStore(db, logger);
    expect(hasColumn("channel_config", "members_visible")).toBe(true);
    expect(hasColumn("channel_config", "admin_pubkey")).toBe(true);
    expect(hasColumn("channel_log", "post_cbor")).toBe(true);
    expect(hasColumn("channel_subscriptions", "guidance_updated_at")).toBe(true);
    expect(tableExists("channel_log_epoch_retired")).toBe(false);
  });

  it("I2. an already-current channel_log is not renamed and keeps its row", () => {
    const { logger } = capturing();
    new ChannelLogStore(db, logger); // creates the current table
    db.prepare(
      `INSERT INTO channel_log (channel_pubkey, seq, published_at, title, post_cbor)
       VALUES (?, 1, 5, 't', ?)`,
    ).run(CH, Buffer.from([1]));

    const { logger: l2, events } = capturing();
    new ChannelLogStore(db, l2); // opening again must be a no-op
    expect(tableExists("channel_log_epoch_retired")).toBe(false);
    expect(rowCount("channel_log")).toBe(1);
    expect(events.some((e) => e.event === "channel.log.legacy_retired")).toBe(false);
  });

  it("I3. opening every store twice is a no-op (no throw, no duplicate columns)", () => {
    const { logger } = capturing();
    new ChannelConfigStore(db, logger);
    new ChannelMembershipStore(db, logger);
    new ChannelLogStore(db, logger);
    new ChannelSubscriptionStore(db, logger);
    expect(() => {
      new ChannelConfigStore(db, logger);
      new ChannelMembershipStore(db, logger);
      new ChannelLogStore(db, logger);
      new ChannelSubscriptionStore(db, logger);
    }).not.toThrow();
    const cols = (db.prepare(`PRAGMA table_info(channel_config)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(new Set(cols).size).toBe(cols.length); // no duplicates
  });
});

// ─── The class is pinned: no channel table's CREATE SQL may gain an unhandled column ────────────

/**
 * Extract the column names from one `CREATE TABLE IF NOT EXISTS <table> (...)` block, ignoring
 * comments and table-level constraints (PRIMARY KEY (...), etc.). Paren-balanced so a
 * `PRIMARY KEY (a, b)` line does not end the block early.
 */
function tableColumns(sql: string, table: string): string[] {
  const marker = `CREATE TABLE IF NOT EXISTS ${table} (`;
  const start = sql.indexOf(marker);
  if (start === -1) throw new Error(`no CREATE TABLE for ${table}`);
  const open = start + marker.length - 1;
  let depth = 0;
  let end = -1;
  for (let j = open; j < sql.length; j++) {
    if (sql[j] === "(") depth++;
    else if (sql[j] === ")") { depth--; if (depth === 0) { end = j; break; } }
  }
  if (end === -1) throw new Error(`unbalanced CREATE TABLE for ${table}`);
  const cols: string[] = [];
  for (const raw of sql.slice(open + 1, end).split("\n")) {
    const line = raw.replace(/--.*$/, "").trim();
    if (!line) continue;
    const token = line.split(/[\s(,]/)[0];
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(token)) continue;
    if (["PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"].includes(token.toUpperCase())) continue;
    cols.push(token);
  }
  return cols;
}

/** Columns an `addColumnIfMissing`/`ALTER … ADD COLUMN` call in a store's source upgrades in place. */
function addColumnNames(sourceRelPath: string): string[] {
  const text = readFileSync(fileURLToPath(new URL(sourceRelPath, import.meta.url)), "utf8");
  return [...text.matchAll(/ADD COLUMN\s+(\w+)/g)].map((m) => m[1]);
}

describe("042-UPGRADE Part C guard: a channel table's CREATE SQL cannot gain an unhandled column", () => {
  // Reading the CURRENT constants keeps the guard honest — it compares live schema, not a copy.
  const cases: Array<{
    label: string;
    table: string;
    currentSql: string;
    firstVersionSql: string;
    source: string;
    /** Columns handled by a mechanism other than addColumnIfMissing. channel_log is upgraded by
     * RETIREMENT keyed on post_cbor's absence, so post_cbor is its sentinel; ANY further new column
     * would slip past that check and this guard forces the next author to handle it. */
    sentinels: string[];
  }> = [
    { label: "channel_config", table: "channel_config", currentSql: CHANNEL_CONFIG_CREATE_SQL, firstVersionSql: CHANNEL_CONFIG_V1_SQL, source: "../channel-config-store.ts", sentinels: [] },
    { label: "channel_log", table: "channel_log", currentSql: CHANNEL_LOG_CREATE_SQL, firstVersionSql: CHANNEL_LOG_V1_SQL, source: "../channel-log-store.ts", sentinels: ["post_cbor"] },
    { label: "channel_members", table: "channel_members", currentSql: CHANNEL_MEMBERS_CREATE_SQL, firstVersionSql: CHANNEL_MEMBERS_V1_SQL, source: "../channel-membership-store.ts", sentinels: [] },
    { label: "channel_subscriptions", table: "channel_subscriptions", currentSql: CHANNEL_SUBSCRIPTION_CREATE_SQL, firstVersionSql: CHANNEL_SUBSCRIPTIONS_V1_SQL, source: "../channel-subscription-store.ts", sentinels: [] },
  ];

  for (const c of cases) {
    it(`${c.label}: every current column is in the first-version SQL, an addColumnIfMissing call, or a documented sentinel`, () => {
      const current = tableColumns(c.currentSql, c.table);
      const covered = new Set([...tableColumns(c.firstVersionSql, c.table), ...addColumnNames(c.source), ...c.sentinels]);
      const unhandled = current.filter((col) => !covered.has(col));
      expect(unhandled, `${c.label} has column(s) with no upgrade path — add an addColumnIfMissing for them (042-UPGRADE)`).toEqual([]);
    });
  }
});
