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
import { mkdtempSync, rmSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import { signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelConfigStore } from "../channel-config-store.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";

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

/** channel_inbox @dceb84af (021-WAKE) — born complete; unchanged since. */
const CHANNEL_INBOX_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_inbox (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    seq             INTEGER NOT NULL,
    post_hash       TEXT    NOT NULL,
    post_cbor       BLOB    NOT NULL,
    receipt_cbor    BLOB,
    from_relay      TEXT    NOT NULL,
    collected_at    INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey, seq, post_hash)
  );
`;

/** channel_state @3e5d9c4d (016-CLIENTREWORK) — born with the post log; unchanged since. */
const CHANNEL_STATE_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_state (
    channel_pubkey   TEXT    NOT NULL PRIMARY KEY,
    next_seq         INTEGER NOT NULL,
    pruned_through   INTEGER NOT NULL DEFAULT 0
  );
`;

/** channel_log_receipts @3e5d9c4d (016-CLIENTREWORK) — born with the post log; unchanged since. */
const CHANNEL_LOG_RECEIPTS_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_log_receipts (
    channel_pubkey   TEXT    NOT NULL,
    seq              INTEGER NOT NULL,
    relay_pubkey     TEXT    NOT NULL,
    received_at      INTEGER NOT NULL,
    receipt_cbor     BLOB    NOT NULL,
    PRIMARY KEY (channel_pubkey, seq, relay_pubkey)
  );
`;

/** channel_subscription_keys @581b0560 (019-MEMBERSHIP) — born complete; unchanged since. */
const CHANNEL_SUBSCRIPTION_KEYS_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_subscription_keys (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    generation      INTEGER NOT NULL,
    key             BLOB    NOT NULL,
    received_at     INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey, generation)
  );
`;

/** channel_poster_passes (043-POSTERS) — born complete. */
const CHANNEL_POSTER_PASSES_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_poster_passes (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    pass_cbor       BLOB    NOT NULL,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey)
  );
`;

/** channel_notice_seen (045-NOTICEBELL) — born complete. */
const CHANNEL_NOTICE_SEEN_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_notice_seen (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    type            TEXT    NOT NULL,
    issued_at       INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey, type)
  );
`;

/** channel_lane_positions (043-POSTERS) — born complete. */
const CHANNEL_LANE_POSITIONS_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_lane_positions (
    agent_id           TEXT    NOT NULL,
    channel_pubkey     TEXT    NOT NULL,
    lane_poster        TEXT    NOT NULL,
    delivered_through  INTEGER NOT NULL DEFAULT 0,
    processed_through  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, channel_pubkey, lane_poster)
  );
`;

/** channel_poster_grants (043-POSTERS) — born complete. */
const CHANNEL_POSTER_GRANTS_V1_SQL = `
  CREATE TABLE IF NOT EXISTS channel_poster_grants (
    channel_pubkey  TEXT    NOT NULL,
    poster_pubkey   TEXT    NOT NULL,
    issued_at       INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL DEFAULT 0,
    revoked_at      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_pubkey, poster_pubkey)
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
  const m = new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\s*\\(`).exec(sql);
  if (!m) throw new Error(`no CREATE TABLE for ${table}`);
  const open = m.index + m[0].length - 1; // the opening paren
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

/**
 * Every `CREATE TABLE IF NOT EXISTS channel_*` the daemon ships, DISCOVERED from source rather than
 * hand-listed. A hand-written list only ever gets shorter when someone forgets a table, and a
 * shorter list is never red — which is the whole failure mode this guard exists to stop. So the set
 * of tables to check is derived: only the CURRENT source can add a table, and adding one with no
 * baseline below fails the test until its first-version SQL is recorded.
 *
 * Scans `core/daemon/src/channel-*.ts` (top level only — the __tests__ baselines below are not
 * daemon source). Returns each table's current column set and the file its CREATE lives in.
 */
const DAEMON_SRC = dirname(dirname(fileURLToPath(import.meta.url)));

function discoverChannelTables(): Map<string, { columns: string[]; file: string }> {
  const found = new Map<string, { columns: string[]; file: string }>();
  const files = readdirSync(DAEMON_SRC).filter((f) => /^channel-.*\.ts$/.test(f));
  for (const f of files) {
    const text = readFileSync(join(DAEMON_SRC, f), "utf8");
    for (const m of text.matchAll(/CREATE TABLE IF NOT EXISTS (channel_[a-z_]+)\s*\(/g)) {
      const table = m[1];
      if (found.has(table)) continue; // a re-exported constant can appear in two files; first wins
      found.set(table, { columns: tableColumns(text, table), file: f });
    }
  }
  return found;
}

/**
 * Every column any `ALTER TABLE <table> ADD COLUMN <col>` upgrades in place, across all channel
 * source — mapped by table, so a birth in one file covers a CREATE in another (channel_config's
 * births live with its store; ChannelMembershipStore only calls them).
 */
function allAddColumns(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const f of readdirSync(DAEMON_SRC).filter((x) => /^channel-.*\.ts$/.test(x))) {
    const text = readFileSync(join(DAEMON_SRC, f), "utf8");
    for (const m of text.matchAll(/ALTER TABLE\s+(\w+)\s+ADD COLUMN\s+(\w+)/g)) {
      if (!out.has(m[1])) out.set(m[1], new Set());
      out.get(m[1])!.add(m[2]);
    }
  }
  return out;
}

/**
 * The first committed CREATE SQL for every channel table (inlined, with the commit it came from).
 * A table discovered from source with NO entry here fails its test — which forces whoever adds a
 * new channel table to record its baseline, so the class can never quietly grow past this guard.
 *
 * `sentinels`: columns covered by an upgrade mechanism OTHER than addColumnIfMissing. channel_log is
 * upgraded by RETIREMENT keyed on `post_cbor`'s absence (Part B), so `post_cbor` is its sentinel;
 * ANY further new column on channel_log would slip past that check, so it is deliberately NOT
 * sentinel'd and this guard forces the next author to handle it.
 */
const BASELINES: Record<string, { firstVersionSql: string; sentinels: string[] }> = {
  channel_config: { firstVersionSql: CHANNEL_CONFIG_V1_SQL, sentinels: [] },
  channel_log: { firstVersionSql: CHANNEL_LOG_V1_SQL, sentinels: ["post_cbor"] },
  channel_members: { firstVersionSql: CHANNEL_MEMBERS_V1_SQL, sentinels: [] },
  channel_subscriptions: { firstVersionSql: CHANNEL_SUBSCRIPTIONS_V1_SQL, sentinels: [] },
  channel_inbox: { firstVersionSql: CHANNEL_INBOX_V1_SQL, sentinels: [] },
  channel_state: { firstVersionSql: CHANNEL_STATE_V1_SQL, sentinels: [] },
  channel_log_receipts: { firstVersionSql: CHANNEL_LOG_RECEIPTS_V1_SQL, sentinels: [] },
  channel_subscription_keys: { firstVersionSql: CHANNEL_SUBSCRIPTION_KEYS_V1_SQL, sentinels: [] },
  // 043-POSTERS: three new tables, each born complete.
  channel_poster_passes: { firstVersionSql: CHANNEL_POSTER_PASSES_V1_SQL, sentinels: [] },
  channel_lane_positions: { firstVersionSql: CHANNEL_LANE_POSITIONS_V1_SQL, sentinels: [] },
  channel_poster_grants: { firstVersionSql: CHANNEL_POSTER_GRANTS_V1_SQL, sentinels: [] },
  // 045-NOTICEBELL: the newest notice each agent applied, per (channel, type) — born complete.
  channel_notice_seen: { firstVersionSql: CHANNEL_NOTICE_SEEN_V1_SQL, sentinels: [] },
};

describe("042-UPGRADE Part C guard: no channel table's CREATE SQL can gain an unhandled column", () => {
  const discovered = discoverChannelTables();
  const alters = allAddColumns();

  it("the daemon still ships channel tables (the scan found some)", () => {
    expect(discovered.size).toBeGreaterThan(0);
  });

  for (const [table, { columns, file }] of discovered) {
    it(`${table} (${file}): every current column is in its first-version baseline, an ADD COLUMN, or a sentinel`, () => {
      const baseline = BASELINES[table];
      expect(
        baseline,
        `${table} has no first-version baseline in this test — record its first committed CREATE SQL (042-UPGRADE)`,
      ).toBeDefined();
      const covered = new Set([
        ...tableColumns(baseline.firstVersionSql, table),
        ...(alters.get(table) ?? new Set<string>()),
        ...baseline.sentinels,
      ]);
      const unhandled = columns.filter((col) => !covered.has(col));
      expect(
        unhandled,
        `${table} has column(s) with no upgrade path — add an addColumnIfMissing for them (042-UPGRADE)`,
      ).toEqual([]);
    });
  }
});
