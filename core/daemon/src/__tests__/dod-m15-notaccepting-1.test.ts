/**
 * DOD-M15-NOTACCEPTING-1 — a tier can be SHUT, and the caller is told.
 *
 * ─── The defect, from the operator's chair ─────────────────────────────────────────────────────
 *
 * An operator could not shut a tier at all. `bounds.<tier>.max_sessions 0` was refused by the
 * validator, and a 0 that reached the store anyway was reverted to the grid default by the READER,
 * with a warning nobody was reading. So the operator set the control, was told it was saved, saw it
 * read back — and was still reachable. Fixing only the validator leaves that second guard in place,
 * which is why every assertion here goes through `resolveTierBound` rather than stopping at
 * `validateSettingValue`.
 *
 * ─── And from the CALLER's chair, which is the half that cost 30 seconds a knock ───────────────
 *
 * A stranger refused by a shut tier was told NOTHING. Their own daemon then waited 30 seconds and
 * reported `timeout` — *"the directory did not return a session assignment; retry once cello status
 * shows directory_signaling connected"*. That blames the wrong machine and instructs a retry that
 * can never succeed. The frames are asserted in `m8c-away-1.test.ts`, beside the cap refusal they
 * share a branch with; this file covers the settings, the reader, the gate and the knock record.
 *
 * ─── What the operator types (D1/D2a, ruled 2026-09-22) ───────────────────────────────────────
 *
 * A bound of 0 is NOT settable by hand on either field — it is refused, naming the remedy. The ONLY
 * producer of a zero is the mark, `bounds.<tier>.not_accepting true`, which writes both zeros with
 * it in one transaction. `true` shuts the tier, so the word typed is the word intended; `accepting
 * false` was rejected as the double negative an operator shuts the wrong tier with.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER, DEFAULT_TIER_BOUNDS } from "../contact-tier.js";
import {
  boundSettingKey, notAcceptingSettingKey, isBoundKey, validateSettingValue,
} from "../agent-settings-keys.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import { registerContactHandlers } from "../contact-handlers.js";
import type { IpcHandler } from "../ipc-server.js";
import { registerNotificationHandlers } from "../notification-handlers.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> {
    return {
      getPeerId: () => "stub", listenAddresses: () => ["/ip4/127.0.0.1/tcp/0"],
      async start() {}, async stop() {}, async dial() { return { peerId: "remote" }; },
      async handle() {}, getProtocols: () => [], getConnections: () => [],
      onPeerConnect() {}, onPeerDisconnect() {},
      getDialability: () => ({ dialable: false, publicAddr: null }),
      onDialabilityChange: () => () => {},
      async newStream() { return { send() {}, async close() {}, abort() {}, status: "open" }; },
    } as unknown as CelloNode;
  }
}

function setTier(db: DaemonDatabase, agentId: string, pubkey: string, tier: number): void {
  db.prepare("INSERT OR REPLACE INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, ?)")
    .run(agentId, pubkey, Date.now(), tier);
}

describe("DOD-M15-NOTACCEPTING-1 — what the operator is allowed to type", () => {
  it("★ a bound of 0 is REFUSED on both fields, and the refusal names the remedy", () => {
    for (const field of ["max_sessions", "max_bytes"] as const) {
      const v = validateSettingValue(boundSettingKey("unknown", field), "0");
      expect(v.ok, `${field} 0 must be refused — a bare zero admits or starves, never shuts`).toBe(false);
      // An affordance, not a verdict: the operator wanting a shut tier must be told what to type.
      expect((v as { reason: string }).reason).toContain("not_accepting");
    }
  });

  it("★ the mark is a BOOLEAN key, and it is not read as a bound", () => {
    const key = notAcceptingSettingKey("unknown");
    // THE TRAP: `isBoundKey` matched anything starting `bounds.`, so this key would have been
    // validated as an integer and refused on BOTH spellings — the control would not exist at all.
    expect(isBoundKey(key), "the mark must not be validated as an integer").toBe(false);
    expect(validateSettingValue(key, "true").ok).toBe(true);
    expect(validateSettingValue(key, "false").ok).toBe(true);
    // The RELAY_ONLY_KEY trap, verbatim: everything that is not a bound key falls through to
    // away-text validation, which accepts any non-empty string. Without its own branch BEFORE that
    // fallback, "flase" stores successfully and reads as not-"true" forever — the operator shuts
    // the tier, is told it was saved, and is still reachable.
    for (const bad of ["flase", "yes", "1", "TRUE", "", " true"]) {
      expect(validateSettingValue(key, bad).ok, bad).toBe(false);
    }
  });
});

describe("DOD-M15-NOTACCEPTING-1 — the mark, the reader, and the gate", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let alice: string;
  let dbPath: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-notacc-"));
    dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    alice = (await seedAgents(seed, ["alice"])).get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("★ DoD 1 — a zero written by the mark READS BACK AS 0, through the reader", () => {
    // The production defect was the SECOND guard: `resolveTierBound` treated a stored <= 0 as
    // corrupt and returned the grid default. A test that stops at the validator cannot see it.
    mgr.setTierNotAccepting("alice", "unknown", true);
    expect(mgr.resolveTierBound("alice", TIER.UNKNOWN, "max_sessions")).toBe(0);
    expect(mgr.resolveTierBound("alice", TIER.UNKNOWN, "max_bytes")).toBe(0);
  });

  it("★ a genuinely corrupt bound still reverts to the default — the reader's guard is narrowed, not removed", () => {
    for (const corrupt of ["-1", "abc", "Infinity", "NaN"]) {
      mgr.setSetting("alice", boundSettingKey("known", "max_sessions"), corrupt);
      expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions"), corrupt)
        .toBe(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxSessionsPerSender);
    }
  });

  it("★ DoD 2 — the mark writes both zeros, and clearing it returns the GRID DEFAULT", () => {
    mgr.setTierNotAccepting("alice", "known", true);
    expect(mgr.isTierNotAccepting("alice", TIER.KNOWN)).toBe(true);
    expect(mgr.getSetting("alice", notAcceptingSettingKey("known"))).toBe("true");

    mgr.setTierNotAccepting("alice", "known", false);
    expect(mgr.isTierNotAccepting("alice", TIER.KNOWN)).toBe(false);
    // "Does not invent numbers" — the overrides are GONE, not rewritten to some remembered value.
    expect(mgr.getSetting("alice", boundSettingKey("known", "max_sessions"))).toBeNull();
    expect(mgr.getSetting("alice", boundSettingKey("known", "max_bytes"))).toBeNull();
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions"))
      .toBe(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxSessionsPerSender);
  });

  it("★ D2b — re-opening may carry a non-zero number in the same gesture", () => {
    mgr.setTierNotAccepting("alice", "known", true);
    mgr.setTierNotAccepting("alice", "known", false, 9);
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions")).toBe(9);
    expect(mgr.isTierNotAccepting("alice", TIER.KNOWN)).toBe(false);
  });

  it("★ DoD 3 — `blocked` reports not-accepting with NOTHING stored", () => {
    expect(mgr.getSetting("alice", "bounds.blocked.not_accepting")).toBeNull();
    expect(mgr.isTierNotAccepting("alice", TIER.BLOCKED)).toBe(true);
  });

  it("★ D2c — the MARK wins at the ACCEPTANCE GATE, not only where the message is chosen", () => {
    const stranger = "aa".repeat(32);
    mgr.setTierNotAccepting("alice", "unknown", true);
    // Drift, forced directly past the setter that refuses it: the mark is set and a non-zero cap
    // is stored. A gate that read only the number would start accepting again, and the mark would
    // be decoration. Assert the refusal, not the wording.
    mgr.setSetting("alice", boundSettingKey("unknown", "max_sessions"), "5");
    expect(mgr.resolveTierBound("alice", TIER.UNKNOWN, "max_sessions")).toBe(5);
    expect(mgr.isTierNotAccepting("alice", TIER.UNKNOWN)).toBe(true);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", stranger)).toMatchObject({ ok: false });
  });

  it("★ DoD 6 — a WHITELISTED contact still gets through with every other tier shut (D7)", () => {
    const friend = "bb".repeat(32);
    setTier(db, alice, friend, TIER.WHITELISTED);
    for (const t of ["unknown", "known", "vip"] as const) mgr.setTierNotAccepting("alice", t, true);
    expect(mgr.isTierNotAccepting("alice", TIER.WHITELISTED)).toBe(false);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", friend)).toEqual({ ok: true });
    // And the shut tiers really are shut — otherwise the line above proves nothing.
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", "cc".repeat(32))).toMatchObject({ ok: false });
  });

  it("★ DoD 7 — a KNOWN sender over a NON-ZERO cap is unaffected: still the cap refusal", () => {
    const friend = "dd".repeat(32);
    setTier(db, alice, friend, TIER.KNOWN);
    const now = Date.now();
    for (let i = 0; i < DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxSessionsPerSender; i++) {
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
      ).run(("a" + i.toString(16)).padStart(32, "0"), alice, friend, now, now);
    }
    expect(mgr.isTierNotAccepting("alice", TIER.KNOWN)).toBe(false);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", friend))
      .toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" });
  });
});

describe("DOD-M15-NOTACCEPTING-1 — D10, the knock record", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let dbPath: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-knock-"));
    dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    await seedAgents(seed, ["alice"]);
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("★ one row per CALLER, with a count — not one row per knock", () => {
    const caller = "11".repeat(32);
    mgr.recordKnock("alice", caller, "not_accepting_connections");
    mgr.recordKnock("alice", caller, "not_accepting_connections");
    mgr.recordKnock("alice", caller, "not_accepting_connections");
    const rows = mgr.listKnocks("alice");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.counterparty_pubkey).toBe(caller);
    expect(rows[0]!.times).toBe(3);
    expect(rows[0]!.first_refused_at).toBeLessThanOrEqual(rows[0]!.last_refused_at);
  });

  it("★ a FLOODER evicts nobody — the key is the anti-spam control, not a row cap", () => {
    /**
     * The shape this exists to stop: the durable refused-SESSION table is keyed on session id, and
     * every knock carries a fresh directory-assigned one, so a flooder does not merely fill it —
     * they push every genuine caller off it while the list still looks complete. Keyed on the
     * caller, volume adds no rows.
     */
    const genuine = "22".repeat(32);
    mgr.recordKnock("alice", genuine, "not_accepting_connections");
    const flooder = "33".repeat(32);
    for (let i = 0; i < 1_000; i++) mgr.recordKnock("alice", flooder, "not_accepting_connections");
    const rows = mgr.listKnocks("alice");
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.counterparty_pubkey === genuine), "the one caller the operator wanted back")
      .toBeDefined();
    expect(rows.find((r) => r.counterparty_pubkey === flooder)!.times).toBe(1_000);
  });

  it("★ it SURVIVES A RESTART — the in-memory list did not, and that was the whole gap", async () => {
    const caller = "44".repeat(32);
    mgr.recordKnock("alice", caller, "not_accepting_connections");
    await mgr.stop?.();
    const again = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await again.initialize();
    try {
      const rows = again.listKnocks("alice");
      expect(rows, "who knocked must outlive the process that heard it").toHaveLength(1);
      expect(rows[0]!.times).toBe(1);
    } finally {
      await again.stop?.();
    }
  });
});

describe("DOD-M15-NOTACCEPTING-1 — what the handler does with it", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let call: (name: string, params?: Record<string, unknown>) => Promise<Record<string, unknown>>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-notacc-h-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    await seedAgents(seed, ["alice"]);
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    // The REAL store, not a stub: the property under test is that one command leaves a CONSISTENT
    // tier, and a stub that records calls cannot show three keys landing together.
    const handlers = new Map<string, IpcHandler>();
    registerContactHandlers({
      handlers,
      sessionNodeManager: mgr,
      getConnState: () => ({ currentAgent: "alice" }),
      resolveCurrentAgent: (cs, explicit) => explicit ?? cs?.currentAgent ?? null,
      agents: [{ name: "alice", state: "online" as const }],
      setAgentMoniker: () => true,
      logger: silent,
      startTelegramPollerIfConfigured: () => {},
    } as unknown as Parameters<typeof registerContactHandlers>[0]);
    call = (name, params) => handlers.get(name)!(params, "conn-1") as Promise<Record<string, unknown>>;
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("★ a 0 typed at the tool is refused, and the refusal tells the operator what to type instead", async () => {
    const res = await call("cello_settings_set", { key: boundSettingKey("unknown", "max_sessions"), value: "0" });
    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("invalid_value");
    expect(String(res["guidance"])).toContain("bounds.unknown.not_accepting");
    // And it changed nothing — a refusal that half-applied would be the worst of both.
    expect(mgr.resolveTierBound("alice", TIER.UNKNOWN, "max_sessions")).toBe(DEFAULT_TIER_BOUNDS[TIER.UNKNOWN].maxSessionsPerSender);
  });

  it("★ ONE command shuts the tier — all three keys land, so a half-shut tier cannot be produced", async () => {
    const res = await call("cello_settings_set", { key: notAcceptingSettingKey("unknown"), value: "true" });
    expect(res["ok"]).toBe(true);
    expect(mgr.resolveTierBound("alice", TIER.UNKNOWN, "max_sessions")).toBe(0);
    expect(mgr.resolveTierBound("alice", TIER.UNKNOWN, "max_bytes")).toBe(0);
    expect(mgr.isTierNotAccepting("alice", TIER.UNKNOWN)).toBe(true);
    // The response tells the operator what callers will now hear — the control is not silent about
    // what it did on their behalf.
    expect(String(res["guidance"])).toContain("not accepting connections");
  });

  it("★ D2c: a number cannot re-open a shut tier — it is refused, naming the gesture that does", async () => {
    await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "true" });
    const res = await call("cello_settings_set", { key: boundSettingKey("known", "max_sessions"), value: "5" });
    expect(res["ok"], "a limit on a shut tier would read as re-opening it").toBe(false);
    expect(res["reason"]).toBe("tier_not_accepting");
    expect(String(res["guidance"])).toContain("not_accepting");
    // The tier is still shut. A refusal that left the mark cleared would be the drift D2c prevents.
    expect(mgr.isTierNotAccepting("alice", TIER.KNOWN)).toBe(true);
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions")).toBe(0);
  });

  it("★ re-opening takes a number in the same gesture, or the built-in default without one", async () => {
    await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "true" });
    const withNumber = await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "false", max_sessions: 9 });
    expect(withNumber["ok"]).toBe(true);
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions")).toBe(9);

    await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "true" });
    await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "false" });
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions")).toBe(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxSessionsPerSender);

    // A 0 offered as the re-open number is refused rather than re-shutting the tier inside the
    // command that re-opens it.
    await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "true" });
    const zero = await call("cello_settings_set", { key: notAcceptingSettingKey("known"), value: "false", max_sessions: 0 });
    expect(zero["ok"]).toBe(false);
    expect(mgr.isTierNotAccepting("alice", TIER.KNOWN), "a refused re-open leaves the tier shut").toBe(true);
  });

  it("★ CLEARING the mark re-opens the tier — it does not leave the two zeros behind", async () => {
    /**
     * The failure this pins: a plain delete of the mark row would report the setting cleared, show
     * nothing set for the tier on the next `settings get`, and still refuse every caller — from two
     * rows the operator never typed and can no longer see the cause of.
     */
    await call("cello_settings_set", { key: notAcceptingSettingKey("vip"), value: "true" });
    const res = await call("cello_settings_set", { key: notAcceptingSettingKey("vip"), value: null });
    expect(res["ok"]).toBe(true);
    expect(res["cleared"]).toBe(true);
    expect(mgr.isTierNotAccepting("alice", TIER.VIP)).toBe(false);
    expect(mgr.resolveTierBound("alice", TIER.VIP, "max_sessions")).toBe(DEFAULT_TIER_BOUNDS[TIER.VIP].maxSessionsPerSender);
    expect(mgr.resolveTierBound("alice", TIER.VIP, "max_bytes")).toBe(DEFAULT_TIER_BOUNDS[TIER.VIP].maxBytesPerSession);
  });
});

describe("DOD-M15-NOTACCEPTING-1 — the inbox notice names a door that is actually open", () => {
  /**
   * The review finding, pinned. The command was hardcoded to tier 3, so an operator who had also
   * shut the whitelisted tier would follow it exactly and drop the caller into a second shut tier —
   * still unreachable, and the notice would have told them it was enough.
   */
  let tempDir: string;
  let mgr: SessionNodeManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-notacc-n-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    await seedAgents(seed, ["alice"]);
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    mgr.recordKnock("alice", "77".repeat(32), "not_accepting_connections");
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  const notice = async (): Promise<string> => {
    const handlers = new Map<string, IpcHandler>();
    registerNotificationHandlers({
      handlers,
      sessionNodeManager: mgr,
      getConnState: () => ({ currentAgent: "alice" }),
      resolveCurrentAgent: (cs: { currentAgent?: string } | undefined, explicit?: string) => explicit ?? cs?.currentAgent ?? null,
      agents: [{ name: "alice", state: "online" as const }],
      loadedAgents: [{ name: "alice", pubkey: "aa".repeat(32) }],
      reapExpiredInboundSessions: () => {},
      inboundSessionQueues: new Map(),
      expiredSessionRequests: new Map(),
      refusedSessionRequests: new Map(),
      logger: silent,
    } as unknown as Parameters<typeof registerNotificationHandlers>[0]);
    const res = await handlers.get("cello_check_notifications")!({}, "conn-1") as Record<string, unknown>;
    // The door answers per agent, so the knocks ride on this agent's section, not the envelope.
    const section = (res["agents"] as Array<Record<string, unknown>>).find((a) => a["agent"] === "alice")!;
    const knocks = section["knocks"] as Array<{ notice: string }>;
    expect(knocks, "a turned-away caller must be listed").toHaveLength(1);
    return knocks[0]!.notice;
  };

  it("★ it names the highest tier still ACCEPTING, not a fixed one", async () => {
    mgr.setTierNotAccepting("alice", "unknown", true);
    mgr.setTierNotAccepting("alice", "vip", true);
    // VIP is shut, so the advice must drop to whitelisted rather than name a shut door.
    expect(await notice()).toContain(`tier: ${TIER.WHITELISTED}`);
    mgr.setTierNotAccepting("alice", "whitelisted", true);
    expect(await notice()).toContain(`tier: ${TIER.KNOWN}`);
  });

  it("★ with EVERY tier shut it says raising them would not help — no command that resolves to nothing", async () => {
    for (const t of ["unknown", "known", "whitelisted", "vip"] as const) mgr.setTierNotAccepting("alice", t, true);
    const text = await notice();
    expect(text).not.toContain("cello_contact_set_tier");
    expect(text).toContain("EVERY tier");
    expect(text).toContain("not_accepting");
  });
});
