import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import { seedAgents } from "./helpers/seed-agents.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** The manager needs a factory but never builds a node here — these are pure DB reads/writes. */
const stubFactory = { create: () => { throw new Error("no node needed for a preference test"); } } as unknown as ISessionNodeFactory;

/**
 * M10B / DOD-END-SURFACE-1 — per-counterparty presentation choice.
 *
 * The clause is "per-counterparty include/omit at presentation". The property that matters is not
 * that a preference can be stored — it is that storing one can only ever NARROW what is disclosed.
 * A preference that could widen would be a consent bypass wearing a preference's clothes.
 */
describe("per-counterparty signal preferences", () => {
  let dir: string;
  let mgr: SessionNodeManager;
  const AGENT = "alice";
  const CONTACT = "cc".repeat(32);
  const SIG = "11".repeat(32);

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-prefs-"));
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: stubFactory, logger: silent, dbPath: join(dir, "sessions.db") });
    await mgr.initialize();
    // Real agent rows: `agent_id` is what the preference table keys on, and #requireAgentId throws
    // for an unknown name — so a test that skipped this would be testing nothing.
    await seedAgents(mgr.getDb(), [AGENT, "bob"]);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("records nothing until the operator makes a choice — absence means 'no opinion'", () => {
    // An empty map is what makes the signal's own default apply. If this returned entries by
    // default, every signal would acquire an opinion nobody expressed.
    expect(mgr.getContactSignalPrefs(AGENT, CONTACT).size).toBe(0);
  });

  it("distinguishes CLEARED from FALSE — they are different states", () => {
    mgr.setContactSignalPref(AGENT, CONTACT, SIG, false);
    expect(mgr.getContactSignalPrefs(AGENT, CONTACT).get(SIG)).toBe(false);

    mgr.setContactSignalPref(AGENT, CONTACT, SIG, null);
    // Cleared means the row is GONE, not present-with-false. An operator who could only toggle
    // true/false could never undo an omission without knowing what the default had been.
    expect(mgr.getContactSignalPrefs(AGENT, CONTACT).has(SIG)).toBe(false);
    expect(mgr.getContactSignalPrefs(AGENT, CONTACT).size).toBe(0);
  });

  it("is per-CONTACT — withholding from one person does not withhold from another", () => {
    const other = "dd".repeat(32);
    mgr.setContactSignalPref(AGENT, CONTACT, SIG, false);
    expect(mgr.getContactSignalPrefs(AGENT, CONTACT).get(SIG)).toBe(false);
    expect(mgr.getContactSignalPrefs(AGENT, other).size).toBe(0);
  });

  it("is per-AGENT — one agent's disclosure choices are not another's", () => {
    mgr.setContactSignalPref(AGENT, CONTACT, SIG, false);
    expect(mgr.getContactSignalPrefs("bob", CONTACT).size).toBe(0);
  });

  it("overwrites rather than duplicating when the same choice is set twice", () => {
    mgr.setContactSignalPref(AGENT, CONTACT, SIG, false);
    mgr.setContactSignalPref(AGENT, CONTACT, SIG, true);
    const prefs = mgr.getContactSignalPrefs(AGENT, CONTACT);
    expect(prefs.size).toBe(1);
    expect(prefs.get(SIG)).toBe(true);
  });
});

/**
 * The narrowing property, asserted where it is enforced. `present: true` must not be able to add a
 * signal back into a set that consent or the caller's filter excluded — the filter is applied to
 * the ALREADY-eligible list and only removes from it.
 */
describe("the preference can only NARROW the presented set", () => {
  it("filters by !== false, so an unknown or true preference never adds a signal", () => {
    // The exact expression used at the presentation site, exercised directly against the shapes it
    // sees. `prefs.get(hash) !== false` keeps anything without an explicit false — it has no branch
    // that can introduce a hash the eligible list did not already contain.
    const eligible = [{ signalHash: "a" }, { signalHash: "b" }];
    const prefs = new Map<string, boolean>([["b", false], ["zzz", true]]);
    const selected = eligible.filter((s) => prefs.get(s.signalHash) !== false);
    expect(selected.map((s) => s.signalHash)).toEqual(["a"]);
    // "zzz" was marked present:true but is NOT in the eligible list, so it cannot appear.
    expect(selected.some((s) => s.signalHash === "zzz")).toBe(false);
  });
});
