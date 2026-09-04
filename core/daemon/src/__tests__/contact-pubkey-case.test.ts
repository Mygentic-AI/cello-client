/**
 * A PUBLIC KEY IS BYTES. ITS HEX CASE IS NOT PART OF ITS IDENTITY.
 *
 * ─── The defect, from the operator's chair ─────────────────────────────────────────────────────
 *
 * You paste a counterparty's public key with any uppercase in it and CELLO stores that string
 * verbatim. The contact is then visible in `cello_contacts` and invisible to every read that decides
 * BEHAVIOUR: the tier is UNKNOWN, so tighter inbound bounds apply and they are never auto-accepted;
 * the pet name never resolves; the per-contact away message never fires; a trust-signal disclosure
 * choice never applies. **And a key blocked in one spelling is unblocked in the other.**
 *
 * Nothing errors and nothing logs. Found by review while ruling on `024-ORPHANTRIAGE`.
 *
 * ─── Both halves are tested, because either alone leaves the bug ───────────────────────────────
 *
 * Normalizing the accessors fixes new rows and strands old ones — a mixed-case row already on disk
 * becomes unreachable rather than merely wrong, taking its block with it. So the fold migration is
 * tested against a POPULATED pre-migration database, which is the project rule for any client-side
 * migration: the operator's machine is where these fail, and a fresh database cannot catch it.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { TIER } from "../contacts-tier-migration.js";
import { normalizeContactPubkey } from "../contact-pubkey-case.js";
import type { Logger, DaemonConfig } from "../types.js";

/** Mixed case on purpose, and it differs at both ends so a prefix cannot stand in for the whole. */
const MIXED = "9C1f4E77" + "b3".repeat(24) + "0D5a72E8";
const LOWER = MIXED.toLowerCase();

describe("A contact's public key is one identity, whatever case it was pasted in", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let logger: Logger;
  let logged: Array<{ event: string; ctx: Record<string, unknown> }>;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-pubkey-case-"));
    logged = [];
    logger = {
      debug() {}, info(event: string, ctx?: Record<string, unknown>) { logged.push({ event, ctx: ctx ?? {} }); },
      warn() {}, error(event: string, ctx?: Record<string, unknown>) { logged.push({ event, ctx: ctx ?? {} }); },
    };
    handle = null;
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function config(): Promise<DaemonConfig> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
  }

  function agentId(): string {
    return (handle!.getSessionNodeManager().getDb()!
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get("alice") as { agent_id: string }).agent_id;
  }

  it("normalizeContactPubkey lowercases, and is idempotent", () => {
    expect(normalizeContactPubkey(MIXED)).toBe(LOWER);
    expect(normalizeContactPubkey(LOWER)).toBe(LOWER);
  });

  it("A KEY ADDED IN ONE CASE IS THE SAME CONTACT IN THE OTHER — tier, name and away message all resolve", async () => {
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.addContact("alice", MIXED, "Bob", null, TIER.WHITELISTED);
    mgr.setContactAwayMessage("alice", MIXED, "back tomorrow");

    // Every behavioural read, against the OTHER spelling.
    expect(mgr.getTier("alice", LOWER), "the tier is what decides inbound bounds and auto-accept").toBe(TIER.WHITELISTED);
    expect(mgr.isKnown("alice", LOWER)).toBe(true);
    expect(mgr.isAutoAccept("alice", LOWER)).toBe(true);
    expect(mgr.isContact("alice", LOWER)).toBe(true);
    expect(mgr.getContactMoniker("alice", LOWER)).toBe("Bob");
    expect(mgr.resolveAwayMessage("alice", LOWER)).toBe("back tomorrow");

    // And back the other way, so this is not a one-directional coincidence.
    expect(mgr.getTier("alice", MIXED)).toBe(TIER.WHITELISTED);
    expect(mgr.getContactMoniker("alice", MIXED)).toBe("Bob");
  });

  it("ONE ROW, NOT TWO — two spellings must not create two contacts", async () => {
    /**
     * The primary key is `(agent_id, pubkey)`, so without normalization the second add creates a
     * SECOND row: two halves of one relationship, each carrying its own tier. That is how a key
     * blocked in one spelling stays reachable in the other.
     */
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.addContact("alice", MIXED, "Bob", null, TIER.KNOWN);
    mgr.addContact("alice", LOWER, null, null, TIER.KNOWN);
    expect(mgr.listContacts("alice").length, "one key, one contact").toBe(1);
    expect(mgr.listContacts("alice")[0]!.pubkey, "stored in one spelling").toBe(LOWER);
  });

  it("BLOCKING IN ONE SPELLING BLOCKS THE KEY — the direction that matters", async () => {
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.addContact("alice", LOWER, "Bob", null, TIER.WHITELISTED);
    expect(mgr.setContactTier("alice", MIXED, TIER.BLOCKED), "the setter must find the row").toBe(true);
    expect(mgr.getTier("alice", LOWER), "and the block must apply to the key, not to a spelling").toBe(TIER.BLOCKED);
    expect(mgr.isKnown("alice", LOWER)).toBe(false);
  });

  it("REMOVING IN ONE SPELLING REMOVES THE CONTACT", async () => {
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.addContact("alice", LOWER, "Bob", null, TIER.KNOWN);
    expect(mgr.removeContact("alice", MIXED)).toBe(true);
    expect(mgr.isContact("alice", LOWER)).toBe(false);
  });

  it("A DISCLOSURE CHOICE SET IN ONE SPELLING APPLIES IN THE OTHER", async () => {
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.setContactSignalPref("alice", MIXED, "aa".repeat(32), false);
    expect(mgr.getContactSignalPrefs("alice", LOWER).get("aa".repeat(32)))
      .toBe(false);
  });

  // ─── The migration, against a POPULATED pre-migration database ───────────────────────────────

  it("A MIXED-CASE ROW ALREADY ON DISK IS FOLDED, not stranded", async () => {
    /**
     * Normalizing the accessors alone would make this row UNREACHABLE — worse than the bug it fixes,
     * because the block and the away message go with it. The row is written the way the old build
     * wrote it: straight into the table, verbatim.
     */
    handle = await startDaemon(await config());
    const db = handle.getSessionNodeManager().getDb()!;
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier, moniker) VALUES (?, ?, ?, ?, ?)")
      .run(agentId(), MIXED, Date.now(), TIER.WHITELISTED, "Bob");
    await handle.stop("test_reopen");

    // Same directory, same SQLCipher file, a fresh open — which is when the fold runs.
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    expect(mgr.getTier("alice", LOWER), "the legacy row is reachable again").toBe(TIER.WHITELISTED);
    expect(mgr.getContactMoniker("alice", LOWER)).toBe("Bob");
    expect(mgr.listContacts("alice")[0]!.pubkey).toBe(LOWER);
    expect(
      logged.filter((l) => l.event === "contacts.pubkey.case.folded").length,
      "and it says so — a silent data migration is one nobody can audit afterwards",
    ).toBe(1);
  });

  it("WHEN BOTH SPELLINGS EXIST, THE MORE RESTRICTIVE SETTING SURVIVES THE MERGE", async () => {
    /**
     * ⚠️ **THE FAILURE DIRECTION IS THE WHOLE DESIGN.** Two spellings are two halves of one
     * relationship, and merging them by taking either at random can silently UNBLOCK a key the
     * operator blocked. The operator can loosen a setting afterwards; they cannot recover from a
     * permission they never knew had been widened.
     */
    handle = await startDaemon(await config());
    const db = handle.getSessionNodeManager().getDb()!;
    const id = agentId();
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier, moniker) VALUES (?, ?, ?, ?, ?)")
      .run(id, LOWER, Date.now(), TIER.WHITELISTED, "Bob");
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier, moniker) VALUES (?, ?, ?, ?, ?)")
      .run(id, MIXED, Date.now(), TIER.BLOCKED, null);
    await handle.stop("test_reopen");

    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    expect(mgr.listContacts("alice").length, "two halves become one contact").toBe(1);
    expect(mgr.getTier("alice", LOWER), "and the BLOCK survives, not the whitelist").toBe(TIER.BLOCKED);
    const folded = logged.find((l) => l.event === "contacts.pubkey.case.folded")!;
    expect(folded.ctx["duplicatesMerged"]).toBe(1);
    expect(folded.ctx["tiersTightened"]).toBe(1);
  });

  it("A CLEAN DATABASE IS SILENT — this runs at every open", async () => {
    handle = await startDaemon(await config());
    handle.getSessionNodeManager().addContact("alice", LOWER, "Bob", null, TIER.KNOWN);
    await handle.stop("test_reopen");
    logged = [];
    handle = await startDaemon(await config());
    expect(
      logged.filter((l) => l.event === "contacts.pubkey.case.folded").length,
      "a line per boot saying nothing happened is how a log stops being read",
    ).toBe(0);
    expect(handle.getSessionNodeManager().getTier("alice", LOWER)).toBe(TIER.KNOWN);
  });
});
