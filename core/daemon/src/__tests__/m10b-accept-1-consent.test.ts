/**
 * M10B / DOD-END-ACCEPT-1 — consent (D-23), the milestone's headline mechanism.
 *
 * Andre's reason, verbatim from the policy audit: *"Otherwise someone could create a rogue
 * endorsement that says you're a piece of shit and never work with this person."* An object authored
 * by a THIRD PARTY can now land in your wallet unbidden, so presentability requires your acceptance.
 *
 * TWO FAILURES THIS FILE EXISTS TO PREVENT, both silent:
 *
 * 1. **The restart clobber.** The client DB has NO migration versioning, and
 *    `ensureTrustSignalSchema` runs on every `startDaemon` behind a bare `catch {}`. A consent
 *    migration written as a sibling `ALTER`/`UPDATE` in there makes the backfill unconditional — so
 *    an operator who REFUSES an endorsement has it flipped back to `accepted` on the next restart,
 *    silently, and it becomes presentable. That is why this uses the `contacts-tier-migration`
 *    pattern instead: a PRAGMA column-birth gate, no column DEFAULT (so the backfill has a real
 *    discriminator), ALTER + backfill in ONE transaction, and a RETHROW.
 * 2. **Fail-open by default.** `M10B-D14` originally specified `DEFAULT 'accepted'`, which was
 *    fail-open on the milestone's headline invariant: consent would hold only because the delivery
 *    path REMEMBERS to write 'pending', so any second write path silently makes an unconsented
 *    signal presentable. Anything that is not exactly 'accepted' is unpresentable.
 *
 * INV-ZEROBUMP: consent is required by `issuer_kind: agent`, never by `type == "endorsement"`. Every
 * future client-sourced type inherits it for free.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore, ensureTrustSignalSchema, type WalletSignalInput } from "../trust-signal-store.js";
import { hashTrustSignalEnvelope, type TrustSignalEnvelope } from "@cello-protocol/protocol-types";
import { migrateWalletAddConsentState } from "../consent-migration.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

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

const HASH = (c: string): string => c.repeat(64);

function envelope(over: Partial<WalletSignalInput> = {}): WalletSignalInput {
  return {
    signalHash: HASH("a"), subjectKind: "agent", subject: "agent-1",
    issuerKind: "portal", issuerPubkey: "aabb", type: "phone", schemaVersion: 1,
    payload: new Uint8Array([1, 2, 3]), issuedAt: 1_768_000_000, expiresAt: null,
    supersedesHash: null, status: "active", ...over,
  };
}

describe("DOD-END-ACCEPT-1 — consent state", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let store: TrustSignalStore;
  let alicePubkey: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "m10b-consent-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    alicePubkey = (await seedAgentKeys(seed, ["alice"])).get("alice")!.pubkeyHex;
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
    store = new TrustSignalStore(db, silent);
  });

  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  const present = (): string[] =>
    store.listAllActive({ presentingAgentPubkeyHex: alicePubkey }).map((s) => s.signalHash);

  describe("the migration", () => {
    it("is NULLABLE in both fresh and migrated schemas — SQLite forces it, so parity wins", () => {
      // SQLite cannot ADD COLUMN with NOT NULL and no DEFAULT, so a migrated DB can only ever be
      // nullable. A stricter fresh DDL would diverge, and the divergence would appear only on fresh
      // installs — every new operator. Nullability is safe because the PREDICATE enforces
      // presentability, not the constraint.
      const cols = db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string; notnull: number }>;
      expect(cols.find((c) => c.name === "consent_state")!.notnull).toBe(0);
    });

    it("adds the column with NO DEFAULT — the backfill needs a real discriminator", () => {
      const cols = db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string; dflt_value: string | null }>;
      const consent = cols.find((c) => c.name === "consent_state");
      expect(consent, "consent_state column must exist").toBeDefined();
      // With a DEFAULT, every existing row gets a value the instant the column is created, so the
      // one-time backfill matches NOTHING — the exact trap contacts-tier-migration documents.
      expect(consent!.dflt_value).toBeNull();
    });

    it("BACKFILLS a LEGACY database's rows to accepted — they are all portal-issued", () => {
      // Simulates the real migration case: a wallet that predates the column entirely. Defaulting
      // those rows to 'pending' would silently make every phone/email signal already in every wallet
      // unpresentable — a data-loss-shaped bug that raises no error.
      // A genuine legacy shape: neither consent column present.
      db.exec("ALTER TABLE wallet_trust_signals DROP COLUMN consent_state");
      db.exec("ALTER TABLE wallet_trust_signals DROP COLUMN consent_notified_at");
      db.prepare(
        `INSERT INTO wallet_trust_signals
           (signal_hash, subject_kind, subject, issuer_kind, issuer_pubkey, type, schema_version,
            payload, issued_at, expires_at, supersedes_hash, status, received_at, default_present)
         VALUES (?, 'agent', ?, 'portal', 'aabb', 'phone', 1, ?, 1, NULL, NULL, 'active', 1, 1)`,
      ).run(HASH("1"), alicePubkey, Buffer.from([1]));

      migrateWalletAddConsentState(db, silent);

      const rows = db.prepare("SELECT consent_state FROM wallet_trust_signals").all() as Array<{ consent_state: string | null }>;
      expect(rows.length).toBe(1);
      expect(rows[0].consent_state).toBe("accepted");
      expect(present()).toContain(HASH("1"));
    });

    it("THE BIRTH GATE: once the column exists, the migration NEVER re-backfills", () => {
      // This is the clobber protection stated directly. The one-time step is tied to the column being
      // CREATED, not to a NULL that could reappear later — so a row deliberately set to something
      // else (or to NULL by a stray write) is never "repaired" into presentability behind the
      // operator's back.
      store.putWalletSignal(envelope({ signalHash: HASH("9"), subject: alicePubkey, issuerKind: "agent" }));
      db.prepare("UPDATE wallet_trust_signals SET consent_state = NULL WHERE signal_hash = ?").run(HASH("9"));

      migrateWalletAddConsentState(db, silent);

      const got = db.prepare("SELECT consent_state FROM wallet_trust_signals WHERE signal_hash = ?").get(HASH("9")) as { consent_state: string | null };
      expect(got.consent_state).toBeNull();   // untouched — NOT promoted to accepted
      expect(present()).not.toContain(HASH("9"));  // and unpresentable, fail-closed
    });

    it("IS IDEMPOTENT — a second run is a no-op, not a re-backfill", () => {
      expect(() => migrateWalletAddConsentState(db, silent)).not.toThrow();
      expect(() => migrateWalletAddConsentState(db, silent)).not.toThrow();
    });

    it("🚨 A REFUSED SIGNAL SURVIVES A RESTART — the clobber this file exists to prevent", () => {
      // The failure: an unconditional backfill inside ensureTrustSignalSchema flips a REFUSED
      // endorsement back to `accepted` on the next daemon start, silently, and it becomes
      // presentable. Tie the one-time step to COLUMN BIRTH, not to NULL-ness, and it cannot happen.
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subject: alicePubkey, issuerKind: "agent" }));
      store.setConsentState(HASH("2"), "refused");

      // Every path a restart runs.
      ensureTrustSignalSchema(db, silent);
      migrateWalletAddConsentState(db, silent);

      expect(store.getWalletSignal(HASH("2"))!.consentState).toBe("refused");
      expect(present()).not.toContain(HASH("2"));
    });

    it("fresh == migrated: a brand-new database has the column too", () => {
      // CREATE_WALLET_SQL must carry it, or a fresh install and a migrated one diverge — and the
      // divergence only shows up on the fresh one, which is every new operator.
      const cols = (db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string }>).map((c) => c.name);
      expect(cols).toContain("consent_state");
    });
  });

  describe("presentability", () => {
    it("an AGENT-issued signal lands PENDING and is NOT presentable", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subject: alicePubkey, issuerKind: "agent" }));
      expect(store.getWalletSignal(HASH("3"))!.consentState).toBe("pending");
      expect(present()).not.toContain(HASH("3"));
    });

    it("a PORTAL-issued signal is presentable with no consent step", () => {
      // Consent keys on issuer_kind, not on type. A portal signal was minted about you, for you, at
      // your own action — there is nobody else's decision to wait for.
      store.putWalletSignal(envelope({ signalHash: HASH("4"), subject: alicePubkey, issuerKind: "portal" }));
      expect(present()).toContain(HASH("4"));
    });

    it("ACCEPTED makes it presentable; REFUSED never does", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("5"), subject: alicePubkey, issuerKind: "agent" }));
      store.setConsentState(HASH("5"), "accepted");
      expect(present()).toContain(HASH("5"));

      store.setConsentState(HASH("5"), "refused");
      expect(present()).not.toContain(HASH("5"));
    });

    it("ANYTHING that is not exactly 'accepted' is unpresentable (§5a, fail-closed)", () => {
      // A missing or unrecognized consent state must make it UNPRESENTABLE, never
      // presentable-by-default. An attacker never has to DEFEAT this check — they omit the thing
      // that triggers it.
      store.putWalletSignal(envelope({ signalHash: HASH("6"), subject: alicePubkey, issuerKind: "agent" }));
      for (const bogus of ["pending", "refused", "", "ACCEPTED", "accepted "]) {
        db.prepare("UPDATE wallet_trust_signals SET consent_state = ? WHERE signal_hash = ?").run(bogus, HASH("6"));
        expect(present(), `consent_state=${JSON.stringify(bogus)}`).not.toContain(HASH("6"));
      }
      db.prepare("UPDATE wallet_trust_signals SET consent_state = NULL WHERE signal_hash = ?").run(HASH("6"));
      expect(present(), "consent_state=NULL").not.toContain(HASH("6"));
    });

    it("the filter is in the SQL, so `include` cannot route around it", () => {
      // listAllActive's `include` branch already bypasses default_present. If consent were a JS
      // filter it would be bypassed the same way, and an operator could present an unconsented
      // endorsement by naming its type explicitly.
      store.putWalletSignal(envelope({ signalHash: HASH("7"), subject: alicePubkey, issuerKind: "agent", type: "endorsement" }));
      const included = store.listAllActive({ presentingAgentPubkeyHex: alicePubkey, include: ["endorsement"] });
      expect(included.map((s) => s.signalHash)).not.toContain(HASH("7"));
    });
  });

  describe("INV-ZEROBUMP", () => {
    it("consent keys on issuer_kind — an UNKNOWN client-sourced type inherits it for free", () => {
      // The generalisation M10B-D1 demands: nothing here learns the string "endorsement".
      store.putWalletSignal(envelope({ signalHash: HASH("8"), subject: alicePubkey, issuerKind: "agent", type: "some_future_type" }));
      expect(store.getWalletSignal(HASH("8"))!.consentState).toBe("pending");
      expect(present()).not.toContain(HASH("8"));
      store.setConsentState(HASH("8"), "accepted");
      expect(present()).toContain(HASH("8"));
    });
  });

  // ── Review F1/F2/F3 — consent must stop ERASURE and cover EVERY read path ──────────────────────
  describe("an unconsented signal cannot destroy a consented one", () => {
    /**
     * Drive the REAL delivery path, because supersession lives there.
     *
     * The first version of these tests used `putWalletSignal` directly — and `putWalletSignal` does
     * not supersede anything, so "the rogue did not supersede" held trivially and the tests were
     * hollow. The control test ("the same issuer's re-issue still supersedes") is what exposed it by
     * failing. Building a real envelope and letting the store hash it is the only way these
     * assertions mean anything.
     */
    const deliver = (o: {
      subject?: string; issuerKind: "portal" | "agent"; issuerPubkey: string;
      type: string; supersedes?: string | null; issuedAt?: number;
    }): string => {
      const env: TrustSignalEnvelope = {
        subject_kind: "agent",
        subject: o.subject ?? alicePubkey,
        issuer_kind: o.issuerKind,
        issuer_pubkey: o.issuerPubkey,
        type: o.type,
        schema_version: 1,
        payload: new Uint8Array([1, 2, 3]),
        issued_at: o.issuedAt ?? 1_768_000_000,
        expires_at: null,
        supersedes_hash: o.supersedes ? new Uint8Array(Buffer.from(o.supersedes, "hex")) : null,
        same_operator: false,
      };
      const hash = Buffer.from(hashTrustSignalEnvelope(env)).toString("hex");
      store.deliverWalletSignal(env, hash);
      return hash;
    };

    it("F1: a PENDING rogue endorsement does not supersede the subject's ACCEPTED one", () => {
      // The half of the threat consent did NOT close. A rogue agent-issued delivery lands pending and
      // is unpresentable — but before this fix its insert superseded Alice's own accepted endorsement
      // of the same type, and she presented NOTHING. Blocking display while permitting deletion
      // leaves the stranger in control of what her counterparties see.
      const good = deliver({ issuerKind: "agent", issuerPubkey: "bb".repeat(32), type: "endorsement" });
      store.setConsentState(good, "accepted");
      expect(present()).toContain(good);

      const rogue = deliver({ issuerKind: "agent", issuerPubkey: "cc".repeat(32), type: "endorsement", issuedAt: 1_768_000_001 });

      expect(store.getWalletSignal(rogue)!.consentState).toBe("pending");
      expect(store.getWalletSignal(good)!.status).toBe("active");   // NOT superseded
      expect(present()).toContain(good);                            // ...and still presentable
    });

    it("F2: a rogue issuer cannot supersede ANOTHER issuer's signal by naming its hash", () => {
      // Pre-existing since M10: supersedes_hash was honoured without asking whether the new issuer
      // was entitled to supersede the target, so anyone who could get one signal delivered could
      // knock out ANY row — phone and email included — just by naming its hash.
      const phone = deliver({ issuerKind: "portal", issuerPubkey: "aa".repeat(32), type: "phone" });
      expect(present()).toContain(phone);

      const rogue = deliver({ issuerKind: "agent", issuerPubkey: "cc".repeat(32), type: "endorsement", supersedes: phone });
      store.setConsentState(rogue, "accepted");   // even CONSENTED, it has no authority here

      expect(store.getWalletSignal(phone)!.status).toBe("active");
      expect(present()).toContain(phone);
    });

    it("the SAME issuer's re-issue still supersedes — the fix must not break supersession", () => {
      // The control, and the test that caught the hollow first draft. Without it, "rogues cannot
      // supersede" would be satisfied by an implementation where nothing supersedes anything, which
      // silently breaks track-record renewal.
      const v1 = deliver({ issuerKind: "portal", issuerPubkey: "aa".repeat(32), type: "phone" });
      const v2 = deliver({ issuerKind: "portal", issuerPubkey: "aa".repeat(32), type: "phone", supersedes: v1, issuedAt: 1_768_000_002 });

      expect(store.getWalletSignal(v1)!.status).toBe("superseded");
      expect(present()).toContain(v2);
    });

    it("supersession is APPLIED when a pending signal is accepted, not silently lost", () => {
      // Deferring the effect must not DROP it: an accepted re-issue has to supersede what it
      // replaces, or the operator ends up presenting both versions.
      const v1 = deliver({ issuerKind: "agent", issuerPubkey: "bb".repeat(32), type: "endorsement" });
      store.setConsentState(v1, "accepted");
      const v2 = deliver({ issuerKind: "agent", issuerPubkey: "bb".repeat(32), type: "endorsement", supersedes: v1, issuedAt: 1_768_000_003 });

      expect(store.getWalletSignal(v1)!.status).toBe("active");      // deferred while pending
      store.setConsentState(v2, "accepted");
      expect(store.getWalletSignal(v1)!.status).toBe("superseded");  // applied on acceptance
    });
  });

  describe("F3: EVERY read path carries the consent predicate, not just listAllActive", () => {
    it("listPresentableTypes does not enumerate a PENDING signal's type", () => {
      // It is the live validator for --include/--exclude. Without the predicate,
      // `--include endorsement` on a wallet holding only a PENDING endorsement validates OK and then
      // presents nothing — the daemon telling the operator the type is fine and silently omitting it,
      // which is the exact lie DOD-END-SCOPE-FIX-1 removed along the scoping dimension.
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subject: alicePubkey, issuerKind: "agent", type: "endorsement" }));
      expect(store.listPresentableTypes(alicePubkey)).not.toContain("endorsement");
      store.setConsentState(HASH("3"), "accepted");
      expect(store.listPresentableTypes(alicePubkey)).toContain("endorsement");
    });

    it("listPresentable — named for presentability — does not return unconsented rows", () => {
      // Exported, and the only implementation of the account-subject half. Returning pending rows
      // makes it a loaded gun for whoever wires that half later.
      store.putWalletSignal(envelope({ signalHash: HASH("4"), subject: alicePubkey, issuerKind: "agent" }));
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" })).toEqual([]);
      store.setConsentState(HASH("4"), "refused");
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" })).toEqual([]);
    });
  });

  it("a PARTIALLY migrated database (one column, not the other) migrates instead of crashing", () => {
    // Self-inflicted boot failure, caught by the suite: both columns were added under ONE birth gate
    // keyed on consent_state, so a DB holding consent_state but missing consent_notified_at hit
    // `duplicate column name`, the migration rethrew, and the daemon refused to start. Each column is
    // gated independently now — and the backfill stays tied to consent_state's birth, so rows that
    // already carry a decision are not re-judged.
    store.putWalletSignal(envelope({ signalHash: HASH("e"), subject: alicePubkey, issuerKind: "agent" }));
    store.setConsentState(HASH("e"), "refused");
    db.exec("ALTER TABLE wallet_trust_signals DROP COLUMN consent_notified_at");

    expect(() => migrateWalletAddConsentState(db, silent)).not.toThrow();

    // THE PAIRED POSITIVE, and it is the assertion that was missing. The two negatives below are
    // satisfied by the migration returning early and doing NOTHING — which is exactly what it did:
    // the outer gate keyed on `consent_state` alone, so every UPGRADED database (the real production
    // shape) skipped the new column entirely while fresh installs got it. The test passed
    // byte-identically on the parent commit. A negative is only as good as the positive beside it.
    const cols = (db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string }>)
      .map((c) => c.name);
    expect(cols, "the column the migration exists to add").toContain("consent_notified_at");

    expect(store.getWalletSignal(HASH("e"))!.consentState).toBe("refused");  // NOT re-backfilled
  });
});
