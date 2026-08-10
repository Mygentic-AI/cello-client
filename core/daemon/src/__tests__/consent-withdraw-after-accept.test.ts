/**
 * WITHDRAWING CONSENT AFTER ACCEPTING — the missing path.
 *
 * "I accepted this endorsement and now I want it gone" had no answer. Refusal was reachable only
 * while an item was `pending`, and revocation is the ISSUER's act, not the subject's — so once you
 * said yes, you were stuck with it being presented.
 *
 * Refusal is the right mechanism rather than revocation, and deliberately so: the decision is
 * RECORDED rather than erased, so the trail stays honest, and a refused signal is already inert
 * everywhere it is checked.
 *
 * The dangerous half is the scope. A refused signal is inert — so if refusal could reach
 * PORTAL-ISSUED signals it would be a back door to suppressing a mandatory track record, achieving
 * by consent exactly what revocation is forbidden from doing. That is what most of this file is
 * about.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore, type WalletSignalInput } from "../trust-signal-store.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

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

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const HASH = (c: string): string => c.repeat(64);

describe("withdrawing consent after acceptance", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let store: TrustSignalStore;
  let alice: string;
  let bob: string;

  const envelope = (over: Partial<WalletSignalInput> = {}): WalletSignalInput => ({
    signalHash: HASH("a"), subjectKind: "agent", subject: alice,
    issuerKind: "agent", issuerPubkey: "bb".repeat(32), type: "endorsement", schemaVersion: 1,
    payload: new Uint8Array([1]), issuedAt: 1_768_000_000, expiresAt: null,
    supersedesHash: null, status: "active", ...over,
  });

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-consent-withdraw-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    const agents = await seedAgentKeys(seed, ["alice", "bob"]);
    alice = agents.get("alice")!.pubkeyHex;
    bob = agents.get("bob")!.pubkeyHex;
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

  it("finds an ACCEPTED attestation as decidable — the path that did not exist", () => {
    store.putWalletSignal(envelope({ signalHash: HASH("1") }));
    store.setConsentState(HASH("1"), "accepted");

    const found = store.findDecidableConsent(alice, HASH("1").slice(0, 8));

    expect(found, "an accepted endorsement must remain decidable").not.toBeNull();
    expect(found!.consentState).toBe("accepted");
  });

  it("still finds a PENDING one — widening must not break the original path", () => {
    store.putWalletSignal(envelope({ signalHash: HASH("2") }));
    expect(store.findDecidableConsent(alice, HASH("2").slice(0, 8))?.consentState).toBe("pending");
  });

  it("REFUSES TO REACH A PORTAL-ISSUED SIGNAL — the back door, closed", () => {
    // THE TEST THIS FILE EXISTS FOR. Refusal makes a signal inert. If it reached portal-issued
    // signals, an operator could refuse their own track record and suppress the behavioural history
    // that mandatory signals exist to keep visible — the same outcome revocation is forbidden from
    // producing, through a different verb.
    store.putWalletSignal(envelope({
      signalHash: HASH("3"), issuerKind: "portal", type: "track_record",
    }));
    store.setConsentState(HASH("3"), "accepted");

    expect(
      store.findDecidableConsent(alice, HASH("3").slice(0, 8)),
      "a portal-issued signal must never be refusable",
    ).toBeNull();
  });

  it("closes the same door for the OTHER mandatory types and the security-derived pair", () => {
    for (const [i, type] of ["email", "phone", "webauthn", "totp"].entries()) {
      const h = HASH(String(i + 4));
      store.putWalletSignal(envelope({
        signalHash: h, issuerKind: "portal", type, subjectKind: "account", subject: "acct-1",
      }));
      expect(store.findDecidableConsent(alice, h.slice(0, 8)), `${type} must not be refusable`).toBeNull();
    }
  });

  it("does NOT filter by TYPE — a stranger's claim called 'track_record' is still refusable", () => {
    // The mandatory rule protects the PORTAL's behavioural record, never a third party's assertion.
    // A hostile peer can issue a signal it calls `track_record`, and refusing a stranger's claim
    // about you is precisely what this verb is for. Filtering on type rather than issuer would have
    // made that unrefusable — protecting the attacker instead of the operator.
    store.putWalletSignal(envelope({
      signalHash: HASH("8"), issuerKind: "agent", type: "track_record",
    }));
    expect(store.findDecidableConsent(alice, HASH("8").slice(0, 8))).not.toBeNull();
  });

  it("is AGENT-SCOPED — Bob cannot withdraw a decision that is Alice's", () => {
    store.putWalletSignal(envelope({ signalHash: HASH("9"), subject: alice }));
    store.setConsentState(HASH("9"), "accepted");

    expect(store.findDecidableConsent(bob, HASH("9").slice(0, 8))).toBeNull();
    expect(store.findDecidableConsent(alice, HASH("9").slice(0, 8))).not.toBeNull();
  });

  it("leaves an already-REFUSED item alone — refusal is terminal, not a toggle", () => {
    // Nothing re-accepts a refusal today, so surfacing one as decidable would offer an action that
    // does not exist and read as a bug.
    store.putWalletSignal(envelope({ signalHash: HASH("b") }));
    store.setConsentState(HASH("b"), "refused");
    expect(store.findDecidableConsent(alice, HASH("b").slice(0, 8))).toBeNull();
  });

  it("the withdrawal actually takes effect — the signal ends refused", () => {
    store.putWalletSignal(envelope({ signalHash: HASH("c") }));
    store.setConsentState(HASH("c"), "accepted");

    const item = store.findDecidableConsent(alice, HASH("c").slice(0, 8))!;
    expect(store.setConsentState(item.signalHash, "refused")).toBe(true);

    expect(store.getWalletSignal(HASH("c"))!.consentState).toBe("refused");
    // And it leaves the pending queue alone — it was never in it.
    expect(store.listPendingConsent(alice)).toEqual([]);
  });
});
