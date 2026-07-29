/**
 * M10B / DOD-END-PENDING-1 — the pending-consent queue (`M10B-D5`).
 *
 * NOT the transcript inbox, and Andre reasoned to that live: *"the inbox normally is for transcripts,
 * you get rid of them from your inbox by reading the transcript or dismissing the transcript. This
 * doesn't have a transcript. So… maybe we should make it a completely different class."* Putting an
 * endorsement awaiting consent in the inbox gives the operator an item they cannot clear the normal
 * way.
 *
 * THE BUG TO AVOID IS TWO LIFETIMES CONFLATED INTO ONE:
 *   - the ITEM persists until it is accepted or refused — it is a decision that is still owed;
 *   - the NOTIFICATION is raised once and stops once seen — the operator must not be re-nagged on
 *     every `cello_use_agent`.
 * One flag cannot express both. A single `seen` bit would either dismiss the item (losing the pending
 * decision) or re-fire forever (nagging). They are separate columns because they are separate facts.
 *
 * INV-ZEROBUMP: the queue is keyed and named by CONSENT STATE, never by type. That is what makes a
 * whole new operator surface legal under a zero-bump milestone — a second client-sourced type appears
 * here for free.
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

describe("DOD-END-PENDING-1 — the pending-consent queue", () => {
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
    tempDir = await mkdtemp(join(tmpdir(), "m10b-pending-"));
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

  describe("the ITEM — persists until decided", () => {
    it("lists a pending signal awaiting THIS agent's decision", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("1") }));
      const items = store.listPendingConsent(alice);
      expect(items.map((i) => i.signalHash)).toEqual([HASH("1")]);
    });

    it("is SCOPED — Bob does not see the decision Alice owes", () => {
      // Same INV-AGENT-SCOPED property DOD-END-SCOPE-FIX-1 established for presentation. A queue that
      // showed every agent's pending items would let one agent accept on another's behalf.
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subject: alice }));
      expect(store.listPendingConsent(bob)).toEqual([]);
      expect(store.listPendingConsent(alice)).toHaveLength(1);
    });

    it("SURVIVES being seen — seeing the notification does not clear the decision", () => {
      // The conflation this unit exists to avoid. An inbox item is cleared by reading it; a decision
      // is not. If marking it notified removed it, the operator would lose the endorsement entirely
      // by the act of being told about it.
      store.putWalletSignal(envelope({ signalHash: HASH("3") }));
      store.markConsentNotified(alice);
      expect(store.listPendingConsent(alice)).toHaveLength(1);
    });

    it("LEAVES the queue once accepted, and once refused", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("4") }));
      store.putWalletSignal(envelope({ signalHash: HASH("5"), issuedAt: 1_768_000_001 }));
      store.setConsentState(HASH("4"), "accepted");
      store.setConsentState(HASH("5"), "refused");
      expect(store.listPendingConsent(alice)).toEqual([]);
    });

    it("never contains a PORTAL-issued signal — there is no third party to wait for", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("6"), issuerKind: "portal", issuerPubkey: "aa".repeat(32), type: "phone" }));
      expect(store.listPendingConsent(alice)).toEqual([]);
    });
  });

  describe("the NOTIFICATION — raised once, silent after", () => {
    it("reports UNNOTIFIED pending items, then stops after they are marked seen", () => {
      // `cello_use_agent` asks this on every agent selection. If it kept answering yes, the operator
      // is nagged forever about a decision they have already been told about.
      store.putWalletSignal(envelope({ signalHash: HASH("7") }));
      expect(store.countUnnotifiedConsent(alice)).toBe(1);

      store.markConsentNotified(alice);
      expect(store.countUnnotifiedConsent(alice)).toBe(0);
      expect(store.countUnnotifiedConsent(alice)).toBe(0);   // still silent on re-ask
    });

    it("a NEW pending item raises the notification again — silence is per-item, not permanent", () => {
      // The inverse failure: a single "already notified" flag on the agent would silence every future
      // endorsement too, and the operator would never hear about the second one.
      store.putWalletSignal(envelope({ signalHash: HASH("8") }));
      store.markConsentNotified(alice);
      expect(store.countUnnotifiedConsent(alice)).toBe(0);

      store.putWalletSignal(envelope({ signalHash: HASH("9"), issuedAt: 1_768_000_002 }));
      expect(store.countUnnotifiedConsent(alice)).toBe(1);
    });

    it("marking notified is SCOPED — it does not silence another agent's items", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("a"), subject: alice }));
      store.putWalletSignal(envelope({ signalHash: HASH("b"), subject: bob }));
      store.markConsentNotified(alice);
      expect(store.countUnnotifiedConsent(alice)).toBe(0);
      expect(store.countUnnotifiedConsent(bob)).toBe(1);
    });

    it("a DECIDED item is never counted as unnotified, even if it was never seen", () => {
      // Accepting straight from a listing without the notification having fired must not leave a
      // phantom unread.
      store.putWalletSignal(envelope({ signalHash: HASH("c") }));
      store.setConsentState(HASH("c"), "accepted");
      expect(store.countUnnotifiedConsent(alice)).toBe(0);
    });
  });

  describe("INV-ZEROBUMP", () => {
    it("keys on CONSENT STATE — an unknown client-sourced type queues for free", () => {
      // The whole reason a new operator surface is legal in a zero-bump milestone: nothing here
      // learns the string "endorsement".
      store.putWalletSignal(envelope({ signalHash: HASH("d"), type: "some_future_type" }));
      expect(store.listPendingConsent(alice).map((i) => i.type)).toEqual(["some_future_type"]);
    });
  });

  describe("review findings — the guards the queue inherited without", () => {
    it("REFUSES a non-pubkey agent key instead of returning an empty queue (F3, §5a)", () => {
      // The silent fallback: a device-local agent_id UUID — the natural thing to have in an IPC
      // handler — matches zero rows, which reads as "nothing pending". For this queue that silence
      // IS the failure it exists to prevent, and markConsentNotified would still match account rows
      // and log success, so the surface would look like it was working.
      store.putWalletSignal(envelope({ signalHash: HASH("f") }));
      for (const bad of ["not-a-key", alice.toUpperCase(), "", "550e8400-e29b-41d4-a716-446655440000"]) {
        expect(() => store.listPendingConsent(bad), bad).toThrow(/lowercase hex/i);
        expect(() => store.countUnnotifiedConsent(bad), bad).toThrow(/lowercase hex/i);
        expect(() => store.markConsentNotified(bad), bad).toThrow(/lowercase hex/i);
      }
      expect(store.listPendingConsent(alice)).toHaveLength(1);   // the paired positive
    });

    it("matches an UPPERCASE-hex stored subject — the lower() is real, not decoration", () => {
      // The previous scoping test could not see this: seedAgentKeys produces lowercase on both
      // sides, so dropping `lower(` from the predicate passed anyway.
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subject: alice.toUpperCase() }));
      expect(store.listPendingConsent(alice).map((i) => i.signalHash)).toEqual([HASH("1")]);
    });

    it("does NOT list or nag about a SUPERSEDED pending item (F6)", () => {
      // Reachable via M10B-D4's correction loop: Bob sends E1, then a corrected E2; accepting E2
      // supersedes E1, whose consent_state stays 'pending'. Without this it sits in the queue
      // forever asking the operator to decide on something that can never be presented.
      store.putWalletSignal(envelope({ signalHash: HASH("2") }));
      store.setWalletStatus(HASH("2"), "superseded");
      expect(store.listPendingConsent(alice)).toEqual([]);
      expect(store.countUnnotifiedConsent(alice)).toBe(0);
    });

    it("does NOT list an EXPIRED pending item", () => {
      const past = Math.floor(Date.now() / 1000) - 3600;
      store.putWalletSignal(envelope({ signalHash: HASH("3"), expiresAt: past }));
      expect(store.listPendingConsent(alice)).toEqual([]);
    });
  });

  describe("DOD-END-SURFACE-1 — the nudge and the verbs are separate steps", () => {
    it("the COUNT is what agent selection reads, and reading it does not mark notified", () => {
      // cello_use_agent surfaces a NUMBER; cello_consent_list is what shows the items and records
      // that the operator saw them. If selection marked notified, the operator would be marked told
      // about something they were never shown — and the next selection would say nothing, so the
      // endorsement would sit there in silence. That is the failure the two lifetimes exist to stop.
      store.putWalletSignal(envelope({ signalHash: HASH("1") }));

      expect(store.countUnnotifiedConsent(alice)).toBe(1);
      expect(store.countUnnotifiedConsent(alice)).toBe(1);   // reading again still says 1
      expect(store.listPendingConsent(alice)).toHaveLength(1);

      store.markConsentNotified(alice);                       // what LISTING does
      expect(store.countUnnotifiedConsent(alice)).toBe(0);    // the nudge goes quiet...
      expect(store.listPendingConsent(alice)).toHaveLength(1); // ...the decision does not
    });
  });
});
