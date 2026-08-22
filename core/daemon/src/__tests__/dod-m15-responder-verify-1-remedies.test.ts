/**
 * DOD-M15-RESPONDER-VERIFY-1 — the two fixes a review found by READING, because no test held them.
 *
 * ─── Why this file exists at all ───────────────────────────────────────────────────────────────
 *
 * Both behaviours below were written in a second review pass, and a third review then reverted each
 * one and ran the full gate:
 *
 *   - reverting the session-awareness of `revokeOfferedDialer` → **2525 tests, all green**
 *   - reverting the pin clear out of its `changes > 0` guard → **2525 tests, all green**
 *
 * A fix nothing can detect the absence of is one refactor away from being undone, and the person
 * undoing it will have a green gate telling them it was safe. That is the guard-nobody-hears
 * pattern in its fourth appearance in this milestone, and it is why these are here rather than
 * being trusted to the comments that explain them.
 *
 * These use a REAL `SessionNodeManager` on a real encrypted database — the pin lives in a SQL
 * column and the gate lives in a live libp2p gater, and a stub for either would be testing the
 * stub.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER } from "../contacts-tier-migration.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
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

const COUNTERPARTY = "aa".repeat(32);
const PINNED_KEY = "cc".repeat(32);

describe("DOD-M15-RESPONDER-VERIFY-1: the identity refusal has a remedy that WORKS", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let aliceId: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "m15-remedies-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    aliceId = (await seedAgents(seed, ["alice"])).get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new StubNodeFactory(),
      logger: silent,
      dbPath,
    });
    await mgr.initialize();
    db = mgr.getDb();
  });

  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  /** A session row carrying a pinned counterparty key — what an accepted inbound session leaves. */
  function pinCounterparty(sessionId: string): void {
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, counterparty_primary_pubkey,
                             status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, ?, 'sealed', 1000, 1000, 0, NULL)`,
    ).run(sessionId, aliceId, COUNTERPARTY, PINNED_KEY);
  }

  it("clears the pin for a counterparty with NO CONTACT ROW — the case the remedy is actually for", () => {
    /**
     * THE WHOLE POINT, and the reason a `changes > 0` guard was wrong.
     *
     * The pin is written on every ACCEPTED INBOUND session. A contact row is written only on an
     * outbound initiate, an explicit add, a reply, or a trust-signal presentation — an inbound
     * requester is deliberately NOT auto-added. So a counterparty you never replied to has a pin
     * and no contact row, and away-mode auto-ack is exactly that shape.
     *
     * With the clear inside the guard, `cello_contact_remove` for them deleted no row, cleared no
     * pin, and returned `{ ok: true, removed: false }`. The operator had followed the refusal's own
     * instructions, been told it worked, and was still locked out — which is harder to notice than
     * the original lockout, because it wears an `ok: true`.
     */
    pinCounterparty("s1".padStart(32, "0"));
    expect(mgr.getPinnedCounterpartyPrimary("alice", COUNTERPARTY)).toBe(PINNED_KEY);

    const removed = mgr.removeContact("alice", COUNTERPARTY);

    expect(
      mgr.getPinnedCounterpartyPrimary("alice", COUNTERPARTY),
      "the pin must be gone, or the identity refusal the operator was told to clear is permanent",
    ).toBeNull();
    expect(
      removed,
      "must report that something WAS cleared — an ok:true with removed:false reads as a no-op",
    ).toBe(true);
  });

  it("still clears the pin when there IS a contact row, and still reports the removal", () => {
    // The ordinary case, so the fix above cannot be 'simplified' by moving the clear into an else.
    pinCounterparty("s2".padStart(32, "0"));
    mgr.addContact("alice", COUNTERPARTY, undefined, "accepted", TIER.KNOWN);

    expect(mgr.removeContact("alice", COUNTERPARTY)).toBe(true);
    expect(mgr.getPinnedCounterpartyPrimary("alice", COUNTERPARTY)).toBeNull();
    expect(mgr.listContacts("alice").some((c) => c.pubkey === COUNTERPARTY)).toBe(false);
  });

  it("removing an unrelated counterparty does not clear this one's pin", () => {
    // A clear scoped too widely would silently un-pin every counterparty on the agent, turning a
    // TOFU anchor into decoration — and it would pass both tests above.
    pinCounterparty("s3".padStart(32, "0"));
    mgr.removeContact("alice", "bb".repeat(32));
    expect(mgr.getPinnedCounterpartyPrimary("alice", COUNTERPARTY)).toBe(PINNED_KEY);
  });

  it("reports NOTHING cleared for a counterparty with neither a contact nor a pin", () => {
    // Fail-loud at the caller: `cello_contact_remove` for someone unknown must not claim success.
    expect(mgr.removeContact("alice", "dd".repeat(32))).toBe(false);
  });
});

describe("DOD-M15-RESPONDER-VERIFY-1: one session's refusal does not collapse another's", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "m15-revoke-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    await seedAgents(seed, ["alice"]);
    seed.close();
    mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new StubNodeFactory(),
      logger: silent,
      dbPath,
    });
    await mgr.initialize();
  });

  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("a refusal for session P leaves the gate that session Q narrowed to Q's peer", async () => {
    /**
     * AN AGENT HAS ONE STANDING RECEIVER WITH ONE ALLOWED PEER, and that is what makes this a
     * cross-session availability defect rather than a tidiness issue.
     *
     * The first version closed the gate unconditionally on any refusal. So: offer P narrows the
     * receiver to P's dialer; offer Q arrives and re-narrows it to Q's; P's assignment then fails a
     * security check and the refusal closes the receiver — which is now Q's. Q's initiator, invited
     * and legitimate, is refused with "nothing invited it", which this daemon had done.
     *
     * One bogus offer/assignment pair, and a concurrent real session dies. It is the same
     * cross-session interference the receiver gate was narrowed to remove, moved one method along.
     */
    await mgr.ensureStandingReceiverForAgent("alice");

    const P_DIALER = "12D3KooWPeerP";
    const Q_DIALER = "12D3KooWPeerQ";
    const P_SESSION = "aa".repeat(16);
    const Q_SESSION = "bb".repeat(16);

    // Offer P narrows the gate, then offer Q re-narrows it — Q now owns the receiver.
    expect(mgr.admitOfferedDialer("alice", P_DIALER, P_SESSION)).toBe("narrowed");
    expect(mgr.admitOfferedDialer("alice", Q_DIALER, Q_SESSION)).toBe("narrowed");
    expect(mgr.getStandingReceiverAllowedPeer("alice")).toBe(Q_DIALER);

    // P's assignment is then refused.
    mgr.revokeOfferedDialer("alice", P_SESSION, P_DIALER);

    expect(
      mgr.getStandingReceiverAllowedPeer("alice"),
      "P's refusal must not close the door Q is standing at — Q's initiator was invited by this daemon",
    ).toBe(Q_DIALER);
    expect(
      mgr.getOfferedDialer("alice", Q_SESSION),
      "and Q's own offer record must survive P's refusal",
    ).toBe(Q_DIALER);
  });

  it("a refusal for the session that STILL owns the gate does close it", () => {
    // The negative control. Without this the test above is satisfied by never closing the gate at
    // all, which is the original defect: the door left open to the peer just declared unauthorised.
    return (async () => {
      await mgr.ensureStandingReceiverForAgent("alice");
      const P_DIALER = "12D3KooWOnlyPeer";
      const P_SESSION = "cc".repeat(16);

      expect(mgr.admitOfferedDialer("alice", P_DIALER, P_SESSION)).toBe("narrowed");
      expect(mgr.getStandingReceiverAllowedPeer("alice")).toBe(P_DIALER);

      mgr.revokeOfferedDialer("alice", P_SESSION, P_DIALER);
      expect(
        mgr.getStandingReceiverAllowedPeer("alice"),
        "the gate must be re-closed against the refused peer",
      ).toBeNull();
    })();
  });
});
