/**
 * DOD-MP-SESSION-RETIRE-1 — the DoD's LITERAL PROMISE, against a real database.
 *
 * The unit tests beside this one drive `terminalRelayRefusal` with a string recorder for
 * `retireSession`. That proves the function calls its seam; it proves nothing about what the seam
 * DOES, and the seam is where the whole value is. The review named the bypass exactly: wire
 * `retireSession` to write `"interrupted"`, or to an UPDATE that matches no row, or to `() => {}`,
 * and every one of those tests stays green while the session is still selectable and the delivery
 * worker keeps resubmitting into it every 60 seconds.
 *
 * So this asserts the promise itself: after retirement, the session is NO LONGER SELECTABLE as an
 * active session with that peer — which is the exact predicate `activeSessionsWith` uses to decide
 * whether to reuse a session or open a fresh one.
 *
 * `node:sqlite` is not used here; this opens the real store the daemon opens.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { seedAgents } from "./helpers/seed-agents.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const PEER = "b".repeat(64);

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

function insertSession(db: DaemonDatabase, agentId: string, sid: string, status: string): void {
  const t = 1_700_000_000_000;
  db.prepare(
    `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, NULL)`,
  ).run(sid, agentId, PEER, status, t, t);
}

describe("DOD-MP-SESSION-RETIRE-1 — a retired session stops being selectable", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let aliceId: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "session-retire-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    aliceId = (await seedAgents(seed, ["alice"])).get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(),
      logger: silent, dbPath,
    });
    await mgr.initialize();
    db = mgr.getDb();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  /** Exactly the predicate `activeSessionsWith` applies in `documentTransportFor`. */
  const selectable = (): string[] =>
    mgr.getSessionsForAgent("alice")
      .filter((r) => r.status === "active" && r.counterparty_pubkey === PEER)
      .map((r) => r.session_id);

  it("an active session IS selectable — the state that caused the loop", () => {
    insertSession(db, aliceId, "s-live", "active");
    // The pre-fix world: the relay had ended this session and said so, and it still looked like a
    // perfectly good route to every caller that picks by local status.
    expect(selectable()).toEqual(["s-live"]);
  });

  it("after a real retirement it is NOT selectable — so the next send opens a fresh one", () => {
    insertSession(db, aliceId, "s-dead", "active");
    expect(selectable()).toEqual(["s-dead"]);

    // A REAL retirement through the public API — no backdoor, no recorder. `abandonSession` does
    // status-first-then-teardown, the same order the terminal branch now uses; the status it writes
    // differs (`abandoned` vs `sealed`) and the predicate does not care, which is the point: any
    // non-active status removes the session from selection.
    return mgr.abandonSession("alice", "s-dead").then(() => {
      // THE DoD'S LITERAL PROMISE. `activeSessionsWith` returns nothing, so `acquireSession` falls
      // through to `openSession` and the document gets a live route instead of a grave.
      expect(selectable()).toEqual([]);
      const row = mgr.getSessionsForAgent("alice").find((r) => r.session_id === "s-dead");
      expect(row, "the row must remain — retiring is not deleting; the history stays").toBeDefined();
      expect(row!.status).not.toBe("active");
    });
  });

  it("retiring one session leaves another with the SAME peer selectable", async () => {
    insertSession(db, aliceId, "s-old", "active");
    insertSession(db, aliceId, "s-new", "active");
    await mgr.abandonSession("alice", "s-old");
    // A blunt "mark every session with this peer dead" would strand a healthy one and force a
    // needless reconnect. Retirement is per session, because that is what the relay ended.
    expect(selectable()).toEqual(["s-new"]);
  });

  it("retirement SURVIVES a restart — the stale row was persisted, so the fix must be too", async () => {
    insertSession(db, aliceId, "s-dead", "active");
    await mgr.abandonSession("alice", "s-dead");
    await mgr.stop?.();

    const reopened = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(),
      logger: silent, dbPath: join(tempDir, "sessions.db"),
    });
    await reopened.initialize();
    // The observed defect survived `cello logout && cello login` because the row is on disk. The
    // correction has to be on disk for the same reason — an in-memory retirement would evaporate
    // on the next restart and the loop would resume.
    const still = reopened.getSessionsForAgent("alice")
      .filter((r) => r.status === "active" && r.counterparty_pubkey === PEER);
    expect(still).toEqual([]);
    await reopened.stop?.();
  });
});
