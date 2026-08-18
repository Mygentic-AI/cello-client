/**
 * DOD-M12B-SESSION-SEED-1 — the DEMAND that drives the revival.
 *
 * `reviveSessionNode` rebuilds an interrupted session at its original peer id, but until something
 * CALLS it the operator sees no change at all: `cello_send` still refuses with `session_not_active`
 * and the session is exactly as stuck as before. A revival mechanism with no caller is dead state
 * that holds key material — the reviewer's own scope note on the first half.
 *
 * THE TRIGGER IS THE OPERATOR SENDING, and nothing else. That is the `REDIAL-1` discipline and it is
 * Andre's tenet in the same breath: a background rebuilder would hold a dialable endpoint open for a
 * session nobody is using, which is the *"open connection a malicious agent can farm for"*. So the
 * revival happens on the send path, once, and only for a session the operator is actively using.
 *
 * WHAT MUST NOT CHANGE: a session that is `sealed`, `abandoned` or `seal_interrupted_pending` still
 * refuses. Those have no identity left — it was destroyed in the same step that wrote the status —
 * and a send must not resurrect them.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { FakeNode } from "./helpers/two-connection-fixture.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { seedAgents } from "./helpers/seed-agents.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const COUNTERPARTY_PEER = "12D3KooWFakeCounterpartyPeerIdForTestingOnly000000000000";

class SeededNode extends FakeNode {
  readonly #id: string;
  constructor(seed: Uint8Array | undefined) {
    super();
    this.#id = seed
      ? `12D3KooW${createHash("sha256").update(seed).digest("hex").slice(0, 40)}`
      : `random-${Math.random().toString(36).slice(2)}`;
  }
  override getPeerId(): string { return this.#id; }
}

class SeedDerivedFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return new SeededNode(config.transportPrivateKey) as unknown as CelloNode;
  }
}

let tempDir: string;
let mgr: SessionNodeManager | undefined;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "cello-msg023-"));
  mgr = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory: new SeedDerivedFactory(),
    logger: silent,
    dbPath: join(tempDir, "sessions.db"),
  });
  await mgr.initialize();
  await seedAgents(mgr.getDb(), ["alice"]);
});

afterEach(async () => {
  await mgr?.gracefulShutdown();
  mgr = undefined;
  await rm(tempDir, { recursive: true, force: true });
});

async function openSession(sessionId: string): Promise<string> {
  await mgr!.ensureStandingReceiverForAgent("alice");
  const res = await mgr!.createSessionNode(sessionId, "alice", "bb".repeat(32), COUNTERPARTY_PEER, "corr", true);
  if (!res.ok) throw new Error(`createSessionNode failed: ${JSON.stringify(res)}`);
  return mgr!.getSessionNodePeerId("alice", sessionId)!;
}

function statusOf(sessionId: string): string {
  const row = mgr!.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(sessionId) as { status: string };
  return row.status;
}

describe("DOD-M12B-SESSION-SEED-1: sending revives an interrupted session", () => {
  it("an interrupted session is revived on demand, at its original peer id", async () => {
    const sid = "41".repeat(32);
    const original = await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");

    const revived = await mgr!.reviveIfNeededForSend("alice", sid);

    expect(revived.ok, JSON.stringify(revived)).toBe(true);
    expect(statusOf(sid), "the status edge is half the fix — without it every send still refuses").toBe("active");
    expect(mgr!.getSessionNodePeerId("alice", sid), "they hold this id; it must not change").toBe(original);
  });

  it("an ACTIVE session is untouched — no rebuild, no churn", async () => {
    // The hook sits on the hot path of every send. It must be a cheap no-op for the normal case,
    // and it must not tear down and replace a perfectly good node.
    const sid = "42".repeat(32);
    const original = await openSession(sid);

    const res = await mgr!.reviveIfNeededForSend("alice", sid);

    expect(res.ok).toBe(true);
    expect(mgr!.getSessionNodePeerId("alice", sid), "the live node was replaced for no reason").toBe(original);
  });

  it("a TERMINAL session is not resurrected by sending into it", async () => {
    const sid = "43".repeat(32);
    await openSession(sid);
    await mgr!.abandonSession("alice", sid);

    const res = await mgr!.reviveIfNeededForSend("alice", sid);

    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("session_terminal");
    expect(statusOf(sid), "a send must never reopen a session that has ended").toBe("abandoned");
  });

  it("a session whose identity did not survive a restart says so, and does not mint a new one", async () => {
    // The honest case, and the one an operator most needs named: after a daemon restart the keypair
    // is genuinely gone. Minting a fresh identity here would "work" while handing the session a
    // second peer id the counterparty has never seen — a silent one-way session.
    const sid = "44".repeat(32);
    await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    mgr!.forgetSessionSeedForTest("alice", sid); // what a process restart does

    const res = await mgr!.reviveIfNeededForSend("alice", sid);

    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("session_identity_lost");
    expect(statusOf(sid), "and it stays interrupted, for RESTART-SEAL-1 to resolve with a receipt").toBe("interrupted");
  });

  /**
   * THE WIRING, pinned at the source. Every case above drives the manager directly, so the hook in
   * `session-content-handlers.ts` could be deleted and all four would stay green — the revival would
   * become dead code holding key material, which is exactly the shape the first half's review warned
   * about. A behavioural test for the real handler needs the whole IPC/gateway/tree path stood up to
   * reach one call; `startup-ordering` and `msg-019` make the same argument for the same reason.
   *
   * Revert test (RUN): delete the `reviveIfNeededForSend` call from the send handler and this fails.
   */
  it("WIRING: the send handler actually calls the revival — it is not dead code", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(join(import.meta.dirname, "..", "session-content-handlers.ts"), "utf-8");

    expect(
      src.includes("reviveIfNeededForSend("),
      "the mechanism works and nothing calls it: cello_send still refuses an interrupted session " +
      "forever, and the held seeds become key material with no consumer",
    ).toBe(true);
  });
});
