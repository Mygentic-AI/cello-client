/**
 * DOD-M12B-SESSION-SEED-1 (case B) — the INBOUND half of the demand edge.
 *
 * `reviveIfNeededForSend` covers the case where WE wake first. Case B's routine triggers — a wifi
 * hop, a relay restart, a directory node cycling — are symmetric, and half the time the COUNTERPARTY
 * wakes first. They send; we have no session node, because revival is demand-driven and we have not
 * demanded anything yet. Their content parks at the relay (that backstop already exists and works).
 *
 * THE GAP, STATED CORRECTLY (the first version of this header overclaimed and review caught it).
 * Parked content is NOT stranded: the drain runs off the AGENT's standing receiver rather than the
 * session node, `ingestReceivedContent` deliberately accepts `interrupted`, and a backstop tick
 * fires for every agent every five minutes. So the counterparty's messages do reach the transcript.
 *
 * What is stuck is the SESSION. It stays `interrupted`, so the operator's own next send is refused,
 * and the inbound content they can see arrives up to five minutes late. A read is the operator's own
 * demand: it returns the session to `active` and pulls what is waiting immediately.
 *
 * WHY A READ IS AN ALLOWED TRIGGER AND AN INBOUND FRAME IS NOT. Andre's tenet is about what a
 * REMOTE party can cause: *"an open connection that a malicious agent can farm for."* Reviving
 * because a peer dialled us would hand exactly that lever to the peer — a stranger could keep our
 * endpoints open indefinitely by poking dead sessions. A read is the OPERATOR asking, on their own
 * machine, for their own session. It is the same class of demand as a send, and it is the class the
 * tenet permits.
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
    this.#id = seed ? `12D3KooW${createHash("sha256").update(seed).digest("hex").slice(0, 40)}` : `rand-${Math.random()}`;
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
  tempDir = await mkdtemp(join(tmpdir(), "cello-msg024-"));
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
  if (!res.ok) throw new Error(JSON.stringify(res));
  return mgr!.getSessionNodePeerId("alice", sessionId)!;
}
function statusOf(sessionId: string): string {
  return (mgr!.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(sessionId) as { status: string }).status;
}

describe("DOD-M12B-SESSION-SEED-1 (case B): reading revives, so inbound is not stranded", () => {
  it("a read on an interrupted session revives it at the original peer id", async () => {
    // The counterparty woke first and sent; their content is parked. The operator comes back and
    // reads. Without this the session stays `interrupted` — so their own next send is refused — and
    // the waiting content arrives only on the next 5-minute backstop tick.
    const sid = "51".repeat(32);
    const original = await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 2, "stream_close");

    const revived = await mgr!.reviveIfNeededForRead("alice", sid);

    expect(revived.ok, JSON.stringify(revived)).toBe(true);
    expect(statusOf(sid)).toBe("active");
    expect(mgr!.getSessionNodePeerId("alice", sid), "the id they parked against must not change").toBe(original);
  });

  it("a read on a TERMINAL session does not resurrect it — reading history is always allowed", async () => {
    // Reading a sealed session's transcript is a normal, permitted thing. It must keep working, and
    // it must not bring the session back: the receipt has been issued and the identity destroyed.
    const sid = "52".repeat(32);
    await openSession(sid);
    await mgr!.abandonSession("alice", sid);

    const res = await mgr!.reviveIfNeededForRead("alice", sid);

    expect(res.ok).toBe(false);
    expect(statusOf(sid), "reading the record of an ended session must never reopen it").toBe("abandoned");
  });

  it("a read triggers the parked-content drain, so what was waiting actually arrives", async () => {
    // Reviving the node is only half of it. The counterparty's messages are at the relay; the
    // backstop would fetch them within five minutes, and firing on revival makes it immediate.
    const sid = "53".repeat(32);
    await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 2, "stream_close");

    const drains: Array<{ agentName: string; reason: string }> = [];
    mgr!.setParkedDrainHook((agentName, reason) => { drains.push({ agentName, reason }); });

    await mgr!.reviveIfNeededForRead("alice", sid);

    expect(
      drains.map((d) => d.reason),
      "the node came back and nothing went to fetch what was waiting for it — the operator would " +
      "see a healthy session and wait up to five minutes for mail that had already arrived",
    ).toContain("session_revived");
  });

  /**
   * THE WIRING, and THE PROPERTY THE HANDLER PROMISES.
   *
   * Review found the old version of this — `src.includes("reviveIfNeededForRead(")` — did NOT
   * survive a revert test: it passes with the call inside `if (false)`, after an early return, or
   * if any comment merely mentions the token. And the property the handler comment promises,
   * *"reading a stored transcript is always allowed"*, had no test at all — so this three-line
   * bypass passed every case above while breaking every read of an ended session:
   *
   *     const r = await sessionNodeManager.reviveIfNeededForRead(agentName, sessionId);
   *     if (!r.ok) return { ok: false, reason: r.reason, guidance: r.guidance };
   *
   * These two assert the STRUCTURE (the call is reached, not merely present) and the BEHAVIOUR (a
   * refusal never costs the operator their history).
   */
  it("WIRING: the call is REACHED — not merely present in the file", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(join(import.meta.dirname, "..", "session-content-handlers.ts"), "utf-8");

    // Strip comments first, so a mention in prose cannot satisfy this.
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(code, "the call is only in a comment").toContain("reviveIfNeededForRead(");

    // And it must be guarded on the interrupted status rather than dead behind a constant.
    const idx = code.indexOf("reviveIfNeededForRead(");
    const preceding = code.slice(Math.max(0, idx - 400), idx);
    expect(
      preceding.includes('record.status === "interrupted"'),
      "the call must sit under the interrupted guard — an unreachable call is the same as none",
    ).toBe(true);
  });

  it("a refusal NEVER costs the operator their history — the revival is opportunistic", async () => {
    // The property the handler comment promises, and the one an operator would hit first. The
    // bypass above returns `{ ok: false }` for every read of a sealed or abandoned session; this is
    // what fails under it.
    const { readFileSync } = await import("node:fs");
    const code = readFileSync(join(import.meta.dirname, "..", "session-content-handlers.ts"), "utf-8")
      .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    const idx = code.indexOf("reviveIfNeededForRead(");
    const following = code.slice(idx, idx + 400);

    expect(
      following.includes("return { ok: false"),
      "a refused revival must not short-circuit the read — reading stored history is always allowed",
    ).toBe(false);
    expect(
      following.includes("revivalDeclined"),
      "the refusal must be carried to the caller, not discarded — session_identity_lost is the one " +
      "message that tells an operator to stop waiting and close for the receipt",
    ).toBe(true);
  });
});
