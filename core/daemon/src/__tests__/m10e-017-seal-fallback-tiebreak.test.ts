/**
 * 017-SEAL — a busy provider still seals every session (Part 2: the directory-only fallback is
 * deadlock-free when BOTH sides take it at once).
 *
 * Step 0 (live) showed the stall's tail: when the rate-limited sign-in made BOTH parties fall back
 * to the directory-mediated bilateral seal at the same moment, each side had already recorded its
 * own half (`seal_interrupted_pending`) by the time the other's co-sign request arrived — so each
 * refused the other `session_seal_already_pending`, and both closes failed
 * (`seal_rejected_by_counterparty`).
 *
 * S3 drives that exact collision with TWO real `SessionNodeManager`s over real SQLCipher and real
 * Ed25519 agent keys, the real `createSealFlows`/`createInboundSealRequestHandler`, and a router
 * that carries the real `seal_interrupted_request`/`ack`/`rejection` frames between them. It forces
 * the asymmetric order the live stall hit: one side completes its bilateral commitment first, then
 * the other's request lands on it while it is already pending.
 *
 * The fix: a side already pending ANSWERS the late request rather than refusing it, with a
 * deterministic tie-break (the higher pubkey answers) so exactly one co-sign completes; and the
 * initiator, finding its own session already pending when the answer (or the tie-break refusal)
 * arrives, treats that as the success it is rather than a failure. Both closes then seal.
 *
 * Revert checks (017-SEAL):
 *   - remove the tie-break → the higher side refuses the late request → `higherAnswered` is false.
 *   - remove the already-pending recovery → the late side's close returns a failure → `.ok` false.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { createSealFlows } from "../seal-flows.js";
import { createInboundSealRequestHandler } from "../inbound-seal-request.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import { loadAgents } from "../agent-loader.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger, AgentInfo, SessionRecord } from "../types.js";
import type { KeyProvider } from "@cello-protocol/crypto";

const SID = "becf36ed71d1433d031813235bd32888"; // 16-byte session id, hex

function makeLogger(): Logger { return { debug() {}, info() {}, warn() {}, error() {} }; }
class StubFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { throw new Error("no node in this test"); }
}

/** A directory signaling stub: the ONLY surface awaitSealAck uses is registerInboundHandler. */
function makeSignaling() {
  const handlers = new Set<(frame: Record<string, unknown>) => void>();
  return {
    status: "connected" as const,
    registerInboundHandler(fn: (frame: Record<string, unknown>) => void): () => void {
      handlers.add(fn);
      return () => handlers.delete(fn);
    },
    deliver(frame: Record<string, unknown>): void { for (const fn of [...handlers]) fn(frame); },
  };
}

interface Side {
  name: string;
  pubkey: string;
  mgr: SessionNodeManager;
  kp: KeyProvider;
  signaling: ReturnType<typeof makeSignaling>;
  flows: ReturnType<typeof createSealFlows>;
  inbound: ReturnType<typeof createInboundSealRequestHandler>;
  sent: Record<string, unknown>[];
}

describe("017-SEAL S3 — both sides in directory-only fallback at once → the session seals", () => {
  let tempDir = "";
  const mgrs: SessionNodeManager[] = [];
  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "m10e-017-tiebreak-")); });
  afterEach(async () => {
    for (const m of mgrs.splice(0)) { try { await m.close?.(); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("the higher-pubkey side answers the late co-sign request, and both closes seal", async () => {
    // Two real managers, real SQLCipher, real agent keys. 'alice'/'bob' are labels; the live
    // stall's roles are decided by pubkey order, which is what the tie-break keys on.
    async function buildSide(label: string, dbName: string): Promise<Side> {
      const mgr = new SessionNodeManager({
        securityGateway: new PassthroughGatewayClient(),
        factory: new StubFactory(),
        logger: makeLogger(),
        dbPath: join(tempDir, dbName),
      });
      await mgr.initialize();
      mgrs.push(mgr);
      const seeded = await seedAgentKeys(mgr.getDb(), [label]);
      const pubkey = seeded.get(label)!.pubkeyHex;
      const { loaded } = await loadAgents(mgr.getDb(), makeLogger());
      const kp = loaded.find((a) => a.name === label)!.keyProvider;
      return { name: label, pubkey, mgr, kp, signaling: makeSignaling(), flows: null as never, inbound: null as never, sent: [] };
    }

    const a = await buildSide("alice", "alice.db");
    const b = await buildSide("bob", "bob.db");
    // The HIGHER pubkey is the one that must answer when already pending. Make it the side that
    // completes first and therefore receives the other's LATE request (the collision the fix is for).
    const [high, low] = a.pubkey > b.pubkey ? [a, b] : [b, a];

    // Insert an ACTIVE session row on each side for the same session id, counterparty = the other.
    const insertActive = async (side: Side, counterparty: string): Promise<void> => {
      const now = Date.now();
      const agentId = side.mgr.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(side.name) as { agent_id: string };
      side.mgr.getDb().prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at)
         VALUES (?, ?, ?, 'active', ?, ?)`,
      ).run(SID, agentId.agent_id, counterparty, now, now);
    };
    await insertActive(a, b.pubkey);
    await insertActive(b, a.pubkey);

    // ── The router: carry the real seal frames between the two real handlers. ──
    // A request is DEFERRED (queued) so the test can release the two in a controlled order and
    // reproduce the asymmetric collision; an ack/rejection is delivered straight to the recipient's
    // signaling (its awaitSealAck is waiting on exactly that).
    const sideByPubkey = new Map<string, Side>([[a.pubkey, a], [b.pubkey, b]]);
    const queuedRequests: Array<{ to: Side; frame: Record<string, unknown> }> = [];
    const makeSendOver = (from: Side) => async (_agentName: string, frame: Record<string, unknown>): Promise<{ ok: boolean }> => {
      from.sent.push(frame);
      const type = frame["type"];
      if (type === "seal_interrupted_request") {
        const to = sideByPubkey.get(frame["counterpartyPubkey"] as string)!;
        queuedRequests.push({ to, frame });
        return { ok: true };
      }
      if (type === "seal_interrupted_ack" || type === "seal_interrupted_rejection") {
        const to = sideByPubkey.get(frame["initiatorPubkey"] as string)!;
        to.signaling.deliver(frame);
        return { ok: true };
      }
      return { ok: true };
    };

    const wire = (side: Side): void => {
      const deps = {
        logger: makeLogger(),
        sessionNodeManager: side.mgr,
        agents: [{ name: side.name, state: "online", pubkey: side.pubkey }] as AgentInfo[],
        getKeyProvider: (n: string) => (n === side.name ? side.kp : undefined),
        signalingFor: (_n: string) => side.signaling as never,
        sendOver: makeSendOver(side),
        recordFrontierMismatch: () => {},
        clearFrontierMismatch: () => {},
      };
      side.flows = createSealFlows(deps);
      side.inbound = createInboundSealRequestHandler(deps);
    };
    wire(a); wire(b);

    const recordOf = (side: Side): SessionRecord => side.mgr.getSessionRecord(side.name, SID)!;

    // Both sides fall back to the directory-only seal at the same moment.
    const pHigh = high.flows.handleActiveSealFlow(SID, recordOf(high), "cid-high");
    const pLow = low.flows.handleActiveSealFlow(SID, recordOf(low), "cid-low");

    // Let both initiators send their requests and begin awaiting (both now queued).
    await new Promise((r) => setTimeout(r, 0));
    expect(queuedRequests.length, "both sides should have sent a co-sign request").toBe(2);

    const reqToHigh = queuedRequests.find((q) => q.to === high)!; // low's request, headed at high
    const reqToLow = queuedRequests.find((q) => q.to === low)!;   // high's request, headed at low

    // 1) Deliver HIGH's request to LOW while LOW is still active: LOW co-signs, advances to pending,
    //    and acks — which completes HIGH's initiator commitment. HIGH's close resolves ok.
    await low.inbound.handleInboundSealInterruptedRequest(reqToLow.frame);
    expect((await pHigh).ok, "the first side to complete must seal").toBe(true);
    expect(recordOf(high).status).toBe("seal_interrupted_pending");

    // 2) Now LOW's request lands on HIGH, which is ALREADY pending. The tie-break says the higher
    //    pubkey answers rather than refusing, so HIGH co-signs — completing LOW's commitment — and
    //    LOW, finding itself already pending, treats that as the success it is.
    await high.inbound.handleInboundSealInterruptedRequest(reqToHigh.frame);
    const lowResult = await pLow;
    expect(lowResult.ok, `the late side must also seal, not strand: ${JSON.stringify(lowResult)}`).toBe(true);

    // The tie-break's observable effect: the HIGHER side ANSWERED the late request (an ack), it did
    // not refuse it. Remove the tie-break and this is a rejection instead.
    const higherAnswered = high.sent.some((f) => f["type"] === "seal_interrupted_ack" && f["sessionId"] === SID);
    expect(higherAnswered, "the higher-pubkey side must ANSWER the late co-sign request, not refuse it").toBe(true);

    // Both sides reached the bilateral commitment.
    expect(recordOf(low).status).toBe("seal_interrupted_pending");
  });
});
