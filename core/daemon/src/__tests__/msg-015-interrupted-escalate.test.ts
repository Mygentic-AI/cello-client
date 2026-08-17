/**
 * DOD-M12B-INTERRUPTED-ESCALATE-1 — an interrupted session must be able to obtain a RECEIPT.
 *
 * Found 2026-08-17 by the review of DOD-M12B-RESTART-SEAL-1. `cello_close_session` on an
 * `interrupted` session takes a branch **every exit returns from**, so the `if (record.status ===
 * "active")` block below it — the only place the unilateral escalation lived — was structurally
 * unreachable. The interrupted branch's success type is literally
 * `{ ok: true; status: "seal_interrupted_pending" }`, and the handler says so itself:
 *
 *   "THE BILATERAL COMMITMENT IS NOT THE SEAL… an interrupted session reached a mutually signed
 *    record that nobody was ever asked to notarize."
 *
 * The responder confirms it: `inbound-seal-request.ts` persists its commitment, acks, and never
 * submits a seal leaf. The relay notarizes only once BOTH parties have posted, so one side's leaf
 * can never be enough — waiting for the relay round was waiting for something that cannot happen.
 *
 * **Measured cost: 26 sessions sat in `seal_interrupted_pending` for up to 10.5 days**, and
 * `cello_close_session` refuses that status by name, so there was no way out at all. This is Andre's
 * "most of the time we can't even close them", stated in code.
 *
 * WHAT MUST NOT BREAK — the trust decision. A unilateral seal notarizes OUR reported root with the
 * counterparty absent. That is legitimate when they agreed (the commitment landed) or when they
 * never answered. It is NOT legitimate after they actively REFUSED: a rejection means the two trees
 * disagree, and notarizing over a stated objection is the one thing a trust layer must not do.
 *
 * Revert test: drop the escalation call and the first case fails — no `seal_unilateral` frame is
 * ever sent and the close returns a commitment instead of a receipt.
 */
import { describe, it, expect, vi } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import type { Logger } from "../types.js";

const AGENT = "alice";
const SESSION = "7a".repeat(32);
const ROOT = "ab".repeat(32);
/** A real relay-witnessed carry: sequences 1..3, contiguous, every leaf relay-receipted. The
 *  escalation refuses locally on an empty or gappy carry, so a stub of `[]` would prove nothing
 *  except that the refusal fires. */
const CARRY = [1, 2, 3].map((n) => ({
  sequenceNumber: n,
  leafKind: n === 3 ? 0x02 : 0x00,
  senderPubkeyHex: "11".repeat(32),
  structure2Cbor: new Uint8Array([n]),
  structure1Cbor: new Uint8Array([n, n]),
  relayId: "relay-1",
  relayTimestamp: 1_700_000_000_000 + n,
  relaySignatureHex: "cc".repeat(64),
}));
const SEALED_ROOT = "cd".repeat(32);

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

function harness(opts: {
  /** The session's status. Defaults to the interrupted case. */
  status?: string;
  /** What the bilateral commitment exchange did. */
  flow: { ok: true; sessionId: string; status: string } | { ok: false; reason: string; guidance: string };
  /** What the directory answers the `seal_unilateral` request with. Absent → never answers. */
  directory?: { ok: true; sealedRootHex: string } | { ok: false; reason: string; remainingSeconds?: number };
  /** Override the relay-witnessed carry (empty / gappy cases). */
  carry?: typeof CARRY;
}) {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const sentFrames: Array<Record<string, unknown>> = [];
  const pendingUnilateralWaiters = new Map<string, (r: unknown) => void>();

  const sendOver = vi.fn(async (_agent: string, frame: Record<string, unknown>) => {
    sentFrames.push(frame);
    // Stand in for the directory: answer the moment the request goes out.
    if (frame["type"] === "seal_unilateral" && opts.directory) {
      const resolve = pendingUnilateralWaiters.get(SESSION);
      if (resolve) queueMicrotask(() => resolve(opts.directory));
    }
    return { ok: true };
  });

  registerCloseSessionHandler({
    handlers,
    logger: silent,
    sessionNodeManager: {
      getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status: opts.status ?? "interrupted" }),
      submitSealLeaf: async () => ({ ok: true as const, sequenceNumber: 4, reportedRootHex: ROOT }),
      getSealCarry: () => (opts.carry ?? CARRY),
      getSealCertificate: () => null,
      resolveAgentId: () => "aid",
      setSessionName: () => {},
      sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0 }),
    },
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    // MUST match the carry's senderPubkeyHex — the duplicate-ctrl-leaf check asks "is this leaf
    // OURS?", and a harness whose agent key differs from every leaf it stubs would answer no to
    // everything and prove nothing.
    getKeyProvider: () => ({ getPublicKey: async () => new Uint8Array(32).fill(0x11) }),
    signalingFor: () => ({ status: "connected" }),
    sendOver,
    waitForSignalingConnected: async () => true,
    openVisitingConnection: () => ({ mgr: {}, stop: async () => {} }),
    crossNodeBrokerBySession: new Map<string, string>(),
    sealKey: (a: string, s: string) => `${a}:${s}`,
    sealInterruptedInProgress: new Set<string>(),
    pendingSealWaiters: new Map(),
    pendingUnilateralWaiters,
    resolveConsortiumRoster: async () => [],
    unilateralTimeoutMs: 50,
    handleSealInterruptedFlow: async () => opts.flow,
    handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
  } as never);

  return {
    close: handlers.get("cello_close_session")!,
    sentFrames,
    unilateralFrames: () => sentFrames.filter((f) => f["type"] === "seal_unilateral"),
  };
}

describe("DOD-M12B-INTERRUPTED-ESCALATE-1: an interrupted close can earn a receipt", () => {
  it("escalates to a unilateral seal and returns a REAL receipt, not a commitment", async () => {
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; sealed_root?: string; seal_type?: string; status?: string;
    };

    expect(
      h.unilateralFrames().length,
      "the interrupted branch must ASK the directory to notarize — before this unit it never could",
    ).toBe(1);
    expect(res.ok).toBe(true);
    expect(res.sealed_root, "a receipt, not a mutually signed record nobody notarized").toBe(SEALED_ROOT);
    expect(res.seal_type).toBe("unilateral");
    expect(res.status, "it must no longer answer with the stuck status").not.toBe("seal_interrupted_pending");

    // WHAT THE FRAME CARRIES, not merely that one was sent. Asserting only `type` let a version of
    // this test pass with an all-zero root, sequence 0 and an empty leaf chain — a request the
    // directory refuses on three separate grounds. The root and sequence must be the ones
    // `submitSealLeaf` computed, and the carry must be forwarded verbatim, because the directory
    // rebuilds and re-verifies the tree from exactly these bytes.
    const frame = h.unilateralFrames()[0]!;
    expect(Buffer.from(frame["reported_root"] as Uint8Array).toString("hex")).toBe(ROOT);
    expect(frame["reported_seq"]).toBe(4);
    const leaves = frame["seal_leaves"] as Array<Record<string, unknown>>;
    expect(leaves.map((l) => l["sequence_number"])).toEqual([1, 2, 3]);
    expect(leaves.map((l) => l["leaf_kind"])).toEqual([0x00, 0x00, 0x02]);
    expect(leaves[0]!["relay_id"], "the relay receipt is the seq-pinning teeth — it must survive the hop").toBe("relay-1");
    expect(Buffer.from(leaves[0]!["relay_signature"] as Uint8Array).toString("hex")).toBe("cc".repeat(64));
  });

  it("refuses LOCALLY, by name, when this side holds no relay-witnessed leaves", async () => {
    // The directory refuses an empty carry with a bare `return` and no frame, so the caller waits
    // 30 s and reports `seal_unilateral_timeout` — the name of our own wait, which is the one thing
    // that was working. Six other directory refusals collapse into that same label. This is the
    // dominant cause and it is knowable here.
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
      carry: [],
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { seal_pending_reason?: string };

    expect(h.unilateralFrames().length, "nothing should be sent when we already know it will be refused").toBe(0);
    expect(res.seal_pending_reason, "the reason must name the cause, not our timeout").toBe("seal_carry_empty");
  });

  it("refuses LOCALLY, by name, when the chain this side holds has a gap", async () => {
    // A unilateral seal requires an unbroken 1..N. A message the relay witnessed but never
    // delivered to us leaves a hole, and the directory's contiguity check is what catches a short
    // chain when the absent counterparty cannot object. Saying so here saves 30 s and names it.
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
      carry: CARRY.filter((l) => l.sequenceNumber !== 2),
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { seal_pending_reason?: string; guidance?: string };

    expect(h.unilateralFrames().length).toBe(0);
    expect(res.seal_pending_reason).toBe("seal_carry_noncontiguous");
    expect(String(res.guidance), "and it must say WHICH sequences it has").toMatch(/1, 3/);
  });

  it("carries the directory's countdown as a NUMBER when the grace has not elapsed", async () => {
    // The field DOD-M12B-RESTART-SEAL-1's resolver consumes. Before this unit it was produced only
    // inside the active branch, which an interrupted session can never enter — so its one named
    // consumer could never reach it.
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: false, reason: "seal_unilateral_too_early", remainingSeconds: 420 },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; retry_after_seconds?: number; seal_receipt?: string; seal_pending_reason?: string;
    };

    expect(res.retry_after_seconds, "a caller that can wait must not have to parse a sentence").toBe(420);
    expect(res.seal_pending_reason).toBe("seal_counterparty_pending");
    // The commitment STANDS. Turning a succeeded commitment into a reported failure is what sends
    // an operator to force:true, which permanently forfeits the half they still hold.
    expect(res.ok, "a successful commitment must never be reported as a failure").toBe(true);
    expect(res.seal_receipt, "but it must not imply a receipt it does not have").toBe("outstanding");
  });

  it("refuses LOCALLY when the carry already holds TWO of our own SEAL ctrl leaves", async () => {
    // The already-poisoned case, and these sessions exist right now: the one-shot submit mark has
    // always been in memory, so any close in flight across a restart could post a second leaf
    // before the durable recovery shipped. The directory refuses them with
    // `unilateral_seal_leaf_invalid` — silently — so each currently costs five resolver attempts
    // and 30 s apiece before surfacing as a directory timeout.
    const poisoned = [...CARRY, {
      sequenceNumber: 4, leafKind: 0x02, senderPubkeyHex: "11".repeat(32),
      structure2Cbor: new Uint8Array([4]), structure1Cbor: new Uint8Array([4, 4]),
      relayId: "relay-1", relayTimestamp: 1_700_000_000_004, relaySignatureHex: "cc".repeat(64),
    }];
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
      carry: poisoned,
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { seal_pending_reason?: string; guidance?: string };

    expect(h.unilateralFrames().length, "no directory can notarize this; asking wastes 30 s to be told nothing").toBe(0);
    expect(res.seal_pending_reason).toBe("seal_carry_duplicate_own_ctrl_leaf");
    expect(String(res.guidance), "and it must say the conversation itself survives").toMatch(/transcript/i);
  });

  it("NEVER escalates after the counterparty REFUSED — that would notarize over their objection", async () => {
    // A rejection means the two trees disagree (leaf_count_mismatch, a diverging index). However
    // stuck the session is, signing our own root against their stated objection is not an option.
    const h = harness({
      flow: { ok: false, reason: "seal_interrupted_rejected_by_counterparty", guidance: "" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; sealed_root?: string };

    expect(h.unilateralFrames().length, "no notarization may be requested over a refusal").toBe(0);
    expect(res.ok).toBe(false);
    expect(res.sealed_root).toBeUndefined();
  });

  it("DOES escalate when the counterparty never answered — that is what a unilateral seal is FOR", async () => {
    // The measured majority case for a restart-orphaned session: the other daemon is not running.
    // Refusing to escalate here would leave exactly the sessions this work exists to resolve stuck.
    const h = harness({
      flow: { ok: false, reason: "seal_interrupted_counterparty_unavailable", guidance: "" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; sealed_root?: string };

    expect(h.unilateralFrames().length, "an absent counterparty is the unilateral seal's whole purpose").toBe(1);
    expect(res.sealed_root).toBe(SEALED_ROOT);
  });

  it("a directory that never answers leaves the commitment intact, and says a receipt is outstanding", async () => {
    // The largest measured failure — `seal_unilateral_timeout`, 50 occurrences. It must not destroy
    // the commitment, and it must not be reported as a receipt.
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      // No `directory` — nothing ever resolves the waiter.
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; seal_receipt?: string; seal_pending_reason?: string; sealed_root?: string;
    };

    expect(res.ok, "the commitment survives a silent directory").toBe(true);
    expect(res.seal_pending_reason).toBe("seal_unilateral_timeout");
    expect(res.seal_receipt).toBe("outstanding");
    expect(res.sealed_root, "and no receipt may be claimed").toBeUndefined();
  });
});

/**
 * DOD-M12B-PENDING-EXIT-1 — `seal_interrupted_pending` had no exit at all.
 *
 * `cello_close_session` refused that status by name with `session_not_closeable` and told the
 * operator it was *"awaiting FROST notarization"*. It was not awaiting anything: nobody ever
 * requests that notarization, because the relay stamps a chain only once BOTH parties have posted a
 * SEAL ctrl leaf and the responder never posts one. **Measured: 26 sessions idle in this status for
 * 0.5 to 10.5 days.**
 *
 * Escalating is safe precisely because of what the status MEANS — both sides signed the same root —
 * and re-entering cannot post a second ctrl leaf, because `submitSealLeaf` recovers the one a
 * previous run posted from the durable carry.
 *
 * Revert test: restore the `session_not_closeable` refusal for this status and the first case fails.
 */
describe("DOD-M12B-PENDING-EXIT-1: a seal_interrupted_pending session can finally end", () => {
  it("escalates instead of refusing, and returns a receipt", async () => {
    const h = harness({
      status: "seal_interrupted_pending",
      flow: { ok: false, reason: "unused", guidance: "" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; reason?: string; sealed_root?: string; seal_type?: string;
    };

    expect(res.reason, "the refusal that gave 26 sessions nowhere to go must be gone").not.toBe("session_not_closeable");
    expect(h.unilateralFrames().length, "it must actually ask the directory").toBe(1);
    expect(res.sealed_root).toBe(SEALED_ROOT);
    expect(res.seal_type).toBe("unilateral");
  });

  it("carries the directory's countdown here too, so an automatic caller can wait", async () => {
    const h = harness({
      status: "seal_interrupted_pending",
      flow: { ok: false, reason: "unused", guidance: "" },
      directory: { ok: false, reason: "seal_unilateral_too_early", remainingSeconds: 300 },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { retry_after_seconds?: number; reason?: string };

    expect(res.retry_after_seconds).toBe(300);
    expect(res.reason).toBe("seal_counterparty_pending");
  });

  it("says the receipt is unobtainable when the relay released the session, rather than 'not closeable'", async () => {
    // The honest end state for an old stuck session: the relay drops one 24 h after the last
    // message, so there is nothing left to notarize from. That is a different fact from "this
    // status cannot be closed", and it is the one the operator needs.
    const h = harness({
      status: "seal_interrupted_pending",
      flow: { ok: false, reason: "unused", guidance: "" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
      carry: [],
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { reason?: string; guidance?: string };

    expect(res.reason).toBe("seal_carry_empty");
    expect(String(res.guidance), "and it must say the conversation itself survives").toMatch(/transcript/i);
  });
});
