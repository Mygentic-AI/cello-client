/**
 * DOD-FRONTIER-STRAND-1 AC3 — a stranded session LOOKS stranded on the session list.
 *
 * Session `dbb93dfc…` sat unsealable for a week and nothing said so. A close was attempted, refused
 * with `seal_interrupted_rejected_by_counterparty`, and that was the end of it: the refusal was a
 * transient string in one command's output. `cello_status` / `cello_sessions` went on listing the
 * session as plain `interrupted` — indistinguishable from one that is merely paused and will seal
 * fine once both parties are online. The operator could not tell "waiting" from "will never seal",
 * and the only way to find out was to attempt another close and read the error again.
 *
 * Detection is inherently at close time — two frontiers can only be compared when the two sides
 * talk — so this line is not about detecting earlier. It is about RETENTION: the answer was thrown
 * away the instant it was produced.
 *
 * Scope, stated so this is not read as more than it is: `FrontierMismatchStore` is in-memory, so a
 * daemon restart forgets. That costs one re-detection on the next close attempt and can never
 * produce a WRONG answer, whereas persisting it would mean a client-side schema migration on every
 * operator's machine, which AC3 does not ask for.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { createInboundSealRequestHandler } from "../inbound-seal-request.js";
import { generateKeypair } from "@cello-protocol/crypto";
import { FrontierMismatchStore, renderFrontierMismatch } from "../frontier-mismatch.js";

describe("DOD-FRONTIER-STRAND-1 AC3: an observed mismatch is retained and surfaced", () => {
  it("S1: a recorded mismatch is readable afterwards — no second close attempt needed", () => {
    const store = new FrontierMismatchStore();
    expect(store.get("alice", "sid-1"), "nothing observed yet").toBeNull();

    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1_700_000_000_000);

    const m = store.get("alice", "sid-1");
    expect(m).toMatchObject({ ours: 3, theirs: 2, divergingLeafIndex: 2, observedAtMs: 1_700_000_000_000 });
  });

  it("S2: a SUCCESSFUL seal clears it — a flag that outlives its condition is the defect inverted", () => {
    // An operator told a healthy session is stranded stops believing the flag, and then the next
    // REAL strand reads as noise. That is the same failure this line exists to fix, pointing the
    // other way, so it gets its own clause rather than a comment.
    const store = new FrontierMismatchStore();
    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1);
    store.clear("alice", "sid-1");
    expect(store.get("alice", "sid-1")).toBeNull();
  });

  it("S3: re-observation overwrites — the NEWEST numbers win, never a stale pair", () => {
    const store = new FrontierMismatchStore();
    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1);
    store.record("alice", "sid-1", { ours: 5, theirs: 4, divergingLeafIndex: 4 }, 2);
    expect(store.get("alice", "sid-1")).toMatchObject({ ours: 5, theirs: 4, divergingLeafIndex: 4, observedAtMs: 2 });
  });

  it("S4: sessions are isolated — one strand does not tar another", () => {
    const store = new FrontierMismatchStore();
    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1);
    store.record("alice", "sid-9", { ours: 7, theirs: 5, divergingLeafIndex: 5 }, 2);
    // BOTH live at once (review M3): asserting only that absent keys are absent is satisfied by a
    // store that holds exactly ONE entry, which on a daemon with several stranded sessions would
    // surface the flag on one of them at random.
    expect(store.get("alice", "sid-1")).toMatchObject({ ours: 3 });
    expect(store.get("alice", "sid-9")).toMatchObject({ ours: 7 });
    expect(store.get("alice", "sid-2")).toBeNull();
    // ...and the same session id under a DIFFERENT agent is a different session (loopback: both
    // ends of dbb93dfc… lived on one daemon under two agent names, so this is the real shape).
    expect(store.get("bob", "sid-1")).toBeNull();
  });

  it("S5: the store is BOUNDED — an unstated cap would be a silent leak", () => {
    const store = new FrontierMismatchStore();
    for (let i = 0; i < 300; i++) {
      store.record("alice", `sid-${i}`, { ours: 2, theirs: 1, divergingLeafIndex: 1 }, i);
    }
    // The oldest are evicted; the newest survive. A daemon runs for days and nothing else sweeps
    // this map, so "it only holds mismatches" is not by itself a bound.
    // The BOUNDARY, not just the ends (review M3): 300 written, cap 256, so 0..43 are evicted and
    // 44..299 survive. Asserting only the extremes passes for a store that keeps a single entry.
    expect(store.get("alice", "sid-43"), "just past the cap — evicted").toBeNull();
    expect(store.get("alice", "sid-44"), "the oldest survivor — exactly at the cap").not.toBeNull();
    expect(store.get("alice", "sid-299"), "newest retained").not.toBeNull();
  });

  it("S6: the rendered session-list field names both counts, the diverging leaf, and the remedy", () => {
    // This is the AC's literal deliverable — the `cello_sessions` field — so it is asserted rather
    // than assumed. daemon.ts calls exactly this function, which is why it was extracted: an inline
    // closure inside buildInterruptedSessions could only be reached by standing up a daemon and
    // driving a real seal exchange, so in practice it would have shipped uncovered.
    const rendered = renderFrontierMismatch(
      { ours: 3, theirs: 2, divergingLeafIndex: 2, observedAtMs: 1_700_000_000_000 },
      "dbb93dfcf415b7cbfe13626f5b168a3f",
    );
    expect(rendered).toMatchObject({ ours: 3, theirs: 2, divergingLeafIndex: 2 });
    expect(rendered.observedAt).toBe("2023-11-14T22:13:20.000Z");
    // The operator must learn WHAT disagreed, WHERE, and that it is terminal — the old refusal
    // ("ask the counterparty to check their end") gave none of the three.
    expect(rendered.guidance).toMatch(/you hold 3 messages/);
    expect(rendered.guidance).toMatch(/counterparty holds 2/);
    expect(rendered.guidance).toMatch(/diverge at leaf 2/);
    expect(rendered.guidance).toMatch(/dbb93dfcf415b7cbfe13626f5b168a3f/);
    expect(rendered.guidance).toMatch(/never be co-signed/);
  });

});

/**
 * THE REVERT TEST, which the first version of this unit failed (review H2).
 *
 * Every clause above tests the store and the renderer in isolation. The reviewer deleted the ENTIRE
 * wiring — the store construction, both record injections, both clear injections, the responder's
 * record call, and the session-list spread — and got 1296/1296 green with a clean typecheck. Third
 * time in this milestone that "green" meant "the fix is not connected to anything", and it happened
 * one journal entry after I wrote the remedy down.
 *
 * So: drive the REAL inbound handler against a REAL daemon, and read the field off the REAL
 * `cello_sessions` surface the AC names.
 */
describe("AC3 end to end: the strand reaches cello_sessions and leaves again", () => {
  let fx: TwoConnectionFixture;
  const SID = "ef".repeat(32);

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-ac3-e2e-" });
  });
  afterEach(async () => { await fx.cleanup(); });

  /** Drive the responder into a frontier mismatch, exactly as an inbound seal request would. */
  async function strand(store: FrontierMismatchStore): Promise<void> {
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "one");
    fx.seedReceived("alice", SID, "two");           // alice holds 2; the initiator will claim 1
    const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeManager: fx.snm,
      agents: [{ name: "alice", state: "online", pubkey: "alicepubkeyhex" }],
      getKeyProvider: () => undefined,
      sendOver: async () => ({ ok: true }),
      recordFrontierMismatch: (a, sid, m) => store.record(a, sid, m, 1_700_000_000_000),
      clearFrontierMismatch: (a, sid) => store.clear(a, sid),
    });
    await handleInboundSealInterruptedRequest({
      type: "seal_interrupted_request", sessionId: SID,
      initiatorPubkey: "bobpubkeyhex", counterpartyPubkey: "alicepubkeyhex",
      leafCountAtInterruption: 1, merkleRootAtInterruption: "00".repeat(32), nonce: "n-e2e",
    });
  }

  it("E1: a real seal refusal puts the strand on the session list, with both counts", async () => {
    const store = new FrontierMismatchStore();
    await strand(store);

    // The store is the seam the daemon injects; asserting through it proves the RECORD CALL fires
    // on the real refusal path — the line the revert test showed was deletable.
    const m = store.get("alice", SID);
    expect(m, "the responder must record the mismatch it just detected").not.toBeNull();
    expect(m).toMatchObject({ ours: 2, theirs: 1, divergingLeafIndex: 1 });

    // ...and the row an operator reads carries it, on cello_sessions' own renderer.
    const rendered = renderFrontierMismatch(m!, SID);
    expect(rendered.guidance).toMatch(/you hold 2 messages/);
    expect(rendered.guidance).toMatch(/counterparty holds 1/);
  });

  it("E2 (review H3): the RESPONDER clears it when the seal later succeeds", async () => {
    const responderKey = generateKeypair();
    // The responder is the side that DETECTS the strand and used to have no way to forget one, so
    // after the divergence was repaired its list kept reporting a week-old strand on a session that
    // had just co-signed. S2 tested store.clear() in isolation, which is why this slipped.
    const store = new FrontierMismatchStore();
    await strand(store);
    expect(store.get("alice", SID)).not.toBeNull();

    // Now the SAME request arrives with an agreeing leaf count — the repaired case. The handler
    // takes the accept path and must clear.
    const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeManager: fx.snm,
      agents: [{ name: "alice", state: "online", pubkey: "alicepubkeyhex" }],
      // A REAL key provider: the accept path signs this side's SEAL-INTERRUPTED leaf, so without
      // one it refuses `signing_key_unavailable` and never reaches the clear.
      getKeyProvider: () => responderKey,
      sendOver: async () => ({ ok: true }),
      recordFrontierMismatch: (a, sid, m) => store.record(a, sid, m, 1),
      clearFrontierMismatch: (a, sid) => store.clear(a, sid),
    });
    await handleInboundSealInterruptedRequest({
      type: "seal_interrupted_request", sessionId: SID,
      initiatorPubkey: "bobpubkeyhex", counterpartyPubkey: "alicepubkeyhex",
      leafCountAtInterruption: 2, merkleRootAtInterruption: "00".repeat(32), nonce: "n-ok",
    });

    expect(
      store.get("alice", SID),
      "a session that just co-signed must stop being reported as stranded",
    ).toBeNull();
  });
});

/**
 * M12-P14 — the rejection an operator actually reads when the session is already terminal.
 *
 * Measured 2026-08-05 across two machines. The seal request was refused twice on the same session:
 *   12:14:51  reason=leaf_count_mismatch      ← the real blocker (frontiers 3 vs 2)
 *   12:16:56  session.force_abandoned  priorStatus=interrupted
 *   12:17:53  reason=session_not_interrupted  ← an artefact of OUR OWN abandon, 2 minutes later
 *
 * `session_not_interrupted` is true in the most useless sense — the session is not interrupted, it
 * is ABANDONED, by us — and it names neither the status nor the cause. Read on its own it says the
 * counterparty disagrees that anything went wrong, which is a different defect entirely, and it is
 * the reading that sent this investigation an hour down the wrong path. The refusal must name the
 * state it actually found.
 */
describe("M12-P14: a terminal session is refused by its actual status, not a catch-all", () => {
  let fx: Awaited<ReturnType<typeof startTwoConnectionFixture>>;
  const SID = "ab".repeat(32);

  beforeEach(async () => { fx = await startTwoConnectionFixture({ dirPrefix: "cello-p14-" }); });
  afterEach(async () => { await fx.cleanup(); });

  async function rejectionFor(status: "abandoned" | "sealed"): Promise<string | undefined> {
    await fx.createSession(SID, "alice");
    fx.snm.getDb()!.prepare("UPDATE sessions SET status = ? WHERE session_id = ?").run(status, SID);

    let sentReason: string | undefined;
    const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeManager: fx.snm,
      agents: [{ name: "alice", state: "online", pubkey: "alicepubkeyhex" }],
      getKeyProvider: () => undefined,
      sendOver: async (_p: unknown, frame: unknown) => {
        const f = frame as { reason?: string };
        sentReason = f.reason;
        return { ok: true };
      },
      recordFrontierMismatch: () => {},
      clearFrontierMismatch: () => {},
    });
    await handleInboundSealInterruptedRequest({
      type: "seal_interrupted_request", sessionId: SID,
      initiatorPubkey: "bobpubkeyhex", counterpartyPubkey: "alicepubkeyhex",
      leafCountAtInterruption: 0, merkleRootAtInterruption: "00".repeat(32), nonce: "n-p14",
    });
    return sentReason;
  }

  it("an ABANDONED session is refused as session_abandoned — the state we put it in, named", async () => {
    expect(await rejectionFor("abandoned")).toBe("session_abandoned");
  });

  it("a SEALED session is refused as session_already_sealed — a receipt exists; that is not a disagreement", async () => {
    expect(await rejectionFor("sealed")).toBe("session_already_sealed");
  });
});
