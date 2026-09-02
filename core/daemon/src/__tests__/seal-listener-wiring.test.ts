/**
 * Every authenticated signaling stream gets the WHOLE seal listener set — or the seal is lost.
 *
 * THE BUG THIS PINS (found by the Seam B refactor, 2026-07-13):
 *
 * The daemon wired three seal listeners onto its home streams, but the VISITING stream (the
 * transient connection opened to another agent's home node for a cross-node session) got only two
 * of them — no `seal_unilateral_notification` handler. That looked deliberate. It was not.
 *
 * The directory drains its durable notification queue on ANY stream that authenticates, visiting
 * included, and `acknowledge()` DELETES the row once it is sent (directory-node.ts ~1894-2003; the
 * queue is cross-node replicated, so every node holds every agent's pending notifications). So:
 *
 *   1. B has an unratified unilateral seal waiting.
 *   2. B opens a routine VISITING connection to some other agent's home node.
 *   3. That node authenticates B, drains the queue, and pushes seal_unilateral_notification down
 *      the visiting stream — where B has no handler for it.
 *   4. The frame is dropped on the floor. The directory deletes the durable row.
 *   5. B never runs the DOD-UP-1 KERNEL, never ratifies, never persists its receipt.
 *      The seal stays unilateral FOREVER.
 *
 * Silent, permanent loss of a notarized seal receipt — the exact guarantee the unilateral/upgrade
 * machinery exists to provide.
 *
 * The fix is structural, not a one-line patch: the coordinator no longer lets a caller register the
 * listeners individually. It exposes ONE bundle, so a stream wired with a partial seal listener set
 * is not something you can express. These tests pin the bundle's contents; the type system pins that
 * every call site uses it.
 */
import { describe, it, expect, vi } from "vitest";
import { createSealCoordinator, sealRejectionGuidance } from "../seal-coordinator.js";
import type { SessionNodeManager } from "../session-node-manager.js";
import type { SignalingManager } from "@cello-protocol/transport";

const AGENT = "bob";
const PUBKEY = "b".repeat(64);
const SESSION = "5e" + "a".repeat(30);

/** A SignalingManager that just records the inbound handlers registered on it, and can fire frames. */
function fakeSignaling() {
  const handlers: Array<(frame: Record<string, unknown>) => void> = [];
  return {
    registerInboundHandler: vi.fn((h: (frame: Record<string, unknown>) => void) => {
      handlers.push(h);
      return () => { /* unregister */ };
    }),
    sendRaw: vi.fn(async () => { /* directory send */ }),
    /** Deliver a frame the way the directory would — to every handler on this stream. */
    deliver(frame: Record<string, unknown>) {
      for (const h of handlers) h(frame);
    },
    handlerCount: () => handlers.length,
  };
}

function harness(opts: { holdsSession?: boolean } = {}) {
  const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
  const recoverContent = vi.fn(async () => { /* pull parked content from the relay */ });
  const recordSealFailure = vi.fn();
  const store = {
    // DOD-M15-SEALPARTIES-1: the refusal listener acts only on a session this agent actually holds,
    // because the directory still broadcasts `session_seal_rejected` on some paths.
    getSessionRecord: vi.fn(() => (opts.holdsSession === false ? undefined : { agent_name: AGENT, session_id: SESSION })),
    // The KERNEL's gate. Refusing here is what makes B never sign content it could not verify;
    // returning a refusal (rather than throwing) keeps this test focused on the WIRING.
    getSealUpgradeReadiness: vi.fn(() => ({ ok: false, reason: "content_unrecoverable" })),
    getSessionTree: vi.fn(() => ({ size: () => 0 })),
    getSealCertificate: vi.fn(() => null),
    recordSealCertificateEnsuringRow: vi.fn(),
    markSealed: vi.fn(() => true),
    destroySessionNode: vi.fn(),
  };

  const coordinator = createSealCoordinator({
    logger,
    sessionNodeManager: store as unknown as SessionNodeManager,
    getPersistence: vi.fn() as never,
    getKeyProvider: vi.fn(() => undefined),
    recoverContent,
    recordSealFailure,
  });

  return { coordinator, recoverContent, store, logger, recordSealFailure };
}

describe("the seal listener set is a BUNDLE — a stream cannot be wired with only part of it", () => {
  it("registerSealListeners wires a handler that REACTS to seal_unilateral_notification", async () => {
    const { coordinator, logger } = harness();
    const signaling = fakeSignaling();

    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, PUBKEY);

    signaling.deliver({
      type: "seal_unilateral_notification",
      session_id: SESSION,
      sealed_root: "c".repeat(64),
      present_pubkey: "d".repeat(64),
    });

    // THE BUG, in one assertion. This frame carries no signed certificate, so the DOD-UP-1 KERNEL
    // refuses it — fail-CLOSED, exactly right. But refusing it PROVES the frame was received and
    // processed by the upgrade listener at all. On a VISITING stream before this fix, there was no
    // handler for it: the frame hit the floor in total silence while the directory deleted its
    // durable row. "Refused" is the sound of the seal machinery working; silence was the bug.
    await vi.waitFor(() =>
      expect(logger.warn).toHaveBeenCalledWith(
        "session.seal.upgrade.refused",
        expect.objectContaining({ sessionId: SESSION, reason: "malformed_notification" }),
      ),
    );
  });

  it("the same bundle also wires session_sealed and seal_upgrade_rejected — all three, always", async () => {
    const { coordinator, store, logger } = harness();
    const signaling = fakeSignaling();

    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, PUBKEY);

    // session_sealed → the sealed listener tears the session node down.
    signaling.deliver({ type: "session_sealed", session_id: SESSION, sealed_root: "c".repeat(64) });
    await vi.waitFor(() => expect(store.destroySessionNode).toHaveBeenCalled());

    // seal_upgrade_rejected → the upgrade listener logs it with its reason (never swallowed).
    signaling.deliver({ type: "seal_upgrade_rejected", session_id: SESSION, reason: "already_bilateral" });
    expect(logger.warn).toHaveBeenCalledWith(
      "session.seal.upgrade.rejected",
      expect.objectContaining({ sessionId: SESSION, reason: "already_bilateral" }),
    );
  });

  it("a frame for a DIFFERENT session type is ignored, not mistaken for a seal", () => {
    const { coordinator, store } = harness();
    const signaling = fakeSignaling();

    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, PUBKEY);
    signaling.deliver({ type: "session_assignment", session_id: SESSION });

    expect(store.getSealUpgradeReadiness).not.toHaveBeenCalled();
    expect(store.destroySessionNode).not.toHaveBeenCalled();
  });

  /**
   * `DOD-M15-SEALPARTIES-1` clause 6 — the refusal reaches the operator instead of the floor.
   *
   * `session_seal_rejected` is a frame the directory has sent since M1 and this client had NO
   * consumer for: the only occurrence of the string in the whole repository was the type
   * declaration. So every refusal was decoded, matched no handler, and vanished — while the close
   * that was waiting on it sat out its full window and then reported that the counterparty had not
   * closed, about a seal the directory had already decided against.
   */
  it("★★★ a seal REFUSED by the directory answers the waiting close, with the cause and a remedy", async () => {
    const { coordinator, logger, recordSealFailure } = harness();
    const signaling = fakeSignaling();
    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, PUBKEY);

    let completion: unknown = null;
    coordinator.pendingSealWaiters.set(coordinator.sealKey(AGENT, SESSION), (c) => { completion = c; });

    signaling.deliver({
      type: "session_seal_rejected",
      session_id: SESSION,
      reason: "seal_approval_missing",
      detail: "only one participant's signed root was carried",
    });

    expect(
      completion,
      "the close is BLOCKED on this waiter — leaving it unresolved is how the operator was told " +
        "something false eleven minutes later",
    ).toEqual(expect.objectContaining({ refused: true, reason: "seal_approval_missing" }));
    const c = completion as { guidance?: string; detail?: string };
    expect(c.detail).toContain("only one participant");
    expect(
      c.guidance ?? "",
      "the remedy comes from the party that knows the cause — a close handler guessing it would " +
        "print 'the directory signed a root that is not your conversation' about a signature that " +
        "was never produced",
    ).toMatch(/counterparty/i);
    expect(c.guidance ?? "").toMatch(/do not force-abandon/i);

    // The durable forensic record keeps its half — the response never replaces the log.
    expect(logger.error).toHaveBeenCalledWith(
      "session.seal.rejected",
      expect.objectContaining({ sessionId: SESSION, reason: "seal_approval_missing" }),
    );
    // And the second surface, because the response is gone the moment its caller reads it.
    expect(recordSealFailure).toHaveBeenCalledWith(AGENT, SESSION, "seal_approval_missing");
  });

  it("★★ the two refusals send the operator to DIFFERENT places, because they accuse different parties", () => {
    const approval = sealRejectionGuidance("seal_approval_missing", "");
    const disagree = sealRejectionGuidance("seal_parties_disagree", "");
    expect(
      approval,
      "nobody's record is wrong here — the counterparty's approval did not arrive, so the next step " +
        "is to have them close again, NOT to go comparing transcripts",
    ).toMatch(/close again/i);
    expect(approval).not.toMatch(/compare the message list/i);
    expect(
      disagree,
      "this one IS a content disagreement, and it cannot be settled from inside the session",
    ).toMatch(/compare the message list/i);
  });

  it("★★ a refusal for a session this agent does NOT hold is ignored — the frame is still broadcast", () => {
    /**
     * The directory broadcasts `session_seal_rejected` to every authenticated stream on the node for
     * the refusal paths that fire before it resolves the roster. Acting on one would let any
     * stranger's session id write a phantom failure into this agent's record and, worse, resolve a
     * waiter that belongs to a healthy close.
     */
    const { coordinator, logger, recordSealFailure } = harness({ holdsSession: false });
    const signaling = fakeSignaling();
    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, PUBKEY);

    signaling.deliver({ type: "session_seal_rejected", session_id: SESSION, reason: "seal_approval_missing" });

    expect(recordSealFailure).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalledWith("session.seal.rejected", expect.anything());
  });

  it("the individual listeners are NOT exported — a partial seal wiring must not be expressible", () => {
    const { coordinator } = harness();

    // The bug was possible only because a caller could register two of the three by hand. Removing
    // that ability is the fix; this asserts the escape hatch is really gone.
    expect(coordinator).not.toHaveProperty("registerSessionSealedListener");
    expect(coordinator).not.toHaveProperty("registerUnilateralConfirmedListener");
    expect(coordinator).not.toHaveProperty("registerUnilateralUpgradeListener");
    expect(coordinator.registerSealListeners).toBeInstanceOf(Function);
  });
});
