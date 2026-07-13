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
import { createSealCoordinator } from "../seal-coordinator.js";
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

function harness() {
  const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
  const recoverContent = vi.fn(async () => { /* pull parked content from the relay */ });
  const store = {
    // The KERNEL's gate. Refusing here is what makes B never sign content it could not verify;
    // returning a refusal (rather than throwing) keeps this test focused on the WIRING.
    getSealUpgradeReadiness: vi.fn(() => ({ ok: false, reason: "content_unrecoverable" })),
    getSessionTree: vi.fn(() => ({ size: () => 0 })),
    getSealCertificate: vi.fn(() => null),
    recordSealCertificateEnsuringRow: vi.fn(),
    destroySessionNode: vi.fn(),
  };

  const coordinator = createSealCoordinator({
    logger,
    sessionNodeManager: store as unknown as SessionNodeManager,
    getPersistence: vi.fn() as never,
    getKeyProvider: vi.fn(() => undefined),
    recoverContent,
  });

  return { coordinator, recoverContent, store, logger };
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
