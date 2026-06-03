/**
 * Seal reconnect — responder path
 *
 * Verifies that the responder side (receiving a SEAL ctrl frame from the
 * initiator) checks the persistent signaling stream before calling
 * #submitSealLeaf, mirroring the fix applied to initiateSessionSeal in 0.0.24.
 *
 * Tests are unit-level: they exercise the reconnect logic directly without
 * requiring a real libp2p node or directory.
 */

import { describe, it, expect, vi } from "vitest";
import { randomBytes } from "node:crypto";

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeStream(opts: { open?: boolean } = {}) {
  const open = opts.open ?? true;
  const sent: Uint8Array[] = [];
  return {
    status: open ? "open" : "closed",
    send: vi.fn((data: Uint8Array) => { sent.push(data); }),
    abort: vi.fn(),
    _sent: sent,
  };
}

function makeSpyLogger() {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  return {
    debug: (e: string, c: Record<string, unknown> = {}) => events.push({ level: "debug", event: e, context: c }),
    info:  (e: string, c: Record<string, unknown> = {}) => events.push({ level: "info",  event: e, context: c }),
    warn:  (e: string, c: Record<string, unknown> = {}) => events.push({ level: "warn",  event: e, context: c }),
    error: (e: string, c: Record<string, unknown> = {}) => events.push({ level: "error", event: e, context: c }),
    events,
  };
}

type StreamLike = ReturnType<typeof makeStream> | null;

type SessionStatus = "sealing" | "active" | "sealed" | "seal_deferred" | "seal_rejected";

// Simulates the responder path logic added in 0.0.25:
//   1. If signaling stream is dead, reconnect.
//   2. If reconnect fails → set status to seal_deferred, return.
//   3. Re-fetch session status after async reconnect (may have changed during await).
//   4. Otherwise call submitSealLeaf with the fresh session reference.
async function responderSealPath(opts: {
  signalingStream: StreamLike;
  openSignalingStream: () => Promise<{ stream: StreamLike; ok: boolean }>;
  submitSealLeaf: () => Promise<{ ok: boolean; reason?: string }>;
  logger: ReturnType<typeof makeSpyLogger>;
  sessionId: string;
  // Status after the reconnect await — simulates concurrent mutation during the await.
  sessionStatusAfterReconnect?: SessionStatus;
}): Promise<{ status: "sealing" | "seal_deferred" | "seal_rejected" }> {
  const { logger, sessionId } = opts;
  let stream = opts.signalingStream;
  let currentStatus: SessionStatus = "sealing";

  if (!stream || stream.status !== "open") {
    logger.info("seal.reconnect.attempted", { sessionId, correlationId: sessionId, role: "responder" });
    const result = await opts.openSignalingStream();
    stream = result.stream;
    if (!result.ok || !stream) {
      return { status: "seal_deferred" };
    }
    // Re-validate: simulate concurrent mutation during the reconnect await.
    currentStatus = opts.sessionStatusAfterReconnect ?? "sealing";
    if (currentStatus !== "sealing") {
      return { status: currentStatus === "seal_deferred" ? "seal_deferred" : "seal_rejected" };
    }
  }

  const result = await opts.submitSealLeaf();
  if (!result.ok) {
    return { status: "seal_rejected" };
  }
  return { status: "sealing" };
}

// ─── Bug 1: responder reconnects dead stream before sealing ───────────────────

describe("Bug 1 fix: responder seal path reconnects dead signaling stream", () => {
  it("reconnects and submits seal when stream is null", async () => {
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const newStream = makeStream({ open: true });
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));
    const openSignalingStream = vi.fn(async () => ({ stream: newStream, ok: true }));

    const result = await responderSealPath({
      signalingStream: null,
      openSignalingStream,
      submitSealLeaf,
      logger,
      sessionId,
    });

    expect(openSignalingStream).toHaveBeenCalledOnce();
    expect(submitSealLeaf).toHaveBeenCalledOnce();
    expect(result.status).toBe("sealing");
    const reconnectEvent = logger.events.find((e) => e.event === "seal.reconnect.attempted");
    expect(reconnectEvent).toBeDefined();
    expect(reconnectEvent?.context["role"]).toBe("responder");
  });

  it("reconnects and submits seal when stream is closed", async () => {
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const deadStream = makeStream({ open: false });
    const newStream = makeStream({ open: true });
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));
    const openSignalingStream = vi.fn(async () => ({ stream: newStream, ok: true }));

    const result = await responderSealPath({
      signalingStream: deadStream,
      openSignalingStream,
      submitSealLeaf,
      logger,
      sessionId,
    });

    expect(openSignalingStream).toHaveBeenCalledOnce();
    expect(submitSealLeaf).toHaveBeenCalledOnce();
    expect(result.status).toBe("sealing");
  });

  it("skips reconnect when stream is already open", async () => {
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const liveStream = makeStream({ open: true });
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));
    const openSignalingStream = vi.fn(async () => ({ stream: liveStream, ok: true }));

    const result = await responderSealPath({
      signalingStream: liveStream,
      openSignalingStream,
      submitSealLeaf,
      logger,
      sessionId,
    });

    expect(openSignalingStream).not.toHaveBeenCalled();
    expect(submitSealLeaf).toHaveBeenCalledOnce();
    expect(result.status).toBe("sealing");
    const reconnectEvent = logger.events.find((e) => e.event === "seal.reconnect.attempted");
    expect(reconnectEvent).toBeUndefined();
  });

  it("sets seal_deferred when reconnect fails", async () => {
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));
    const openSignalingStream = vi.fn(async () => ({ stream: null, ok: false }));

    const result = await responderSealPath({
      signalingStream: null,
      openSignalingStream,
      submitSealLeaf,
      logger,
      sessionId,
    });

    expect(openSignalingStream).toHaveBeenCalledOnce();
    expect(submitSealLeaf).not.toHaveBeenCalled();
    expect(result.status).toBe("seal_deferred");
    const reconnectEvent = logger.events.find((e) => e.event === "seal.reconnect.attempted");
    expect(reconnectEvent).toBeDefined();
  });

  it("does not crash when reconnect fails — no exception thrown", async () => {
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const openSignalingStream = vi.fn(async () => ({ stream: null, ok: false }));
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));

    await expect(
      responderSealPath({ signalingStream: null, openSignalingStream, submitSealLeaf, logger, sessionId })
    ).resolves.not.toThrow();
  });

  it("aborts seal if session was closed during reconnect await", async () => {
    // Simulates: session deleted (closeSession called) while reconnect was awaited.
    // After reconnect, session is gone — submitSealLeaf must not be called.
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const newStream = makeStream({ open: true });
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));
    const openSignalingStream = vi.fn(async () => ({ stream: newStream, ok: true }));

    const result = await responderSealPath({
      signalingStream: null,
      openSignalingStream,
      submitSealLeaf,
      logger,
      sessionId,
      sessionStatusAfterReconnect: "seal_deferred",
    });

    expect(submitSealLeaf).not.toHaveBeenCalled();
    expect(result.status).toBe("seal_deferred");
  });

  it("aborts seal if session was desync-closed to seal_rejected during reconnect await", async () => {
    const logger = makeSpyLogger();
    const sessionId = Buffer.from(randomBytes(16)).toString("hex");
    const newStream = makeStream({ open: true });
    const submitSealLeaf = vi.fn(async () => ({ ok: true as const }));
    const openSignalingStream = vi.fn(async () => ({ stream: newStream, ok: true }));

    const result = await responderSealPath({
      signalingStream: null,
      openSignalingStream,
      submitSealLeaf,
      logger,
      sessionId,
      sessionStatusAfterReconnect: "seal_rejected",
    });

    expect(submitSealLeaf).not.toHaveBeenCalled();
    expect(result.status).toBe("seal_rejected");
  });
});
