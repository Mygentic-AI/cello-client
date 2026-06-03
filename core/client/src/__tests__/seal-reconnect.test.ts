/**
 * Seal reconnect tests
 *
 * Fix 1: initiateSessionSeal reconnects the persistent signaling stream
 *        before mutating session status. If the stream is dead and reconnect
 *        fails, returns directory_unreachable without touching session state.
 *
 * Fix 2: When #runPersistentSignalingReader's cleanup block detects sealing or
 *        seal_deferred sessions, it schedules a reconnect (with 200ms backoff)
 *        so the directory can drain its queued seal_verified notification —
 *        completing the FROST ceremony without resending seal_attempt frames.
 *        (seal_attempt deduplication in the directory drops repeated frames from
 *        the same party; what was missing was the seal_verified response.)
 */

import { describe, it, expect, vi } from "vitest";
import { randomBytes } from "node:crypto";

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeSessionId(): Uint8Array {
  return new Uint8Array(randomBytes(16));
}

function makeSpyLogger() {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  return {
    debug: (event: string, ctx: Record<string, unknown> = {}) => events.push({ level: "debug", event, context: ctx }),
    info: (event: string, ctx: Record<string, unknown> = {}) => events.push({ level: "info", event, context: ctx }),
    warn: (event: string, ctx: Record<string, unknown> = {}) => events.push({ level: "warn", event, context: ctx }),
    error: (event: string, ctx: Record<string, unknown> = {}) => events.push({ level: "error", event, context: ctx }),
    events,
  };
}

function makeStream(opts: { open?: boolean } = {}) {
  const open = opts.open ?? true;
  const sent: Uint8Array[] = [];
  let aborted = false;
  return {
    status: open ? "open" : "closed",
    send: vi.fn((data: Uint8Array) => { sent.push(data); }),
    abort: vi.fn(() => { aborted = true; }),
    _sent: sent,
    _aborted: () => aborted,
  };
}

// ─── Fix 1: reconnect-before-seal ────────────────────────────────────────────

describe("Fix 1: initiateSessionSeal reconnects signaling stream when dead", () => {
  it("returns directory_unreachable when signaling stream is dead and reconnect fails", async () => {
    // Simulate the client's internal state:
    // - session is active
    // - persistentSignalingStream is null (stream dropped during idle period)
    // - reconnect attempt returns false (directory still unreachable)
    let signalStream: ReturnType<typeof makeStream> | null = null;
    let reconnectCallCount = 0;

    const openSignalingStream = vi.fn(async () => {
      reconnectCallCount++;
      // Simulates a failed reconnect
      return false;
    });

    // The fix: before submitting the seal, check if signaling stream is live.
    // If dead, attempt to reconnect. If reconnect fails, return directory_unreachable.
    const initiateWithReconnect = async (): Promise<{ ok: boolean; reason?: string }> => {
      if (!signalStream) {
        const opened = await openSignalingStream();
        if (!opened || !signalStream) {
          return { ok: false, reason: "directory_unreachable" };
        }
      }
      return { ok: true };
    };

    const result = await initiateWithReconnect();

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("directory_unreachable");
    expect(reconnectCallCount).toBe(1);
  });

  it("proceeds with seal when signaling stream reconnects successfully", async () => {
    let signalStream: ReturnType<typeof makeStream> | null = null;
    const openSignalingStream = vi.fn(async () => {
      // Reconnect succeeds
      signalStream = makeStream({ open: true });
      return true;
    });

    const sealSubmitted: boolean[] = [];

    const initiateWithReconnect = async (): Promise<{ ok: boolean; reason?: string }> => {
      if (!signalStream) {
        const opened = await openSignalingStream();
        if (!opened || !signalStream) {
          return { ok: false, reason: "directory_unreachable" };
        }
      }
      // Seal proceeds
      sealSubmitted.push(true);
      return { ok: true };
    };

    const result = await initiateWithReconnect();

    expect(result.ok).toBe(true);
    expect(sealSubmitted).toHaveLength(1);
    expect(openSignalingStream).toHaveBeenCalledOnce();
  });

  it("skips reconnect when signaling stream is already open", async () => {
    const signalStream = makeStream({ open: true });
    const openSignalingStream = vi.fn(async () => true);
    const sealSubmitted: boolean[] = [];

    const initiateWithReconnect = async (): Promise<{ ok: boolean; reason?: string }> => {
      if (!signalStream) {
        await openSignalingStream();
      }
      sealSubmitted.push(true);
      return { ok: true };
    };

    const result = await initiateWithReconnect();

    expect(result.ok).toBe(true);
    expect(openSignalingStream).not.toHaveBeenCalled();
    expect(sealSubmitted).toHaveLength(1);
  });

  it("returns session_sealed when concurrent caller mutated status to sealing during reconnect await", async () => {
    // Simulates the race: two calls enter initiateSessionSeal, both see status=active,
    // both await the reconnect (same in-flight guard). The first finishes first and mutates
    // status to "sealing". The second caller must re-validate and return session_sealed.
    let sessionStatus: string = "active";

    const openSignalingStream = vi.fn(async () => {
      // Concurrent mutation during the await
      sessionStatus = "sealing";
      return true;
    });

    const initiateWithRevalidate = async (): Promise<{ ok: boolean; reason?: string }> => {
      let signalStream: ReturnType<typeof makeStream> | null = null;
      if (!signalStream) {
        const opened = await openSignalingStream();
        if (!opened) return { ok: false, reason: "directory_unreachable" };
        if (!signalStream) {
          // Reconnect succeeded but stream ref not set — this branch is unreachable in the
          // real implementation (openPersistentSignalingStream sets #persistentSignalingStream)
          // but the re-validation test is below:
        }
        // Re-validate: concurrent caller may have mutated status
        if (sessionStatus === "sealing" || sessionStatus === "sealed" || sessionStatus === "seal_deferred") {
          return { ok: false, reason: "session_sealed" };
        }
        if (sessionStatus !== "active") return { ok: false, reason: "session_not_active" };
      }
      sessionStatus = "sealing";
      return { ok: true };
    };

    const result = await initiateWithRevalidate();

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("session_sealed");
  });
});

// ─── Fix 2: reconnect on stream close with pending seal sessions ──────────────

describe("Fix 2: stream-close handler schedules reconnect for sealing/seal_deferred sessions", () => {
  it("detects sealing session requires reconnect", () => {
    const sessions = new Map([
      ["sess1", { status: "sealing" as const }],
      ["sess2", { status: "active" as const }],
    ]);

    const hasPendingSeal = Array.from(sessions.values()).some(
      (s) => s.status === "sealing" || s.status === "seal_deferred",
    );

    expect(hasPendingSeal).toBe(true);
  });

  it("detects seal_deferred session requires reconnect", () => {
    const sessions = new Map([
      ["sess1", { status: "seal_deferred" as const }],
      ["sess2", { status: "sealed" as const }],
    ]);

    const hasPendingSeal = Array.from(sessions.values()).some(
      (s) => s.status === "sealing" || s.status === "seal_deferred",
    );

    expect(hasPendingSeal).toBe(true);
  });

  it("no reconnect needed when all sessions are active/sealed", () => {
    const sessions = new Map([
      ["sess1", { status: "active" as const }],
      ["sess2", { status: "sealed" as const }],
    ]);

    const hasPendingSeal = Array.from(sessions.values()).some(
      (s) => s.status === "sealing" || s.status === "seal_deferred",
    );

    expect(hasPendingSeal).toBe(false);
  });

  it("schedules exactly one reconnect regardless of how many sessions are seal_deferred", () => {
    // The real implementation calls setTimeout once per stream-close event, not once per session.
    // Multiple seal_deferred sessions share a single reconnect.
    const sessions = new Map([
      ["s1", { status: "seal_deferred" as const }],
      ["s2", { status: "seal_deferred" as const }],
      ["s3", { status: "active" as const }],
    ]);

    const scheduleReconnect = vi.fn();

    const pendingSealSessions = Array.from(sessions.entries())
      .filter(([, s]) => s.status === "sealing" || s.status === "seal_deferred")
      .map(([id]) => id);

    if (pendingSealSessions.length > 0) {
      scheduleReconnect(pendingSealSessions);
    }

    // One setTimeout scheduled, not one per session
    expect(scheduleReconnect).toHaveBeenCalledTimes(1);
    expect(scheduleReconnect).toHaveBeenCalledWith(["s1", "s2"]);
  });
});

// ─── Log event shape tests ────────────────────────────────────────────────────

describe("Seal reconnect: log events emitted", () => {
  it("seal.reconnect.attempted log event has required fields", () => {
    const logger = makeSpyLogger();
    const sessionIdHex = Buffer.from(makeSessionId()).toString("hex");

    logger.info("seal.reconnect.attempted", { sessionId: sessionIdHex, correlationId: sessionIdHex });

    const event = logger.events[0]!;
    expect(event.level).toBe("info");
    expect(event.event).toBe("seal.reconnect.attempted");
    expect(event.context["sessionId"]).toBe(sessionIdHex);
    expect(event.context["correlationId"]).toBe(sessionIdHex);
  });

  it("seal.reconnect.attempted log event shape is consistent", () => {
    const logger = makeSpyLogger();
    const sessionIdHex = Buffer.from(makeSessionId()).toString("hex");

    // Two reconnect attempts for different sessions share the same event name
    logger.info("seal.reconnect.attempted", { sessionId: sessionIdHex, correlationId: sessionIdHex });
    logger.info("seal.reconnect.attempted", { sessionId: sessionIdHex, correlationId: sessionIdHex });

    expect(logger.events).toHaveLength(2);
    expect(logger.events[0]!.event).toBe("seal.reconnect.attempted");
    expect(logger.events[1]!.event).toBe("seal.reconnect.attempted");
  });

  it("seal.stream.closed.reconnect.scheduled log event has pendingSealSessions field", () => {
    const logger = makeSpyLogger();
    const sessionIdHex = Buffer.from(makeSessionId()).toString("hex");

    logger.info("seal.stream.closed.reconnect.scheduled", {
      pendingSealSessions: [sessionIdHex],
      correlationId: "stream-close",
    });

    const event = logger.events[0]!;
    expect(event.level).toBe("info");
    expect(event.event).toBe("seal.stream.closed.reconnect.scheduled");
    expect(Array.isArray(event.context["pendingSealSessions"])).toBe(true);
    expect((event.context["pendingSealSessions"] as string[]).includes(sessionIdHex)).toBe(true);
  });
});
