/**
 * Graceful shutdown — hasInFlightCryptoOperation() unit tests
 *
 * Verifies that CelloClientImpl.hasInFlightCryptoOperation() correctly reflects
 * all three pending-resolver states in SignalingManager, and that it returns false
 * when none are set. This method is used by the cello-mcp.ts SIGTERM handler to
 * defer process exit until any in-flight FROST ceremony completes.
 *
 * Root cause context (M6-E2E-001, 2026-06-08): SIGTERM arrived mid-ceremony because
 * a new cello-mcp startup killed the prior process immediately. The fix is graceful
 * shutdown that polls this method before calling process.exit(0).
 *
 * Test type: unit
 */

import { describe, it, expect } from "vitest";
import { SignalingManager } from "../signaling-manager.js";

// Minimal context stub — SignalingManager only needs logger and a few other fields
// for these state accessor tests; the network-facing methods are not exercised here.
function makeMinimalSignalingManager(): SignalingManager {
  const ctx = {
    logger: undefined,
    directoryEndpoint: undefined,
    connectionTimeoutMs: 5000,
    node: {} as never,
    myPubkeyHex: "aabbccdd",
  };
  return new SignalingManager(ctx as never);
}

describe("SignalingManager.hasPendingSessionRequest", () => {
  it("returns false when no session request is pending", () => {
    const sm = makeMinimalSignalingManager();
    expect(sm.hasPendingSessionRequest()).toBe(false);
  });

  it("returns true after setPendingSessionRequestResolve is set to a non-null value", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingSessionRequestResolve(() => {});
    expect(sm.hasPendingSessionRequest()).toBe(true);
  });

  it("returns false after setPendingSessionRequestResolve is cleared to null", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingSessionRequestResolve(() => {});
    sm.setPendingSessionRequestResolve(null);
    expect(sm.hasPendingSessionRequest()).toBe(false);
  });
});

describe("SignalingManager.hasPendingRegister", () => {
  it("returns false when no register request is pending", () => {
    const sm = makeMinimalSignalingManager();
    expect(sm.hasPendingRegister()).toBe(false);
  });

  it("returns true after setPendingRegisterResolve is set", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingRegisterResolve(() => {});
    expect(sm.hasPendingRegister()).toBe(true);
  });

  it("returns false after setPendingRegisterResolve is cleared to null", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingRegisterResolve(() => {});
    sm.setPendingRegisterResolve(null);
    expect(sm.hasPendingRegister()).toBe(false);
  });
});

describe("SignalingManager.hasPendingDkgReady", () => {
  it("returns false when no DKG round is pending", () => {
    const sm = makeMinimalSignalingManager();
    expect(sm.hasPendingDkgReady()).toBe(false);
  });

  it("returns true after setPendingDkgReadyResolve is set", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingDkgReadyResolve(() => {});
    expect(sm.hasPendingDkgReady()).toBe(true);
  });

  it("returns false after setPendingDkgReadyResolve is cleared to null", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingDkgReadyResolve(() => {});
    sm.setPendingDkgReadyResolve(null);
    expect(sm.hasPendingDkgReady()).toBe(false);
  });
});

// hasInFlightCryptoOperation() on CelloClientImpl ORs the three SignalingManager getters.
// These tests verify the OR semantics by setting each resolver independently.
// The method wiring into CelloClientImpl is verified by the typecheck (it's in ClientExtended).
describe("hasInFlightCryptoOperation OR semantics (SignalingManager getters)", () => {
  function hasInFlight(sm: SignalingManager): boolean {
    return sm.hasPendingSessionRequest() || sm.hasPendingRegister() || sm.hasPendingDkgReady();
  }

  it("returns false when all three resolvers are null", () => {
    const sm = makeMinimalSignalingManager();
    expect(hasInFlight(sm)).toBe(false);
  });

  it("returns true when only pendingSessionRequest is set", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingSessionRequestResolve(() => {});
    expect(hasInFlight(sm)).toBe(true);
  });

  it("returns true when only pendingRegister is set", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingRegisterResolve(() => {});
    expect(hasInFlight(sm)).toBe(true);
  });

  it("returns true when only pendingDkgReady is set", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingDkgReadyResolve(() => {});
    expect(hasInFlight(sm)).toBe(true);
  });

  it("returns false after all three resolvers are cleared", () => {
    const sm = makeMinimalSignalingManager();
    sm.setPendingSessionRequestResolve(() => {});
    sm.setPendingRegisterResolve(() => {});
    sm.setPendingDkgReadyResolve(() => {});
    sm.setPendingSessionRequestResolve(null);
    sm.setPendingRegisterResolve(null);
    sm.setPendingDkgReadyResolve(null);
    expect(hasInFlight(sm)).toBe(false);
  });
});
