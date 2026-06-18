/**
 * CELLO-M7-TRANSPORT-001 — transport-selector.test.ts
 *
 * ─── Specification (Phase S) ──────────────────────────────────────────────────
 * Exercises the daemon-side transport selection logic.
 *
 * AC-005 — transport_mode 'direct', direct dial succeeds → dials direct (not
 *   relay), logs session.transport.mode.selected{mode:'direct'}.
 * AC-006 — transport_mode 'direct', direct dial fails, relay succeeds → WARN
 *   session.transport.direct_dial.failed (failureReason = actual error message)
 *   THEN INFO session.transport.mode.selected{mode:'relay'}. The failed direct
 *   dial is NOT surfaced as an error. Relay addr comes from the relay registry,
 *   not the assignment address fields.
 * AC-007 — relay session → dcutr upgrade attempted (non-blocking): success logs
 *   session.transport.dcutr.upgraded (INFO); failure logs session.transport.
 *   dcutr.failed (DEBUG) and the session continues with no error returned.
 * AC-008 — both direct and relay fail → terminal { ok:false,
 *   reason:'relay_fallback_also_failed', guidance } and mode.selected NOT logged.
 * AC-009 — LocalTransportSelectorStub returns configurable results.
 * AC-014 — the four error codes are unique, distinct strings.
 * AC-015 — transport_mode is authoritative; address format never overrides it.
 * AC-004 / AC-019 — selectAdvertisedAddress: dialable→direct, else→relay.
 * SI-001 — 'direct' with an attacker relay-format address is dialed as DIRECT
 *   (never voluntarily routed through the attacker's relay).
 * SI-003 — a dcutr failure never disrupts the relay session.
 * DB-002 — relay unreachable on a 'relay' assignment → relay_fallback_also_failed.
 */

import { describe, it, expect } from "vitest";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import {
  TransportSelector,
  LocalTransportSelectorStub,
  TRANSPORT_ERROR,
  selectAdvertisedAddress,
  type TransportDialer,
  type TransportResult,
} from "../transport-selector.js";
import type { Logger } from "../types.js";

// ─── Test doubles ─────────────────────────────────────────────────────────────

interface LogEntry {
  level: "debug" | "info" | "warn" | "error";
  event: string;
  context: Record<string, unknown>;
}

function recordingLogger(): { logger: Logger; entries: LogEntry[] } {
  const entries: LogEntry[] = [];
  const mk = (level: LogEntry["level"]) => (event: string, context: Record<string, unknown>) =>
    entries.push({ level, event, context });
  return {
    entries,
    logger: { debug: mk("debug"), info: mk("info"), warn: mk("warn"), error: mk("error") },
  };
}

interface FakeDialerOpts {
  directOutcome?: "ok" | Error;
  relayOutcome?: "ok" | Error;
  dcutrOutcome?: "ok" | Error;
  relayAddr?: string;
}

interface FakeDialerCalls {
  dialDirect: Array<{ peerId: string | undefined; addrs: string[] }>;
  dialRelay: Array<{ relayCircuitAddr: string; peerId: string | undefined }>;
  attemptDcutr: Array<{ peerId: string | undefined }>;
}

function fakeDialer(opts: FakeDialerOpts = {}): { dialer: TransportDialer; calls: FakeDialerCalls } {
  const calls: FakeDialerCalls = { dialDirect: [], dialRelay: [], attemptDcutr: [] };
  const relayAddr = opts.relayAddr ?? "/ip4/198.51.100.9/tcp/4001/p2p/12D3KooWRelay/p2p-circuit";
  const dialer: TransportDialer = {
    async dialDirect(peerId, addrs) {
      calls.dialDirect.push({ peerId, addrs });
      if (opts.directOutcome instanceof Error) throw opts.directOutcome;
    },
    async dialRelay(relayCircuitAddr, peerId) {
      calls.dialRelay.push({ relayCircuitAddr, peerId });
      if (opts.relayOutcome instanceof Error) throw opts.relayOutcome;
    },
    relayCircuitAddr() {
      return relayAddr;
    },
    async attemptDcutr(peerId) {
      calls.attemptDcutr.push({ peerId });
      if (opts.dcutrOutcome instanceof Error) throw opts.dcutrOutcome;
    },
  };
  return { dialer, calls };
}

function makeAssignment(overrides: Partial<SessionAssignment> = {}): SessionAssignment {
  const base = {
    session_id: new Uint8Array(16).fill(7),
    participant_a: { pubkey: new Uint8Array(32).fill(1), peer_id: "12D3KooWA", multiaddrs: [] },
    participant_b: { pubkey: new Uint8Array(32).fill(2), peer_id: "12D3KooWB", multiaddrs: [] },
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/198.51.100.9/tcp/4001"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/203.0.113.1/tcp/4001"] },
    session_timestamp: 1_700_000_000_000,
    directory_pubkey: new Uint8Array(32).fill(3),
    directory_signature: new Uint8Array(64).fill(4),
    signature_type: "frost" as const,
    signer_pubkey: new Uint8Array(32).fill(5),
    counterparty_session_peer_id: "12D3KooWCounterSession",
    counterparty_session_addrs: ["/ip4/203.0.113.50/tcp/4001/p2p/12D3KooWCounterSession"],
    transport_mode: "direct" as const,
  };
  return { ...base, ...overrides } as SessionAssignment;
}

const CID = "corr-123";

// ─── AC-005: direct success ────────────────────────────────────────────────────

describe("AC-005: transport_mode 'direct' dials directly and logs mode:'direct'", () => {
  it("dials the direct addresses, never the relay, and logs mode.selected:direct", async () => {
    const { dialer, calls } = fakeDialer({ directOutcome: "ok" });
    const { logger, entries } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const assignment = makeAssignment({ transport_mode: "direct" });
    const result = await sel.dial(assignment, { correlationId: CID });

    expect(result).toEqual({ ok: true, mode: "direct" });
    expect(calls.dialDirect).toHaveLength(1);
    expect(calls.dialDirect[0]!.addrs).toEqual(assignment.counterparty_session_addrs);
    expect(calls.dialRelay).toHaveLength(0);

    const sel0 = entries.find((e) => e.event === "session.transport.mode.selected");
    expect(sel0).toBeDefined();
    expect(sel0!.level).toBe("info");
    expect(sel0!.context).toMatchObject({ mode: "direct", correlationId: CID });
  });
});

// ─── AC-006: direct fails → relay fallback ──────────────────────────────────────

describe("AC-006: direct dial fails, falls back to relay transparently", () => {
  it("logs WARN direct_dial.failed then INFO mode.selected:relay; relay addr from registry", async () => {
    const dialError = new Error("dial timeout after 5000ms");
    const { dialer, calls } = fakeDialer({ directOutcome: dialError, relayOutcome: "ok", dcutrOutcome: "ok" });
    const { logger, entries } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const result = await sel.dial(makeAssignment({ transport_mode: "direct" }), { correlationId: CID });

    expect(result.ok).toBe(true);
    expect(result).toMatchObject({ mode: "relay" });
    expect(calls.dialDirect).toHaveLength(1);
    expect(calls.dialRelay).toHaveLength(1);
    // Relay address comes from the registry, not from the assignment address fields.
    expect(calls.dialRelay[0]!.relayCircuitAddr).toContain("/p2p-circuit");

    const warn = entries.find((e) => e.event === "session.transport.direct_dial.failed");
    const info = entries.find((e) => e.event === "session.transport.mode.selected");
    expect(warn).toBeDefined();
    expect(warn!.level).toBe("warn");
    // failureReason is the actual error message — never ${error}/[object Object].
    expect(warn!.context["failureReason"]).toBe("dial timeout after 5000ms");
    expect(info).toBeDefined();
    expect(info!.level).toBe("info");
    expect(info!.context).toMatchObject({ mode: "relay" });
    // Order: WARN before INFO.
    expect(entries.indexOf(warn!)).toBeLessThan(entries.indexOf(info!));
  });
});

// ─── AC-007: dcutr upgrade (success + failure) ──────────────────────────────────

describe("AC-007: dcutr upgrade is non-blocking and best-effort", () => {
  it("success: logs session.transport.dcutr.upgraded and dcutrSettled resolves true", async () => {
    const { dialer } = fakeDialer({ relayOutcome: "ok", dcutrOutcome: "ok" });
    const { logger, entries } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const result = await sel.dial(makeAssignment({ transport_mode: "relay" }), { correlationId: CID });
    expect(result.ok).toBe(true);
    expect(result).toMatchObject({ mode: "relay" });
    if (result.ok && result.mode === "relay") {
      await expect(result.dcutrSettled).resolves.toBe(true);
    }
    const up = entries.find((e) => e.event === "session.transport.dcutr.upgraded");
    expect(up).toBeDefined();
    expect(up!.level).toBe("info");
    expect(up!.context).toMatchObject({ sessionId: expect.any(String), correlationId: CID });
  });

  it("failure: logs session.transport.dcutr.failed at DEBUG, returns no error, session continues via relay", async () => {
    const { dialer } = fakeDialer({ relayOutcome: "ok", dcutrOutcome: new Error("hole punch blocked") });
    const { logger, entries } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const result = await sel.dial(makeAssignment({ transport_mode: "relay" }), { correlationId: CID });
    expect(result.ok).toBe(true);
    expect(result).toMatchObject({ mode: "relay" });
    if (result.ok && result.mode === "relay") {
      await expect(result.dcutrSettled).resolves.toBe(false);
    }
    const failed = entries.find((e) => e.event === "session.transport.dcutr.failed");
    expect(failed).toBeDefined();
    expect(failed!.level).toBe("debug");
    expect(failed!.context["failureReason"]).toBe("hole punch blocked");
  });
});

// ─── AC-008: both fail → terminal relay_fallback_also_failed ────────────────────

describe("AC-008: both direct and relay fail → terminal error", () => {
  it("returns { ok:false, reason:'relay_fallback_also_failed', guidance } and does NOT log mode.selected", async () => {
    const { dialer } = fakeDialer({
      directOutcome: new Error("ECONNREFUSED"),
      relayOutcome: new Error("relay unreachable"),
    });
    const { logger, entries } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const result = await sel.dial(makeAssignment({ transport_mode: "direct" }), { correlationId: CID });

    expect(result).toEqual({
      ok: false,
      reason: "relay_fallback_also_failed",
      guidance:
        "Both direct P2P connection and relay fallback failed. The counterparty may be " +
        "offline or unreachable from any path. Try again later, or check network connectivity.",
    });
    expect(entries.find((e) => e.event === "session.transport.mode.selected")).toBeUndefined();
  });
});

// ─── DB-002: relay unreachable on a relay assignment ────────────────────────────

describe("DB-002: relay unreachable (transport_mode 'relay') → relay_fallback_also_failed", () => {
  it("returns the terminal error with actionable guidance", async () => {
    const { dialer, calls } = fakeDialer({ relayOutcome: new Error("relay down") });
    const { logger } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const result = await sel.dial(makeAssignment({ transport_mode: "relay" }), { correlationId: CID });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("relay_fallback_also_failed");
      expect(result.guidance).toContain("Both direct P2P connection and relay fallback failed");
    }
    // transport_mode 'relay' must NOT attempt a direct dial.
    expect(calls.dialDirect).toHaveLength(0);
  });
});

// ─── AC-015 / SI-001: transport_mode is authoritative ───────────────────────────

describe("AC-015 / SI-001: transport_mode is the only authority for dial strategy", () => {
  it("transport_mode 'relay' with a direct /ip4/ address still dials the relay (not the /ip4/ address)", async () => {
    const { dialer, calls } = fakeDialer({ relayOutcome: "ok", dcutrOutcome: "ok" });
    const { logger } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    await sel.dial(
      makeAssignment({
        transport_mode: "relay",
        counterparty_session_addrs: ["/ip4/203.0.113.77/tcp/4001/p2p/12D3KooWX"],
      }),
      { correlationId: CID },
    );
    expect(calls.dialDirect).toHaveLength(0);
    expect(calls.dialRelay).toHaveLength(1);
  });

  it("transport_mode 'direct' with a /p2p-circuit address still dials direct (not relay)", async () => {
    const { dialer, calls } = fakeDialer({ directOutcome: "ok" });
    const { logger } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const circuitAddr = "/ip4/198.51.100.1/tcp/4001/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWX";
    await sel.dial(
      makeAssignment({ transport_mode: "direct", counterparty_session_addrs: [circuitAddr] }),
      { correlationId: CID },
    );
    expect(calls.dialDirect).toHaveLength(1);
    expect(calls.dialDirect[0]!.addrs).toEqual([circuitAddr]);
    expect(calls.dialRelay).toHaveLength(0);
  });

  it("SI-001: 'direct' with an attacker relay-format address is dialed as DIRECT, never routed through the attacker relay", async () => {
    const attackerRelayAddr = "/ip4/10.6.6.6/tcp/4001/p2p/12D3KooWAttacker/p2p-circuit/p2p/12D3KooWX";
    // Direct dial of the attacker's relay-format address fails (wrong protocol).
    const { dialer, calls } = fakeDialer({
      directOutcome: new Error("connection refused"),
      relayOutcome: "ok",
      dcutrOutcome: "ok",
      relayAddr: "/ip4/198.51.100.9/tcp/4001/p2p/12D3KooWLegitRelay/p2p-circuit",
    });
    const { logger } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    await sel.dial(
      makeAssignment({ transport_mode: "direct", counterparty_session_addrs: [attackerRelayAddr] }),
      { correlationId: CID },
    );
    // The attacker address was attempted as a DIRECT dial...
    expect(calls.dialDirect[0]!.addrs).toEqual([attackerRelayAddr]);
    // ...and the relay fallback used the LEGITIMATE relay from the registry, not the attacker address.
    expect(calls.dialRelay[0]!.relayCircuitAddr).not.toContain("12D3KooWAttacker");
    expect(calls.dialRelay[0]!.relayCircuitAddr).toContain("12D3KooWLegitRelay");
  });
});

// ─── SI-003: dcutr failure never disrupts the relay session ─────────────────────

describe("SI-003: a dcutr failure must not disrupt the established relay session", () => {
  it("dial resolves to a usable relay session and never throws when dcutr fails", async () => {
    const { dialer } = fakeDialer({ relayOutcome: "ok", dcutrOutcome: new Error("STUN injected") });
    const { logger } = recordingLogger();
    const sel = new TransportSelector({ dialer, logger });

    const result = await sel.dial(makeAssignment({ transport_mode: "relay" }), { correlationId: CID });
    expect(result.ok).toBe(true);
    expect(result).toMatchObject({ mode: "relay" });
    // The background dcutr failure resolves false; it does not reject (no DoS vector).
    if (result.ok && result.mode === "relay") {
      await expect(result.dcutrSettled).resolves.toBe(false);
    }
  });
});

// ─── AC-014: error codes are unique, distinct strings ───────────────────────────

describe("AC-014: transport error codes are unique and distinct", () => {
  it("the four error codes are the fixed, distinct strings from the registry", () => {
    expect(TRANSPORT_ERROR.AUTONAT_UNAVAILABLE).toBe("autonat_unavailable");
    expect(TRANSPORT_ERROR.DIRECT_DIAL_FAILED_FALLING_BACK).toBe("direct_dial_failed_falling_back_to_relay");
    expect(TRANSPORT_ERROR.RELAY_FALLBACK_ALSO_FAILED).toBe("relay_fallback_also_failed");
    expect(TRANSPORT_ERROR.DCUTR_UPGRADE_FAILED).toBe("dcutr_upgrade_failed");
    const all = Object.values(TRANSPORT_ERROR);
    expect(new Set(all).size).toBe(all.length); // all unique
  });
});

// ─── AC-009: LocalTransportSelectorStub ─────────────────────────────────────────

describe("AC-009: LocalTransportSelectorStub returns configurable results", () => {
  it("defaults to a successful relay selection", async () => {
    const stub = new LocalTransportSelectorStub();
    const result = await stub.dial(makeAssignment(), { correlationId: CID });
    expect(result.ok).toBe(true);
    expect(result).toMatchObject({ mode: "relay" });
  });

  it("returns the configured result", async () => {
    const direct: TransportResult = { ok: true, mode: "direct" };
    const stub = new LocalTransportSelectorStub(direct);
    expect(await stub.dial(makeAssignment(), { correlationId: CID })).toEqual(direct);
    stub.setResult({ ok: false, reason: "relay_fallback_also_failed", guidance: "x" });
    expect((await stub.dial(makeAssignment(), { correlationId: CID })).ok).toBe(false);
  });
});

// ─── AC-004 / AC-019: advertised-address selection from dialability ─────────────

describe("AC-004 / AC-019: selectAdvertisedAddress chooses direct vs relay from dialability", () => {
  const relayCircuitAddr = "/ip4/198.51.100.9/tcp/4001/p2p/12D3KooWRelay/p2p-circuit";

  it("AC-004: not dialable (or AutoNAT unavailable) → advertises the relay circuit address", () => {
    const adv = selectAdvertisedAddress({ dialable: false, publicAddr: null }, relayCircuitAddr);
    expect(adv).toEqual({ kind: "relay", addr: relayCircuitAddr });
  });

  it("dialable with a public address → advertises the direct address", () => {
    const pub = "/ip4/203.0.113.5/tcp/4001/p2p/12D3KooWSelf";
    const adv = selectAdvertisedAddress({ dialable: true, publicAddr: pub }, relayCircuitAddr);
    expect(adv).toEqual({ kind: "direct", addr: pub });
  });

  it("AC-019: when dialability flips to false, a NEW selection advertises relay", () => {
    // Previously dialable=true would have advertised direct; the next standing
    // receiver, reflecting the updated (false) dialability, advertises relay.
    const adv = selectAdvertisedAddress({ dialable: false, publicAddr: null }, relayCircuitAddr);
    expect(adv.kind).toBe("relay");
  });
});
