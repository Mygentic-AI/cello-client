/**
 * CELLO-M7-SESSION-003 — the unilateral-seal liveness GATE (client)
 *
 * AC understanding:
 *   - AC-007 (logic): a counterparty whose session-path is 'alive' is recorded
 *     DELIVERED, never ABSENT. The seal_unilateral frame carries
 *     counterparty_liveness:'alive' and counterparty_attestation:'DELIVERED', and
 *     session.seal.attestation.determined fires at INFO with attestation
 *     'DELIVERED'. (Full cross-process headline is AC-007 e2e / SI-001 e2e.)
 *   - AC-008 (logic): liveness 'gone' → ABSENT on the frame.
 *   - AC-009: liveness 'unknown' → DELIVERED (fail-safe), never ABSENT.
 *   - AC-013 / DB-001 / SI-003: a relay liveness query failure does NOT record
 *     ABSENT — it defaults to DELIVERED and fires session.liveness.query.failed.
 *   - AC-016: session.seal.attestation.determined carries attestation, liveness,
 *     authority, and the correlationId; session.liveness.query.failed carries
 *     reason + error. No console.log — all via the injected Logger.
 *   - SI-004: for a relay-path session the ABSENT verdict originates from the
 *     authority's response (here the injected verdict), never manufactured locally.
 *
 * Self-contained — no external state; no CELLO_E2E_LIVE guard.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { decode } from "cbor-x";
import { SealManager } from "../seal-manager.js";
import type { SealContext } from "../seal-manager.js";
import type { SessionRecord } from "../types.js";
import type { LivenessVerdict } from "../session-liveness.js";

interface LogEntry { level: string; event: string; ctx: Record<string, unknown> }

function makeLogger() {
  const entries: LogEntry[] = [];
  const mk = (level: string) => (event: string, ctx?: Record<string, unknown>) =>
    entries.push({ level, event, ctx: ctx ?? {} });
  return { entries, logger: { debug: mk("debug"), info: mk("info"), warn: mk("warn"), error: mk("error") } };
}

function makeSession(transport_mode: "direct" | "relay"): SessionRecord {
  return {
    session_id: new Uint8Array(randomBytes(16)),
    counterparty_pubkey: new Uint8Array(32).fill(5),
    counterparty_peer_id: "",
    counterparty_multiaddrs: [],
    relay_endpoint: { peer_id: "", multiaddrs: [] },
    directory_endpoint: { peer_id: "", multiaddrs: [] },
    directory_pubkey: new Uint8Array(32),
    genesis_prev_root: new Uint8Array(32).fill(1),
    last_seen_seq: 0,
    last_sent_seq: 0,
    status: "active",
    transport_mode,
    local_tree_leaves: [],
    next_expected_seq: 1,
    desynchronized: false,
  };
}

/**
 * Run initiateUnilateralSeal with a controlled liveness verdict, capture the
 * seal_unilateral frame the client sends, and return it + the log entries.
 */
async function runSeal(verdict: LivenessVerdict, session: SessionRecord, transport: "direct" | "relay") {
  const { entries, logger } = makeLogger();
  const sent: Uint8Array[] = [];
  const fakeStream = {
    status: "open",
    send: (data: Uint8Array) => { sent.push(data); },
  } as unknown as import("@libp2p/interface").Stream;

  const ctx: Partial<SealContext> & {
    getCounterpartyLivenessVerdict: (s: SessionRecord, c: string) => Promise<LivenessVerdict>;
  } = {
    logger,
    persistence: null,
    getSession: () => session,
    getPersistentSignalingStream: () => fakeStream,
    setPersistentSignalingStream: () => {},
    setPersistentSignalingIter: () => {},
    openPersistentSignalingStream: async () => true,
    getCounterpartyLivenessVerdict: async () => verdict,
  };

  const mgr = new SealManager(ctx as unknown as SealContext, 1_000);
  const sealPromise = mgr.initiateUnilateralSeal(Buffer.from(session.session_id).toString("hex"));

  // Wait for the frame to be sent, then resolve the directory response.
  for (let i = 0; i < 200 && sent.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
  expect(sent.length).toBeGreaterThan(0);

  // Decode the length-prefixed frame: skip the varint length prefix.
  const raw = sent[0]!;
  // it-length-prefixed single() prepends an unsigned varint length; strip it by
  // scanning for the CBOR map start. Simplest: decode after the 1-2 byte prefix.
  let frame: Record<string, unknown> | null = null;
  for (let off = 0; off < 3 && frame === null; off++) {
    try { frame = decode(raw.subarray(off)) as Record<string, unknown>; } catch { /* try next offset */ }
  }
  expect(frame).not.toBeNull();
  expect(frame!["type"]).toBe("seal_unilateral");

  // Resolve the waiter so initiateUnilateralSeal returns.
  mgr.resolvePendingUnilateralSeal({
    type: "seal_unilateral_confirmed",
    sealed_root: new Uint8Array(32).fill(9),
    sealed_at: 123,
  });
  await sealPromise;

  void transport;
  return { frame: frame!, entries };
}

describe("unilateral-seal liveness gate (AC-007/008/009/013/016/SI-003/SI-004)", () => {
  it("AC-007: 'alive' direct session → DELIVERED on the frame, never ABSENT", async () => {
    const session = makeSession("direct");
    const { frame, entries } = await runSeal(
      { liveness: "alive", authority: "session_node" }, session, "direct");
    expect(frame["counterparty_liveness"]).toBe("alive");
    expect(frame["counterparty_attestation"]).toBe("DELIVERED");
    const det = entries.find((e) => e.event === "session.seal.attestation.determined");
    expect(det).toBeDefined();
    expect(det!.level).toBe("info");
    expect(det!.ctx["attestation"]).toBe("DELIVERED");
    expect(det!.ctx["liveness"]).toBe("alive");
    expect(det!.ctx["authority"]).toBe("session_node");
    expect(det!.ctx["correlationId"]).toBeDefined();
    // No ABSENT anywhere.
    expect(entries.some((e) => e.ctx["attestation"] === "ABSENT")).toBe(false);
  });

  it("AC-008: 'gone' → ABSENT on the frame", async () => {
    const session = makeSession("relay");
    const { frame, entries } = await runSeal(
      { liveness: "gone", authority: "relay" }, session, "relay");
    expect(frame["counterparty_liveness"]).toBe("gone");
    expect(frame["counterparty_attestation"]).toBe("ABSENT");
    const det = entries.find((e) => e.event === "session.seal.attestation.determined");
    expect(det!.ctx["attestation"]).toBe("ABSENT");
    expect(det!.ctx["authority"]).toBe("relay");
  });

  it("AC-009: 'unknown' → DELIVERED (fail-safe), never ABSENT", async () => {
    const session = makeSession("relay");
    const { frame } = await runSeal(
      { liveness: "unknown", authority: "relay" }, session, "relay");
    expect(frame["counterparty_liveness"]).toBe("unknown");
    expect(frame["counterparty_attestation"]).toBe("DELIVERED");
  });

  it("AC-013/SI-003: relay query failure → DELIVERED + session.liveness.query.failed", async () => {
    const session = makeSession("relay");
    const { frame, entries } = await runSeal(
      { liveness: "unknown", authority: "relay", failureReason: "liveness_query_unreachable" },
      session, "relay");
    expect(frame["counterparty_attestation"]).toBe("DELIVERED"); // never ABSENT
    const fail = entries.find((e) => e.event === "session.liveness.query.failed");
    expect(fail).toBeDefined();
    expect(fail!.level).toBe("warn");
    expect(fail!.ctx["reason"]).toBe("liveness_query_unreachable");
    expect(fail!.ctx["correlationId"]).toBeDefined();
  });
});
