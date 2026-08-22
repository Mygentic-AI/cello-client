/**
 * F2-a — verifyBilateralSealCertificate must return a REASON on every
 * verified:false (accept-without-independent-verify) branch, so the
 * daemon's session.sealed.signature.checked log can never again read as a
 * silently-tolerated failed check.
 *
 * The two cheapest, share-free branches are covered here (they pin the new
 * `reason` contract deterministically without a real FROST share):
 *   - non_frost_certificate: signatureType !== "frost" → immediate accept.
 *   - no_frost_share:        persistence holds no share → cannot verify.
 *
 * The share-holding branches (own_primary_unavailable / signer_key_not_held)
 * are exercised end-to-end by the live seal path and the DAEMON-004 IPC seal
 * tests; the reason plumbing they share is validated here.
 */
import { describe, it, expect } from "vitest";
import { verifyBilateralSealCertificate, wireSessionOfferHandler, wireSessionCeremonyHandler, sendSealFrostSignature } from "../session-ceremony.js";
import type { DaemonRegistrationPersistence } from "../registration-persistence.js";
import type { SignalingSeam } from "../registration-context.js";
import type { Logger } from "../types.js";

const noopLogger: Logger = {
  debug() {}, info() {}, warn() {}, error() {},
};

/** Minimal persistence stub — only loadActiveFrostKeyShare is reached by these branches. */
function makePersistence(share: unknown): DaemonRegistrationPersistence {
  return {
    async loadActiveFrostKeyShare() { return share as never; },
  } as unknown as DaemonRegistrationPersistence;
}

const AGENT_PUBKEY_HEX = "aa".repeat(32);

function baseCert(signatureType: "frost" | "single") {
  return {
    sessionId: new Uint8Array(32),
    sealedRoot: new Uint8Array(32),
    leafCount: 4,
    closeTimestamp: 1,
    frostSignature: new Uint8Array(64),
    signerPubkey: new Uint8Array(32), // 32 bytes so the length guard passes
    signatureType,
    legibility: null,
  };
}

describe("F2-a: verifyBilateralSealCertificate returns a reason on verified:false", () => {
  it("non-FROST certificate → { ok:true, verified:false, reason:'non_frost_certificate' }", async () => {
    const verdict = await verifyBilateralSealCertificate(
      { persistence: makePersistence(null), agentPubkeyHex: AGENT_PUBKEY_HEX, logger: noopLogger, counterpartyPrimaryHex: null },
      baseCert("single"),
    );
    expect(verdict.ok).toBe(true);
    expect(verdict).toMatchObject({ ok: true, verified: false, reason: "non_frost_certificate" });
  });

  it("no local FROST share → { ok:true, verified:false, reason:'no_frost_share' }", async () => {
    const verdict = await verifyBilateralSealCertificate(
      { persistence: makePersistence(null), agentPubkeyHex: AGENT_PUBKEY_HEX, logger: noopLogger, counterpartyPrimaryHex: null },
      baseCert("frost"),
    );
    expect(verdict.ok).toBe(true);
    expect(verdict).toMatchObject({ ok: true, verified: false, reason: "no_frost_share" });
  });

  it("still fails closed: a malformed (short) signer pubkey → { ok:false, reason:'no_signer_pubkey' }", async () => {
    const cert = baseCert("frost");
    cert.signerPubkey = new Uint8Array(16); // wrong length
    const verdict = await verifyBilateralSealCertificate(
      { persistence: makePersistence(null), agentPubkeyHex: AGENT_PUBKEY_HEX, logger: noopLogger, counterpartyPrimaryHex: null },
      cert,
    );
    expect(verdict).toMatchObject({ ok: false, reason: "no_signer_pubkey" });
  });
});

// ─── DOD-OFFER-REJECT-1 (D1, M8C-PHANTOM-SESSION-FIX-PLAN §4) ────────────────────────────────
// The responder must ANSWER, not vanish. Before this, wireSessionOfferHandler returned silently
// on standing_receiver_unavailable / no_session_id, and the directory stalled 2 s then signed an
// assignment with an empty counterparty endpoint ("proceed with empty defaults") — the phantom
// session's origin. The reject frame is the Generic Reject of 2026-07-08_inbound-state-matrix,
// arriving as a protocol necessity. The directory's handling of it is D2 (this half is inert
// until the directory understands the frame).
describe("DOD-OFFER-REJECT-1: wireSessionOfferHandler answers with session_offer_reject instead of vanishing", () => {
  interface LogEvent { level: string; event: string; context: Record<string, unknown> }

  function makeCapturingLogger(): { logger: Logger; events: LogEvent[] } {
    const events: LogEvent[] = [];
    const logger: Logger = {
      debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
      info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
      warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
      error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
    };
    return { logger, events };
  }

  function makeSeam(opts?: { sendRawError?: Error; sendRawResult?: { ok: boolean; reason?: string } }): {
    seam: SignalingSeam;
    sent: Record<string, unknown>[];
    inject: (frame: Record<string, unknown>) => void;
  } {
    const sent: Record<string, unknown>[] = [];
    let handler: ((frame: Record<string, unknown>) => void) | null = null;
    const seam: SignalingSeam = {
      status: "connected",
      async sendRaw(frame: unknown) {
        if (opts?.sendRawError) throw opts.sendRawError;
        // The PRODUCTION seam (transport SignalingManager.sendRaw) never throws — it resolves
        // {ok:false, reason} on every failure mode. A fake that only throws lets an
        // implementation that discards the result pass (D1 review F1).
        if (opts?.sendRawResult) return opts.sendRawResult as never;
        sent.push(frame as Record<string, unknown>);
        return { ok: true } as never;
      },
      registerInboundHandler(h) { handler = h; return () => { handler = null; }; },
    };
    return { seam, sent, inject: (frame) => handler?.(frame) };
  }

  const SID = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 7));
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

  function wire(deps: {
    sr: { peerId: string; addrs: string[] } | null;
    seamOpts?: { sendRawError?: Error; sendRawResult?: { ok: boolean; reason?: string } };
  }) {
    const { logger, events } = makeCapturingLogger();
    const { seam, sent, inject } = makeSeam(deps.seamOpts);
    wireSessionOfferHandler({
      agentName: "bob",
      getStandingReceiverEndpoint: () => deps.sr,
      // DOD-M15-ASSIGN-1: the receiver is narrowed to the offered dialer before the accept goes
      // out. These tests are about the REJECT contract, so the narrowing succeeds and stays out of
      // their way; the narrowing itself is pinned in dod-m15-assign-1-receiver-gate.test.ts.
      admitOfferedDialer: () => true,
      signaling: seam,
      logger,
    });
    return { events, sent, inject };
  }

  it("AC1: standing_receiver_unavailable → sends session_offer_reject {type, session_id, reason}", async () => {
    const h = wire({ sr: null });
    h.inject({ type: "session_offer", session_id: SID, initiator_session_peer_id: "12D3KooInitiator" });
    await wait(20);

    const reject = h.sent.find((f) => f["type"] === "session_offer_reject");
    expect(reject).toBeDefined();
    expect(reject!["session_id"]).toEqual(SID);
    expect(reject!["reason"]).toBe("standing_receiver_unavailable");
    // Nothing else went out — no accept for an offer we cannot serve.
    expect(h.sent.find((f) => f["type"] === "session_offer_accept")).toBeUndefined();
  });

  it("AC3: session.offer.abort is STILL logged with the same reason (the reject adds, never replaces)", async () => {
    const h = wire({ sr: null });
    h.inject({ type: "session_offer", session_id: SID, initiator_session_peer_id: "12D3KooInitiator" });
    await wait(20);

    const abort = h.events.find((e) => e.event === "session.offer.abort");
    expect(abort).toBeDefined();
    expect(abort!.level).toBe("warn");
    expect(abort!.context["reason"]).toBe("standing_receiver_unavailable");
    expect(abort!.context["agentName"]).toBe("bob");
  });

  it("AC1: no_session_id → sends session_offer_reject with reason (session_id omitted — there is none to echo)", async () => {
    const h = wire({ sr: { peerId: "bob-sr-peer", addrs: [] } });
    h.inject({ type: "session_offer" }); // no session_id
    await wait(20);

    const reject = h.sent.find((f) => f["type"] === "session_offer_reject");
    expect(reject).toBeDefined();
    expect(reject!["reason"]).toBe("no_session_id");
    expect("session_id" in reject!).toBe(false);
    const abort = h.events.find((e) => e.event === "session.offer.abort");
    expect(abort).toBeDefined();
    expect(abort!.context["reason"]).toBe("no_session_id");
  });

  it("regression: a healthy offer still sends session_offer_accept, and NO reject", async () => {
    const h = wire({ sr: { peerId: "bob-sr-peer", addrs: ["/ip4/127.0.0.1/tcp/1"] } });
    h.inject({ type: "session_offer", session_id: SID, initiator_session_peer_id: "12D3KooInitiator" });
    await wait(20);

    const accept = h.sent.find((f) => f["type"] === "session_offer_accept");
    expect(accept).toBeDefined();
    expect(accept!["counterparty_session_peer_id"]).toBe("bob-sr-peer");
    expect(h.sent.find((f) => f["type"] === "session_offer_reject")).toBeUndefined();
    expect(h.events.find((e) => e.event === "session.offer.accepted")).toBeDefined();
  });

  it("SI: a failed reject send is LOUD (session.offer.reject.failed with the upstream detail), never thrown", async () => {
    const h = wire({ sr: null, seamOpts: { sendRawError: new Error("stream torn down") } });
    h.inject({ type: "session_offer", session_id: SID, initiator_session_peer_id: "12D3KooInitiator" });
    await wait(20);

    const failed = h.events.find((e) => e.event === "session.offer.reject.failed");
    expect(failed).toBeDefined();
    expect(failed!.level).toBe("warn");
    expect(failed!.context["agentName"]).toBe("bob");
    expect(failed!.context["reason"]).toBe("standing_receiver_unavailable");
    expect(String(failed!.context["detail"])).toContain("stream torn down");
    // The abort is still there — the operator sees both the cause and the failed answer.
    expect(h.events.find((e) => e.event === "session.offer.abort")).toBeDefined();
  });

  // D1 review F1: the PRODUCTION seam never throws — it resolves {ok:false, reason} (transport
  // signaling-manager.ts sendRaw). An implementation that discards the result logs reject.sent
  // while nothing left the machine — a silent vanish under exactly the degraded condition this
  // unit exists to fix. These two tests drive the production failure contract.
  it("SI (production contract): sendRaw resolving {ok:false} → reject.failed with the reason, and NO reject.sent", async () => {
    const h = wire({ sr: null, seamOpts: { sendRawResult: { ok: false, reason: "signaling_lost" } } });
    h.inject({ type: "session_offer", session_id: SID, initiator_session_peer_id: "12D3KooInitiator" });
    await wait(20);

    const failed = h.events.find((e) => e.event === "session.offer.reject.failed");
    expect(failed).toBeDefined();
    expect(failed!.level).toBe("warn");
    expect(failed!.context["reason"]).toBe("standing_receiver_unavailable");
    expect(String(failed!.context["detail"])).toContain("signaling_lost");
    expect(h.events.find((e) => e.event === "session.offer.reject.sent")).toBeUndefined();
  });

  it("SI (production contract, accept path — review F3): accept sendRaw {ok:false} → accept.failed with the reason, and NO session.offer.accepted", async () => {
    const h = wire({
      sr: { peerId: "bob-sr-peer", addrs: [] },
      seamOpts: { sendRawResult: { ok: false, reason: "signaling_reconnecting" } },
    });
    h.inject({ type: "session_offer", session_id: SID, initiator_session_peer_id: "12D3KooInitiator" });
    await wait(20);

    const failed = h.events.find((e) => e.event === "session.offer.accept.failed");
    expect(failed).toBeDefined();
    expect(failed!.level).toBe("warn");
    expect(String(failed!.context["detail"])).toContain("signaling_reconnecting");
    expect(h.events.find((e) => e.event === "session.offer.accepted")).toBeUndefined();
  });

  it("frames that are not session_offer are untouched (no reject, no events)", async () => {
    const h = wire({ sr: null });
    h.inject({ type: "session_assignment" });
    await wait(20);
    expect(h.sent).toHaveLength(0);
    expect(h.events).toHaveLength(0);
  });
});

// ─── DOD-SENDRAW-1: sendRaw resolves {ok:false} — it never throws in production ─────────────
// The transport SignalingManager.sendRaw has zero throw statements; every failure resolves
// {ok:false, reason}. A site that discards the result logs success while nothing left the
// machine, and its catch-based failure event can never fire. These tests drive the RESOLVE
// contract (a throwing fake is exactly what let this class hide — D1 review F1).
describe("DOD-SENDRAW-1: seal + ceremony sends branch on the seam's resolved result", () => {
  interface LogEvent { level: string; event: string; context: Record<string, unknown> }
  function makeCapturingLogger(): { logger: Logger; events: LogEvent[] } {
    const events: LogEvent[] = [];
    const logger: Logger = {
      debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
      info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
      warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
      error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
    };
    return { logger, events };
  }
  function makeSeam(result: { ok: boolean; reason?: string; guidance?: string }): { seam: SignalingSeam; sent: Record<string, unknown>[]; inject: (frame: Record<string, unknown>) => void } {
    const sent: Record<string, unknown>[] = [];
    let handler: ((frame: Record<string, unknown>) => void) | null = null;
    const seam: SignalingSeam = {
      status: "connected",
      async sendRaw(frame: unknown) {
        sent.push(frame as Record<string, unknown>);
        return result as never;
      },
      registerInboundHandler(h) { handler = h; return () => { handler = null; }; },
    };
    return { seam, sent, inject: (frame) => handler?.(frame) };
  }
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const SID = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 21));
  const SID_HEX = Buffer.from(SID).toString("hex");

  it("seal_frost_signature: {ok:false} → signature.send.failed with the reason AND the specific guidance, and NO .sent", async () => {
    const { logger, events } = makeCapturingLogger();
    const { seam } = makeSeam({ ok: false, reason: "signaling_lost", guidance: "Send failed: stream reset by peer" });
    await sendSealFrostSignature({ agentName: "bob", signaling: seam, logger }, SID, SID_HEX, new Uint8Array(64));
    const failed = events.find((e) => e.event === "session.seal.frost.signature.send.failed");
    expect(failed).toBeDefined();
    expect(failed!.level).toBe("warn");
    expect(failed!.context["agentName"]).toBe("bob");
    expect(failed!.context["sessionId"]).toBe(SID_HEX);
    expect(String(failed!.context["detail"])).toContain("signaling_lost");
    // Review F2: `reason` is the generic label; the SPECIFIC cause rides in guidance — it must
    // reach the operator's log, not be discarded.
    expect(String(failed!.context["guidance"])).toContain("stream reset by peer");
    expect(events.find((e) => e.event === "session.seal.frost.signature.sent")).toBeUndefined();
  });

  it("seal_frost_signature: {ok:true} → .sent, and NO failure event", async () => {
    const { logger, events } = makeCapturingLogger();
    const { seam, sent } = makeSeam({ ok: true });
    await sendSealFrostSignature({ agentName: "bob", signaling: seam, logger }, SID, SID_HEX, new Uint8Array(64));
    expect(sent[0]!["type"]).toBe("seal_frost_signature");
    expect(events.find((e) => e.event === "session.seal.frost.signature.sent")).toBeDefined();
    expect(events.find((e) => e.event === "session.seal.frost.signature.send.failed")).toBeUndefined();
  });

  it("ceremony reply: a {ok:false} ceremony_result send → session.ceremony.reply.failed with the reason (previously unreachable)", async () => {
    const { logger, events } = makeCapturingLogger();
    const { seam, sent, inject } = makeSeam({ ok: false, reason: "signaling_reconnecting" });
    // Minimal deps: the no-tbs abort path reaches reply(null) → sendRaw without touching the
    // FROST machinery (persistence/keyProvider/node stubs are never called on this path).
    wireSessionCeremonyHandler({
      agentName: "bob",
      persistence: {} as never,
      agentPubkeyHex: "aa".repeat(32),
      keyProvider: {} as never,
      getNode: () => null,
      getDirectoryEndpoint: async () => null,
      getConsortiumEndpoints: async () => null,
      signaling: seam,
      logger,
    });
    inject({ type: "ceremony_request", ceremony_id: "cer-1" }); // no tbs → reply(null)
    await wait(20);
    expect(sent[0]!["type"]).toBe("ceremony_result");
    const failed = events.find((e) => e.event === "session.ceremony.reply.failed");
    expect(failed).toBeDefined();
    expect(failed!.level).toBe("warn");
    expect(String(failed!.context["detail"])).toContain("signaling_reconnecting");
  });
});
