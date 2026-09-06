/**
 * `DOD-M15-SELFCHAIN-1` — A SESSION OFFERED WITH NO DIRECTORY RECORD IS REFUSED, AND THE OPERATOR
 * IS TOLD.
 *
 * ─── Why this is a security refusal and not a malformed frame ──────────────────────────────────
 *
 * Every real session is brokered: the directory produces a threshold-signed establishment record
 * and each side verifies it before the session begins. One of the things inside those signed bytes
 * is the conversation's STARTING POINT, and every first message chains to it.
 *
 * So a session offered without one is a conversation whose order could never be proven afterwards,
 * by either party, ever. The thing being offered is a conversation that leaves no record — which is
 * a reason to refuse rather than a shape to tidy up. Ruled 2026-09-06.
 *
 * ─── The two causes that used to share one exit, and one notice ────────────────────────────────
 *
 * The extractor returns `null` for FOUR conditions: no `assignment` object at all, and three ways a
 * present assignment can be unreadable. Only the first is "no directory record". The other three
 * are a wire or version fault — and they were reaching the operator under a notice reading
 * "NOTHING LEGITIMATE PRODUCES THIS. TREAT IT AS SUSPICIOUS."
 *
 * One exit point standing in for two causes, with the wrong one of the two being the loud one. That
 * is how an operator learns to scroll past the notice that matters.
 *
 * ─── The three surfaces, and why the old test could not see two of them ────────────────────────
 *
 * A refusal has to reach the log, the operator's inbox, and the durable record. The existing test
 * asserted only the log — and it ran on the shared-signaling path, where the handler is given no
 * agent name, so the two inbox calls could not execute at all. Both could be deleted with the gate
 * green. These drive the PER-AGENT wiring, which is what production uses.
 */

import { describe, it, expect } from "vitest";
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import { REFUSAL_REASONS, REFUSAL_GUIDANCE } from "../refusal-reasons.js";
import type { Logger } from "../types.js";
import type { SignalingManager } from "@cello-protocol/transport";

const AGENT = "alice";
const AGENT_PUBKEY = "bb".repeat(32);
const SESSION_ID_HEX = "9".repeat(32);

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

/**
 * The real inbound handler over fakes, wired PER AGENT — which is the whole point. Production calls
 * `wirePerAgentSessionInbound(mgr, agentName)`; the shared-signaling path passes no name, and
 * without a name there is nobody to file a refusal under.
 */
function harness() {
  const events: LogEvent[] = [];
  const push = (level: string) => (event: string, context?: Record<string, unknown>) => {
    events.push({ level, event, context: context ?? {} });
  };
  const logger = {
    debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error"),
  } as unknown as Logger;

  let inbound: ((frame: Record<string, unknown>) => void) | null = null;
  /** The DURABLE rows — what stops parked content re-pulling forever across a restart. */
  const durable: Array<{ agent: string; session: string; reason: string }> = [];

  const sessionNodeManager = {
    recordRefusedSession: (agent: string, session: string, reason: string) => {
      durable.push({ agent, session, reason });
    },
    getSessionRecord: () => undefined,
    resolveAgentId: () => "agent-id",
    getDb: () => { throw new Error("no db in this harness"); },
  };

  const api = createInboundSessions({
    logger,
    sessionNodeManager,
    agents: [{ name: AGENT, pubkey: AGENT_PUBKEY }],
    sendOver: async () => ({ ok: true }),
    isExplicitlyOffline: () => false,
    getConnState: () => undefined,
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: {},
    getKeyProvider: () => undefined,
    handleInboundSealInterruptedRequest: async () => {},
    reapDeadHalfOpenSessions: () => {},
    sendAwayResponse: async () => {},
    dispatchSessionStateChangedWithTelegram: () => {},
    sendTelegramDoorbell: async () => {},
    isDeliveryOpenToAgent: () => false,
  } as unknown as InboundSessionDeps);

  api.wirePerAgentSessionInbound(
    {
      registerInboundHandler(h: (frame: Record<string, unknown>) => void) {
        // Two handlers register; only the second cares about `session_assignment`. Chaining them
        // means the test drives the real dispatch rather than a hand-picked one.
        const prev = inbound;
        inbound = (f) => { prev?.(f); h(f); };
        return () => {};
      },
    } as unknown as SignalingManager,
    AGENT,
  );

  return {
    inject: (f: Record<string, unknown>) => inbound?.(f),
    events,
    durable,
    /** What `cello_inbox` would show this operator. */
    operatorSees: (): Array<{ reason: string; sessionIdHex: string; counterpartyPubkeyHex: string }> =>
      (api.refusedSessionRequests.get(AGENT) ?? []) as Array<{
        reason: string; sessionIdHex: string; counterpartyPubkeyHex: string;
      }>,
  };
}

describe("DOD-M15-SELFCHAIN-1: a session offered with no directory record", () => {
  it("★★★ is refused, and reaches ALL THREE surfaces — log, inbox, durable record", async () => {
    /**
     * THE REVERT TEST. Delete either `recordRefusal` or `recordRefusedSession` and this goes red on
     * the surface that lost its writer. The previous test asserted only the log, so both could be
     * deleted with the whole gate green.
     */
    const h = harness();
    h.inject({ type: "session_assignment" });   // no `assignment` at all

    const refused = h.events.find((e) => e.event === "session.inbound.assignment.no_assignment");
    expect(refused, "the refusal must be reported").toBeDefined();
    // ERROR, not warn: nothing legitimate produces this, and the level is what decides whether the
    // operator's tooling shows it at all.
    expect(refused!.level).toBe("error");
    expect(String(refused!.context["impact"]), "it must say what it COSTS, not that a field was absent")
      .toMatch(/starting point/);

    const seen = h.operatorSees();
    expect(seen, "a refusal nobody can see is indistinguishable from the session never arriving")
      .toHaveLength(1);
    expect(seen[0]!.reason).toBe(REFUSAL_REASONS.SESSION_WITHOUT_ASSIGNMENT);

    expect(h.durable, "and it survives a restart, so parked content does not re-pull forever")
      .toHaveLength(1);
    expect(h.durable[0]!.reason).toBe(REFUSAL_REASONS.SESSION_WITHOUT_ASSIGNMENT);
  });

  it("★★ its guidance branches on RECOGNITION — a stranger cannot be reached out of band", () => {
    /**
     * The wording is the operator's whole experience of this refusal, so it is asserted rather than
     * trusted. It must not tell someone to contact a party they have no way to identify.
     */
    const g = REFUSAL_GUIDANCE[REFUSAL_REASONS.SESSION_WITHOUT_ASSIGNMENT];
    expect(g.startsWith("REFUSED ON PURPOSE"), "pin the opening — a truncation cannot survive it").toBe(true);
    expect(g, "the claim that makes it suspicious must be unmissable").toMatch(/NOTHING LEGITIMATE PRODUCES THIS/);
    expect(g, "and the only move that settles it is out of band").toMatch(/OUT OF BAND/);
    expect(g, "conditioned on recognising them — you cannot email a stranger").toMatch(/IF THEY LOOK LIKE SOMEONE YOU KNOW/);
  });

  it("★★★ an assignment that IS there and cannot be read takes a DIFFERENT path, by name", () => {
    /**
     * THE SPLIT. Both conditions came out of the same `null`, so a version difference between two
     * agents was being reported to the operator as an attack. That is worse than not reporting it:
     * it teaches them the loud notice is noise.
     *
     * Here the assignment object exists and its participants are missing — exactly what an older or
     * newer peer produces.
     */
    const h = harness();
    h.inject({ type: "session_assignment", assignment: { session_id: Buffer.from(SESSION_ID_HEX, "hex") } });

    expect(
      h.events.find((e) => e.event === "session.inbound.assignment.no_assignment"),
      "a readable-but-incomplete assignment is NOT the security case and must not borrow its notice",
    ).toBeUndefined();
    const unreadable = h.events.find((e) => e.event === "session.inbound.assignment.unreadable");
    expect(unreadable, "it still refuses, and still says so").toBeDefined();

    const seen = h.operatorSees();
    expect(seen).toHaveLength(1);
    expect(seen[0]!.reason).toBe(REFUSAL_REASONS.ASSIGNMENT_UNREADABLE);
    /**
     * ⚠️ AND THE SESSION ID IS CARRIED. It was read from the top level of the frame, where a
     * `session_assignment` never has one, so it was ALWAYS empty — the notice named no
     * conversation, and the durable write was gated on that empty value and therefore never ran.
     */
    expect(seen[0]!.sessionIdHex, "the refusal must name the conversation it refused").toBe(SESSION_ID_HEX);

    const g = REFUSAL_GUIDANCE[REFUSAL_REASONS.ASSIGNMENT_UNREADABLE];
    expect(g, "and it must NOT call this an attack").toMatch(/PROBABLY NOT AN ATTACK/);
    expect(g, "it must send them to compare versions, which is the likely cause").toMatch(/version/i);
  });
});
