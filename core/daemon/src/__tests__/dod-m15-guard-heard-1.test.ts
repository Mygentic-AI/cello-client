/**
 * DOD-M15-GUARD-HEARD-1 — every refusal reason reaches somebody who can act on it.
 *
 * ─── The pattern this exists to stop, and why it earned a line ─────────────────────────────────
 *
 * Four times in one milestone a guard fired into silence. Andre's rule: three fixed individually is
 * a coincidence, a fourth is a defect class.
 *
 *   1. `SIGNUP-DURABLE-1` — a fail-closed refusal invisible to the person it refused. A
 *      table-scoped database error took the whole signup flow down while the health check reported
 *      healthy; from each person's side the bot was simply dead.
 *   2. `OFFER-SIGNED-1` — two security refusals recorded in memory only. No durable row, so content
 *      the initiator had already parked re-pulled forever; and no word to the counterparty, who saw
 *      a transport-shaped failure naming nothing that was actually wrong.
 *   3. `RESPONDER-VERIFY-1` — an identity refusal whose printed remedy did not work, and a
 *      certificate accepted without verification returning the same response shape as a verified
 *      one.
 *   4. That unit's review, which reverted three fixes and ran the gate: **2525 green, 2525 green,
 *      4057 green.** Three security fixes, each one refactor from being undone.
 *
 * None was a missing check. Every one was a check that fired where nobody was listening.
 *
 * ─── What is testable here, and what is not ────────────────────────────────────────────────────
 *
 * The general form — *delete the guard and see if the gate goes red* — is a procedure, not a test;
 * it lives in `M15-PROCEDURE.md`. What IS mechanical is the audience question, and that is what
 * this file pins: for every reason code the daemon can refuse with, somebody is told, in words they
 * can act on, through the surface they actually read.
 *
 * It drives the REAL `cello_check_notifications` handler. Asserting against `REFUSAL_GUIDANCE`
 * directly would prove the table has an entry — which was never the failure. The failure was the
 * entry not being reached: a rename on either side of the lookup silently dropped it and left the
 * operator with a bare reason code, which is the state the guidance was added to fix.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { registerNotificationHandlers, type NotificationHandlerDeps } from "../notification-handlers.js";
import { REFUSAL_REASONS, REFUSAL_GUIDANCE, type RefusalReason } from "../refusal-reasons.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const AGENT = "alice";
const ALL_REASONS = Object.values(REFUSAL_REASONS) as RefusalReason[];

interface RefusedRow { sessionIdHex: string; counterpartyPubkeyHex: string; reason: string; refusedAt: number }

/**
 * Drive the real inbox handler with one refusal per reason and return what the agent receives.
 *
 * Everything the handler needs beyond the refusal list is stubbed to empty — this file is about one
 * section of the response, and a stub that returned plausible content elsewhere would only make a
 * failure harder to read.
 */
async function inboxFor(reasons: readonly string[]): Promise<Array<Record<string, unknown>>> {
  const handlers = new Map<string, IpcHandler>();
  const refusedSessionRequests = new Map<string, RefusedRow[]>([
    [
      AGENT,
      reasons.map((reason, i) => ({
        sessionIdHex: String(i).repeat(32),
        counterpartyPubkeyHex: "aa".repeat(32),
        reason,
        refusedAt: 1_700_000_000_000 + i,
      })),
    ],
  ]);

  const sessionNodeManager = {
    getUnreadSummary: () => [],
    getEndedUnread: () => [],
    getRenameNotices: () => [],
    getConsentRequests: () => [],
    listSessions: () => [],
    getPendingAttestationConsents: () => [],
  };

  registerNotificationHandlers({
    handlers,
    logger: silent,
    sessionNodeManager,
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    loadedAgents: [{ name: AGENT, pubkey: "bb".repeat(32) }],
    agents: [{ name: AGENT, pubkey: "bb".repeat(32), state: "online" }],
    reapExpiredInboundSessions: () => {},
    inboundSessionQueues: new Map(),
    expiredSessionRequests: new Map(),
    refusedSessionRequests,
  } as unknown as NotificationHandlerDeps);

  const handler = handlers.get("cello_check_notifications");
  expect(handler, "cello_check_notifications must be registered for this file to mean anything").toBeDefined();
  // The response nests per-agent under `agents`, which is the shape `cello_inbox` actually returns.
  const res = (await handler!({}, "conn-1")) as {
    agents?: Array<{ agent: string; refused_session_requests?: Array<Record<string, unknown>> }>;
  };
  const mine = res.agents?.find((a) => a.agent === AGENT);
  expect(mine, "the inbox must contain a section for this agent").toBeDefined();
  return mine?.refused_session_requests ?? [];
}

describe("DOD-M15-GUARD-HEARD-1: every refusal reason reaches the operator's inbox", () => {
  it("has at least one reason to check — an empty enumeration would pass everything below", () => {
    expect(ALL_REASONS.length).toBeGreaterThan(0);
  });

  it("EVERY reason arrives with guidance attached, through the real handler", async () => {
    const rows = await inboxFor(ALL_REASONS);
    expect(rows.length, "every refusal must appear in the inbox").toBe(ALL_REASONS.length);

    const bare = rows
      .filter((r) => typeof r["guidance"] !== "string" || (r["guidance"] as string).length === 0)
      .map((r) => String(r["reason"]));

    expect(
      bare,
      `These refusal reasons reach the operator as a bare code with nothing to act on: ` +
        `${bare.join(", ")}. A reason code is not an affordance — the agent cannot look it up, and ` +
        `a refusal the operator cannot act on is indistinguishable from the session never arriving. ` +
        `Add the reason to REFUSAL_GUIDANCE, and check the lookup still finds it: the guidance table ` +
        `and the recording site are joined by a string, and a rename on either side drops it silently.`,
    ).toEqual([]);
  });

  it("the guidance says what was refused AND what to do — not just that something happened", async () => {
    // "Refused on purpose" is the part that stops an operator hunting a bug that is not there; the
    // second half is the affordance. A message with neither is a longer bare code.
    for (const row of await inboxFor(ALL_REASONS)) {
      const guidance = String(row["guidance"]);
      expect(guidance, `${String(row["reason"])} does not say the refusal was deliberate`).toMatch(
        /refused on purpose/i,
      );
      expect(
        guidance.length,
        `${String(row["reason"])}'s guidance is too short to carry both the cause and a next step`,
      ).toBeGreaterThan(120);
    }
  });

  it("names no verb the READER cannot perform — the reader is the responder's operator", async () => {
    /**
     * Review F13. Two of these told the responder's operator to "Retry". They did not start the
     * session and have nothing to retry — the initiator holds it. An affordance that resolves to
     * nothing is worse than none, because they will try to follow it and conclude the system is
     * broken when it does nothing.
     *
     * Retry advice belongs in the `session_refused` frame, which goes to the side that can act.
     */
    for (const row of await inboxFor(ALL_REASONS)) {
      const guidance = String(row["guidance"]);
      expect(
        /\bretry\b/i.test(guidance) && !/cannot retry|nothing for you to retry/i.test(guidance),
        `${String(row["reason"])} tells the RESPONDER's operator to retry. They did not initiate ` +
          `this session and hold nothing to retry — put that advice in the session_refused frame ` +
          `instead, which reaches the side that can use it.`,
      ).toBe(false);
    }
  });

  it("an UNKNOWN reason gets no invented guidance — silence beats a wrong instruction", async () => {
    // Capacity and abuse bounds carry their own self-explanatory codes and are deliberately not in
    // the table. What must never happen is a default string that sounds like advice: a confidently
    // wrong next step costs more than a bare code, because the operator acts on it.
    const rows = await inboxFor(["some_bound_that_speaks_for_itself"]);
    expect(rows).toHaveLength(1);
    expect(rows[0]["guidance"]).toBeUndefined();
    expect(rows[0]["reason"]).toBe("some_bound_that_speaks_for_itself");
  });
});

describe("DOD-M15-GUARD-HEARD-1: no security refusal is recorded with a loose string", () => {
  it("every reason in REFUSAL_GUIDANCE is one the constant declares", () => {
    // The table is typed as a total map over RefusalReason, so this cannot drift — but the tests in
    // this repo are typechecked by a separate tsconfig, and asserting it at runtime costs nothing
    // and survives someone widening the type to Record<string, string> to make an error go away.
    const declared = new Set<string>(ALL_REASONS);
    const extra = Object.keys(REFUSAL_GUIDANCE).filter((k) => !declared.has(k));
    expect(extra, `guidance exists for reasons nothing can emit: ${extra.join(", ")}`).toEqual([]);
  });

  it("EVERY declared reason is actually emitted by a refusal site", () => {
    /**
     * The other direction, and the one that rots quietly. A reason nobody emits is dead weight that
     * still reads as coverage — and the tests above would happily prove that a reason no code path
     * can produce reaches the inbox beautifully.
     */
    const sources = ["inbound-sessions.ts", "session-node-manager.ts", "outbound-sessions.ts"]
      .map((f) => {
        try { return readFileSync(join(SRC, f), "utf8"); } catch { return ""; }
      })
      .join("\n");

    const memberFor: Record<string, string> = Object.fromEntries(
      Object.entries(REFUSAL_REASONS).map(([member, value]) => [value, member]),
    );
    const unemitted = ALL_REASONS.filter(
      (value) => !sources.includes(`REFUSAL_REASONS.${memberFor[value]}`),
    );
    expect(
      unemitted,
      `These reasons are declared and given guidance but no refusal site emits them: ` +
        `${unemitted.join(", ")}. Either wire the refusal or delete the reason — a reason with ` +
        `guidance and no emitter reads as a control that exists.`,
    ).toEqual([]);
  });

  it("the security refusal sites use the constant, never a bare string literal", () => {
    /**
     * The failure this prevents is a rename that silently misses. `recordRefusal` takes a
     * free-form `string` because capacity bounds legitimately pass their own codes — so nothing in
     * the type system stops a security path passing `"counterparty_primary_key_chnged"`. The
     * guidance lookup would miss, the operator would get a bare code, and every test above would
     * still pass because they enumerate the CONSTANT.
     */
    const src = readFileSync(join(SRC, "inbound-sessions.ts"), "utf8");
    const literals = ALL_REASONS.filter((value) => src.includes(`"${value}"`));
    expect(
      literals,
      `inbound-sessions.ts writes these reason values as bare string literals: ${literals.join(", ")}. ` +
        `Use REFUSAL_REASONS.<MEMBER> so a rename is a compile error rather than a silently missed ` +
        `guidance lookup.`,
    ).toEqual([]);
  });
});
