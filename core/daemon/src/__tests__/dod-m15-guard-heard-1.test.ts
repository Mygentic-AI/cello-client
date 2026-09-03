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
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import { TIER } from "../contacts-tier-migration.js";
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
async function inboxFor(
  reasons: readonly string[],
  opts: { endedUnread?: boolean } = {},
): Promise<Array<Record<string, unknown>>> {
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
    /**
     * THE OTHER RETURN. `cello_check_notifications` has TWO, and which one runs turns on whether
     * this is empty (`notification-handlers.ts`). A review measured the cost of only ever exercising
     * one: leave `refused_session_requests` present on the ended-unread branch but let it build its
     * rows without the guidance spread, and **24 tests stay green** while every operator who has any
     * ended-unread history — sealed conversations they have not read, i.e. the normal steady state —
     * gets bare reason codes on every security refusal.
     *
     * That is DOD-M12B-INBOX-TRUTH-1 recurring one field deeper, in the file whose whole subject is
     * that class. So both branches are driven.
     */
    getEndedUnread: () =>
      opts.endedUnread === true
        ? [{ session_id: "ff".repeat(16), counterparty_pubkey: "cc".repeat(32), unread_count: 1, status: "sealed" }]
        : [],
    getRenameNotices: () => [],
    // DOD-M15-NO-SILENT-REFUSAL-1: the inbox reads refusal notices too. Empty here — this fake
    // exists to isolate a DIFFERENT section, and a fake that omits the method makes the whole
    // handler throw rather than the section it is testing fail.
    takeAgentContentRefusals: () => [],
    // DOD-M15-CORROBORATE-1: the inbox reads relay witness alerts too. Empty here — this file is
    // about refusal guidance, and a stub that omitted the method made every case throw.
    getWitnessAlerts: () => [],
    getWitnessUnreadable: () => [],
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
      // A FLOOR, not the property — kept because it catches a stub left behind by a refactor, and
      // named as a floor because it cannot express "carries a next step". The three real entries are
      // 433, 510 and 455 characters, so this constrains nothing in the live range.
      expect(
        guidance.length,
        `${String(row["reason"])}'s guidance is a stub — too short to carry a cause and a next step`,
      ).toBeGreaterThan(120);

      /**
       * THE ACTUAL PROPERTY. A review cleared the length floor with 154 characters of
       * "Something went wrong with this session and it was not accepted", twice, plus "Contact
       * support if needed" — magic phrase present, floor cleared, no verb the reader can perform,
       * Invariant 4 violated in the same breath.
       *
       * An allowlist of REAL affordances instead: a tool this operator can run, or an action they
       * can take outside CELLO. Prose gets an allowlist; wire names get a denylist.
       */
      const AFFORDANCES = [
        /cello_[a-z_]+/,                       // a tool they can actually call
        /out of band/i,                        // the one remedy that is deliberately not a tool
        /do not accept/i,                      // a decision they can make about a counterparty
        /confirm(ed)? (that )?with them/i,
      ];
      expect(
        AFFORDANCES.some((re) => re.test(guidance)),
        `${String(row["reason"])}'s guidance names nothing the operator can DO. It says what ` +
          `happened and stops. Name a tool (cello_*), or an action outside CELLO ("confirm out of ` +
          `band"), or a decision they can take ("do not accept a session from them until…").`,
      ).toBe(true);
    }
  });

  it("guidance survives the OTHER inbox branch — the one an operator with unread history gets", async () => {
    // H2. `cello_check_notifications` has two returns and this is the one taken whenever the agent
    // has ended-unread sessions, which is the ordinary steady state rather than an edge case.
    const rows = await inboxFor(ALL_REASONS, { endedUnread: true });
    expect(rows.length, "the refused list must survive the ended-unread branch").toBe(ALL_REASONS.length);
    const bare = rows.filter((r) => typeof r["guidance"] !== "string").map((r) => String(r["reason"]));
    expect(
      bare,
      `On the ended-unread branch these arrive as bare codes: ${bare.join(", ")}. The presence of ` +
        `the LIST on this branch is pinned by DOD-M12B-INBOX-TRUTH-1; the guidance on its rows was ` +
        `not, and a branch that builds its own row objects can drop it with every test green.`,
    ).toEqual([]);
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
      /**
       * SENTENCE-SCOPED, because the first version was not and one reason was already exempt.
       *
       * It tested the whole string for "retry" and then excused it if the whole string ALSO
       * contained "nothing for you to retry" — a phrase `inbound_assignment_invalid` legitimately
       * contains. So that reason was permanently exempt from the rule in the committed tree: a
       * review prefixed it with "Retry now to reach a different directory node." and got 8/8 green,
       * while the identical edit to a sibling went red. The check worked only where it was not
       * needed.
       *
       * The natural way this happens is a copy-paste: that exact sentence exists verbatim in the
       * LOG guidance for the same refusal, where it is correct, because the log is also read by
       * whoever is debugging rather than by the refused party.
       */
      const offending = guidance
        .split(/(?<=\.)\s+/)
        .filter((sentence) => /\bretry\b/i.test(sentence))
        .filter((sentence) => !/\b(no|nothing|cannot|can't|not)\b/i.test(sentence));
      expect(
        offending,
        `${String(row["reason"])} tells the RESPONDER's operator to retry, in: ` +
          `"${offending.join(" ")}". They did not initiate this session and hold nothing to retry — ` +
          `put that advice in the session_refused frame instead, which reaches the side that can ` +
          `use it. A sentence NEGATING retry ("there is nothing for you to retry") is fine and is ` +
          `why this reads one sentence at a time rather than the whole paragraph.`,
      ).toEqual([]);
    }
  });

  it("an UNKNOWN reason gets no invented guidance — silence beats a wrong instruction", async () => {
    // Capacity and abuse bounds carry their own self-explanatory codes and are deliberately not in
    // the table. What must never happen is a default string that sounds like advice: a confidently
    // wrong next step costs more than a bare code, because the operator acts on it.
    const rows = await inboxFor(["some_bound_that_speaks_for_itself"]);
    expect(rows).toHaveLength(1);
    expect(
      rows[0]["guidance"],
      `A reason with no entry in REFUSAL_GUIDANCE received guidance anyway, which means something ` +
        `is supplying a default. A generic next step attached to a refusal nobody wrote it for is ` +
        `worse than a bare code: the operator ACTS on it. Leave it absent.`,
    ).toBeUndefined();
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
    // NO `catch { return "" }` here. It silently turned a renamed or split file into an empty
    // string, so the scan would check two files instead of three and say nothing — masked today
    // only because all three reasons happen to live in one of them.
    const sources = ["inbound-sessions.ts", "session-node-manager.ts", "outbound-sessions.ts"]
      .map((f) => {
        const text = readFileSync(join(SRC, f), "utf8");
        expect(text.length, `${f} is empty — the emitter scan would silently check less`).toBeGreaterThan(0);
        // Comments do not emit. A commented-out reference used to satisfy this scan, so a real
        // emission could be replaced by a bare literal with the old line left as a `// was: …` note.
        return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
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

/**
 * Drive the REAL shared refusal path for one reason, and capture every audience it reaches.
 *
 * `refuseInboundSession` rather than an injected frame: the point is to enumerate over REASONS, and
 * constructing a frame that provokes each specific refusal would tie the enumeration back to the
 * call sites it exists to be independent of.
 */
async function refusalHarness(
  reason: string,
  opts: { tier?: number } = {},
): Promise<{ durable: Array<{ reason: string }>; sent: Array<Record<string, unknown>> }> {
  const durable: Array<{ reason: string }> = [];
  const sent: Array<Record<string, unknown>> = [];

  const sessionNodeManager = {
    getOfferedDialer: () => null,
    clearOfferedDialer: () => {},
    revokeOfferedDialer: async () => {},
    recordRefusedSession: (_a: string, _s: string, r: string) => { durable.push({ reason: r }); },
    getTier: () => opts.tier ?? TIER.KNOWN,
    resolveTierBound: () => 3,
    getPinnedCounterpartyPrimary: () => null,
    getSessionRecord: () => undefined,
    getStandingReceiverReady: () => true,
  };

  const api = createInboundSessions({
    logger: silent,
    sessionNodeManager,
    agents: [{ name: AGENT, pubkey: "bb".repeat(32) }],
    sharedSignaling: { registerInboundHandler: () => () => {} },
    sendOver: async (_agent: string, frame: Record<string, unknown>) => { sent.push(frame); return { ok: true }; },
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

  api.refuseInboundSession({
    agentName: AGENT,
    sessionIdHex: "ab".repeat(16),
    counterpartyPubkeyHex: "aa".repeat(32),
    reason,
    offeredDialer: null,
    counterpartyGuidance:
      REFUSAL_GUIDANCE[reason as RefusalReason] ?? "no guidance was supplied for this reason",
    correlationId: "corr-1",
  });
  // sendOver is awaited inside a floating promise; let it settle.
  await new Promise((r) => setImmediate(r));
  return { durable, sent };
}

describe("DOD-M15-GUARD-HEARD-1: all THREE audiences, enumerated over the reasons", () => {
  /**
   * ─── Why this exists when `dod-m15-offer-signed-1.test.ts` already covers the same property ───
   *
   * It covers it PER CALL SITE. Delete the durable row or the `session_refused` send and three of
   * its tests go red, so the property genuinely holds today — I checked rather than assumed.
   *
   * But the DoD line asked for something different, and the difference is the entire reason the
   * line exists:
   *
   *   > an enumeration over the refusal reason codes asserting each one reaches the operator
   *   > surface AND, where a counterparty is involved, THE WIRE.
   *
   * A per-site test covers the sites that exist. The failure mode this line is named for is the
   * NEXT site — the fifth occurrence, written by someone who copies the shortest nearby example,
   * which is exactly how the two security refusals came to do one of the four things the cap
   * refusal does. Enumerating over the reasons means a new reason arrives already covered.
   *
   * The three audiences, and what losing each one costs:
   *
   *   1. the operator's inbox — a refusal they never see is indistinguishable from the session
   *      never arriving
   *   2. the DURABLE row — content the initiator already parked re-pulls forever without it (the
   *      78-times-per-message loop), and the in-memory list dies with the process
   *   3. the WIRE — otherwise the counterparty sees a transport-shaped failure naming nothing that
   *      is wrong, and reports that CELLO is broken while this side holds a precise finding
   */
  it("every SECURITY reason reaches the durable store and the counterparty, not just the inbox", async () => {
    for (const reason of ALL_REASONS) {
      const h = await refusalHarness(reason);

      expect(
        h.durable.map((d) => d.reason),
        `${reason} left no durable row. The initiator held a valid assignment and will have parked ` +
          `content for this session; with no refused-session row the drain re-pulls it forever, and ` +
          `the in-memory record dies with the daemon — so the most serious thing this path detects ` +
          `would be more perishable than a routine capacity refusal.`,
      ).toContain(reason);

      const frame = h.sent.find((f) => f["type"] === "session_refused");
      expect(
        frame,
        `${reason} told the counterparty nothing. They dialled an assignment their directory called ` +
          `valid, hit a shut gate, and see only a transport failure naming nothing that is wrong.`,
      ).toBeDefined();
      expect(frame?.["reason"]).toBe(reason);
      expect(
        String(frame?.["guidance"]).length,
        `${reason}'s wire guidance is empty — the frame arrives naming a code they cannot look up`,
      ).toBeGreaterThan(80);
    }
  });

  it("a STRANGER is still told nothing — the oracle rule survives this enumeration", async () => {
    // The counterexample that stops the test above being satisfied by telling everyone everything.
    // UNKNOWN and BLOCKED get silence on purpose: a stranger learns nothing, and a blocked party
    // cannot tell blocking from a refusal. Only KNOWN+ earn a reason, and an identity-change
    // refusal is by definition a repeat counterparty.
    const h = await refusalHarness(REFUSAL_REASONS.COUNTERPARTY_PRIMARY_KEY_CHANGED, { tier: TIER.UNKNOWN });
    expect(h.durable.length, "the durable record is kept regardless of tier").toBe(1);
    expect(
      h.sent.find((f) => f["type"] === "session_refused"),
      "a stranger must not be told why they were refused — that is a blocking oracle",
    ).toBeUndefined();
  });
});
