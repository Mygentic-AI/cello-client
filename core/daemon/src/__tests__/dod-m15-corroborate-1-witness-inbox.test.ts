/**
 * DOD-M15-CORROBORATE-1 clause 3+7 — the last three links, which nothing was testing.
 *
 * The relay flags, the client decodes, the callback fires — and then the alert has to reach a
 * PERSON. Review measured the gap: deleting `...witnessSection(agent)` from both returns in
 * `notification-handlers.ts` left both repos green, and the guidance prose — which is the whole
 * clause-7 artifact — was pinned by nothing at all.
 *
 * This drives the REAL `cello_check_notifications` handler and the REAL `SessionNodeManager`
 * recorder, so a rename or a dropped spread on either side fails here.
 *
 * Both inbox returns are exercised. The handler has TWO, and which one runs turns on whether the
 * agent has ended-unread history — the normal steady state for anyone with sealed conversations
 * they have not read. A section present on one and missing from the other is a defect this file's
 * sibling (`dod-m15-guard-heard-1`) already caught once, one field deeper.
 */
import { describe, it, expect } from "vitest";
import { registerNotificationHandlers, type NotificationHandlerDeps } from "../notification-handlers.js";
import { SessionNodeManager } from "../session-node-manager.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { RelayWitnessAlert } from "../session-relay-client.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";

const AGENT = "alice";
const SESSION = "2f".repeat(16);
const RELAY_ID = "ab".repeat(32);
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

function alert(over: Partial<RelayWitnessAlert> = {}): RelayWitnessAlert {
  return {
    sessionIdHex: SESSION,
    reason: "leaf_signed_by_neither_participant",
    relayId: RELAY_ID,
    observedAt: 1_760_000_000_000,
    submitterIsCounterparty: true,
    witnessPeerId: "12D3KooWRelayA",
    verifiable: true,
    ...over,
  };
}

async function inbox(
  seed: (m: SessionNodeManager) => void,
  opts: { endedUnread?: boolean } = {},
): Promise<Record<string, unknown>> {
  /**
   * A REAL SessionNodeManager, not a stub — the recorder's cap and its dedupe are half of what is
   * under test here, and a stub would assert the handler against behaviour nobody implements. Never
   * `initialize()`d: the witness list is in memory and nothing on this path touches the database.
   */
  const m = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), logger: silent } as never);
  seed(m);
  const handlers = new Map<string, IpcHandler>();
  const sessionNodeManager = {
    getUnreadSummary: () => [],
    getEndedUnread: () =>
      opts.endedUnread === true
        ? [{ session_id: "ff".repeat(16), counterparty_pubkey: "cc".repeat(32), unread_count: 1, status: "sealed" }]
        : [],
    getRenameNotices: () => [],
    // DOD-M15-NO-SILENT-REFUSAL-1: the inbox reads refusal notices too. Empty here — this fake
    // exists to isolate a DIFFERENT section, and a fake that omits the method makes the whole
    // handler throw rather than the section it is testing fail.
    takeAgentContentRefusals: () => [],
    getConsentRequests: () => [],
    listSessions: () => [],
    getPendingAttestationConsents: () => [],
    // The two REAL implementations, bound to the real manager.
    getWitnessAlerts: (a: string) => m.getWitnessAlerts(a),
    getWitnessUnreadable: (a: string) => m.getWitnessUnreadable(a),
    witnessAlertsTruncated: (a: string) => m.witnessAlertsTruncated(a),
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
    refusedSessionRequests: new Map(),
  } as unknown as NotificationHandlerDeps);
  const handler = handlers.get("cello_check_notifications");
  expect(handler, "cello_check_notifications must be registered or this file means nothing").toBeDefined();
  const res = (await handler!({}, "conn-1")) as { agents?: Array<Record<string, unknown>> };
  const mine = res.agents?.find((a) => a["agent"] === AGENT);
  expect(mine, "the inbox must contain a section for this agent").toBeDefined();
  return mine!;
}

describe("DOD-M15-CORROBORATE-1: a witness alert reaches the operator's inbox", () => {
  it.each([false, true])("★★★ the alert and its guidance are present (endedUnread=%s — BOTH returns)", async (endedUnread) => {
    const mine = await inbox((m) => { m.recordRelayWitnessAlert(AGENT, alert()); }, { endedUnread });

    const rows = mine["relay_witness_alerts"] as Array<Record<string, unknown>>;
    expect(rows, "the operator must be told, on whichever branch their inbox takes").toHaveLength(1);
    expect(rows[0]!["session_id"]).toBe(SESSION);
    expect(rows[0]!["witness_relay"]).toBe(RELAY_ID);
    expect(rows[0]!["submitter_was_your_counterparty"]).toBe(true);
    expect(rows[0]!["provable_to_a_third_party"]).toBe(true);
    expect(rows[0]!["times_observed"]).toBe(1);

    const guidance = String(mine["relay_witness_alerts_guidance"] ?? "");
    // Clause 7: what ONE witness establishes, and no more.
    expect(guidance, "it must say this is one relay's observation").toMatch(/ONE RELAY'S OBSERVATION, NOT A FINDING/);
    expect(guidance, "it must refuse to name a culprit").toMatch(/does not establish who sent it/);
    expect(guidance, "it must say there is no second witness").toMatch(/no second witness/);
    // The converse, which is the half an operator gets wrong.
    expect(guidance, "silence must not read as an all-clear").toMatch(/ABSENCE OF AN ALERT ESTABLISHES NOTHING/);
    // And a real next step, that exists.
    expect(guidance).toMatch(/cello_close_session/);
  });

  it("★★ a repeat of the same observation raises a COUNT — it does not take a second slot", async () => {
    /**
     * The bounded list is a resource, and whoever submits forged leaves chooses how many. Twenty
     * rows saying the same thing are one fact and nineteen ways to push another one off the list.
     */
    const mine = await inbox((m) => {
      m.recordRelayWitnessAlert(AGENT, alert());
      m.recordRelayWitnessAlert(AGENT, alert({ observedAt: 1_760_000_009_999 }));
    });
    const rows = mine["relay_witness_alerts"] as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!["times_observed"]).toBe(2);
    expect(rows[0]!["first_observed_at"]).toBe(1_760_000_000_000);
    expect(rows[0]!["last_observed_at"], "and the operator can see it is still happening").toBe(1_760_000_009_999);
  });

  it("★★★ a FLOOD cannot evict the first real alert", async () => {
    /**
     * ⚠️ THE DIRECTION OF THE CAP IS THE WHOLE POINT. Keeping the newest 20 hands the mute button
     * back to whoever can generate alerts: at the relay's own submit limit, about ten seconds of
     * fabrications would push the genuine one out before anyone read it.
     */
    const first = alert({ witnessPeerId: "12D3KooWFirst", relayId: "11".repeat(32), sessionIdHex: "aa".repeat(16) });
    const mine = await inbox((m) => {
      m.recordRelayWitnessAlert(AGENT, first);
      for (let i = 0; i < 200; i++) {
        // Distinct witness+session each time, so dedupe cannot be what saves it.
        m.recordRelayWitnessAlert(AGENT, alert({ witnessPeerId: `12D3KooWRelay${String(i)}`, relayId: String(i % 10).repeat(64).slice(0, 64), sessionIdHex: String(i).padStart(2, "0").repeat(16) }));
      }
    });
    const rows = mine["relay_witness_alerts"] as Array<Record<string, unknown>>;
    expect(rows.length, "bounded, or an attacker fills the operator's memory").toBeLessThanOrEqual(20);
    expect(
      rows[0]!["session_id"],
      "and the FIRST observation is the one that survives — it is the one that mattered",
    ).toBe("aa".repeat(16));
    expect(
      mine["relay_witness_alerts_incomplete"],
      "and the list must SAY it is incomplete — twenty rows that look whole is its own failure",
    ).toBe(true);
  });

  it("★★ two UNNAMED relays reporting on one session are two rows, not one", async () => {
    /**
     * The dedupe key is the relay's PEER ID, not `relayId` — which is absent for any relay that
     * could not sign. Keyed on the missing name, two different witnesses collapsed into one row and
     * the operator read one witness where there were two, which is the opposite of what a
     * corroboration layer is for.
     */
    const mine = await inbox((m) => {
      m.recordRelayWitnessAlert(AGENT, alert({ witnessPeerId: "12D3KooWOne", relayId: null, verifiable: false }));
      m.recordRelayWitnessAlert(AGENT, alert({ witnessPeerId: "12D3KooWTwo", relayId: null, verifiable: false }));
    });
    const rows = mine["relay_witness_alerts"] as Array<Record<string, unknown>>;
    expect(rows, "two witnesses is a materially different fact from one saying it twice").toHaveLength(2);
    expect(rows.every((r) => r["times_observed"] === 1)).toBe(true);
  });

  it("★★ an UNPROVABLE alert is shown, and shown as unprovable", async () => {
    const mine = await inbox((m) => { m.recordRelayWitnessAlert(AGENT, alert({ relayId: null, verifiable: false })); });
    const rows = mine["relay_witness_alerts"] as Array<Record<string, unknown>>;
    expect(rows[0]!["witness_relay"]).toBe("unnamed");
    expect(rows[0]!["provable_to_a_third_party"]).toBe(false);
    expect(
      String(mine["relay_witness_alerts_guidance"]),
      "the operator must be told what they can and cannot show someone",
    ).toMatch(/provable_to_a_third_party/);
  });

  it("★★ a relay whose alerts cannot be READ reaches the operator too — and accuses nobody", async () => {
    /**
     * If a version skew makes every relay's alert unreadable, the witness layer is silently dead and
     * the operator has no way to find that out. It must reach them, and it must say nothing about
     * any conversation or any counterparty.
     */
    const mine = await inbox((m) => { m.recordRelayWitnessUnreadable(AGENT, "12D3KooWRelay", "declared_relay_id_without_signature"); });
    const rows = mine["relay_witness_unreadable"] as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!["relay_peer_id"]).toBe("12D3KooWRelay");
    expect(rows[0]!["cause"]).toBe("declared_relay_id_without_signature");
    const guidance = String(mine["relay_witness_unreadable_guidance"] ?? "");
    expect(guidance, "it must say plainly that it is about no conversation").toMatch(/NOTHING about any conversation/);
    expect(guidance, "and that silence from that relay is not cleanliness").toMatch(/silent rather than as clean/);
    expect(mine["relay_witness_alerts"], "and it is NOT an alert").toBeUndefined();
  });

  it("★★ an agent with nothing to report gets NEITHER section — the inbox is not padded", async () => {
    const mine = await inbox(() => {});
    expect(mine["relay_witness_alerts"]).toBeUndefined();
    expect(mine["relay_witness_alerts_guidance"]).toBeUndefined();
    expect(mine["relay_witness_unreadable"]).toBeUndefined();
  });
});
