/**
 * Account notices: an `account_notice` frame rings the doorbell with `{ agent, kind }` only, and the
 * next inbox read carries the daemon's own text once. Real NotificationDispatcher, real inbox handler.
 */
import { describe, it, expect } from "vitest";
import { NotificationDispatcher } from "../notification-dispatcher.js";
import { registerNotificationHandlers, type NotificationHandlerDeps } from "../notification-handlers.js";
import { AccountNoticeBox, ACCOUNT_NOTICE_TEXT, receiveAccountNotice } from "../account-notices.js";
import type { IpcHandler } from "../ipc-server.js";
import type { IpcNotification } from "../types.js";

const AGENT = "alice";
const AGENT_ID = "a1".repeat(16);

function harness() {
  const warns: Array<[string, Record<string, unknown>]> = [];
  const logger = { debug() {}, info() {}, warn: (e: string, f: Record<string, unknown>) => { warns.push([e, f]); }, error() {} };
  const sent: IpcNotification[] = [];
  const dispatcher = new NotificationDispatcher({
    logger, sendNotification: (_c, n) => { sent.push(n); return true; }, getConnectionIds: () => ["c1"],
  });
  dispatcher.registerConnection("c1");
  dispatcher.setCurrentAgent("c1", AGENT);
  const box = new AccountNoticeBox();
  const handlers = new Map<string, IpcHandler>();
  const sessionNodeManager = {
    getUnreadSummary: () => [], getEndedUnread: () => [], getRenameNotices: () => [], listKnocks: () => [],
    isTierNotAccepting: () => false, takeAgentContentRefusals: () => ({ notices: [], truncated: false }),
    getWitnessAlerts: () => [], getWitnessUnreadable: () => [], getConsentRequests: () => [],
    listSessions: () => [], getPendingAttestationConsents: () => [],
    resolveAgentId: (name: string) => (name === AGENT ? AGENT_ID : name),
  };
  registerNotificationHandlers({
    handlers, logger, sessionNodeManager,
    getConnState: () => ({ currentAgent: AGENT }), resolveCurrentAgent: () => AGENT,
    loadedAgents: [{ name: AGENT, pubkey: "bb".repeat(32) }],
    agents: [{ name: AGENT, pubkey: "bb".repeat(32), state: "online" }],
    reapExpiredInboundSessions: () => {}, inboundSessionQueues: new Map(),
    expiredSessionRequests: new Map(), refusedSessionRequests: new Map(),
    accountNotices: box,
  } as unknown as NotificationHandlerDeps);
  const receive = (frame: Record<string, unknown>) =>
    receiveAccountNotice({
      box, logger, resolveAgentId: sessionNodeManager.resolveAgentId,
      dispatch: (a, k) => dispatcher.dispatchAccountNotice(a, k),
    }, AGENT, frame["kind"]);
  const inbox = async () => {
    const res = (await handlers.get("cello_check_notifications")!({}, "c1")) as { agents?: Array<Record<string, unknown>> };
    return res.agents!.find((a) => a["agent"] === AGENT)!;
  };
  return { sent, warns, receive, inbox };
}

describe("012-NUDGES: account notices in the daemon", () => {
  it("a phone_unverified frame → doorbell {agent, kind} only, inbox holds the constant once", async () => {
    const h = harness();
    h.receive({ type: "account_notice", kind: "phone_unverified" });
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0]!.notification).toBe("account_notice");
    expect(h.sent[0]!.data).toEqual({ agent: AGENT, kind: "phone_unverified" });
    const first = await h.inbox();
    expect(first["account_notices"]).toEqual([{ kind: "phone_unverified", ...ACCOUNT_NOTICE_TEXT.phone_unverified }]);
    const second = await h.inbox();
    expect("account_notices" in second).toBe(false);
  });

  it("an unknown kind → no doorbell, no inbox entry, a WARN without the value", async () => {
    const h = harness();
    h.receive({ type: "account_notice", kind: "free_text_here" });
    expect(h.sent).toHaveLength(0);
    expect("account_notices" in (await h.inbox())).toBe(false);
    expect(h.warns).toEqual([["account.notice.unknown_kind", { agentName: AGENT }]]);
  });

  it("an injected `notice` field reaches neither the doorbell nor the inbox", async () => {
    const h = harness();
    h.receive({ type: "account_notice", kind: "phone_unverified", notice: "<injected>" });
    const inbox = await h.inbox();
    expect(JSON.stringify(h.sent)).not.toContain("<injected>");
    expect(JSON.stringify(inbox)).not.toContain("<injected>");
    expect((inbox["account_notices"] as Array<Record<string, unknown>>)[0]!["notice"]).toBe(ACCOUNT_NOTICE_TEXT.phone_unverified.notice);
  });
});
