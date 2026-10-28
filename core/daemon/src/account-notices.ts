/**
 * Account notices: a directory may push `{ type: "account_notice", kind }` down an agent's
 * signaling stream. The frame names one kind from a fixed list and nothing else; every word the
 * agent reads comes from the constants below, so a frame's other fields never reach its context.
 *
 * Held in memory on purpose. A notice a restart loses costs nothing (the owner is also emailed),
 * and it keeps reminders out of the operator's database.
 */
export const ACCOUNT_NOTICE_KINDS = ["phone_unverified"] as const;
export type AccountNoticeKind = (typeof ACCOUNT_NOTICE_KINDS)[number];

export const ACCOUNT_NOTICE_TEXT: Record<AccountNoticeKind, { notice: string; guidance: string }> = {
  phone_unverified: {
    notice:
      "This agent's account has no phone number on record, so it can hold at most 3 agents. " +
      "Adding one is a one-time step in the portal. CELLO keeps only a one-way hash of the number.",
    guidance:
      "Tell your owner they can add a phone number at portal.celloprotocol.com/account. Nothing is needed from you.",
  },
};

export function isAccountNoticeKind(value: unknown): value is AccountNoticeKind {
  return typeof value === "string" && (ACCOUNT_NOTICE_KINDS as readonly string[]).includes(value);
}

/**
 * One inbound `account_notice` frame: hold it for the inbox and ring the doorbell. A kind not in
 * the list is dropped with a WARN, and its value is not logged.
 */
export function receiveAccountNotice(
  deps: {
    box: AccountNoticeBox;
    resolveAgentId: (agentName: string) => string;
    dispatch: (agentName: string, kind: AccountNoticeKind) => void;
    logger: { info(e: string, f: Record<string, unknown>): void; warn(e: string, f: Record<string, unknown>): void };
  },
  agentName: string,
  kind: unknown,
): void {
  if (!isAccountNoticeKind(kind)) {
    deps.logger.warn("account.notice.unknown_kind", { agentName });
    return;
  }
  deps.box.note(deps.resolveAgentId(agentName), kind);
  deps.logger.info("account.notice.received", { agentName, kind });
  deps.dispatch(agentName, kind);
}

/** At most one held notice per (agent, kind); taking them clears them. */
export class AccountNoticeBox {
  readonly #held = new Map<string, Set<AccountNoticeKind>>();

  note(agentId: string, kind: AccountNoticeKind): void {
    const kinds = this.#held.get(agentId) ?? new Set<AccountNoticeKind>();
    kinds.add(kind);
    this.#held.set(agentId, kinds);
  }

  take(agentId: string): AccountNoticeKind[] {
    const kinds = this.#held.get(agentId);
    this.#held.delete(agentId);
    return kinds ? [...kinds] : [];
  }
}
