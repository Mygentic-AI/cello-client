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
    // Andre's copy (2026-10-29): the verb is verify; "does not store", never add/hold/on record.
    notice:
      "CELLO does not store phone numbers. It asks each owner to verify one, so every agent has a real " +
      "owner behind it and nobody can easily flood the network with bots. Your owner hasn't verified " +
      "yet, so this account can run at most 3 agents.",
    guidance:
      "Mention this to your owner at a natural pause, not mid-task. They can verify their phone number " +
      "at portal.celloprotocol.com/account.",
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

/**
 * The daemon's account-notice state: the box the inbox reads, and the doorbell, bound to the
 * notification dispatcher once it exists. A notice that arrives before then is still held.
 */
export class AccountNoticeWiring {
  readonly box = new AccountNoticeBox();
  #ring: ((agentName: string, kind: AccountNoticeKind) => void) | null = null;

  constructor(
    private readonly logger: Parameters<typeof receiveAccountNotice>[0]["logger"],
    private readonly resolveAgentId: (agentName: string) => string,
  ) {}

  receive(agentName: string, kind: unknown): void {
    receiveAccountNotice(
      { box: this.box, logger: this.logger, resolveAgentId: this.resolveAgentId, dispatch: (n, k) => this.#ring?.(n, k) },
      agentName, kind,
    );
  }

  ringWith<D extends { dispatchAccountNotice(agentName: string, kind: string): void }>(dispatcher: D): D {
    this.#ring = (n, k) => dispatcher.dispatchAccountNotice(n, k);
    return dispatcher;
  }
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
