/**
 * 008-POLICY (amended 2026-09-28) — the agent proposes, the operator approves.
 *
 * A proposal is stored PENDING and is not in force. It gets a short local id `p<n>` (per agent,
 * monotonic, never reused). One pending proposal per slot (scope, target, type): a new one replaces
 * the old. Proposals older than 24 hours are deleted on every read and never shown.
 *
 * `approve` is the only caller of `PolicyStore.set` / `clear`. The IPC layer lets only a `cli`
 * connection reach it, and the CLI asks only at an interactive terminal.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { PolicyRow, PolicyScope, PolicyStore, PolicyType, PolicyValue } from "./policy-store.js";

export const PROPOSAL_TTL_MS = 24 * 60 * 60 * 1000;

export type ProposedBy = "agent" | "operator";

export interface ProposalInput {
  scope: PolicyScope; target: string; type: PolicyType;
  action: "set" | "clear"; value?: PolicyValue; everyN?: number;
}

export interface PolicyProposal {
  proposal_id: string; scope: PolicyScope; target: string; type: PolicyType;
  action: "set" | "clear"; mode: "text" | "none" | null; text: string | null; every_n: number | null;
  proposed_by: ProposedBy; created_at: number;
}

export type ApproveResult =
  | { ok: true; proposal: PolicyProposal }
  | { ok: false; reason: "proposal_not_found" };

export class PolicyProposals {
  constructor(
    private readonly db: DaemonDatabase,
    private readonly logger: Logger,
    private readonly store: PolicyStore,
    private readonly now: () => number = Date.now,
  ) {}

  /** Validates now (named reasons), then REPLACES any pending proposal for the same slot. */
  propose(agentId: string, p: ProposalInput, proposedBy: ProposedBy): PolicyProposal {
    const v = this.store.validate(p.scope, p.target, p.type, p.action === "set" ? (p.value ?? { mode: "text", text: "" }) : undefined, p.everyN);
    const id = this.#nextId(agentId);
    const row: PolicyProposal = {
      proposal_id: id, scope: p.scope, target: v.target, type: p.type, action: p.action,
      mode: p.action === "set" ? (p.value?.mode ?? "text") : null,
      text: p.action === "set" ? v.text : null,
      every_n: p.action === "set" ? v.everyN : null,
      proposed_by: proposedBy, created_at: this.now(),
    };
    this.db.prepare("DELETE FROM agent_policy_proposals WHERE agent_id = ? AND scope = ? AND target = ? AND type = ?")
      .run(agentId, row.scope, row.target, row.type);
    this.db.prepare(
      `INSERT INTO agent_policy_proposals (agent_id, proposal_id, scope, target, type, action, mode, text, every_n, proposed_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(agentId, id, row.scope, row.target, row.type, row.action, row.mode, row.text, row.every_n, row.proposed_by, row.created_at);
    this.logger.info("policy.proposed", { agentId, proposalId: id, scope: row.scope, target: row.target, type: row.type, proposedBy });
    return row;
  }

  /** What is waiting, oldest first, each with the row currently in force at its slot (`was`). */
  pending(agentId: string): Array<PolicyProposal & { was: PolicyRow | null }> {
    this.#expire(agentId);
    const rows = this.db.prepare(
      `SELECT proposal_id, scope, target, type, action, mode, text, every_n, proposed_by, created_at
       FROM agent_policy_proposals WHERE agent_id = ? ORDER BY created_at, proposal_id`,
    ).all(agentId) as PolicyProposal[];
    return rows.map((r) => ({ ...r, was: this.store.get(agentId, r.scope, r.target, r.type) }));
  }

  approve(agentId: string, proposalId: string): ApproveResult {
    const p = this.#find(agentId, proposalId);
    if (!p) return { ok: false, reason: "proposal_not_found" };
    if (p.action === "clear") {
      this.store.clear(agentId, p.scope, p.target, p.type);
    } else {
      const value: PolicyValue = p.mode === "none" ? { mode: "none" } : { mode: "text", text: p.text ?? "" };
      this.store.set(agentId, p.scope, p.target, p.type, value, p.every_n ?? undefined);
    }
    this.#delete(agentId, proposalId);
    this.logger.info("policy.approved", { agentId, proposalId });
    return { ok: true, proposal: p };
  }

  /** The operator answered no: the proposal is discarded and the store is untouched. */
  decline(agentId: string, proposalId: string): boolean {
    if (!this.#find(agentId, proposalId)) return false;
    this.#delete(agentId, proposalId);
    this.logger.info("policy.declined", { agentId, proposalId });
    return true;
  }

  #find(agentId: string, proposalId: string): PolicyProposal | null {
    this.#expire(agentId);
    return (this.db.prepare(
      `SELECT proposal_id, scope, target, type, action, mode, text, every_n, proposed_by, created_at
       FROM agent_policy_proposals WHERE agent_id = ? AND proposal_id = ?`,
    ).get(agentId, proposalId) as PolicyProposal | undefined) ?? null;
  }

  #delete(agentId: string, proposalId: string): void {
    this.db.prepare("DELETE FROM agent_policy_proposals WHERE agent_id = ? AND proposal_id = ?").run(agentId, proposalId);
  }

  #expire(agentId: string): void {
    const cutoff = this.now() - PROPOSAL_TTL_MS;
    const old = this.db.prepare("SELECT proposal_id FROM agent_policy_proposals WHERE agent_id = ? AND created_at < ?")
      .all(agentId, cutoff) as Array<{ proposal_id: string }>;
    if (old.length === 0) return;
    this.db.prepare("DELETE FROM agent_policy_proposals WHERE agent_id = ? AND created_at < ?").run(agentId, cutoff);
    for (const o of old) this.logger.info("policy.expired", { agentId, proposalId: o.proposal_id });
  }

  #nextId(agentId: string): string {
    this.db.prepare(
      "INSERT INTO agent_policy_proposal_seq (agent_id, last) VALUES (?, 1) ON CONFLICT (agent_id) DO UPDATE SET last = last + 1",
    ).run(agentId);
    const r = this.db.prepare("SELECT last FROM agent_policy_proposal_seq WHERE agent_id = ?").get(agentId) as { last: number };
    return `p${r.last}`;
  }
}
