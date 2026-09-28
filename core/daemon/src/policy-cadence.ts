/**
 * 008-POLICY — when the operator's policy rides a delivery, and the one place each surface builds
 * the `policy` field.
 *
 * A conduct policy is attached to a delivery when ANY of:
 *   1. it is the first delivery there since the daemon started ("first");
 *   2. the resolved text differs from the one last attached there ("changed");
 *   3. at least `every_n` messages/posts have been delivered there since it was last attached
 *      ("cadence").
 * One attachment per delivery, never per message. In memory on purpose: a restart re-attaches on
 * the first delivery, which is the safe direction.
 *
 * A lookup that fails must NOT look like "no policy" — silent absence reads exactly like an
 * operator who set nothing. So a throwing store gives no `policy` field, a `policy_error` line the
 * agent reads, and `policy.resolve.failed` in the log.
 */
import type { Logger } from "./types.js";
import type { PolicyStore, ResolvedPolicy, PolicyType } from "./policy-store.js";
import { extractErrorMessage } from "./error-message.js";

export type AttachReason = "first" | "changed" | "cadence";

export interface PolicyField { type: PolicyType; level: ResolvedPolicy["level"]; text: string }

export const POLICY_ERROR_TEXT =
  "Your operator's policy for this peer could not be read, so none is shown here. That is a fault " +
  "on this machine, not a sign that no policy exists — act cautiously and tell your operator.";

export class PolicyCadence {
  readonly #state = new Map<string, { sinceLast: number; lastText: string | null }>();

  /** Decides and records. `deliveredCount` must be > 0 — an empty delivery never reaches here. */
  shouldAttach(key: string, resolved: ResolvedPolicy, deliveredCount: number): AttachReason | null {
    const s = this.#state.get(key);
    let reason: AttachReason | null;
    if (!s) reason = "first";
    else if (s.lastText !== resolved.text) reason = "changed";
    else if (s.sinceLast + deliveredCount >= resolved.everyN) reason = "cadence";
    else reason = null;
    if (reason === null) {
      s!.sinceLast += deliveredCount;
    } else {
      this.#state.set(key, { sinceLast: 0, lastText: resolved.text });
    }
    return reason;
  }

  drop(key: string): void { this.#state.delete(key); }
}

export const sessionCadenceKey = (agentId: string, sessionId: string): string => `s:${agentId}:${sessionId}`;
export const channelCadenceKey = (agentId: string, channelHex: string): string => `c:${agentId}:${channelHex.toLowerCase()}`;

const field = (r: ResolvedPolicy): { policy: PolicyField } => ({ policy: { type: r.type, level: r.level, text: r.text } });

function failed(logger: Logger, agentId: string, type: PolicyType, err: unknown): { policy_error: string } {
  logger.warn("policy.resolve.failed", { agentId, type, reason: extractErrorMessage(err) });
  return { policy_error: POLICY_ERROR_TEXT };
}

/** The admission policy for a knock. Attaches every time — `every_n` is not used for admission. */
export function admissionPolicyField(a: {
  store: PolicyStore; logger: Logger; agentId: string; peerPubkeyHex: string; tierName: string;
}): { policy?: PolicyField; policy_error?: string } {
  try {
    const r = a.store.resolveSession(a.agentId, "admission", a.peerPubkeyHex, a.tierName);
    return r ? field(r) : {};
  } catch (err: unknown) {
    return failed(a.logger, a.agentId, "admission", err);
  }
}

export function attachConductPolicy(a: {
  store: PolicyStore; cadence: PolicyCadence; logger: Logger; agentId: string; sessionId: string;
  peerPubkeyHex: string; tierName: string; count: number; correlationId: string;
}): { policy?: PolicyField; policy_error?: string } {
  let r: ResolvedPolicy | null;
  try {
    r = a.store.resolveSession(a.agentId, "conduct", a.peerPubkeyHex, a.tierName);
  } catch (err: unknown) {
    return failed(a.logger, a.agentId, "conduct", err);
  }
  if (!r || a.count <= 0) return {};
  const reason = a.cadence.shouldAttach(sessionCadenceKey(a.agentId, a.sessionId), r, a.count);
  if (reason === null) return {};
  a.logger.info("policy.attached", {
    agentId: a.agentId, sessionId: a.sessionId, type: r.type, level: r.level, reason, correlationId: a.correlationId,
  });
  return field(r);
}

/** `foreignCount` excludes the agent's own posts; a batch of only own posts attaches nothing. */
export function attachChannelPolicy(a: {
  store: PolicyStore; cadence: PolicyCadence; logger: Logger; agentId: string; channelHex: string;
  foreignCount: number; correlationId: string;
}): { policy?: PolicyField; policy_error?: string } {
  if (a.foreignCount <= 0) return {};
  let r: ResolvedPolicy | null;
  try {
    r = a.store.resolveChannel(a.agentId, a.channelHex);
  } catch (err: unknown) {
    return failed(a.logger, a.agentId, "conduct", err);
  }
  if (!r) return {};
  const reason = a.cadence.shouldAttach(channelCadenceKey(a.agentId, a.channelHex), r, a.foreignCount);
  if (reason === null) return {};
  a.logger.info("policy.attached", {
    agentId: a.agentId, channel: a.channelHex, type: r.type, level: r.level, reason, correlationId: a.correlationId,
  });
  return field(r);
}
