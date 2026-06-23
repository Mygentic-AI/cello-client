/**
 * @cello-protocol/gateway — the security gateway contract.
 *
 * The gateway is a SEPARATE program from the daemon (M9-CORE-001 / V3 split-deployment).
 * The daemon holds ONLY this interface and its two call sites; all detection lives in the
 * gateway program. The same interface backs both the local sidecar (Phase 1) and the
 * remote mTLS gateway (Phase 2) — Phase 2 is a transport swap behind `SecurityGatewayClient`,
 * not a rewrite.
 *
 * M9-CORE-001 implements the seam with a pass-through: every message is screened (the call
 * happens at the two fixed points) but the verdict is always `allow`, except the fail-closed
 * `block` a configured-but-unreachable gateway returns. Detectors and the redact/warn
 * dispositions arrive in later stories (M9-IN-*, M9-OUT-*, M9-FEED-001).
 */

/** Which direction the content is flowing relative to the daemon. */
export type ScreenDirection = "outbound" | "inbound";

/**
 * What the gateway decided to do with a message.
 *
 * - `allow`  — deliver/send as-is (or as transformed via `content`).
 * - `block`  — do not deliver/send. M9-CORE-001 uses this only for fail-closed
 *              (`gateway_unavailable`); detectors add real blocks later.
 * - `redact` — deliver/send a transformed `content` (M9-OUT-* / M9-FEED-001).
 * - `warn`   — held pending an explicit governance decision (M9-FEED-001).
 *
 * M9-CORE-001 only ever returns `allow` or `block`; `redact`/`warn` are declared here so the
 * seam code that switches on the disposition is complete from the start.
 */
export type ScreenDisposition = "allow" | "block" | "redact" | "warn";

/** The per-stage governance disposition (the §6 model: advisory, mutating, needs-decision, blocking). */
export type GovernanceDisposition = "observe" | "redact" | "block" | "warn";

/**
 * One governance finding published by a screen stage (§6). The verdict aggregates these; the daemon
 * renders them to the agent (M9-FEED-001) — as the transformations on a redact, the reasons on a
 * block, or the flagged items (with `flagId`) on a warn.
 */
export interface GovernanceEvent {
  stage: string;
  disposition: GovernanceDisposition;
  category: string;
  reason: string;
  /** Deterministic handle the agent passes on a governance re-send (warn items). */
  flagId?: string;
}

/** Context the daemon passes with each screen request. Identity-scoped, never content-derived. */
export interface ScreenContext {
  direction: ScreenDirection;
  agentName: string;
  sessionId: string;
  /** The async-flow correlation id, threaded through every event in this send/receive (INV-7). */
  correlationId?: string;
}

/**
 * A screening verdict.
 *
 * `content` is the bytes the daemon should act on: for `allow` it equals the input; for
 * `redact` it is the transformed form; for `block`/`warn` it is absent (nothing is
 * delivered/sent). `reason` is a stable machine code; `guidance` is actionable text the
 * agent sees on a non-allow outcome (INV-7).
 */
export interface ScreenVerdict {
  disposition: ScreenDisposition;
  content?: Uint8Array;
  reason?: string;
  guidance?: string;
  /** The governance findings behind this verdict (M9-FEED-001 renders them to the agent). */
  events?: GovernanceEvent[];
}

/**
 * The narrow interface the daemon holds. Two methods, two seams:
 *   - `screenOutbound` runs in `cello_send` before `sessionNodeManager.sendContent`.
 *   - `screenInbound`  runs in the inbound funnel before content enters the receive buffer.
 *
 * Implementations MUST be non-hanging: every call resolves to a terminal verdict within a
 * deadline. A timeout or unreachable gateway resolves to a fail-closed `block`
 * (`gateway_unavailable`), never a rejected/never-settling promise (INV-6 / SI-001).
 */
export interface SecurityGatewayClient {
  screenOutbound(content: Uint8Array, ctx: ScreenContext): Promise<ScreenVerdict>;
  screenInbound(content: Uint8Array, ctx: ScreenContext): Promise<ScreenVerdict>;
}

/** The reason code a fail-closed verdict carries when the gateway cannot be reached. */
export const GATEWAY_UNAVAILABLE = "gateway_unavailable";
/** The reason a fail-closed verdict carries when the gateway is reachable but the screening
 *  deadline was exceeded — a timeout is a verdict, not a hang (INV-6 / FEED-001 AC-005). */
export const GOVERNANCE_TIMEOUT = "governance_timeout";

/**
 * Build the fail-closed verdict (SI-001 / DB-001 / INV-6): never deliver/send ungated content, never
 * hang. `reason` distinguishes "could not connect" (`gateway_unavailable`) from "connected but the
 * screening deadline elapsed" (`governance_timeout`).
 */
export function failClosedVerdict(direction: ScreenDirection, reason: string = GATEWAY_UNAVAILABLE): ScreenVerdict {
  const cause = reason === GOVERNANCE_TIMEOUT
    ? "the security gateway did not return a verdict within the screening deadline"
    : "the security gateway could not be reached";
  return {
    disposition: "block",
    reason,
    guidance:
      direction === "outbound"
        ? `Fail-closed: ${cause}, so this message was NOT sent. Nothing left the machine. ` +
          "Check that the gateway sidecar is running, then retry."
        : `Fail-closed: ${cause}, so inbound content was not delivered to the agent. It was left ` +
          "unacknowledged, so the sender redelivers it on a later attempt — screened once the gateway responds.",
  };
}
