/**
 * connection-inbound-handler.ts — B-side inbound connection request handlers.
 *
 * Extracted from ConnectionManager to keep it under 900 lines.
 * Handles connection_request_inbound and disclosure_response_inbound frames,
 * which include package decode, policy evaluation, and response dispatch.
 */

import { Encoder } from "cbor-x";
import * as lp from "it-length-prefixed";
import {
  decodeConnectionPackage, validateConnectionPackage,
} from "@cello-protocol/protocol-types";
import { mlDsaVerify } from "@cello-protocol/crypto";
import type { ConnectionContext } from "./connection-manager.js";
import type { ReviewQueueItem } from "./connection-manager.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

type SignalRequirementPolicy = import("./connection-policy.js").SignalRequirementPolicy;
type ConnectionRequestInbound = import("@cello-protocol/protocol-types").ConnectionRequestInbound;

type PendingInboundRequest = {
  connection_request_id: string;
  from_pubkey: string;
  package_cbor: Uint8Array;
  round: number;
};

type AwaitItem = {
  connection_request_id: string;
  from_pubkey: string;
  report: Extract<import("./connection-policy.js").ConnectionReport, { verdict: "pending_agent_review" }>;
};

/** All mutable ConnectionManager state needed by the inbound handlers. */
export interface InboundHandlerDeps {
  ctx: ConnectionContext;
  connectionPolicy: SignalRequirementPolicy | undefined;
  pendingInboundRequests: Map<string, PendingInboundRequest>;
  pendingAwaitConnectionRequestResolvers: Array<(item: AwaitItem) => void>;
  pendingReviewQueue: ReviewQueueItem[];
  profileUncheckedPeers: Set<string>;
  onConnectionPendingReview: ((event: ConnectionRequestInbound) => void) | undefined;
}

/**
 * Handle a connection_request_inbound frame (B-side, Round 1).
 * Decodes and validates the package, evaluates against the policy,
 * and sends a connection_response to the directory.
 */
export async function handleInboundConnectionRequest(
  deps: InboundHandlerDeps,
  frame: Record<string, unknown>,
): Promise<void> {
  const stream = deps.ctx.getPersistentSignalingStream();
  if (!stream) return;

  const connectionRequestId = frame["connection_request_id"] as string;
  const fromPubkey = frame["from_pubkey"] as string;
  const packageCborRaw = frame["package_cbor"];
  const packageCbor = packageCborRaw instanceof Uint8Array ? packageCborRaw
    : Buffer.isBuffer(packageCborRaw) ? new Uint8Array(packageCborRaw as Buffer) : null;

  if (!connectionRequestId || !fromPubkey || !packageCbor) return;

  const senderRegisteredAt = typeof frame["sender_registered_at"] === "number"
    ? frame["sender_registered_at"] : 0;
  const senderIsProvisional = frame["sender_is_provisional"] === true;

  let verdict: "accept" | "reject" | "insufficient" = "reject";
  let rejectReason: string | undefined;
  let unmetRequirements: unknown[] | undefined;

  const isWhitelisted = deps.ctx.whitelist.includes(fromPubkey);

  if (isWhitelisted) {
    verdict = "accept";
  } else if (!deps.connectionPolicy) {
    verdict = "accept";
  } else {
    let pkg;
    try {
      pkg = decodeConnectionPackage(packageCbor);
    } catch {
      verdict = "reject";
      rejectReason = "package_decode_failed";
      pkg = null;
    }

    if (pkg !== null) {
      const fromPubkeyBytes = Buffer.from(fromPubkey, "hex");
      const validatedPackage = validateConnectionPackage(
        pkg, fromPubkeyBytes, Date.now(), mlDsaVerify,
      );

      if (!validatedPackage.valid) {
        verdict = "reject";
        rejectReason = validatedPackage.reason;
      } else {
        const context: import("@cello-protocol/protocol-types").DirectoryContext = {
          registered_at: senderRegisteredAt,
          is_provisional: senderIsProvisional,
          conversation_count: 0,
          clean_close_rate: 0,
        };

        if (deps.ctx.trackEvaluateCount) {
          deps.ctx.incrementEvaluateCallCount();
        }

        const { evaluateConnectionPackage } = await import("./connection-policy.js");
        const report = evaluateConnectionPackage(
          validatedPackage, deps.connectionPolicy, context, Date.now(),
        );

        if (report.verdict === "auto_accept") {
          verdict = "accept";
        } else if (report.verdict === "auto_reject") {
          verdict = "reject";
          rejectReason = report.reason;
        } else if (report.verdict === "auto_insufficient") {
          if (deps.ctx.round2TimeoutMs > 0) {
            deps.pendingInboundRequests.set(connectionRequestId, {
              connection_request_id: connectionRequestId,
              from_pubkey: fromPubkey,
              package_cbor: packageCbor,
              round: 1,
            });
            const disclosureFrame = CBOR_ENC.encode({
              type: "disclosure_request",
              connection_request_id: connectionRequestId,
              requested_items: report.unmet_requirements.map((u) => ({
                type: u.signal_type,
                condition: u.condition,
              })),
            }) as Uint8Array;
            try {
              stream.send(lp.encode.single(disclosureFrame));
            } catch { /* stream closed */ }
            setTimeout(() => {
              const stillPending = deps.pendingInboundRequests.get(connectionRequestId);
              if (stillPending) {
                deps.pendingInboundRequests.delete(connectionRequestId);
                const currentStream = deps.ctx.getPersistentSignalingStream();
                if (currentStream) {
                  const timeoutFrame = CBOR_ENC.encode({
                    type: "connection_response",
                    connection_request_id: connectionRequestId,
                    verdict: "reject",
                    reason: "disclosure_timeout",
                  }) as Uint8Array;
                  try {
                    currentStream.send(lp.encode.single(timeoutFrame));
                  } catch { /* stream closed */ }
                }
              }
            }, deps.ctx.round2TimeoutMs);
            return;
          }
          verdict = "insufficient";
          unmetRequirements = report.unmet_requirements;
        } else {
          // pending_agent_review: store for agent review and fire callback
          deps.pendingInboundRequests.set(connectionRequestId, {
            connection_request_id: connectionRequestId,
            from_pubkey: fromPubkey,
            package_cbor: packageCbor,
            round: 1,
          });

          const reviewItem: ReviewQueueItem = {
            connection_request_id: connectionRequestId,
            from_pubkey: fromPubkey,
            report,
            package_cbor: packageCbor,
            sender_registered_at: senderRegisteredAt,
            sender_is_provisional: senderIsProvisional,
          };

          const awaitResolver = deps.pendingAwaitConnectionRequestResolvers.shift();
          if (awaitResolver) {
            awaitResolver({ connection_request_id: connectionRequestId, from_pubkey: fromPubkey, report });
          } else {
            deps.pendingReviewQueue.push(reviewItem);
          }

          if (deps.ctx.persistence) {
            void deps.ctx.persistence.persistPendingConnectionRequest({
              requestId: connectionRequestId,
              fromPubkey,
              packageCbor,
              round: 1,
            });
          }

          if (deps.onConnectionPendingReview) {
            deps.onConnectionPendingReview({
              type: "connection_request_inbound",
              from_pubkey: fromPubkey,
              connection_request_id: connectionRequestId,
              package_cbor: packageCbor,
              sender_registered_at: senderRegisteredAt,
              sender_is_provisional: senderIsProvisional,
            });
          }

          if (deps.ctx.round2TimeoutMs > 0) {
            setTimeout(() => {
              const stillPending = deps.pendingInboundRequests.get(connectionRequestId);
              if (stillPending) {
                deps.pendingInboundRequests.delete(connectionRequestId);
                const currentStream = deps.ctx.getPersistentSignalingStream();
                if (currentStream) {
                  const responseFrame = CBOR_ENC.encode({
                    type: "connection_response",
                    connection_request_id: connectionRequestId,
                    verdict: "reject",
                    reason: "disclosure_timeout",
                  }) as Uint8Array;
                  try {
                    currentStream.send(lp.encode.single(responseFrame));
                  } catch { /* stream closed */ }
                }
              }
            }, deps.ctx.round2TimeoutMs);
          }
          return;
        }
      }
    }
  }

  // DB-003: cross-check logic
  if (verdict === "accept" && deps.ctx.crossCheckDirectoryOnInbound) {
    deps.profileUncheckedPeers.add(fromPubkey);
  }

  const responsePayload: Record<string, unknown> = {
    type: "connection_response",
    connection_request_id: connectionRequestId,
    verdict,
  };
  if (rejectReason !== undefined) responsePayload["reason"] = rejectReason;
  if (unmetRequirements !== undefined) responsePayload["unmet_requirements"] = unmetRequirements;

  const responseFrame = CBOR_ENC.encode(responsePayload) as Uint8Array;
  try {
    stream.send(lp.encode.single(responseFrame));
  } catch { /* stream closed */ }
}

/**
 * Handle a disclosure_response_inbound frame (B-side, Round 2).
 * Re-evaluates the updated package and sends final connection_response.
 */
export async function handleDisclosureResponse(
  deps: InboundHandlerDeps,
  frame: Record<string, unknown>,
): Promise<void> {
  const stream = deps.ctx.getPersistentSignalingStream();
  if (!stream) return;

  const connectionRequestId = frame["connection_request_id"] as string;
  const packageCborRaw = frame["package_cbor"];
  const packageCbor = packageCborRaw instanceof Uint8Array ? packageCborRaw
    : Buffer.isBuffer(packageCborRaw) ? new Uint8Array(packageCborRaw as Buffer) : null;

  if (!connectionRequestId || !packageCbor) return;

  const pending = deps.pendingInboundRequests.get(connectionRequestId);
  if (!pending) return;

  deps.pendingInboundRequests.delete(connectionRequestId);
  const fromPubkey = pending.from_pubkey;

  let verdict: "accept" | "reject" | "insufficient" = "reject";
  let rejectReason: string | undefined;
  let unmetRequirements: unknown[] | undefined;

  if (!deps.connectionPolicy) {
    verdict = "accept";
  } else {
    let pkg;
    try {
      pkg = decodeConnectionPackage(packageCbor);
    } catch {
      verdict = "reject";
      rejectReason = "package_decode_failed";
      pkg = null;
    }

    if (pkg !== null) {
      const fromPubkeyBytes = Buffer.from(fromPubkey, "hex");
      const validatedPackage = validateConnectionPackage(
        pkg, fromPubkeyBytes, Date.now(), mlDsaVerify,
      );

      if (!validatedPackage.valid) {
        verdict = "reject";
        rejectReason = validatedPackage.reason;
      } else {
        const context: import("@cello-protocol/protocol-types").DirectoryContext = {
          registered_at: 0,
          is_provisional: false,
          conversation_count: 0,
          clean_close_rate: 0,
        };

        if (deps.ctx.trackEvaluateCount) {
          deps.ctx.incrementEvaluateCallCount();
        }

        const { evaluateConnectionPackage } = await import("./connection-policy.js");
        const report = evaluateConnectionPackage(
          validatedPackage, deps.connectionPolicy, context, Date.now(),
        );

        if (report.verdict === "auto_accept") {
          verdict = "accept";
        } else if (report.verdict === "auto_reject") {
          verdict = "reject";
          rejectReason = report.reason;
        } else if (report.verdict === "auto_insufficient") {
          verdict = "insufficient";
          unmetRequirements = report.unmet_requirements;
        } else {
          // pending_agent_review in Round 2
          const round2Report = { ...report, is_round_2: true };
          deps.pendingInboundRequests.set(connectionRequestId, {
            connection_request_id: connectionRequestId,
            from_pubkey: fromPubkey,
            package_cbor: packageCbor,
            round: 2,
          });
          if (deps.ctx.persistence) {
            void deps.ctx.persistence.persistPendingConnectionRequest({
              requestId: connectionRequestId,
              fromPubkey,
              packageCbor,
              round: 2,
            });
          }
          const round2ReviewItem: ReviewQueueItem = {
            connection_request_id: connectionRequestId,
            from_pubkey: fromPubkey,
            report: round2Report,
            package_cbor: packageCbor,
            sender_registered_at: 0,
            sender_is_provisional: false,
          };
          const awaitResolver = deps.pendingAwaitConnectionRequestResolvers.shift();
          if (awaitResolver) {
            awaitResolver({ connection_request_id: connectionRequestId, from_pubkey: fromPubkey, report: round2Report });
          } else {
            deps.pendingReviewQueue.push(round2ReviewItem);
          }
          return;
        }
      }
    }
  }

  const responsePayload: Record<string, unknown> = {
    type: "connection_response",
    connection_request_id: connectionRequestId,
    verdict,
  };
  if (rejectReason !== undefined) responsePayload["reason"] = rejectReason;
  if (unmetRequirements !== undefined) responsePayload["unmet_requirements"] = unmetRequirements;

  const responseFrame = CBOR_ENC.encode(responsePayload) as Uint8Array;
  try {
    stream.send(lp.encode.single(responseFrame));
  } catch { /* stream closed */ }
}
