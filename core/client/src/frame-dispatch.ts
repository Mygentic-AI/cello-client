/**
 * dispatchSignalingFrame — routes decoded signaling frames to the appropriate manager.
 *
 * Extracted from CelloClientImpl to keep the facade under 600 lines.
 * Called by SignalingManager's persistent reader loop for every decoded frame.
 */

import type { Stream } from "@libp2p/interface";
import type { Logger } from "@cello-protocol/interfaces";
import type { SignalingManager } from "./signaling-manager.js";
import type { ConnectionManager } from "./connection-manager.js";
import type { SealManager } from "./seal-manager.js";
import type { SessionManager } from "./session-manager.js";
import { parseSessionAssignment } from "./session-assignment-parser.js";

/** Managers and shared state needed by dispatchSignalingFrame. */
export interface FrameDispatchDeps {
  signalingManager: SignalingManager;
  connectionManager: ConnectionManager;
  sealManager: SealManager;
  sessionManager: SessionManager;
  logger: Logger;
  getMyPubkeyHex(): string | null;
  receiveSessionAssignment(assignment: import("@cello-protocol/protocol-types").SessionAssignment, myPubkey: Uint8Array, opts?: { mySessionPeerId?: string; correlationId?: string }): Promise<unknown>;
}

/** Extract session_id bytes → hex from a frame. Returns null if not found. */
function extractSessionIdHex(frame: Record<string, unknown>, injected: string | null): string | null {
  if (injected) return injected;
  const raw = frame["session_id"];
  const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
  return sid ? Buffer.from(sid).toString("hex") : null;
}

/**
 * Route a decoded signaling frame to the correct manager action.
 * Called by CelloClientImpl.#dispatchSignalingFrame.
 */
export function dispatchSignalingFrame(
  stream: Stream,
  frame: Record<string, unknown>,
  deps: FrameDispatchDeps,
): void {
  const injectedSessionIdHex = typeof frame["__session_id_hex"] === "string"
    ? frame["__session_id_hex"] : null;
  const injectedDirectoryPubkey = frame["__directory_pubkey"] instanceof Uint8Array
    ? frame["__directory_pubkey"]
    : Buffer.isBuffer(frame["__directory_pubkey"])
      ? new Uint8Array(frame["__directory_pubkey"] as Buffer) : null;

  const type = frame["type"] as string;

  if (type === "session_assignment" || type === "session_request_error") {
    const resolve = deps.signalingManager.getPendingSessionRequestResolve();
    if (resolve) {
      deps.signalingManager.setPendingSessionRequestResolve(null);
      resolve(frame);
    } else if (type === "session_assignment") {
      const rawAssignment = frame["assignment"] as Record<string, unknown> | undefined;
      if (rawAssignment) {
        const assignment = parseSessionAssignment(rawAssignment);
        const myPubkeyHex = deps.getMyPubkeyHex();
        if (assignment && myPubkeyHex) {
          void deps.receiveSessionAssignment(assignment, Buffer.from(myPubkeyHex, "hex"));
        }
      }
    }
  } else if (type === "session_sealed") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) {
      const session = deps.sessionManager.getSession(sessionIdHex);
      if (session) {
        const dirPubkey = injectedDirectoryPubkey ?? session.directory_pubkey;
        deps.sealManager.handleDirectorySessionSealed(sessionIdHex, frame, dirPubkey);
      }
    }
  } else if (type === "session_seal_rejected") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) deps.sealManager.handleDirectorySessionSealRejected(sessionIdHex, frame);
  } else if (type === "seal_rejected_tree_mismatch") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) deps.sealManager.handleSealRejectedTreeMismatch(sessionIdHex, frame);
  } else if (type === "seal_unilateral_confirmed") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) deps.sealManager.handleSealUnilateralConfirmed(sessionIdHex, frame);
    deps.sealManager.resolvePendingUnilateralSeal(frame);
  } else if (type === "seal_unilateral_notification") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) deps.sealManager.handleSealUnilateralNotification(sessionIdHex, frame);
  } else if (type === "seal_unilateral_too_early") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) {
      const remainingSeconds = typeof frame["remaining_seconds"] === "number" ? frame["remaining_seconds"] : 0;
      deps.logger.warn("session.unilateral.too.early", { sessionId: sessionIdHex, remainingSeconds });
    }
    deps.sealManager.resolvePendingUnilateralSeal(frame);
  } else if (type === "seal_verified") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) void deps.sealManager.handleSealVerified(sessionIdHex, frame);
  } else if (type === "session_frost_sealed") {
    const sessionIdHex = extractSessionIdHex(frame, injectedSessionIdHex);
    if (sessionIdHex) deps.sealManager.handleSessionFrostSealed(sessionIdHex, frame);
  } else if (type === "ceremony_request") {
    void deps.sealManager.handleCeremonyRequest(stream, frame);
  } else if (type === "dkg_ready") {
    deps.signalingManager.resolvePendingDkgReady(frame);
  } else if (type === "register_success" || type === "register_error") {
    deps.signalingManager.resolvePendingDkgReady(frame);
    deps.signalingManager.resolvePendingRegister(frame);
  } else if (
    type === "connection_established" ||
    type === "connection_rejected" ||
    type === "connection_insufficient" ||
    type === "connection_request_error" ||
    type === "disclosure_request_inbound"
  ) {
    deps.connectionManager.routeConnectionFrame(frame);
  } else if (type === "connection_request_inbound") {
    void deps.connectionManager.handleInboundConnectionRequest(frame);
  } else if (type === "disclosure_response_inbound") {
    void deps.connectionManager.handleDisclosureResponse(frame);
  }
}
