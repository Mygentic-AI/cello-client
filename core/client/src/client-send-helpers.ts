/**
 * client-send-helpers.ts — low-level send and receive utilities for CelloClientImpl.
 *
 * Extracted from client.ts to keep the facade under the 600-line AC budget.
 */

import * as lp from "it-length-prefixed";
import { deserializeEnvelope, validateEnvelope } from "@cello-protocol/protocol-types";
import { CELLO_PROTOCOL_ID } from "@cello-protocol/transport";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { SendResult, ReceivedEnvelope } from "./types.js";

// ─── Error helpers ────────────────────────────────────────────────────────────

export function isStructuredError(err: unknown, reason: string): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "reason" in err &&
    (err as Record<string, unknown>).reason === reason
  );
}

export function mapSendError(
  err: unknown,
): "remote_rejected" | "connection_lost" | "peer_unreachable" | "transport_not_started" {
  if (isStructuredError(err, "node_stopped")) return "transport_not_started";
  if (isStructuredError(err, "connection_lost")) return "connection_lost";
  if (isStructuredError(err, "protocol_not_supported")) return "peer_unreachable";
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes("reset") || msg.includes("aborted")) return "remote_rejected";
  return "connection_lost";
}

// ─── Core send path ───────────────────────────────────────────────────────────

/**
 * Open a CELLO_PROTOCOL_ID stream to peerId, send bytes length-prefixed,
 * drain the read side, and return a SendResult.
 */
export async function sendBytesViaNode(
  node: CelloNode,
  peerId: string,
  bytes: Uint8Array,
  contentHash: Uint8Array | undefined,
): Promise<SendResult> {
  let stream: Stream;
  try {
    stream = await node.newStream(peerId, CELLO_PROTOCOL_ID);
  } catch (err) {
    const reason = isStructuredError(err, "node_stopped")
      ? "transport_not_started"
      : "peer_unreachable";
    return { delivered: false, reason };
  }

  try {
    stream.send(lp.encode.single(bytes));
    await stream.close();

    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _ of lp.decode(stream)) { /* drain */ }
    } catch { /* read side error — ignore */ }

    if (stream.status === "reset" || stream.status === "aborted") {
      return { delivered: false, reason: "remote_rejected" };
    }

    const hashHex = contentHash ? Buffer.from(contentHash).toString("hex") : "";
    return { delivered: true, contentHash: hashHex };
  } catch (err) {
    return { delivered: false, reason: mapSendError(err) };
  }
}

// ─── Inbound envelope handler ─────────────────────────────────────────────────

/**
 * Read a single length-prefixed envelope from an inbound stream,
 * validate it, and push it onto the receive queue.
 * Extracted from CelloClientImpl.handleInbound.
 */
export async function handleInboundEnvelope(
  stream: Stream,
  receiveQueues: Map<string, ReceivedEnvelope[]>,
  arrivalLog: Array<{ senderPubkeyHex: string; envelope: ReceivedEnvelope }>,
  onMessageQueued: ((senderPubkeyHex: string) => void) | undefined,
): Promise<void> {
  let payload: Uint8Array | undefined;
  let timeoutFired = false;
  const readFrame = async (): Promise<void> => {
    for await (const chunk of lp.decode(stream)) {
      payload = (chunk as unknown as { slice(): Uint8Array }).slice();
      return;
    }
  };
  let timerId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((_, reject) => {
    timerId = setTimeout(
      () => { timeoutFired = true; reject(new Error("truncated_frame")); },
      5_000,
    );
  });
  try {
    await Promise.race([readFrame(), timeout]);
    clearTimeout(timerId);
  } catch {
    clearTimeout(timerId);
    stream.abort(new Error(timeoutFired ? "truncated_frame: read timeout" : "truncated_frame: stream error"));
    return;
  }
  if (!payload) { stream.abort(new Error("truncated_frame: no frame received")); return; }
  const deserResult = deserializeEnvelope(payload);
  if (!deserResult.ok) { stream.abort(new Error(`malformed_envelope: ${deserResult.error.reason}`)); return; }
  const validateResult = validateEnvelope(deserResult.envelope);
  if (!validateResult.ok) { stream.abort(new Error(`validation_failed: ${validateResult.error.reason}`)); return; }
  const senderHex = Buffer.from(deserResult.envelope.sender_pubkey).toString("hex");
  const received: ReceivedEnvelope = {
    content: deserResult.envelope.content,
    senderPubkey: deserResult.envelope.sender_pubkey,
    contentHash: deserResult.envelope.content_hash,
    timestamp: deserResult.envelope.timestamp,
  };
  if (!receiveQueues.has(senderHex)) receiveQueues.set(senderHex, []);
  receiveQueues.get(senderHex)!.push(received);
  arrivalLog.push({ senderPubkeyHex: senderHex, envelope: received });
  onMessageQueued?.(senderHex);
  await stream.close().catch(() => {});
}
