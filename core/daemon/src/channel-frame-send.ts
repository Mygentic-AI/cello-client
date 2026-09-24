import { randomUUID } from "node:crypto";
import type { Logger } from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import { LEAF_KIND_MSG } from "./session-relay-client.js";
import { sentAuthorship } from "./session-content-handlers.js";

export type ChannelFrameSendDeps = {
  sessions: Pick<SessionNodeManager, "contentHashForSession" | "sendContent" | "placeOwnLeaf">;
  logger: Logger;
};

/**
 * Sends a channel join frame in a session and commits it to THIS side's record.
 *
 * Every daemon path that sends session content commits its own leaf afterwards with `placeOwnLeaf`
 * — `cello_send`, the away replies, the document transport. The join-frame sender did not: it
 * discarded the send result, so the relay witnessed the frame at position N while this side's tree
 * never gained leaf N. `nextExpected` stayed at N and every later message, in both directions, was
 * held behind the gap forever. This routes join frames through the same commit step, and fails
 * loudly rather than silently when the send is lost.
 */
export function createChannelFrameSender(
  deps: ChannelFrameSendDeps,
): (agentName: string, sessionId: string, content: Uint8Array) => Promise<void> {
  return async (agentName, sessionId, content) => {
    const correlationId = randomUUID();
    // The hash comes from the SESSION, because a salted session hashes differently — computing it
    // here would produce a leaf the counterparty's chain cannot match.
    const { hash, alg } = await deps.sessions.contentHashForSession(agentName, sessionId, content);
    // Leaf kind `msg`: a join frame is not conversation, but a leaf kind is what a VERIFIER renders a
    // leaf by, and a third kind would make every existing verifier unable to read a transcript
    // carrying a join.
    const sendResult = await deps.sessions.sendContent(
      agentName, sessionId, content, new Uint8Array(hash), correlationId, LEAF_KIND_MSG, alg,
    );
    if (!sendResult.ok && !sendResult.durable) {
      // A lost send reached no leaf and no queue — the other side never receives the frame. Fail
      // loudly: the callers already handle a rejected send (channel-subscribe returns `send_failed`,
      // the membership wiring's `.catch` logs). No retries here.
      deps.logger.error("channel.frame.send.failed", {
        agentName, sessionId, reason: sendResult.reason, correlationId,
        impact: "the join frame was not sent and not queued — the other side never receives it",
      });
      throw new Error(`channel_frame_send_failed: ${sendResult.reason}`);
    }
    // Delivered OR durably queued: the relay already witnessed the position, so the leaf goes THERE,
    // never at the tail — a gap on this side would otherwise put our leaf at someone else's index.
    // No `recordTranscriptMessage`: a join frame is not something a person said, and the receive
    // side already appends a leaf and writes no row; this mirrors it.
    const hashHex = Buffer.from(hash).toString("hex");
    const placed = deps.sessions.placeOwnLeaf(
      agentName, sessionId, hashHex, content, sendResult.sequenceNumber, correlationId,
      "msg", sentAuthorship(sendResult),
    );
    deps.logger.info("channel.frame.sent", {
      agentName, sessionId, sequenceNumber: sendResult.sequenceNumber, committed: placed.placed, correlationId,
    });
  };
}
