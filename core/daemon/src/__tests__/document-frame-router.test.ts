/**
 * DOD-DOC-INBOUND-2 — routing a session frame to the document layer.
 *
 * Getting this wrong in one direction puts CRDT bytes into an operator's conversation; getting it
 * wrong in the other makes a message vanish. Neither is recoverable by the operator.
 */

import { describe, it, expect } from "vitest";
import {
  encodeDocumentUpdateEnvelope,
  encodeDocumentAck,
  DOCUMENT_UPDATE_ENCODING_V1,
  DOCUMENT_EPOCH_V1,
  type DocumentUpdateEnvelope,
  type DocumentAck,
} from "@cello-protocol/protocol-types";
import { DocumentFrameRouter } from "../document-frame-router.js";
import type { DocumentInbound } from "../document-inbound.js";
import type { DocumentAckInbound } from "../document-ack-inbound.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const DOC = "cc".repeat(32);
const NOW = 1_700_000_000_000;

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

const updateEnvelope: DocumentUpdateEnvelope = {
  type: "document_update",
  document_id: DOC,
  epoch_id: DOCUMENT_EPOCH_V1,
  doc_prev_hash: null,
  sender_agent_id: "peer-agent",
  sender_client_id: 4242,
  update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
  state_vector: new Uint8Array([0]),
  update: new Uint8Array([1, 2, 3]),
  signature: new Uint8Array(64).fill(3),
};

const ackFrame: DocumentAck = {
  type: "document_ack",
  ack_version: 1,
  document_id: DOC,
  envelope_hash: "bb".repeat(32),
  acker_agent_id: "peer-agent",
  admitted: true,
  acked_at_ms: NOW,
  signature: new Uint8Array(64).fill(4),
};

function newRouter(over: { onUpdate?: () => unknown; onAck?: () => unknown } = {}) {
  const { logger, events } = recordingLogger();
  const calls: string[] = [];
  const inbound = {
    receive: () => {
      calls.push("update");
      return over.onUpdate ? over.onUpdate() : { ok: true, admitted: true, envelopeHash: "x", duplicate: false };
    },
  } as unknown as DocumentInbound;
  const ackInbound = {
    receive: () => {
      calls.push("ack");
      return over.onAck ? over.onAck() : { ok: true, admitted: true, envelopeHash: "x" };
    },
  } as unknown as DocumentAckInbound;
  return { router: new DocumentFrameRouter({ inbound, ackInbound, logger }), calls, events };
}

describe("DocumentFrameRouter — classification is by DECODE", () => {
  it("routes an update envelope to the document inbound path", () => {
    const r = newRouter();
    const res = r.router.route(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");
    expect(res).toMatchObject({ consumed: true, kind: "update", ok: true });
    expect(r.calls).toEqual(["update"]);
  });

  it("routes an ack to the ack path", () => {
    const r = newRouter();
    const res = r.router.route(AGENT, encodeDocumentAck(ackFrame), NOW, "c");
    expect(res).toMatchObject({ consumed: true, kind: "ack", ok: true });
    expect(r.calls).toEqual(["ack"]);
  });

  it("leaves an ordinary conversation message alone", () => {
    const r = newRouter();
    const message = new TextEncoder().encode("Hey — did you see the draft I sent over?");
    // Not consumed means the caller records it as a transcript message and fires the doorbell
    // exactly as before. Nothing about the conversation path changes.
    expect(r.router.route(AGENT, message, NOW, "c")).toEqual({ consumed: false });
    expect(r.calls).toEqual([]);
  });

  it("leaves ARBITRARY bytes alone rather than guessing", () => {
    const r = newRouter();
    for (const bytes of [new Uint8Array(0), new Uint8Array([0]), new Uint8Array([0xa1, 0x01, 0x02])]) {
      expect(r.router.route(AGENT, bytes, NOW, "c")).toEqual({ consumed: false });
    }
    // A misrouted document frame lands in a transcript and is visible; a misrouted MESSAGE would
    // vanish into the document layer and never reach the operator. Not-document is the safe default.
    expect(r.calls).toEqual([]);
  });

  it("does not let one document type claim the other's frame", () => {
    const r = newRouter();
    r.router.route(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");
    r.router.route(AGENT, encodeDocumentAck(ackFrame), NOW, "c");
    // Both decoders check their `type` discriminator before anything else, so the try-in-turn
    // ordering cannot misassign a well-formed frame.
    expect(r.calls).toEqual(["update", "ack"]);
  });

  it("says nothing in the log for an ordinary message", () => {
    const r = newRouter();
    r.router.route(AGENT, new TextEncoder().encode("hello"), NOW, "c");
    // EVERY conversation message reaches the classifier. A log line here would put one entry per
    // message into the daemon log for the ordinary case.
    expect(r.events).toEqual([]);
  });
});

describe("DocumentFrameRouter — a refusal is CONSUMED, not handed to the conversation path", () => {
  it("reports the document layer's reason without falling back to transcript", () => {
    const r = newRouter({
      onUpdate: () => ({ ok: false, reason: "document_signature_invalid", detail: "nope" }),
    });
    const res = r.router.route(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");
    // Falling through to the conversation path on a refusal would put a refused CRDT envelope into
    // the operator's transcript, where cello_receive hands it to an agent as something a person said.
    expect(res).toMatchObject({ consumed: true, ok: false, reason: "document_signature_invalid" });
  });
});

describe("DocumentFrameRouter — a handler throw does not take the session down", () => {
  it("contains it, reports it, and keeps the frame consumed", () => {
    const r = newRouter({
      onUpdate: () => {
        throw new Error("boom");
      },
    });
    const res = r.router.route(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");

    // Letting it escape into the session content path means a peer could stop the operator's
    // MESSAGES from being delivered by sending one bad document frame.
    expect(res).toMatchObject({ consumed: true, ok: false, reason: "document_frame_handler_threw" });
    const logged = r.events.find((e) => e.event === "document.frame.handler_threw");
    expect(logged!.fields.reason).toContain("boom");
    expect(logged!.fields.correlationId).toBe("c");
  });
});


describe("DocumentFrameRouter — hostile bytes never reach a CBOR decoder", () => {
  it("refuses the MEASURED pathological inputs instantly", () => {
    const r = newRouter();
    // 9f = indefinite-length ARRAY header. Handed to the decoder, `9f b0` takes 5.0 seconds on this
    // machine and `9f 26` was independently measured at 10 seconds and 1.6 GB. classify() runs on
    // EVERY inbound frame, so a peer could stall or OOM the daemon's whole content path — stopping
    // the operator's ordinary MESSAGES — with a handful of two-byte frames. The try/catch does not
    // help: the cost is inside the decode, not in the throw.
    for (const bytes of [
      new Uint8Array([0x9f, 0xb0]),
      new Uint8Array([0x9f, 0x26]),
      new Uint8Array([0x9f]),
      new Uint8Array([0xbf]), // indefinite-length MAP
    ]) {
      const started = Date.now();
      expect(r.router.route(AGENT, bytes, NOW, "c")).toEqual({ consumed: false });
      expect(Date.now() - started).toBeLessThan(100);
    }
  });

  it("refuses a map header claiming an enormous field count", () => {
    const r = newRouter();
    // 0xbb + an 8-byte count is a few bytes asking for an enormous allocation. No document frame has
    // four billion fields, so those header forms never reach a decoder at all.
    expect(r.router.route(AGENT, new Uint8Array([0xbb, 255, 255, 255, 255, 255, 255, 255, 255]), NOW, "c"))
      .toEqual({ consumed: false });
    expect(r.router.route(AGENT, new Uint8Array([0xb9, 0xff, 0xff]), NOW, "c")).toEqual({ consumed: false });
  });

  it("STILL admits the real frames, which use a non-minimal 2-byte count", () => {
    const r = newRouter();
    const wire = encodeDocumentUpdateEnvelope(updateEnvelope);
    // b9 00 0a — cbor.ts documents this encoder's non-minimal map header deliberately, so a guard
    // that only admitted the inline-count form would route every genuine document frame to the
    // transcript.
    expect(Buffer.from(wire.slice(0, 3)).toString("hex")).toBe("b9000a");
    expect(r.router.route(AGENT, wire, NOW, "c")).toMatchObject({ consumed: true, kind: "update" });
  });
});
