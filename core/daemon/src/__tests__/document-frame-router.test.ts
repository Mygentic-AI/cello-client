/**
 * DOD-DOC-INBOUND-2 — routing a session frame to the document layer.
 *
 * Getting this wrong in one direction puts CRDT bytes into an operator's conversation; getting it
 * wrong in the other makes a message vanish. Neither is recoverable by the operator.
 */

import { describe, it, expect, vi } from "vitest";
import {
  encodeDocumentUpdateEnvelope,
  encodeDocumentAck,
  encodeDocumentProposal,
  encodeDocumentRejection,
  DOCUMENT_UPDATE_ENCODING_V1,
  DOCUMENT_EPOCH_V1,
  type DocumentUpdateEnvelope,
  type DocumentAck,
} from "@cello-protocol/protocol-types";
import {
  DocumentFrameRouter,
  MAX_DOCUMENT_FRAME_BYTES,
  MAX_DOCUMENT_FRAME_FIELDS,
} from "../document-frame-router.js";
import type { DocumentInbound } from "../document-inbound.js";
import type { DocumentAckInbound } from "../document-ack-inbound.js";
import type { Logger } from "../types.js";

/** The agent NAME the session path carries — deliberately not the owner key it maps to. */
const AGENT = "owner-agent";
/** The stable owner key every document row is scoped by (M14-D5: our own pubkey hex). */
const OWNER = "dd".repeat(32);
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
  /** Whichever id each downstream call was actually scoped by. */
  const owners: string[] = [];
  const inbound = {
    receive: (ownerAgentId: string) => {
      calls.push("update");
      owners.push(ownerAgentId);
      return over.onUpdate ? over.onUpdate() : { ok: true, admitted: true, envelopeHash: "x", duplicate: false };
    },
  } satisfies Pick<DocumentInbound, "receive"> as DocumentInbound;
  const ackInbound = {
    receive: (ownerAgentId: string) => {
      calls.push("ack");
      owners.push(ownerAgentId);
      return over.onAck ? over.onAck() : { ok: true, admitted: true, envelopeHash: "x" };
    },
  } satisfies Pick<DocumentAckInbound, "receive"> as DocumentAckInbound;
  const recorded: string[] = [];
  return {
    router: new DocumentFrameRouter({
      inbound,
      ackInbound,
      logger,
      sendAck: async () => {},
      rewriteFile: async () => {},
      sendFrameToPeer: async () => {},
      ownerKeyFor: (agentName) => (agentName === AGENT ? OWNER : null),
      recordProposal: (ownerAgentId) => {
        recorded.push("proposal");
        owners.push(ownerAgentId);
      },
      recordRejection: (ownerAgentId) => {
        recorded.push("rejection");
        owners.push(ownerAgentId);
      },
    }),
    calls,
    events,
    recorded,
    owners,
  };
}

describe("DocumentFrameRouter — classification is by DECODE", () => {
  it("routes an update envelope to the document inbound path", async () => {
    const r = newRouter();
    // routeSync answers what the session path needs INLINE — is this document traffic, and which
    // leaf kind. The handling is async because a refusal must sign a 0x05 leaf.
    expect(r.router.routeSync(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c")).toEqual({
      consumed: true,
      kind: "update",
    });
    await vi.waitFor(() => expect(r.calls).toEqual(["update"]));
  });

  it("routes an ack to the ack path", async () => {
    const r = newRouter();
    expect(r.router.routeSync(AGENT, encodeDocumentAck(ackFrame), NOW, "c")).toEqual({
      consumed: true,
      kind: "ack",
    });
    await vi.waitFor(() => expect(r.calls).toEqual(["ack"]));
  });

  it("leaves an ordinary conversation message alone", async () => {
    const r = newRouter();
    const message = new TextEncoder().encode("Hey - did you see the draft I sent over?");
    // Not consumed means the caller records it as a transcript message and fires the doorbell
    // exactly as before. Nothing about the conversation path changes.
    expect(r.router.routeSync(AGENT, message, NOW, "c")).toEqual({ consumed: false });
    expect(r.calls).toEqual([]);
  });

  it("leaves ARBITRARY bytes alone rather than guessing", async () => {
    const r = newRouter();
    for (const bytes of [new Uint8Array(0), new Uint8Array([0]), new Uint8Array([0xa1, 0x01, 0x02])]) {
      expect(r.router.routeSync(AGENT, bytes, NOW, "c")).toEqual({ consumed: false });
    }
    // A misrouted document frame lands in a transcript and is visible; a misrouted MESSAGE would
    // vanish into the document layer and never reach the operator. Not-document is the safe default.
    expect(r.calls).toEqual([]);
  });

  it("does not let one document type claim the other's frame", async () => {
    const r = newRouter();
    r.router.routeSync(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");
    r.router.routeSync(AGENT, encodeDocumentAck(ackFrame), NOW, "c");
    // Both decoders check their `type` discriminator before anything else, so the try-in-turn
    // ordering cannot misassign a well-formed frame. And the two arrive in the order sent — the
    // per-owner queue is what guarantees an envelope's predecessor is stored before its successor
    // is chain-checked.
    await vi.waitFor(() => expect(r.calls).toEqual(["update", "ack"]));
  });

  it("says nothing in the log for an ordinary message", async () => {
    const r = newRouter();
    r.router.routeSync(AGENT, new TextEncoder().encode("hello"), NOW, "c");
    // EVERY conversation message reaches the classifier. A log line here would put one entry per
    // message into the daemon log for the ordinary case.
    expect(r.events).toEqual([]);
  });
});

describe("DocumentFrameRouter — a refusal is CONSUMED, not handed to the conversation path", () => {
  it("reports the document layer's reason without falling back to transcript", async () => {
    const r = newRouter({
      onUpdate: () => ({ ok: false, reason: "document_signature_invalid", detail: "nope" }),
    });
    // Falling through to the conversation path on a refusal would put a refused CRDT envelope into
    // the operator's transcript, where cello_receive hands it to an agent as something a person said.
    // The frame is CONSUMED synchronously; the refusal is reported when the handling completes.
    expect(r.router.routeSync(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c")).toEqual({
      consumed: true,
      kind: "update",
    });
    await vi.waitFor(() =>
      expect(r.events.some((e) => e.event === "document.frame.refused")).toBe(true),
    );
  });
});

describe("DocumentFrameRouter — a handler throw does not take the session down", () => {
  it("contains it, reports it, and keeps the frame consumed", async () => {
    const r = newRouter({
      onUpdate: () => {
        throw new Error("boom");
      },
    });
    r.router.routeSync(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");

    // Letting it escape means a peer could stop the operator's MESSAGES from being delivered by
    // sending one bad document frame — and now that handling is async, an escaped throw would also
    // be an unhandled rejection.
    await vi.waitFor(() => {
      const logged = r.events.find((e) => e.event === "document.frame.handler_threw");
      expect(logged!.fields.reason).toContain("boom");
      expect(logged!.fields.correlationId).toBe("c");
    });
  });
});


describe("DocumentFrameRouter — hostile bytes never reach a CBOR decoder", () => {
  it("handles every MEASURED pathological input in milliseconds", async () => {
    const r = newRouter();
    // Each of these cost SECONDS and gigabytes before the decoder was bounded. The last two get
    // PAST the header guard — `a1 9f` is a one-pair map whose first key is an indefinite array, and
    // `b9 000a 9f 26` wears the real frames' own header — which is why the guard is a fast path and
    // the decoder limit in cbor.ts is the actual boundary.
    for (const hex of ["9fb0", "9f26", "9f", "bf", "a19f", "b9000a9f26", "a1bf", "b8209f26"]) {
      const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
      const started = Date.now();
      r.router.routeSync(AGENT, bytes, NOW, "c");
      // The guarded path measures well under a millisecond and the regression this catches is a
      // 5-10 SECOND stall, so the margin is ~300x — a GC pause cannot false-positive it.
      expect(Date.now() - started).toBeLessThan(100);
    }
  });

  it("a map header claiming an enormous field count never reaches a decoder", async () => {
    const r = newRouter();
    // The wall clock is the assertion that has teeth. Asserting only `consumed: false` was hollow:
    // these inputs also return consumed:false WITHOUT the guard, because they throw quickly — so
    // the test passed identically either way and pinned routing rather than cost.
    for (const bytes of [
      new Uint8Array([0xbb, 255, 255, 255, 255, 255, 255, 255, 255]),
      new Uint8Array([0xb9, 0xff, 0xff]),
    ]) {
      const started = Date.now();
      expect(r.router.routeSync(AGENT, bytes, NOW, "c")).toEqual({ consumed: false });
      expect(Date.now() - started).toBeLessThan(100);
    }
  });

  it("the real frames declare fewer fields than the CONSTANT admits", async () => {
    // Against the CONSTANT, not a hardcoded 32. The earlier version compared to a literal, so
    // lowering MAX_DOCUMENT_FRAME_FIELDS to 8 kept it green while real frames were reclassified as
    // conversation — the exact defect its own comment described.
    for (const wire of [encodeDocumentUpdateEnvelope(updateEnvelope), encodeDocumentAck(ackFrame)]) {
      expect(wire[0]).toBe(0xb9);
      expect((wire[1]! << 8) | wire[2]!).toBeLessThanOrEqual(MAX_DOCUMENT_FRAME_FIELDS);
    }
  });

  it("refuses an oversized frame without decoding it", async () => {
    const r = newRouter();
    const huge = new Uint8Array(MAX_DOCUMENT_FRAME_BYTES + 1);
    huge[0] = 0xb9;
    const started = Date.now();
    // The length cap is what bounds the nesting depth, and it runs before anything else looks at
    // the frame. The decoder's per-container limit only reduces amplification.
    expect(r.router.routeSync(AGENT, huge, NOW, "c")).toEqual({ consumed: false });
    expect(Date.now() - started).toBeLessThan(100);
  });

  it("the admitted header range stays inside the UTF-8 continuation bytes", async () => {
    // The header comment's proof — that no conversation message can be classified as a document
    // frame — rests entirely on every admitted first byte being a UTF-8 CONTINUATION byte
    // (0x80-0xbf), which can never begin a valid sequence. Widen the range past 0xbf and the
    // argument dies silently, with an operator's message vanishing from their transcript. So it is
    // a test rather than a paragraph.
    const decoder = new TextDecoder("utf-8", { fatal: true });
    for (let b = 0xa0; b <= 0xb9; b++) {
      expect(() => decoder.decode(new Uint8Array([b]))).toThrow();
    }
    // And the other half: a real message is UTF-8 by construction, not by convention — the send
    // path encodes it with TextEncoder. Its first byte is ASCII (< 0x80) or a LEAD byte (>= 0xc2);
    // it is never a continuation byte, which is the range the guard admits.
    //
    // Stated as "always below 0x80" first, which this test proved false: "Ça va?" begins 0xc3. A
    // message in French, Arabic or Chinese starts at or above 0x80 and is still perfectly safe,
    // because 0xc2-0xf4 are lead bytes and sit clear of 0xa0-0xb9. The property is "never a
    // CONTINUATION byte", and getting that wrong in the comment would have invited someone to
    // widen the guard's range on a false premise.
    for (const text of ["hello", "Ça va?", "مرحبا", "你好", "1234", " ", "[[WRAP]]"]) {
      const first = new TextEncoder().encode(text)[0]!;
      expect(first < 0x80 || first >= 0xc2).toBe(true);
      expect(first >= 0xa0 && first <= 0xb9).toBe(false);
    }
  });

  it("the byte cap clears the largest update the gate will admit", async () => {
    // Sized off the payload rather than picked: refusing a legitimate 1 MiB update would be the
    // worse failure direction, exactly as with the decoder limit.
    expect(MAX_DOCUMENT_FRAME_BYTES).toBeGreaterThan(1024 * 1024);
  });

  it("STILL admits the real frames, which use a non-minimal 2-byte count", async () => {
    const r = newRouter();
    const wire = encodeDocumentUpdateEnvelope(updateEnvelope);
    // b9 00 0a — cbor.ts documents this encoder's non-minimal map header deliberately, so a guard
    // that only admitted the inline-count form would route every genuine document frame to the
    // transcript.
    expect(Buffer.from(wire.slice(0, 3)).toString("hex")).toBe("b9000a");
    expect(r.router.routeSync(AGENT, wire, NOW, "c")).toMatchObject({ consumed: true, kind: "update" });
  });
});


describe("DocumentFrameRouter — every document frame kind is classified", () => {
  it("routes a PROPOSAL to the handshake instead of the transcript", async () => {
    const r = newRouter();
    const proposal = encodeDocumentProposal({
      type: "document_proposal",
      feature_version: 1,
      proposer_agent_id: "peer-agent",
      peer_agent_id: AGENT,
      document_type: "markdown",
      properties: {
        assurance_tier: "authenticated",
        schema_enforcement: false,
        topology: "hub-and-spoke",
        append_only: false,
      },
      starting_content: null,
      nonce: new Uint8Array([1]),
      proposed_at_ms: NOW,
      signature: new Uint8Array(64),
    });

    // Unclassified, a proposal is "not document traffic" and lands in the operator's transcript as
    // unreadable bytes — the exact failure the classification exists to prevent, arriving through
    // the one frame kind nobody had wired.
    expect(r.router.routeSync(AGENT, proposal, NOW, "c")).toEqual({ consumed: true, kind: "proposal" });
    await vi.waitFor(() => expect(r.recorded).toEqual(["proposal"]));
  });

  it("routes a REJECTION to the receiving half", async () => {
    const r = newRouter();
    const rejection = encodeDocumentRejection({
      type: "document_rejection",
      rejection_version: 1,
      document_id: DOC,
      rejected_envelope_hash: "bb".repeat(32),
      rejecting_agent_id: "peer-agent",
      reason: "document_append_only_violation",
      round: 1,
      rejected_at_ms: NOW,
      signature: new Uint8Array(64),
    });
    expect(r.router.routeSync(AGENT, rejection, NOW, "c")).toEqual({ consumed: true, kind: "rejection" });
    await vi.waitFor(() => expect(r.recorded).toEqual(["rejection"]));
  });

  it("still leaves a conversation message alone", async () => {
    const r = newRouter();
    expect(r.router.routeSync(AGENT, new TextEncoder().encode("just a message"), NOW, "c")).toEqual({
      consumed: false,
    });
    expect(r.recorded).toEqual([]);
  });
});


describe("DocumentFrameRouter — the AGENT NAME is mapped, never used as an owner key", () => {
  it("scopes every downstream call by the OWNER KEY", async () => {
    const r = newRouter();
    r.router.routeSync(AGENT, encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c");
    await vi.waitFor(() => expect(r.owners).toEqual([OWNER]));
    // The name must not reach the store. Scoped by name, an inbound envelope lands where the
    // delivery sweep — which scopes by key — never looks: no rows returned, nothing attempted, no
    // error on any path. Agent NAME is also mutable and reusable, so it is not a join key at all.
    expect(r.owners).not.toContain(AGENT);
  });

  it("CONSUMES a frame whose owner key cannot be resolved, and reports it", async () => {
    const r = newRouter();
    // Consumed: it IS document traffic. The alternative is the conversation path, which would hand
    // an operator's agent a CBOR envelope as something a person said.
    expect(r.router.routeSync("unknown-agent", encodeDocumentUpdateEnvelope(updateEnvelope), NOW, "c")).toEqual({
      consumed: true,
      kind: "update",
    });
    expect(r.calls).toEqual([]);
    expect(r.events.map((e) => e.event)).toContain("document.frame.owner_unresolved");
  });
});
