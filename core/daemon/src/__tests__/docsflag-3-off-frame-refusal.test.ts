/**
 * 074-DOCSFLAG — the one hook that stays wired with documents OFF, and what it does.
 *
 * Written because the unit reviewer found it: gating the layer off introduced exactly one piece of NEW
 * production behaviour, and it had no test. Everything else in the order is an ABSENCE — no verb, no
 * tool, no command, no row, no timer — and absence is what the sibling suites assert. This is the one
 * thing that is present.
 *
 * ── WHY THE HOOK IS WIRED AT ALL, WHICH IS THE PROPERTY UNDER TEST ────────────────────────────
 *
 * `setOnDocumentFrame` is not a verb, a tool or a timer. It is the ROUTING FORK in
 * `session-content-ingest.ts`: the ingest calls the hook, and diverges to a `doc` leaf with no
 * transcript row and no doorbell ONLY when the hook returns `consumed: true`. Leave it unset and a
 * document frame from a peer who still holds a document with this agent takes the CONVERSATION path —
 * appended to the durable transcript as a `msg` leaf, ringing the doorbell, handed to the agent by
 * `cello_receive` as raw canonical CBOR. There is a live-fleet report behind that: a counterparty
 * pasted the bytes back.
 *
 * So with documents off the classifier stays installed and the frame is CONSUMED and REFUSED.
 *
 * ── IS THIS THE "HANDLER THAT RETURNS DISABLED" THE ORDER FORBIDS? NO, AND THE DIFFERENCE MATTERS ─
 *
 * The order's prohibition is about ADVERTISED surfaces: a registered IPC verb or a declared MCP tool
 * that answers "disabled" still tells a caller the feature exists, and the caller is an agent reading
 * a list. This hook is on no list. It is not reachable by asking, it cannot be enumerated, and no
 * agent can call it — it fires only when a peer sends bytes of a shape this agent did not ask for. It
 * changes what happens to an inbound frame, which is the opposite of advertising.
 *
 * ── AND WHAT IT DOES NOT DO, SAID PLAINLY ─────────────────────────────────────────────────────
 *
 * The refusal is LOCAL. The peer is told nothing on the wire: `session-content-ingest.ts` deliberately
 * stopped reading the hook's `ok`/`reason` fields (a verdict is not knowable at that point in the
 * flow), so they are discarded here too. The counterparty's own reconcile sweep therefore keeps
 * re-attempting at its sweep INTERVAL indefinitely — with no backoff at all, because the backoff is
 * refusal-driven (`onPeerRefusal` → `noteRefusal`) and fires only on a refusal that arrives on the wire,
 * and we send none. From its side "documents disabled" is indistinguishable from
 * "unreachable". That is the order's own 321-refusals-in-85-minutes pathology relocated to the other
 * side, and it is disclosed in the order rather than described as a refusal the peer receives.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { FileKeyProvider } from "@cello-protocol/crypto";
import {
  encodeDocumentUpdateEnvelope,
  DOCUMENT_UPDATE_ENCODING_V1,
  type DocumentUpdateEnvelope,
} from "@cello-protocol/protocol-types";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { DOCUMENTS_FLAG_ENV } from "../document-flag.js";
import { isDocumentFrame } from "../document-frame-router.js";
import type { Logger, DaemonConfig } from "../types.js";
import { createHash } from "node:crypto";

/** A real document update envelope, encoded the way a peer puts it on the wire. */
function documentFrameBytes(): Uint8Array {
  const envelope: DocumentUpdateEnvelope = {
    type: "document_update",
    document_id: "a".repeat(64),
    doc_prev_hash: null,
    sender_agent_id: "peer-agent",
    sender_client_id: 4242,
    update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
    governance_parents: [],
    state_vector: new Uint8Array([0]),
    update: new Uint8Array([1, 2, 3]),
    signature: new Uint8Array(64).fill(3),
  };
  return encodeDocumentUpdateEnvelope(envelope);
}

interface Captured {
  level: string;
  event: string;
  fields: Record<string, unknown>;
}

describe("074-DOCSFLAG — an inbound document frame with the layer OFF", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let events: Captured[];
  let savedFlag: string | undefined;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    savedFlag = process.env[DOCUMENTS_FLAG_ENV];
    tempDir = await mkdtemp(join(tmpdir(), "cello-docsflag-frame-"));
    handle = null;
    events = [];
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
    if (savedFlag === undefined) delete process.env[DOCUMENTS_FLAG_ENV];
    else process.env[DOCUMENTS_FLAG_ENV] = savedFlag;
  });

  async function start(flag: "on" | "off"): Promise<DaemonHandle> {
    if (flag === "on") process.env[DOCUMENTS_FLAG_ENV] = "1";
    else delete process.env[DOCUMENTS_FLAG_ENV];
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    const push = (level: string) => (event: string, fields?: Record<string, unknown>) =>
      events.push({ level, event, fields: fields ?? {} });
    const logger = {
      debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error"),
    } as unknown as Logger;
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
    return handle;
  }

  /**
   * Drive the REAL inbound path: a session node, then `ingestReceivedContent` with the frame's own
   * leaf hash — the same call `session-relay-client` makes when a peer's bytes arrive.
   *
   * ⚠️ NOT the installed hook read off a getter. An earlier version of this file reached for
   * `SessionNodeManager`'s internal `onDocumentFrame`, which is not public, and that was the weaker
   * test anyway: what matters is what the INGEST does with a document frame, and the ingest is the
   * only thing that knows whether a consumed frame becomes a `doc` leaf or a transcript row.
   */
  async function ingestDocumentFrame(
    h: DaemonHandle,
    sessionId: string,
    frame: Uint8Array,
    correlationId: string,
  ) {
    const mgr = h.getSessionNodeManager();
    // Seeded BEFORE creation: `createSessionNode` refuses a session it cannot anchor.
    mgr.setSessionGenesisForTest("alice", sessionId, new Uint8Array(32).fill(0x9c));
    await mgr.createSessionNode(sessionId, "alice", "bobpubkey", "bob-peer-id", correlationId);
    return mgr.ingestReceivedContent(
      "alice", sessionId, frame, contentHash(frame), correlationId,
    );
  }

  /**
   * The content hash the receiver recomputes: sha256(0x00 ‖ content).
   *
   * ⚠️ THE 0x00 PREFIX IS RIGHT EVEN THOUGH THIS IS A DOCUMENT FRAME, and it is not a guess.
   * `wire-content-hash.ts` names the constant `CONTENT_HASH_DOMAIN`, fixes it at `0x00` "for ALL
   * content frames", and its comment states outright that this is NOT the leaf kind. The `0x04` LEAF
   * kind is chosen downstream, by the document fork, from the hook's verdict.
   *
   * Reproduced here rather than imported, so this test cannot pass merely by agreeing with the same
   * function the code under test uses.
   *
   * Measured, because getting it wrong fails in the direction that matters. Hashed as `0x04`, the
   * ingest quarantines on the cross-check and never reaches the fork — the events were
   * `session.content.cross_check.failed`, a transcript row, and a quarantine, with no document event
   * anywhere. That is what the first version of this test did, and it would have reported the frame as
   * refused while it was in fact being filed as conversation.
   */
  function contentHash(content: Uint8Array): Uint8Array {
    return new Uint8Array(
      createHash("sha256").update(new Uint8Array([0x00])).update(content).digest(),
    );
  }

  it("OFF: a real document frame is CONSUMED — it becomes a `doc` leaf and never a transcript row", async () => {
    const h = await start("off");
    events = [];
    await ingestDocumentFrame(h, "sess-off-1", documentFrameBytes(), "corr-off-1");

    // THE PROPERTY. `session.document.received` is logged only on the consumed branch — the branch
    // that appends a `doc` leaf, writes NO transcript row and rings NO doorbell. If the hook were
    // unset, the frame would take the conversation path instead and this event would be absent.
    const seen = events.map((e) => e.event);
    // The whole flow, in the order it happens, because each step is a different claim:
    //   the classifier recognised it and the message screen was skipped …
    expect(seen, "the classifier is not installed with documents off").toContain(
      "session.content.screen.skipped_document_frame",
    );
    //   … the frame was refused by the gated hook …
    expect(seen).toContain("document.frame.refused");
    //   … and it was still CONSUMED, which is the bit that keeps it out of the conversation.
    // `session.document.received` is logged only on the consumed branch — the branch that appends a
    // `doc` leaf, writes NO transcript row and rings NO doorbell. With the hook unset the frame takes
    // the conversation path and this event is absent.
    expect(seen, "the frame was NOT consumed — it took the conversation path").toContain(
      "session.document.received",
    );

    // And the durable transcript is empty, asserted on the database rather than inferred from a log.
    const db = h.getSessionNodeManager().getDb()!;
    const rows = db
      .prepare("SELECT COUNT(*) AS n FROM transcript WHERE session_id = ?")
      .get("sess-off-1") as { n: number };
    expect(rows.n, "a document frame was written to the operator's conversation history").toBe(0);
  }, 120_000);

  it("OFF: the refusal is loud — cause, consequence and a remedy, under the correlationId", async () => {
    const h = await start("off");
    events = [];
    await ingestDocumentFrame(h, "sess-off-2", documentFrameBytes(), "corr-off-2");

    const refusal = events.find((e) => e.event === "document.frame.refused");
    expect(refusal, "the refusal produced no log line at all").toBeDefined();
    // A refusal warns rather than debugs: the durable forensic record is the point.
    expect(refusal?.level).toBe("warn");
    expect(refusal?.fields["reason"]).toBe("documents_disabled");
    // correlationId threading — this is how "was this frame ingested?" is answered by a join.
    expect(refusal?.fields["correlationId"]).toBe("corr-off-2");
    expect(refusal?.fields["agentName"]).toBe("alice");
    // The consequence and the remedy are named, not implied, and the remedy names a real variable.
    expect(String(refusal?.fields["consequence"])).toContain("DROPPED");
    expect(String(refusal?.fields["remedy"])).toContain(DOCUMENTS_FLAG_ENV);
  }, 120_000);

  it("OFF: the peer key is truncated in the log and no frame content is logged", async () => {
    const h = await start("off");
    events = [];
    await ingestDocumentFrame(h, "sess-off-3", documentFrameBytes(), "corr-off-3");
    const refusal = events.find((e) => e.event === "document.frame.refused");
    expect(String(refusal?.fields["senderPubkey"]).length).toBeLessThanOrEqual(16);
    // Content never reaches the log. Asserted on the whole record, because a field added later is
    // exactly how content leaks into a log nobody re-reads.
    expect(JSON.stringify(refusal)).not.toContain("document_update");
  }, 120_000);

  it("ON: the same frame is ROUTED, not refused as disabled — the gate did not replace behaviour", async () => {
    const h = await start("on");
    events = [];
    await ingestDocumentFrame(h, "sess-on-1", documentFrameBytes(), "corr-on-1");
    // Consumed in both states — the difference is the reason, and with the layer on it is not ours.
    expect(events.find((e) => e.event === "session.document.received")).toBeDefined();
    expect(
      events.filter((e) => e.event === "document.frame.refused")
        .map((e) => e.fields["reason"]),
      "with documents ON a frame must not be refused as documents_disabled",
    ).not.toContain("documents_disabled");
  }, 120_000);

  it("a conversation message is NOT claimed as a document — the catastrophic direction of the fork", async () => {
    // A plain message classified as a document is a message silently dropped. The classifier is
    // shared with the router precisely so the two callers cannot disagree about what a frame is.
    const message = new TextEncoder().encode("hello there, ordinary message");
    expect(isDocumentFrame(message)).toBe(false);
    // Reach control: the same function says true for a real frame, so the false above is a judgement
    // and not a broken classifier.
    expect(isDocumentFrame(documentFrameBytes())).toBe(true);
  });
});
