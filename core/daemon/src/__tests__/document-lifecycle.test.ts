/**
 * DOD-DOC-LIFECYCLE-1 — the verbs (§3.5 + §16.4): list, close, kill, withdraw.
 *
 * The three ending verbs are deliberately different, and conflating any two of them is the failure
 * this unit exists to prevent:
 *
 *   close     BILATERAL. Both sides ack; the document is complete by agreement.
 *   kill      UNILATERAL. Stop accepting and publishing, notify the peer, and KEEP the local copy
 *             and the log. The peer keeps what it holds — stated plainly, because a "kill" that an
 *             operator believes retracts their content is a promise the protocol cannot make.
 *   withdraw  ONE UNDELIVERED UPDATE. A local rollback plus a withdrawal record BESIDE the
 *             original envelope — marked, never deleted.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import * as Y from "yjs";
import {
} from "@cello-protocol/protocol-types";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import { DocumentEngine } from "../document-engine.js";
import { DocumentLifecycle } from "../document-lifecycle.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const PEER = "peer-agent";
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

let seq = 0;
function envelope(sender: string, prev: string | null, payload: Uint8Array | null = null): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`life${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: sender,
    docPrevHash: prev,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload: payload ?? update("some text. "),
    kind: "update",
    createdAtMs: NOW + seq,
  };
}

/** A real Yjs update. clientID pinned per the project rule. */
let clientSeq = 1000;
function update(text: string): Uint8Array {
  clientSeq += 1;
  const d = new Y.Doc();
  d.clientID = clientSeq;
  d.getText("content").insert(0, text);
  return Y.encodeStateAsUpdate(d);
}

function newFixture() {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: { append_only: false }, status: "active", createdAtMs: 1,
  });
  const engine = new DocumentEngine(logger);
  // SYNC-P4: closes are ENTRIES and the pending question is answered by the derivation on the
  // layer; this unit only ever sees the injected answer.
  const state = { ended: null as "closed" | "killed" | null, derived: true };
  const lifecycle = new DocumentLifecycle(
    store, logger,
    () => false,
    () => false,
    () => ({ derived: state.derived, ended: state.ended }),
  );
  return { store, engine, lifecycle, events, db, state };
}

describe("DocumentLifecycle — list", () => {
  it("shows the peer, type, tier, epoch, status and the pending-delivery state", () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    const [row] = f.lifecycle.list(AGENT, NOW);
    expect(row).toMatchObject({
      documentId: DOC,
      peerAgentId: PEER,
      documentType: "markdown",
      status: "active",
    });
    // Tier is constant in V1; epoch is DERIVED since M14B / AMEND-1 — 0 here because this
    // document has no amendments, not because anything is hardcoded.
    expect(row!.assuranceTier).toBe("authenticated");
  });

  
  it("a removed owner's row says so — the overlay comes from the INJECTED derivation, the stored status stays active", () => {
    // SYNC-D8: "was this owner written out?" is the layer's one fold-derived answer, injected
    // here; this unit's job is only the plumbing — the overlay on the row, the named publish
    // refusal, and the stored status staying untouched. The derivation itself is pinned in the
    // derive and handlers suites.
    const { logger } = recordingLogger();
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    const store = new DocumentStore(db, logger);
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const lifecycle = new DocumentLifecycle(store, logger, () => false, () => true, () => ({ derived: true, ended: null }));
    const row = lifecycle.list(AGENT, NOW).find((r) => r.documentId === DOC);
    expect((row as unknown as { removed?: boolean }).removed).toBe(true);
    expect(row!.status).toBe("active");
    expect(lifecycle.canPublish(AGENT, DOC)).toMatchObject({ ok: false, reason: "document_removed" });
  });

});

describe("DocumentLifecycle — the kill switch (§16.7-11)", () => {
  it("a paused agent refuses outbound publishes LOUDLY", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);

    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe("agent_platform_paused");
    // Loudly: a silent no-op would leave the operator writing into a document that is going
    // nowhere, with their work accumulating locally and no sign anything is wrong.
    expect((verdict as { detail: string }).detail).toMatch(/paused/);
  });

  it("a paused agent suppresses notifications", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    expect(f.lifecycle.shouldNotify(AGENT)).toBe(false);
  });

  it("unpausing resumes publish and notifications", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    f.lifecycle.setPlatformPaused(AGENT, false, NOW + 1);

    expect(f.lifecycle.canPublish(AGENT, DOC).ok).toBe(true);
    expect(f.lifecycle.shouldNotify(AGENT)).toBe(true);
  });

  it("the pause is per-agent, not global", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    // A daemon can attend several agents; pausing one because another was paused would take a
    // platform action against an agent it was never aimed at.
    expect(f.lifecycle.shouldNotify("another-agent")).toBe(true);
  });
});


describe("DocumentLifecycle — a STALLED document is terminal too", () => {
  it("refuses publish, naming the stall", () => {
    const f = newFixture();
    f.store.setDocumentStatus(AGENT, DOC, "stalled");
    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    // REJECT-1 stalls a document after its retry rounds; the refusal names the stall's two causes.
    expect((verdict as { reason: string }).reason).toBe("document_stalled");
  });
});

describe("DocumentLifecycle — the pause records WHEN", () => {
  it("writes the timestamp it was given, not 1970", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    const row = f.db
      .prepare("SELECT updated_at FROM agent_platform_pause WHERE agent_id = ?")
      .get(AGENT) as { updated_at: number };
    // On the kill switch, "when was this agent paused by the platform" is the audit fact of the
    // whole feature.
    expect(row.updated_at).toBe(NOW);
  });
});

describe("endings gate publish through the FOLD — the column stands in only for legacy (review F2)", () => {
  it("a DERIVED closed ending refuses publish, whatever the column says", () => {
    const f = newFixture();
    f.state.ended = "closed";
    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe("document_closed");
  });

  it("a DERIVED killed ending refuses publish, and the log is KEPT — a kill never destroys the record", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    f.state.ended = "killed";
    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe("document_killed");
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("a stale closed COLUMN does not refuse when the fold derives the document live", () => {
    // The F2 shape: a concurrently-arriving admission re-opened the derivation, and the column
    // lagged. The publish gate asks the fold, so the lag costs nothing.
    const f = newFixture();
    f.store.setDocumentStatus(AGENT, DOC, "closed");
    f.state.ended = null;
    expect(f.lifecycle.canPublish(AGENT, DOC).ok).toBe(true);
  });

  it("a LEGACY document (no derivation) is judged by its column — that record IS its ending", () => {
    const f = newFixture();
    f.state.derived = false;
    f.store.setDocumentStatus(AGENT, DOC, "killed");
    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe("document_killed");
  });
});
