/**
 * DOD-DOC-TOOLS-1 review, special check 1 — §16.5's passive notification had NO PRODUCTION CALLER
 * at either end.
 *
 * ── THE SHAPE THIS MILESTONE KEEPS HITTING ───────────────────────────────────────────────────────
 *
 * `DocumentNotifications.notice()` writes "the peer changed this document and you have not read it".
 * `.pending()` reads them back. Both were fully implemented, both were tested — and **neither had a
 * caller outside its own test file**. So:
 *
 *   - an admitted inbound update wrote no notice;
 *   - `cello_check_notifications` had no document section at all, so nothing could read one;
 *   - `cello_doc_read` dutifully called `clear()` on rows that could never exist.
 *
 * An agent learned a document had moved only by polling `cello_doc_list` or `cello_doc_diff`. The
 * DoD line carried this clause explicitly — "wire the notice section into the inbox aggregation" —
 * and it was the one clause left unmet, on the very line whose own history is "everything was built,
 * tested, and called by nothing".
 *
 * A unit with no caller reads exactly like a working one. No test can fail for "the only caller is a
 * fixture", which is why this file asserts the CHAIN rather than the units: an update arriving must
 * end up visible to an operator who asks their inbox, through the real composition root.
 *
 * ── WHY THE COUNT IS DERIVED, NOT INCREMENTED ────────────────────────────────────────────────────
 *
 * Envelopes redeliver — that is how an offline peer is caught up — so a counter bumped per arrival
 * drifts upward and tells the operator there is more to read than there is. The count is computed
 * from the envelope log against the read mark, so it cannot disagree with the document.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { createDocumentLayer } from "../document-layer.js";
import { agentPublicKeyFromId } from "../document-handlers.js";
import type { Logger } from "../types.js";

function silentLogger(): Logger {
  const noop = () => {};
  const l = { debug: noop, info: noop, warn: noop, error: noop, child: () => l } as unknown as Logger;
  return l;
}

const DAEMON_SRC = readFileSync(new URL("../daemon.ts", import.meta.url), "utf8");
const ROUTER_SRC = readFileSync(new URL("../document-frame-router.ts", import.meta.url), "utf8");

describe("the notification path has production callers at BOTH ends", () => {
  it("the composition root reads notices into the inbox", () => {
    // The reader half. Asserted on the composition root's source because that is the seam where a
    // fully-built feature stays invisible: nothing fails when it is simply never passed in.
    expect(
      /documentNotices:\s*\(ownerAgentId\)\s*=>\s*documentLayer\.notifications\.pending\(/.test(DAEMON_SRC),
      "cello_check_notifications is not wired to document notices — the reader exists and nothing calls it",
    ).toBe(true);
  });

  it("an admitted inbound update writes one", () => {
    // The writer half, at the only place that knows an update was ADMITTED. Refused updates
    // deliberately do not notice: nothing was applied, so there is nothing new to read.
    expect(
      /noticeInboundUpdate\(ownerAgentId, content\)/.test(ROUTER_SRC),
      "an admitted update writes no notice — the writer exists and nothing calls it",
    ).toBe(true);
  });
});

describe("the unread count is derived from the log, so redelivery cannot inflate it", () => {
  function newLayer() {
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    return createDocumentLayer({
      db,
      logger: silentLogger(),
      publicKeyFor: agentPublicKeyFromId,
      ownerKeyFor: () => null,
      notifyPeer: async () => ({ ok: true }),
      rollback: () => ({ ok: true }),
      sign: async () => new Uint8Array(64),
    });
  }

  const OWNER = "aa".repeat(32);
  const PEER = "bb".repeat(32);
  const DOC = "cc".repeat(32);

  it("counts the peer's updates and not our own", () => {
    const layer = newLayer();
    layer.store.createDocument({
      documentId: DOC, ownerAgentId: OWNER, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });

    // `appendEnvelope(ownerAgentId, row)` — the owner is the FIRST argument, not a field.
    const put = (sender: string, hash: string, at: number) =>
      layer.store.appendEnvelope(OWNER, {
        documentId: DOC, envelopeHash: hash, senderAgentId: sender,
        docPrevHash: null, epochId: 0, signature: new Uint8Array(64),
        stateVector: new Uint8Array([0]), payload: new Uint8Array([1]), kind: "update", createdAtMs: at,
      });

    put(PEER, "11".repeat(32), 100);
    put(OWNER, "22".repeat(32), 101); // ours — never unread to us
    put(PEER, "33".repeat(32), 102);

    expect(
      layer.notifications.unreadFromPeer(OWNER, DOC),
      "our own writes were counted as things we have not read",
    ).toBe(2);
  });

  it("a document never read counts everything the peer sent", () => {
    const layer = newLayer();
    layer.store.createDocument({
      documentId: DOC, ownerAgentId: OWNER, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    layer.store.appendEnvelope(OWNER, {
      documentId: DOC, envelopeHash: "44".repeat(32), senderAgentId: PEER,
      docPrevHash: null, epochId: 0, signature: new Uint8Array(64),
      stateVector: new Uint8Array([0]), payload: new Uint8Array([1]), kind: "update", createdAtMs: 50,
    });

    expect(layer.notifications.unreadFromPeer(OWNER, DOC)).toBe(1);
  });
});
