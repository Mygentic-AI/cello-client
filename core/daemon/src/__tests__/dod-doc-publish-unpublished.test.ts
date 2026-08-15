/**
 * DOD-DOC-TOOLS-1 review, findings 3 and 5 — a failed `cello_doc_publish` must stay recoverable,
 * and must be screened like `cello_doc_write`.
 *
 * ── FINDING 3: the edit is applied, unpublishable, and invisible ─────────────────────────────────
 *
 * `writePath.publish()` folds the file's edits into the live document AND advances the recorded
 * projection before it returns. If the send then fails, `cello_doc_write` remembers the document in
 * `unpublishedEdits` so a later identical write can flush it. `cello_doc_publish` did not — while
 * its own comment claimed it was "reported the same way".
 *
 * The sequence an operator lives through:
 *
 *   1. Publish fails — paused agent, no key provider, a stalled document.
 *   2. They clear the cause and publish again. The file has not changed and now MATCHES the
 *      projection, so the fold returns nothing: `{ok: true, changed: false, published: false}` —
 *      no reason, no guidance. A clean "nothing to do".
 *   3. They try `cello_doc_write` with the same text instead. `before === content`, and there is no
 *      `unpublishedEdits` entry, so again `{changed: false, published: false}`.
 *   4. `cello_doc_list` shows `pendingDeliveries: 0`, because pending is derived from the envelope
 *      log and no envelope was ever written.
 *
 * Every surface reports a document fully in sync while the peer has never seen the change. This is
 * the identical defect already found and fixed in `cello_doc_write` — left in the neighbouring verb.
 *
 * ── FINDING 5: the file path ran no authoring-side screening ─────────────────────────────────────
 *
 * `cello_doc_write` screens what it is about to publish, so a character the peer will refuse is
 * caught where it was WRITTEN rather than becoming a rejection round — and three rejection rounds
 * stall the document. `cello_doc_publish` ran none of it, on the surface §4.1 calls primary: a human
 * editing the file in their editor. Paste a line from a web page, a zero-width space rides along
 * invisibly, and the refusal arrives from the peer with no clue where it came from.
 */

import { describe, it, expect, afterEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeypair } from "@cello-protocol/crypto";
import { createDocumentLayer } from "../document-layer.js";
import { DocumentPublish } from "../document-publish.js";
import { registerDocumentHandlers } from "../document-handlers.js";
import { agentPublicKeyFromId } from "../document-handlers.js";
import type { IpcHandler } from "../types.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const CONN = "conn-1";
const NOW = 1_700_000_000_000;

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function silentLogger(): Logger {
  const noop = () => {};
  const l = { debug: noop, info: noop, warn: noop, error: noop, child: () => l } as unknown as Logger;
  return l;
}

/**
 * A fixture WITH a workspace — the reason this path had no coverage. Both existing daemon fixtures
 * omit `workspaceRoot`, so `layer.writePath` is null and every publish answers
 * `document_files_unavailable`. Every test in this file would have passed against any
 * implementation.
 */
async function newFixture(opts: { publishBlocked?: string } = {}) {
  // The real failure lever. `publish.publish` records and signs the envelope; the SEND is the
  // delivery worker's job and happens later, so failing the transport does not fail a publish.
  // `canPublish` is what refuses — a paused agent, a closed or stalled document.
  let publishBlocked = opts.publishBlocked;
  const keys = generateKeypair();
  const owner = Buffer.from(await keys.getPublicKey()).toString("hex");
  const peerKeys = generateKeypair();
  const peer = Buffer.from(await peerKeys.getPublicKey()).toString("hex");

  const workspaceRoot = mkdtempSync(join(tmpdir(), "cello-doc-publish-"));
  dirs.push(workspaceRoot);

  const logger = silentLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");

  const layer = createDocumentLayer({
    db,
    logger,
    publicKeyFor: agentPublicKeyFromId,
    ownerKeyFor: (a) => (a === AGENT ? owner : null),
    notifyPeer: async () => ({ ok: true }),
    rollback: () => ({ ok: true }),
    sign: async (_o, tbs) => keys.sign(tbs),
    workspaceRoot,
  });

  const sent: Array<{ bytes: Uint8Array }> = [];
  const transport = {
    isPeerReachable: async () => ({ reachable: true, unknownAgent: false }),
    sendBytes: async (input: { peerAgentId: string; bytes: Uint8Array }) => {
      sent.push({ bytes: input.bytes });
      return { ok: true as const, sessionId: "s1", sessionOpened: true };
    },
    deliver: async () => ({ ok: true as const, sessionId: "s", sessionOpened: false, admitted: null }),
  } as never;

  const handlers = new Map<string, IpcHandler>();
  registerDocumentHandlers({
    handlers, logger, layer,
    publish: new DocumentPublish({
      governanceFrontierFor: (o, d) => layer.governanceFrontierFor(o, d),
      holdersFor: (o, d) => {
        const doc = layer.store.getDocument(o, d);
        return doc ? [doc.peerAgentId] : null;
      },
      store: layer.store, engine: layer.engine, logger,
      sign: async (_o, tbs) => keys.sign(tbs),
      senderIdFor: (o) => o,
      canPublish: (o, d) =>
        publishBlocked ? { ok: false as const, reason: publishBlocked, detail: "blocked for this test" } : layer.lifecycle.canPublish(o, d),
      nudgeSeats: () => {},
    }),
    transportFor: () => transport,
    resolveAgent: (_c, explicit) => explicit ?? AGENT,
    ownerKeyFor: (a) => (a === AGENT ? owner : null),
    sign: async (_a, tbs) => keys.sign(tbs),
    now: () => NOW,
  } as never);

  const call = (verb: string, params: Record<string, unknown> = {}) =>
    handlers.get(verb)!(params, CONN) as Promise<Record<string, unknown>>;

  const proposed = await call("cello_doc_propose", {
    peer_pubkey: peer,
    starting_content: "line one\n",
  });
  const documentId = String(proposed["documentId"]);
  // The peer accepting is what makes the document publishable.
  layer.store.recordConsent?.(owner, documentId, "accepted", NOW);

  const filePath = (): string => {
    const dir = join(workspaceRoot, owner);
    const found = readdirSync(dir, { recursive: true } as never) as unknown as string[];
    const rel = found.find((f) => String(f).includes(documentId.slice(0, 16)));
    return join(dir, String(rel));
  };

  const envelopeCount = (): number => layer.store.getEnvelopeLog(owner, documentId).length;
  return { call, documentId, filePath, sent, envelopeCount, unblock: () => { publishBlocked = undefined; }, layer, owner };
}

describe("a publish that could not be sent stays recoverable", () => {
  it("remembers the edit, so a later publish flushes it instead of reporting nothing to do", async () => {
    // THE DEFECT IN ONE SEQUENCE. Without the fix step 3 answers `changed: false, published: false`
    // with no reason — a clean 'nothing to do' over a change the peer has never seen.
    const fx = await newFixture({ publishBlocked: "agent_platform_paused" });

    writeFileSync(fx.filePath(), "line one\nline two from the editor\n");
    const first = await fx.call("cello_doc_publish", { document_id: fx.documentId });
    expect(first["published"]).toBe(false);
    expect(first["changed"]).toBe(true);

    // The cause is cleared. The file is untouched and now matches the projection.
    fx.unblock();
    const second = await fx.call("cello_doc_publish", { document_id: fx.documentId });

    expect(
      second["published"],
      "the edit was applied locally, could not be sent, and no later publish can ever flush it — " +
        "every surface reports a document in sync that the peer has never seen",
    ).toBe(true);
  });

  it("and the flush actually puts bytes on the wire, not just a truthy field", async () => {
    const fx = await newFixture({ publishBlocked: "agent_platform_paused" });
    writeFileSync(fx.filePath(), "line one\nline two\n");
    await fx.call("cello_doc_publish", { document_id: fx.documentId });
    const before = fx.envelopeCount();

    fx.unblock();
    await fx.call("cello_doc_publish", { document_id: fx.documentId });

    expect(fx.envelopeCount(), "no envelope was ever written for the flushed edit").toBeGreaterThan(before);
  });

  it("an unchanged file with nothing pending is still a clean no-op", async () => {
    // The guard against over-correcting: if every publish flushed, an ordinary no-op would cost a
    // leaf and a round trip each time someone ran it.
    const fx = await newFixture();
    writeFileSync(fx.filePath(), "line one\nline two\n");
    await fx.call("cello_doc_publish", { document_id: fx.documentId });

    const again = await fx.call("cello_doc_publish", { document_id: fx.documentId });
    expect(again["changed"]).toBe(false);
    expect(again["published"]).toBe(false);
  });
});

describe("publishing from the file screens what it is about to send", () => {
  it("refuses a character the peer's gate would refuse, instead of spending a rejection round", async () => {
    // Three rejection rounds stall a document permanently. `cello_doc_write` catches this at the
    // keystroke; the file path — which §4.1 calls the primary surface — did not catch it at all.
    const fx = await newFixture();

    // U+200B ZERO WIDTH SPACE: invisible, rides along on a paste from a web page.
    writeFileSync(fx.filePath(), "line one\nline​two\n");
    const res = await fx.call("cello_doc_publish", { document_id: fx.documentId });

    expect(res["ok"], "an invisible character went out to be refused by the peer").toBe(false);
    expect(res["reason"]).toBe("document_content_refused");
    // The guidance has to name the character, or an operator staring at an editor that renders it
    // as nothing has no way to find it.
    expect(String(res["guidance"])).toContain("U+200B");
  });
});
