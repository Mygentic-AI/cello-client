/**
 * DOD-DOC-TOOLS-1 — telling the peer a document has ended.
 *
 * `DocumentLifecycle` ends a document locally without asking anyone, deliberately: a kill is a
 * safety verb, and a safety verb that needs the counterparty's cooperation is not one. But a peer
 * who is never told keeps publishing into a document that will never answer — their updates refused
 * at the far end forever, with nothing on their screen explaining why. So the notification is
 * REQUIRED to be attempted, ALLOWED to fail, and the operator is told which happened.
 *
 * ── WHY THIS IS A MODULE AND NOT A CLOSURE IN THE COMPOSITION ROOT ────────────────────────────
 *
 * It was one, and that is precisely how the surface tests passed while the feature did nothing.
 * `createDocumentLayer` takes `notifyPeer` as an injected seam, so the two-party test wired it to
 * `async () => ({ ok: true })` — which reported success, sent nothing, and agreed with whatever the
 * near side did. Kill "worked" on both sides of the assertion and on neither side of the wire.
 *
 * That is the same shape as the two defects the DELIVERY-2 review found: a stub on the far side
 * cannot disagree with you. So the construction lives here, and both the daemon and the test build
 * it from this function — the test can still substitute the TRANSPORT, which is the part that has
 * to be substituted, without also substituting the logic under test.
 *
 * ── WHY THE DOCUMENT IS FOUND BY SCANNING ─────────────────────────────────────────────────────
 *
 * `notifyPeer`'s signature carries no owner: lifecycle calls it knowing only the document id, and
 * widening that interface would push a multi-agent daemon concern into a unit that deliberately has
 * none. So the owner is resolved here, by asking each agent this daemon holds whether the document
 * is theirs. A document id is a hash committing to both parties and a nonce, so at most one agent
 * can answer.
 */

import { randomUUID } from "node:crypto";
import {
  encodeDocumentControl,
  buildDocumentControlTbs,
  DOCUMENT_CONTROL_VERSION,
  type DocumentControl,
  type DocumentControlVerb,
} from "@cello-protocol/protocol-types";
import type { DocumentStore } from "./document-store.js";

export interface DocumentControlNotifierDeps {
  store: DocumentStore;
  /** The agents this daemon holds — name for signing and sending, owner key for scoping the store. */
  owners(): ReadonlyArray<{ agentName: string; ownerAgentId: string }>;
  /** Sign as the named agent. A miss must REFUSE, not substitute another agent's key. */
  sign(agentName: string, tbs: Uint8Array): Promise<Uint8Array>;
  send(
    agentName: string,
    input: { peerAgentId: string; documentId: string; bytes: Uint8Array; correlationId: string },
  ): Promise<{ ok: true } | { ok: false; reason: string }>;
  now(): number;
}

export type NotifyPeer = (
  documentId: string,
  verb: DocumentControlVerb,
) => Promise<{ ok: true } | { ok: false; reason: string }>;

export function createDocumentControlNotifier(deps: DocumentControlNotifierDeps): NotifyPeer {
  return async (documentId, verb) => {
    for (const { agentName, ownerAgentId } of deps.owners()) {
      const doc = deps.store.getDocument(ownerAgentId, documentId);
      if (!doc) continue;

      const control: DocumentControl = {
        type: "document_control",
        control_version: DOCUMENT_CONTROL_VERSION,
        document_id: documentId,
        sender_agent_id: ownerAgentId,
        verb,
        sent_at_ms: deps.now(),
        signature: new Uint8Array(0),
      };
      let signature: Uint8Array;
      try {
        signature = await deps.sign(agentName, buildDocumentControlTbs(control));
      } catch {
        // REFUSED, not skipped and not sent unsigned. The peer must reject an unsigned control
        // frame, so shipping one would report a notification that cannot possibly land — and the
        // caller reports `peerNotified` straight to the operator.
        return { ok: false, reason: "document_control_unsigned" };
      }
      control.signature = signature;

      return deps.send(agentName, {
        peerAgentId: doc.peerAgentId,
        documentId,
        bytes: encodeDocumentControl(control),
        correlationId: randomUUID(),
      });
    }
    // No agent on this daemon holds it. Named as such rather than reported as a transport failure:
    // the two want different things from whoever reads the log.
    return { ok: false, reason: "document_unknown" };
  };
}
