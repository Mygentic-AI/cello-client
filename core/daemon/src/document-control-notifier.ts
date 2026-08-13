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
 *
 * ── DOD-MP-CONTROL-N-1 — WHY THE TARGET IS DERIVED, NOT `peerAgentId` ─────────────────────────
 *
 * This addressed `doc.peerAgentId` and returned after one send. That column is the GENESIS
 * counterparty, frozen at creation, and multiplayer made it wrong in two ways at once: with three
 * holders only one was told, and after a removal the genesis counterparty can BE the removed
 * holder — so the frame went to the one party it must not reach while the remaining co-author was
 * never told, under a reported `peerNotified: true`. Found by the M14B live fleet smoke.
 *
 * The target is now the DERIVED participant set, the same source FANOUT-1 established for update
 * envelopes; control frames were simply never migrated to it. Deriving needs the genesis proposal,
 * the amendment chain and signature verification — all of which live above this module, so it
 * arrives as an injected `holders()` rather than by widening this unit into the replay engine.
 *
 * A derivation failure REFUSES. It must never fall back to `peerAgentId`: that is the old bug, and
 * it aims the frame at exactly the wrong party in the case that motivated the change.
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
  /**
   * The CURRENT holders of this document OTHER than the owner, derived from the genesis proposal
   * plus the amendment chain — the same set that governs update delivery. A failure to derive is
   * returned, not swallowed: this unit refuses rather than guessing a recipient.
   */
  holders(
    ownerAgentId: string,
    documentId: string,
  ): { ok: true; holders: readonly string[] } | { ok: false; reason: string };
  /** Sign as the named agent. A miss must REFUSE, not substitute another agent's key. */
  sign(agentName: string, tbs: Uint8Array): Promise<Uint8Array>;
  send(
    agentName: string,
    input: { peerAgentId: string; documentId: string; bytes: Uint8Array; correlationId: string },
    /**
     * `parked: true` means the RELAY took it because the holder had no live counterparty — the
     * ending is not with them. Without this the fast path reported `holdersNotified: true` for a
     * frame nobody had received, and spent one of five sends doing it, while the drain loop
     * correctly treated the same outcome as not-sent. Two halves of one feature disagreeing about
     * what "sent" means, in the direction that reports success.
     */
  ): Promise<{ ok: true; parked?: boolean } | { ok: false; reason: string }>;
  now(): number;
  /**
   * Optional, and only for reporting a LOCAL fault. This module used to swallow the signing error
   * entirely, so the one description of "your key could not be loaded" existed nowhere — not in the
   * return value, not in a log line — and the operator was sent to wait for a peer who was already
   * there.
   */
  logger?: { warn(event: string, ctx: Record<string, unknown>): void };
}

export type NotifyPeer = (
  documentId: string,
  verb: DocumentControlVerb,
) => Promise<
  | {
      ok: true;
      holdersNotified: Record<string, boolean>;
      /**
       * WHY each holder did not get it, per holder. The boolean alone throws the cause away, and
       * the operator's sentence then has to guess — it guessed "most likely offline" for a
       * `session_sealed`, which waiting can never fix. That is the exact substitution
       * `notifyGuidance` exists to prevent, reintroduced one layer up.
       */
      holderFailures: Record<string, string>;
    }
  | { ok: false; reason: string; detail?: string }
>;

/**
 * How long before an unconfirmed control frame is offered again.
 *
 * A control frame has no ack, so this is insurance rather than a schedule: re-send a few times over
 * a long window in case the holder was merely away, then stop and say so.
 */
export const CONTROL_RESEND_AFTER_MS = 600_000;

/** How many SENDS a control frame gets before the daemon stops and reports it unconfirmed. */
export const CONTROL_MAX_SENDS = 5;

/**
 * How many failed ATTEMPTS before an unreachable holder is reported — while delivery keeps trying.
 *
 * The send ceiling can never fire for a holder who is never reachable, because only a successful
 * send spends it. Without this the loud report existed only for the case you can see.
 */
export const CONTROL_UNREACHABLE_REPORT_AFTER = 5;

export function createDocumentControlNotifier(deps: DocumentControlNotifierDeps): NotifyPeer {
  return async (documentId, verb) => {
    for (const { agentName, ownerAgentId } of deps.owners()) {
      const doc = deps.store.getDocument(ownerAgentId, documentId);
      if (!doc) continue;

      const targets = deps.holders(ownerAgentId, documentId);
      if (!targets.ok) {
        deps.logger?.warn("document.control.holders_underivable", {
          documentId, verb, agentName, reason: targets.reason,
        });
        return { ok: false, reason: targets.reason };
      }
      if (targets.holders.length === 0) {
        // Distinct from a failed send, and reported rather than returned as a vacuous success: an
        // empty map behind `ok: true` reads as "everyone was told" to a caller that checks only ok.
        return { ok: false, reason: "document_no_holders" };
      }

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
      } catch (err: unknown) {
        // REFUSED, not skipped and not sent unsigned. The peer must reject an unsigned control
        // frame, so shipping one would report a notification that cannot possibly land — and the
        // caller reports `peerNotified` straight to the operator.
        //
        // THE MESSAGE IS KEPT. A bare `catch {}` here threw away the only description of a LOCAL
        // fault — a key file that moved, a locked keychain, an agent with no provider — and the
        // operator was then told their peer had not heard them and to try again when the peer was
        // back. Waiting cannot fix a signing failure. The reason travels up so the caller can say
        // which of the two it is.
        const detail = err instanceof Error ? err.message : String(err);
        deps.logger?.warn("document.control.unsigned", { documentId, verb, agentName, reason: detail });
        return { ok: false, reason: "document_control_unsigned", detail };
      }
      control.signature = signature;
      // Signed ONCE. The TBS commits to the document, the sender and the verb — never to a
      // recipient — so every holder receives byte-identical evidence and cannot be handed a
      // frame that differs from their co-holders'.
      const bytes = encodeDocumentControl(control);

      // DOD-MP-CONTROL-DURABLE-1 — RECORD THE DEBT BEFORE TRYING TO PAY IT.
      //
      // The loop below is a fast path, not the guarantee. It used to be both: one failed send and
      // the frame was gone, so a holder who happened to be offline never learned the document had
      // ended and their copy stayed open forever — with this call reporting the close as done.
      //
      // Seeding first also covers the crash window: a daemon that dies between here and the send
      // still owes the ending on restart.
      deps.store.seedControlDeliveries(
        ownerAgentId, documentId, verb, bytes, targets.holders, deps.now(),
      );
      const holdersNotified: Record<string, boolean> = {};
      const holderFailures: Record<string, string> = {};
      for (const holder of targets.holders) {
        // Sequential and independent: one unreachable holder must neither block nor abort the
        // others (availability is a first-class protocol concern), and a throw from the transport
        // is that holder's failure alone, not the fan-out's.
        try {
          const sent = await deps.send(agentName, {
            peerAgentId: holder,
            documentId,
            bytes,
            correlationId: randomUUID(),
          });
          const landed = sent.ok && sent.parked !== true;
          holdersNotified[holder] = landed;
          if (!landed && sent.ok) {
            holderFailures[holder] = "relay_parked";
            deps.logger?.warn("document.control.holder_not_notified", {
              documentId, verb, holderAgentId: holder, reason: "relay_parked",
              detail: "the relay is holding it — the holder had no live counterparty",
            });
          }
          if (landed) {
            // SENT, never acked — a control frame has no answer, so the most this can honestly say
            // is that the bytes left. The row stays owed and the worker re-offers it until the
            // send ceiling is spent, then says so loudly rather than pretending.
            deps.store.markControlSent(
              ownerAgentId, documentId, verb, holder, deps.now(), CONTROL_RESEND_AFTER_MS,
            );
          }
          if (!sent.ok) {
            holderFailures[holder] = sent.reason;
            deps.logger?.warn("document.control.holder_not_notified", {
              documentId, verb, holderAgentId: holder, reason: sent.reason,
            });
          }
        } catch (err: unknown) {
          holdersNotified[holder] = false;
          holderFailures[holder] = err instanceof Error ? err.message : String(err);
          deps.logger?.warn("document.control.holder_not_notified", {
            documentId, verb, holderAgentId: holder,
            reason: err instanceof Error ? err.message : String(err),
          });
        }
      }
      // `ok` means SIGNED AND ATTEMPTED TO EVERY CURRENT HOLDER. Who actually took it is the map's
      // job — collapsing that into one boolean is how a partial fan-out reads as a clean one.
      return { ok: true, holdersNotified, holderFailures };
    }
    // No agent on this daemon holds it. Named as such rather than reported as a transport failure:
    // the two want different things from whoever reads the log.
    return { ok: false, reason: "document_unknown" };
  };
}
