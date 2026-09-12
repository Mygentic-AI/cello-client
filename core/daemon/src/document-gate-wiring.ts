/**
 * 074-DOCSFLAG — whether the collaborative-document layer is BUILT in this process.
 *
 * NAMED `document-gate-wiring` and NOT `document-gate`: `document-gate.ts` is the VALIDATION gate
 * (DOD-DOC-GATE-1 — shadow-apply, judge the projected diff, admit or quarantine), a different thing
 * entirely and one of the files this module conditionally constructs.
 *
 * ONE value decides it, default off (`core/daemon/src/document-flag.ts`), and what it gates is
 * CONSTRUCTION rather than behaviour: with the flag off `createDocumentWiring` and
 * `createDocumentSurface` are never called, so the fourteen IPC verbs are never registered and the
 * reconcile sweep timer is never created.
 *
 * **The two ways to get this wrong, both of which this module exists to avoid.** A handler that
 * answered `documents_disabled` would still be a handler: a client enumerating the socket still sees
 * the verb, and an agent reading a tool list still calls it — which is the entire problem being
 * fixed. And a timer that fired every 120 seconds and returned early would still be a timer: it
 * still wakes the process and still writes log lines.
 *
 * NOTHING IS DELETED. Every line of the document layer is where it was, its tests keep running (the
 * suite runs with the flag ON — see `vitest.config.ts`), and with the flag on behaviour is identical
 * to before this gate existed.
 *
 * ⚠️ EXTRACTED FROM `daemon.ts` BECAUSE OF ITS LINE CEILING, and that turns out to be the right seam
 * anyway: this is the one place in the composition root that decides whether a whole subsystem
 * exists, and the alternative was eighty lines of branch in the middle of the wiring.
 */
import { createDocumentWiring } from "./document-wiring.js";
import { createDocumentSurface } from "./document-surface.js";
import { isDocumentFrame } from "./document-frame-router.js";
import { documentsEnabled, documentLayerState, DOCUMENTS_FLAG_ENV } from "./document-flag.js";
import type { ReconcileScheduler } from "./document-reconcile-scheduler.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";

type WiringDeps = Parameters<typeof createDocumentWiring>[0];
type SurfaceDeps = Parameters<typeof createDocumentSurface>[0];

export interface DocumentGateDeps
  extends Omit<WiringDeps, "getReconcileScheduler">,
    Pick<SurfaceDeps, "handlers" | "perConnectionState" | "resolveCurrentAgent"> {
  /**
   * ⚠️ A GETTER OVER THE ROOT'S `let`, NOT THE VALUE. The scheduler is produced BELOW, by the
   * surface this module builds from this module's own wiring — so at the moment the wiring is
   * constructed the binding is `undefined`. Passing the value captures that `undefined` for the life
   * of the process and the refusal backoff becomes a permanent no-op: 321 attempts against two
   * documents in 85 minutes, refused every time. `document-wiring.ts` carries the full note.
   */
  getReconcileScheduler: () => { noteRefusal: ReconcileScheduler["noteRefusal"] } | undefined;
}

export interface DocumentGateResult {
  /** The layer, or `undefined` when the gate is closed. `stop()` refuses new outbound work on it. */
  documentLayer: ReturnType<typeof createDocumentWiring>["documentLayer"] | undefined;
  /** The sweep interval, or `undefined` when the gate is closed — there is then nothing to clear. */
  reconcileSweepTimer: ReturnType<typeof setInterval> | undefined;
  /** Produced by the surface; the root assigns it back into the `let` the getters above read. */
  reconcileScheduler: ReconcileScheduler | undefined;
  /** Owner key for an agent NAME, or `undefined` — the reachable triggers already guard on it. */
  documentOwnerKeyFor: ((agentName: string) => string | null) | undefined;
}

export function wireDocumentGate(
  deps: DocumentGateDeps & { sessionNodeManager: SessionNodeManager; logger: Logger },
): DocumentGateResult {
  const { logger, sessionNodeManager } = deps;

  // Said once, at startup, so "are documents on?" is one grep rather than an inference from the
  // absence of something (order clause 9).
  logger.info("document.layer.state", {
    state: documentLayerState(),
    flag: DOCUMENTS_FLAG_ENV,
    consequence: documentsEnabled()
      ? "document verbs, tools and the reconcile sweep are ACTIVE"
      : "no document verb is registered, no document tool is advertised, and no sweep timer exists",
  });

  if (!documentsEnabled()) {
    // ⚠️ THE ONE THING STILL WIRED WITH DOCUMENTS OFF, AND IT IS NOT A DOCUMENT SURFACE.
    //
    // `setOnDocumentFrame` is not a verb, a tool or a timer — it is the ROUTING FORK in
    // session-node-manager, and leaving it unset does not make document frames go away. It makes them
    // take the CONVERSATION path: a document frame from a peer who still holds a document with this
    // agent would be appended to the durable transcript as a `msg` leaf, ring the doorbell, and be
    // handed to the agent by `cello_receive` as raw canonical CBOR. That is a real defect with a
    // live-fleet report behind it — a counterparty pasted the bytes back — and the comment at that
    // fork used to claim an unwired hook "cannot change the conversation path". It can, and did.
    //
    // So the classifier stays installed and a document frame is CONSUMED and REFUSED. Loud in the log
    // because the refusal is otherwise invisible, and answered on the wire by the frame router's own
    // refusal path rather than by silence.
    sessionNodeManager.setOnDocumentFrame(
      (agentName, sessionId, _content, senderPubkey, correlationId) => {
        logger.warn("document.frame.refused", {
          agentName,
          sessionId,
          senderPubkey: senderPubkey.slice(0, 16),
          ...(correlationId !== undefined ? { correlationId } : {}),
          reason: "documents_disabled",
          consequence:
            "the frame was DROPPED, not ingested as a conversation message; the peer's document " +
            "cannot converge with this agent until the document layer is enabled",
          remedy:
            `set ${DOCUMENTS_FLAG_ENV}=1 and restart the daemon, or tell the peer ` +
            `this agent does not hold documents`,
        });
        return { consumed: true, kind: "doc", ok: false, reason: "documents_disabled" };
      },
      isDocumentFrame,
    );
    return {
      documentLayer: undefined,
      reconcileSweepTimer: undefined,
      reconcileScheduler: undefined,
      documentOwnerKeyFor: undefined,
    };
  }

  // 040-DAEMONROOT unit 4: the document layer and its per-agent carrier → document-wiring.ts.
  const wiring = createDocumentWiring(deps);

  // 040-DAEMONROOT unit 15: the document operator surface and the sweep that keeps shared documents
  // converging → document-surface.ts.
  const surface = createDocumentSurface({
    logger,
    handlers: deps.handlers,
    loadedAgents: deps.loadedAgents,
    keyProviders: deps.keyProviders,
    perConnectionState: deps.perConnectionState,
    perAgentSignaling: deps.perAgentSignaling,
    resolveCurrentAgent: deps.resolveCurrentAgent,
    documentLayer: wiring.documentLayer,
    documentOwnerKeyFor: wiring.documentOwnerKeyFor,
    documentTransportFor: wiring.documentTransportFor,
  });

  return {
    documentLayer: wiring.documentLayer,
    reconcileSweepTimer: surface.reconcileSweepTimer,
    reconcileScheduler: surface.reconcileScheduler,
    documentOwnerKeyFor: wiring.documentOwnerKeyFor,
  };
}
