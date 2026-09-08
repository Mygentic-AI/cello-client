/**
 * The document OPERATOR surface, and the sweep that keeps shared documents converging.
 *
 * Registered last of the document wiring, deliberately: this is the only part that can CREATE a
 * document, and everything it creates has to have somewhere to go. Without the inbound path a peer's
 * answer is unroutable; without the delivery worker a published update never leaves.
 *
 * The reconcile sweep travels with it because it is what makes the surface's promise true over time
 * — a document published to a peer who was unreachable is not lost, it is retried on a bound.
 */
import { DocumentPublish } from "./document-publish.js";
import { ReconcileScheduler } from "./document-reconcile-scheduler.js";
import { registerDocumentHandlers } from "./document-handlers.js";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager } from "@cello-protocol/transport";
import { extractErrorMessage } from "./error-message.js";

export interface DocumentSurfaceDeps {
  logger: Logger;
  handlers: Map<string, IpcHandler>;
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string; keyProvider: KeyProvider }>;
  keyProviders: Map<string, KeyProvider>;
  perConnectionState: ReadonlyMap<string, { currentAgent: string | null }>;
  perAgentSignaling: ReadonlyMap<string, { signaling: SignalingManager }>;
  resolveCurrentAgent: (connState: { currentAgent: string | null } | undefined, explicitAgent?: string) => string | null;
  documentLayer: ReturnType<typeof import("./document-layer.js").createDocumentLayer>;
  documentOwnerKeyFor: (agentName: string) => string | null;
  documentTransportFor: (agentName: string) => ReturnType<typeof import("./document-delivery-transport.js").createDocumentDeliveryTransport>;
}

export function createDocumentSurface(deps: DocumentSurfaceDeps) {
  const {
    logger, handlers, loadedAgents, keyProviders, perConnectionState, perAgentSignaling,
    resolveCurrentAgent, documentLayer, documentOwnerKeyFor, documentTransportFor,
  } = deps;
  // ⚠️ ASSIGNED HERE AND READ ELSEWHERE. Two modules built EARLIER hold getters over the root's
  // `let` for this scheduler; the value is produced below and handed back so the root can set it.
  // Returning it is what keeps those getters correct — they resolve at call time, which is always
  // after this runs.
  let reconcileScheduler: ReconcileScheduler | undefined;

  // M14 / DOD-DOC-TOOLS-1 — the OPERATOR SURFACE. Registered last of the document wiring, because
  // it is the only part that can create a document, and everything it creates has to have somewhere
  // to go: without the inbound path a peer's answer is unroutable, and without the delivery worker a
  // published update never leaves.
  const documentPublish = new DocumentPublish({
    holdersFor: (ownerAgentId, documentId) => documentLayer.holdersFor(ownerAgentId, documentId),
    governanceFrontierFor: (ownerAgentId, documentId) =>
      documentLayer.governanceFrontierFor(ownerAgentId, documentId),
    store: documentLayer.store,
    engine: documentLayer.engine,
    logger,
    sign: async (ownerAgentId, tbs) => {
      // `ownerAgentId` is the owner KEY here, and keyProviders is keyed by NAME — so it is resolved
      // back through the same map the owner key came from rather than guessed. A miss throws: an
      // unsigned envelope in an append-only log is worse than a failed publish.
      const agentName = loadedAgents.find((a) => a.pubkey?.toLowerCase() === ownerAgentId)?.name;
      const provider = agentName ? keyProviders.get(agentName) : undefined;
      if (!provider) {
        throw new Error(
          `document_publish_unsigned: no key provider for owner ${ownerAgentId.slice(0, 16)}…, ` +
            `so this update cannot be signed`,
        );
      }
      return provider.sign(tbs);
    },
    // M14-D5: our wire sender id IS the owner key. Kept as its own callback because they are
    // different facts that happen to coincide — see DocumentStore.pendingDeliveries.
    senderIdFor: (ownerAgentId) => ownerAgentId,
    canPublish: (ownerAgentId, documentId) => documentLayer.lifecycle.canPublish(ownerAgentId, documentId),
    // SYNC-P4 (R39's first trigger): each seat gets an initiated reconcile exchange — the
    // envelope rides the exchange's own difference computation. Fire-and-forget by contract.
    nudgeSeats: (ownerAgentId, documentId, seats) => {
      for (const seat of seats) {
        void documentLayer
          .initiateReconcile(ownerAgentId, seat, [documentId])
          .then((sent) => {
            if (!sent.ok) {
              // NOT SILENT (review F3): a lost nudge is legal for correctness (any later
              // exchange recomputes the difference — R40), but until P5's sweeps exist this
              // line is the only trace an operator has for "my edit never arrived".
              logger.warn("document.reconcile.nudge_failed", {
                documentId, peerAgentId: seat, reason: sent.reason,
              });
            }
          })
          .catch((err: unknown) => {
            logger.warn("document.reconcile.nudge_failed", {
              documentId, peerAgentId: seat,
              reason: extractErrorMessage(err),
            });
          });
      }
    },
  });
  registerDocumentHandlers({
    handlers,
    logger,
    layer: documentLayer,
    publish: documentPublish,
    transportFor: documentTransportFor,
    resolveAgent: (connectionId, explicit) =>
      resolveCurrentAgent(perConnectionState.get(connectionId), explicit),
    ownerKeyFor: documentOwnerKeyFor,
    sign: async (agentName, tbs) => {
      const provider = keyProviders.get(agentName);
      if (!provider) throw new Error(`document_proposal_unsigned: no key provider for ${agentName}`);
      return provider.sign(tbs);
    },
    now: () => Date.now(),
  });

  // SYNC-P5 (R39–R43) — WHEN reconciling is attempted: the periodic sweep and the party-became-
  // reachable trigger. All state volatile (R41); a lost tick costs latency, never correctness.
  reconcileScheduler = new ReconcileScheduler({
    now: () => Date.now(),
    logger,
    sweepTargets: (ownerAgentId) => documentLayer.sweepTargets(ownerAgentId),
    pendingFor: (ownerAgentId, documentId, partyAgentId) =>
      documentLayer.pendingFor(ownerAgentId, documentId, partyAgentId),
    initiateReconcile: (ownerAgentId, peerAgentId, documentIds) =>
      documentLayer.initiateReconcile(ownerAgentId, peerAgentId, documentIds),
    ...(Number.isFinite(Number(process.env["CELLO_DOCUMENT_RECONCILE_BACKOFF_MS"])) &&
    Number(process.env["CELLO_DOCUMENT_RECONCILE_BACKOFF_MS"]) >= 250
      ? { backoffBaseMs: Number(process.env["CELLO_DOCUMENT_RECONCILE_BACKOFF_MS"]) }
      : {}),
  });
  // Overridable for tests (the delivery tick precedent); floored so a misread env cannot busy-loop.
  const reconcileTickOverride = Number(process.env["CELLO_DOCUMENT_RECONCILE_SWEEP_MS"]);
  const RECONCILE_SWEEP_MS =
    Number.isFinite(reconcileTickOverride) && reconcileTickOverride >= 250
      ? reconcileTickOverride
      : 120_000;
  // Review F2: the guard is TIME-STAMPED, not a bare boolean — a pass that never settles (a
  // dial with no timeout) would otherwise end the sweep silently for the daemon's lifetime,
  // the exact R42 stall one level above the module that fixed it. Past the bound the wedge is
  // WARNED and the guard force-released; the abandoned pass's own scheduler marks are
  // themselves time-bounded, so double-attempts are latency, never correctness.
  const RECONCILE_PASS_BOUND_MS = 5 * 60_000;
  let reconcileSweepStartedAt: number | null = null;
  const reconcileSweepTimer = setInterval(() => {
    if (reconcileSweepStartedAt !== null) {
      if (Date.now() - reconcileSweepStartedAt < RECONCILE_PASS_BOUND_MS) return;
      logger.warn("document.reconcile.sweep_wedged", {
        heldMs: Date.now() - reconcileSweepStartedAt,
        impact: "a sweep pass never settled; the guard is force-released so sweeping continues",
      });
    }
    reconcileSweepStartedAt = Date.now();
    void (async () => {
      try {
        for (const agentName of perAgentSignaling.keys()) {
          const ownerAgentId = documentOwnerKeyFor(agentName);
          if (ownerAgentId === null) continue;
          const result = await reconcileScheduler.sweep(ownerAgentId);
          if (result.attempted > 0 || result.failed > 0) {
            logger.debug("document.reconcile.sweep", { agentName, ...result });
          }
        }
      } catch (err: unknown) {
        logger.warn("document.reconcile.sweep_threw", {
          reason: extractErrorMessage(err),
        });
      } finally {
        reconcileSweepStartedAt = null;
      }
    })();
  }, RECONCILE_SWEEP_MS);
  reconcileSweepTimer.unref?.();

  // `documentPublish` is NOT returned: its only consumer is the handler registration inside this
  // module. Returning it would widen the surface for no caller.
  return { reconcileSweepTimer, reconcileScheduler };
}
