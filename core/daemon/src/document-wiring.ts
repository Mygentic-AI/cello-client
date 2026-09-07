/**
 * The document layer, and the per-agent carrier that moves its frames.
 *
 * Built as ONE thing on purpose — every half-wiring is a distinct silent failure. An inbound path
 * with no ack producer leaves the peer retrying until their document dies; a delivery worker with no
 * inbound counterpart publishes envelopes nobody can answer. So this module returns the layer, the
 * owner-key resolver and the transport factory together, or it returns nothing.
 *
 * ⚠️ FOURTEEN DEPENDENCIES, TWO OVER THE ORDER'S BOUND, RECORDED RATHER THAN HIDDEN — and the same
 * answer as `signal-handlers.ts`. The seam a reader will look for is "inbound layer" versus
 * "delivery transport", and it is not there: both need the session manager, the logger, the signing
 * keys and the agent registry, so splitting produces two contexts of ten that share eight members.
 * The order's own rule is that two modules needing the same values are one module.
 *
 * ⚠️ THREE VALUES WERE NARROWED ON THE WAY OUT, and each replaced a reach for something wider.
 * `config.securityGateway` and `config.celloDir` became the two values themselves, so this module
 * cannot read the rest of the daemon's configuration; and the handler map became
 * `getCloseSessionHandler`, because the delivery path calls exactly one other handler and holding
 * the whole map would let it call — or replace — any of them.
 */
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { createDocumentLayer, agentPublicKeyFromId } from "./document-layer.js";
import { isDocumentFrame } from "./document-frame-router.js";
import { createDocumentDeliveryTransport } from "./document-delivery-transport.js";
import { INBOUND_INJECTION_BLOCKED, type SecurityGatewayClient } from "@cello-protocol/gateway";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { LoadedAgent } from "./agent-loader.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager } from "@cello-protocol/transport";
import type { NotificationDispatcher } from "./notification-dispatcher.js";
import type { DiscoveryOutcome } from "./cross-node-negotiation.js";

export interface DocumentWiringDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** The LIVE registry — `cello_create_agent` pushes into it, so a new agent works without a restart. */
  loadedAgents: ReadonlyArray<LoadedAgent>;
  keyProviders: Map<string, KeyProvider>;
  /** The gateway itself, not the config that holds it. */
  securityGateway: SecurityGatewayClient;
  /** Where the daemon keeps its data; documents live under it. */
  celloDir: string;
  deliveryOpens: { begin: (openerPubkey: string, targetPubkey: string) => () => void };
  pubkeyOfAgent: (name: string) => string;
  openSessionFor: (agentName: string, opts: { targetPubkey: string }) => Promise<unknown>;
  perAgentSignaling: Map<string, { signaling: SignalingManager }>;
  runDiscoveryLookup: (
    signaling: SignalingManager,
    targetHex: string,
    timeoutMs: number,
    correlationId: string,
  ) => Promise<DiscoveryOutcome>;
  reconcileScheduler: { noteRefusal: (ownerAgentId: string, peerAgentId: string, terminal: boolean) => void } | undefined;
  notificationDispatcher: NotificationDispatcher;
  /** ONE other handler, not the map it lives in. */
  getCloseSessionHandler: () => IpcHandler | undefined;
}

export function createDocumentWiring(deps: DocumentWiringDeps) {
  const {
    logger, sessionNodeManager, loadedAgents, keyProviders, securityGateway, celloDir,
    deliveryOpens, pubkeyOfAgent, openSessionFor, perAgentSignaling, runDiscoveryLookup,
    reconcileScheduler, notificationDispatcher, getCloseSessionHandler,
  } = deps;

  // M14 / DOD-DOC-INBOUND-2: the document layer, wired to the session content path.
  //
  // Built as ONE thing (see `document-layer.ts`): every half-wiring is a distinct silent failure —
  // an inbound path with no ack producer leaves the peer retrying until their document stalls, a
  // delivery worker with no inbound counterpart publishes envelopes nobody can answer.
  //
  // It shares the daemon's SQLCipher handle rather than opening its own. One encrypted database,
  // one key, one file to back up — and a second opener is a second thing that has to agree about
  // the key, which is how a store ends up plaintext.
  // THE owner key. One function, used by the inbound router and the delivery sweep alike, because
  // the two halves scoping differently is a silent-empty-query bug rather than a visible one.
  //
  // Reads `loadedAgents`, which is the live registry — `cello_create_agent` pushes into it at
  // runtime — rather than the boot-time snapshot, so an agent registered after startup resolves
  // without a restart. Lower-cased because the store compares owner keys as strings and a peer's
  // id arrives off the wire in whatever case they sent.
  const documentOwnerKeyFor = (agentName: string): string | null =>
    loadedAgents.find((a) => a.name === agentName)?.pubkey?.toLowerCase() ?? null;

  const documentLayer = createDocumentLayer({
    db: sessionNodeManager.getDb(),
    logger,
    // DOD-DOC-SCREEN-CONTENT-1 — the gateway, reached with TEXT for once.
    //
    // The same program that screens conversation messages, called from the document gate's shadow
    // with the readable projected text instead of the signed binary envelope the wire carries.
    //
    // ── WHICH VERDICTS REFUSE, AND WHY IT IS NOT "ALL OF THEM" ────────────────────────────────
    //
    // ONLY the injection verdict. The gateway runs its whole inbound composition, and two of its
    // other terminal blocks must not refuse a document:
    //
    //   - the LANGUAGE ALLOWLIST (default: Latin only). A shared document written in Japanese,
    //     Arabic or Russian is ordinary use, and every update would be refused — permanently, since
    //     the same bytes are the same language on redelivery. The allowlist exists so a jailbreak
    //     phrased in a low-resource language cannot dodge English-trained screening; refusing a
    //     colleague's document outright is a far worse trade than that gap, and the character
    //     denylist still runs on every script.
    //   - the SIZE CAP, which is the sanitizer's per-message cap and not this path's limit. The
    //     gate already bounds an update and the whole document by its own numbers.
    //
    // A REDACT verdict is never honoured: rewriting one holder's replica is permanent divergence
    // both sides converge on and neither can see.
    //
    // A TRANSIENT block means the gateway is DOWN or its screener faulted. The update is admitted —
    // holding document convergence hostage to an optional layer breaks a layer that degrades by
    // design — but it is LOGGED BY NAME, because a weaker guarantee that looks identical to the
    // stronger one at every surface is how this whole class of defect survives.
    screenProjected: async (text, ctx) => {
      const verdict = await securityGateway.screenInbound(new TextEncoder().encode(text), {
        direction: "inbound",
        agentName: ctx.ownerAgentId,
        sessionId: ctx.documentId,
        ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
      });
      if (verdict.disposition !== "block") return { block: false };
      if (verdict.terminal !== true) {
        logger.warn("document.inbound.screen.unavailable", {
          documentId: ctx.documentId,
          senderAgentId: ctx.senderAgentId,
          reason: verdict.reason,
          consequence: "the update was admitted WITHOUT a semantic screen",
          correlationId: ctx.correlationId,
        });
        return { block: false };
      }
      if (verdict.reason !== INBOUND_INJECTION_BLOCKED) {
        logger.info("document.inbound.screen.not_applicable", {
          documentId: ctx.documentId,
          senderAgentId: ctx.senderAgentId,
          reason: verdict.reason,
          consequence: "a terminal block this path does not apply to documents — admitted",
          correlationId: ctx.correlationId,
        });
        return { block: false };
      }
      return { block: true, reason: verdict.reason };
    },
    // M14-D5: a remote agent's id IS its K_local pubkey hex, so this needs no lookup — and a lookup
    // on the critical path of every signature check is precisely what it must not have.
    publicKeyFor: agentPublicKeyFromId,
    ownerKeyFor: documentOwnerKeyFor,
    // Documents materialize as files under the operator's CELLO_DIR, alongside the database that
    // is their source of truth. Not the current working directory: a daemon serves many agents and
    // outlives any shell, so a relative root would scatter one operator's documents across
    // wherever they happened to launch it from.
    workspaceRoot: join(celloDir, "documents"),
    // The ack's road to the peer — the same open-or-reuse-then-seal path every other document frame
    // takes. Resolved from the owner KEY back to the agent name, because the transport is per agent.
    sendFrame: async (ownerAgentId, peerAgentId, bytes, leafKind) => {
      const agentName = loadedAgents.find((a) => a.pubkey?.toLowerCase() === ownerAgentId)?.name;
      if (!agentName) return { ok: false, reason: "document_ack_no_agent" };
      const sent = await documentTransportFor(agentName).sendBytes({
        peerAgentId,
        documentId: "ack",
        bytes,
        correlationId: randomUUID(),
        ...(leafKind === undefined ? {} : { leafKind }),
      });
      return sent.ok ? { ok: true } : { ok: false, reason: sent.reason };
    },
    // Read LAZILY: the scheduler is constructed after this layer (it consumes the layer's sweep
    // targets), so the binding must be resolved at call time rather than captured here.
    onPeerRefusal: (ownerAgentId, peerAgentId, terminal) =>
      reconcileScheduler?.noteRefusal(ownerAgentId, peerAgentId, terminal),
    // ONE implementation, shared with the two-party test. It was a closure here, and that is exactly
    // how the surface tests passed while the feature did nothing: the test wired this seam to
    // `async () => ({ ok: true })`, which reported success, sent nothing, and agreed with whatever
    // the near side did.
    // DOD-DOC-WATCH-1 — the ONLY doorbell a document update can ring, and only for an agent that
    // asked for it by naming the paths. §11.3's no-doorbell-on-update rule is otherwise untouched.
    nudge: (ownerAgentId, documentId, paths) => {
      const agentName = loadedAgents.find((a) => a.pubkey?.toLowerCase() === ownerAgentId)?.name;
      if (!agentName) return;
      notificationDispatcher.dispatchDocumentWatch(agentName, documentId, paths);
    },
    sign: async (ownerAgentId, tbs) => {
      // Signs as the OWNING agent, over the rejection's canonical preimage (DOD-DOC-REJECT-2).
      //
      // `ownerAgentId` here is the OWNER KEY — pubkey hex — because that is what the layer is
      // scoped by, and `keyProviders` is keyed by agent NAME. This did `keyProviders.get(ownerAgentId)`
      // and the comment above it asserted the two were the same thing. They are not: the lookup
      // missed on every call, so every auto-rejection threw `document_rejection_unsigned` and NO
      // rejection was ever signed or sent. A peer whose update we refused was never told why —
      // their sender retried into a gate that would refuse it every time, until the document
      // stalled for a reason neither operator could see.
      //
      // Invisible to every test: the unit and e2e fixtures alike wire `sign: (_o, tbs) => keys.sign(tbs)`,
      // discarding the agent argument, so nothing could disagree about which key was resolved.
      const agentName = loadedAgents.find((a) => a.pubkey?.toLowerCase() === ownerAgentId)?.name;
      const provider = agentName ? keyProviders.get(agentName) : undefined;
      if (!provider) {
        // Still throws rather than substituting another agent's key — an earlier version took no
        // agent at all and reached for whichever provider was first in the map, which is fabricated
        // crypto wearing a real signature.
        throw new Error(
          `document_rejection_unsigned: no key provider for owner ${ownerAgentId.slice(0, 16)}…, ` +
            `so its rejection cannot be signed — refusing rather than writing an unsigned leaf ` +
            `into an append-only log`,
        );
      }
      return provider.sign(tbs);
    },
  });
  // The classify-only half rides the same setter so the router and the ingest cannot disagree
  // about what a document frame is (DOD-DOC-SCREEN-CLASSIFY-1).
  sessionNodeManager.setOnDocumentFrame(documentLayer.onDocumentFrame, isDocumentFrame);

  // M14 / DOD-DOC-DELIVERY-2 — the outbound half, wired only now that INBOUND-2 is. The ordering
  // constraint on the DoD line is real and this is where it is honoured: a delivery worker with no
  // inbound counterpart publishes envelopes nobody can answer, so every document would stall at the
  // unacked ceiling.
  //
  // PER AGENT, because every capability below is: the signaling stream is authenticated as one
  // agent, sessions belong to one agent, and `openSessionFor` signs as one agent. A single worker
  // with an agent-shaped hole in it is how a delivery ends up sent under the wrong identity.
  //
  // The frame carrier, cached per agent (SYNC-P4: the delivery worker and its sweep are deleted —
  // scheduling returns as the P5 reconcile triggers).
  const documentTransports = new Map<string, ReturnType<typeof createDocumentDeliveryTransport>>();
  const documentTransportFor = (agentName: string) => {
    const cached = documentTransports.get(agentName);
    if (cached) return cached;
    const transport = createDocumentDeliveryTransport({
        agentName,
        logger,
        // The SAME 3-state discovery answer cello_initiate_session uses, from the same closure —
        // online / offline / unknown_agent, kept distinct from "the lookup itself failed". A second
        // implementation of that distinction drifts until one of them reports a directory outage as
        // the peer being offline.
        lookupPeer: async (peerAgentId, correlationId) => {
          const entry = perAgentSignaling.get(agentName);
          if (!entry) {
            // Our OWN stream is not up. A transport fault, never the peer being away — the
            // reachability mapper turns this into a throw, which the worker logs as lookup_failed.
            return { kind: "send_failed", reason: "signaling_unavailable" };
          }
          return runDiscoveryLookup(entry.signaling, peerAgentId, 10_000, correlationId);
        },
        // Most recent LAST — §16.4 reuses the most recent active session, and getSessionsForAgent
        // returns newest first.
        activeSessionsWith: (agent, peerAgentId) =>
          sessionNodeManager
            .getSessionsForAgent(agent)
            .filter((row) => row.status === "active" && row.counterparty_pubkey === peerAgentId)
            .map((row) => row.session_id)
            .reverse(),
        openSession: async (agent, peerAgentId, correlationId) => {
          // DOD-M12B-DELIVERY-QUIET-1: THIS is the only place the delivery worker opens a session,
          // so bracketing it is what makes "who opened this" knowable everywhere else. The window
          // must cover the whole open — the inbound doorbell on a co-resident pair fires DURING
          // negotiation, and the initiator-side reachability hook fires just before this returns.
          // Released in `finally`: a throw that left the intent registered would silence this
          // peer's doorbell for the life of the process, which is a worse outage than the storm.
          const releaseDeliveryOpen = deliveryOpens.begin(pubkeyOfAgent(agent), peerAgentId);
          try {
            // The same path `cello_initiate_session` takes, now callable without an IPC connection.
            const res = (await openSessionFor(agent, { targetPubkey: peerAgentId })) as {
              ok?: boolean; sessionId?: string; reason?: string; guidance?: string;
            };
            if (res.ok !== true || typeof res.sessionId !== "string") {
              return { ok: false, reason: res.reason ?? "session_open_failed", guidance: res.guidance };
            }
            logger.info("document.delivery.session_opened", { agent, peerAgentId, sessionId: res.sessionId, correlationId });
            return { ok: true, sessionId: res.sessionId };
          } finally {
            releaseDeliveryOpen();
          }
        },
        sealSession: async (agent, sessionId, correlationId) => {
          // §16.4: the autonomous session still carries the seal — the ceremony goes to zero, the
          // seal does not. Only ever called for a session this worker OPENED; one it reused belongs
          // to whoever started that conversation.
          const close = getCloseSessionHandler();
          if (!close) {
            // Reported, not swallowed. The outcome of a missing handler is a live session node the
            // operator never started, with no sealed record — the exact thing the seal exists to
            // prevent, and previously indistinguishable from a clean seal.
            logger.error("document.delivery.seal_failed", { agent, sessionId, reason: "close_handler_missing", correlationId });
            return;
          }
          /**
           * `wait_for_seal: true` — DOD-M15-CLOSEWAIT-1 review MEDIUM-5.
           *
           * This is NOT an IPC caller. It is an in-process worker awaiting the close for a session
           * it opened itself, and the `ok !== true` check below is the only thing that ever reports
           * a failed document-delivery seal. The new default answers `ok: true` at COMMITMENT, so
           * without this flag that check could never fire for a ceremony failure again — §16.4's
           * "the autonomous session still carries the seal" would rest on a detached task nobody
           * awaited, retried or reported on.
           *
           * The whole point of answering early is that a human is watching a terminal. Nobody is
           * watching this one, so it takes the blocking form — which also stops each delivery
           * leaving a detached ceremony holding a visiting connection for up to eleven minutes,
           * overlapping instead of serialising.
           */
          const sealed = (await close({ session_id: sessionId, agent, wait_for_seal: true }, `doc-delivery-${correlationId}`)) as
            { ok?: boolean; reason?: string } | undefined;
          if (sealed?.ok !== true) {
            // `cello_close_session` has distinct failure codes — session_already_sealed,
            // seal_interrupted_*, signaling_reconnecting — and every one of them landed nowhere.
            logger.warn("document.delivery.seal_failed", { agent, sessionId, reason: sealed?.reason ?? "unknown", correlationId });
          }
        },
        // `leafKind` IS LOAD-BEARING AND MUST BE FORWARDED. This adapter took five parameters and
        // dropped the sixth, which TypeScript accepts without a word — a function of lower arity is
        // assignable to one of higher arity, and the dep declares `leafKind?: number`. So the
        // transport asked for 0x04, the composition root threw it away, and every document leaf
        // still reached the relay as a MESSAGE. Verified on live traffic: daemon 0.0.145 shipped
        // the fix everywhere except here and the wire was unchanged.
        //
        // ⚠️ AND `contentHashAlg` IS THE SECOND PARAMETER THIS ADAPTER MUST NOT DROP. The note above
        // is about `leafKind`, which this wrapper silently swallowed while every other caller passed
        // it — a thin pass-through is exactly where a new argument goes missing, because nothing
        // about the call site looks wrong afterwards. B2b's failure mode if it happens again: the
        // document path sends a salted hash labelled `sha256`, and every peer refuses it.
        sendContent: (agent, sessionId, content, contentHash, correlationId, leafKind, contentHashAlg) =>
          sessionNodeManager.sendContent(agent, sessionId, content, contentHash, correlationId, leafKind, contentHashAlg),
        contentHashForSession: (agent, sessionId, content) =>
          sessionNodeManager.contentHashForSession(agent, sessionId, content),
        // The `0x04` doc leaf for a frame WE sent — the same step `cello_send` takes after its own
        // successful send. See the comment at the call site for why this is delivery-critical and
        // not audit bookkeeping.
        appendLeaf: (agent, sessionId, contentHash, frameBytes, correlationId, assignedSeq) => {
          // DOD-M12B-INDEX-1: a document leaf takes a position in the CONVERSATION's sequence space
          // (deliberate — f75ea09), so it obeys the same discipline a message does — including
          // being HELD when the position is ahead of the tail, which is why the real frame bytes
          // have to travel with it.
          const placed = sessionNodeManager.placeOwnLeaf(
            agent,
            sessionId,
            Buffer.from(contentHash).toString("hex"),
            frameBytes,
            assignedSeq,
            correlationId,
            "doc",
            /**
             * No proof — and the reason I first wrote here was FALSE, which review traced rather
             * than read.
             *
             * ⚠️ IT SAID *"the document transport does not go through `sendContent`, so no Structure-1
             * was signed."* Both halves are wrong. `document-delivery-transport.ts` calls
             * `deps.sendContent(...)`, wired straight to `sessionNodeManager.sendContent` a few lines
             * above this; and `session-relay-client.ts` signs the Structure-1 with no `leafKind` gate
             * at all, so a `0x04` doc leaf is signed exactly like a message. **A proof exists and is
             * discarded here.**
             *
             * That matters more than a wrong comment usually would, because this unit's whole thesis
             * is *"`undefined` is a claim the author made rather than one the signature made for
             * them"* — and the first claim made under the new signature was untrue.
             *
             * THE TRUE REASON, which is a better one: **no consumer.** A doc leaf released from a
             * hold writes no transcript row — `#releaseHeld` skips `recordTranscriptMessage` for
             * `kind === "doc"` — so there is nothing for the proof to reach. Discarding it is
             * no-consumer-no-ship, deliberately.
             *
             * **If doc rows ever reach the transcript, `appendLeaf` needs an authorship parameter**
             * and this `undefined` becomes a defect rather than a decision.
             */
            undefined,
          );
          return { placed: placed.placed, leafIndex: placed.placed ? placed.leafIndex : null };
        },
    });
    documentTransports.set(agentName, transport);
    return transport;
  };

  return { documentLayer, documentOwnerKeyFor, documentTransportFor };
}
