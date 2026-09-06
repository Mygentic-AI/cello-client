/**
 * CELLO Daemon — WHAT THE CONTENT PATH NEEDS FROM THE MANAGER
 *
 * One context, shared by both halves of the content path — `session-content-send.ts` and
 * `session-content-ingest.ts`. It lives in its own file because two classes hold it and a shape
 * declared beside one of them reads as belonging to that one.
 *
 * ⚠️ **IT IS WIDE ON PURPOSE, AND THAT IS THE TRADE THIS SPLIT MAKES.** The narrow contexts the
 * earlier collaborators hold (a dozen members each) are not reachable here: inbound ingest reads
 * session state, held content, salts, ephemeral keys, the relay client, the ordering record, the
 * screening gateway and the transcript, and it does so inside ONE method whose forty guards each
 * read locals the guards above them declared. A narrower seam would have to be bought with a
 * rewrite of that method, and a rewrite of the ingest path is a correctness risk on the most
 * load-bearing code in the daemon. Explicit and typed but wide beats implicit and narrow: every
 * member below is named, so what these files can reach is a list a reader can check, not a `this`.
 *
 * **Nothing here is state the content path owns.** The maps are shared BY REFERENCE with the
 * manager and with the other collaborators — one Map object, not a copy — for the same reason
 * `HeldContent` shares `heldContent`: two sources of truth for "what is in flight" is worse than
 * one shared one.
 */
import { type KeyProvider } from "@cello-protocol/crypto";
import { type CelloNode } from "@cello-protocol/transport";
import { type SecurityGatewayClient } from "@cello-protocol/gateway";
import type { Logger } from "./types.js";
import type { SessionTree, WritableSessionTreeLeafKind } from "./session-tree.js";
import { AgentRelayClient } from "./session-relay-client.js";
import type { SessionOwnChainStore } from "./session-own-chain-store.js";
import type { AuthorshipVerifier } from "./authorship-verification.js";
import type { InboundRefusals } from "./inbound-refusals.js";
import type { SessionRecords } from "./session-records.js";
import type { ParkRecovery } from "./park-recovery.js";
import type { SessionSalts } from "./session-salts.js";
import type { SessionQueries } from "./session-queries.js";
import type { RefusalNotices } from "./refusal-notices.js";
import type { SessionEphemerals } from "./session-ephemerals.js";
import type { SessionLiveness } from "./session-liveness.js";
import type { HeldContent, HeldEntry } from "./held-content.js";
import type { SessionLeafRecords } from "./session-leaf-records.js";
import { type ActiveSessionEntry, type AwaitingAckEntry, type ReceivedContentEntry } from "./session-node-types.js";
/**
 * What the content pipeline needs from the manager.
 *
 * Three shapes appear here and the difference between them is load-bearing:
 *
 * - **Plain readonly properties** are things the manager may REPLACE after this object is built —
 *   the wired-in hooks, the own-chain store (opened with the database, long after construction).
 *   The manager implements each as a getter over its own field, so this file always sees the
 *   current value rather than a snapshot taken during construction. A captured VALUE here would
 *   have frozen `null` in place for the life of the process; that exact mistake once left signing
 *   silently disabled while every test stayed green.
 * - **Mutable properties** are the three fault-injection counters, which this file both reads and
 *   decrements. They are accessor pairs on the manager's side.
 * - **Methods** are calls back into the manager, and the shared maps are passed by reference.
 */
export interface SessionContentPipelineContext {
  readonly logger: Logger;
  /**
   * M9-CORE-001: the inbound screening seam. Held rather than reached for, because a pipeline that
   * could choose not to screen is one that will eventually be built to skip it (INV-9).
   */
  readonly securityGateway: SecurityGatewayClient;

  // ── Collaborators, all constructed before this one and shared by reference ──────────────────
  readonly records: SessionRecords;
  readonly authorship: AuthorshipVerifier;
  readonly refusals: InboundRefusals;
  readonly park: ParkRecovery;
  readonly salts: SessionSalts;
  readonly queries: SessionQueries;
  readonly notices: RefusalNotices;
  readonly ephemerals: SessionEphemerals;
  readonly liveness: SessionLiveness;
  readonly held: HeldContent;
  readonly leafRecords: SessionLeafRecords;

  // ── Shared in-memory session state: ONE Map object each, never a copy ───────────────────────
  readonly activeNodes: Map<string, ActiveSessionEntry>;
  readonly awaitingAck: Map<string, Map<string, AwaitingAckEntry>>;
  readonly heldContent: Map<string, Map<number, HeldEntry>>;
  readonly witnessedSeq: Map<string, Map<string, number>>;
  readonly leafFetchTimers: Map<string, ReturnType<typeof setTimeout>>;
  readonly lastAck: Map<string, { seq: number; hash: Uint8Array }>;
  readonly receivedContent: Map<string, ReceivedContentEntry[]>;
  readonly resolvedContent: Map<string, Set<string>>;
  readonly undeliverableSeqs: Map<string, Set<number>>;
  readonly highWaterSeq: Map<string, number>;
  readonly counterpartyAddrs: Map<string, string[]>;
  readonly lingeringStreams: Set<ReturnType<typeof setTimeout>>;
  readonly redialNotBefore: Map<string, number>;
  readonly orderingObserved: Set<string>;

  // ── Settings and lifecycle flags the manager may change after construction ──────────────────
  readonly shuttingDown: boolean;
  readonly contentTtfMs: number;
  readonly leafFetchGraceMs: number;
  /** Opened with the database, which happens long after this object is built — never a snapshot. */
  readonly ownChainStore: SessionOwnChainStore | null;

  // ── Hooks the composition root wires in, each possibly absent ───────────────────────────────
  /**
   * ⚠️ **`null` AND "returns false" ARE DIFFERENT ANSWERS, everywhere below.** An absent durable
   * queue is not a queue that refused; an absent document classifier is not a frame that is not a
   * document. Each of these stays nullable so the code can keep saying which it was, which is why
   * they are properties rather than pre-bound calls.
   */
  readonly onParkFailed:
    | ((
        agentName: string,
        sessionId: string,
        contentHashHex: string,
        content: Uint8Array,
        structure1Cbor?: Uint8Array,
        structure2Cbor?: Uint8Array,
        contentHashAlg?: string,
      ) => boolean)
    | null;
  readonly onContentArrived: ((agentName: string, sessionId: string, senderPubkey: string) => void) | null;
  readonly onDocumentFrame:
    | ((
        agentName: string,
        sessionId: string,
        content: Uint8Array,
        senderPubkey: string,
        correlationId?: string,
      ) => { consumed: boolean; kind?: string })
    | null;
  readonly isDocumentFrame: ((content: Uint8Array) => boolean) | null;
  readonly onAwaitingPersisted: ((agentName: string, sessionId: string, contentHashHex: string) => void) | null;
  readonly inboundFrameObserver: ((frame: Record<string, unknown>) => void) | null;

  // ── Fault injection, read AND written here ──────────────────────────────────────────────────
  sendFaultRemaining: number;
  ackFaultRemaining: number;
  connectionLossRemaining: number;

  // ── Calls back into the manager ─────────────────────────────────────────────────────────────
  /** DOD-LOOP-1: (agentName, sessionId), never sessionId alone — see the manager's own note. */
  sessionKey(agentName: string, sessionId: string): string;
  keyProvider(agentName: string): KeyProvider | undefined;
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  appendSessionLeaf(
    agentName: string,
    sessionId: string,
    kind: WritableSessionTreeLeafKind,
    leafHashHex: string,
    correlationId?: string,
  ): { leafIndex: number; newRootHex: string };
  mailboxRouteAvailable(agentName: string): boolean;
  streamCensus(node: CelloNode, peerId: string): Record<string, number>;
  freezeOnIdentityFailure(
    agentName: string,
    sessionId: string,
    reason: string,
    correlationId?: string,
  ): Promise<void>;
  handleTtfExpiry(agentName: string, sessionId: string, hashHex: string): void;
  markContentUnverifiable(agentName: string, sessionId: string, why: "tampered" | "unverifiable"): void;
  maybeAutoAcknowledgeSeal(agentName: string, sessionId: string, correlationId: string): void;
  ownChainOf(
    agentName: string,
    sessionId: string,
    entry: { relayClient?: AgentRelayClient; relaySessionIdBytes?: Uint8Array } | undefined,
    ownPubkey: Uint8Array,
  ): Uint8Array | undefined;
  updateSessionStatus(
    agentName: string,
    sessionId: string,
    status: "active" | "sealed" | "interrupted" | "abandoned",
    interruptedBy?: "local",
  ): boolean;
  abandonSession(agentName: string, sessionId: string): Promise<boolean>;
  connectToCounterparty(
    agentName: string,
    sessionId: string,
    addrs: string[],
  ): Promise<{ ok: true } | { ok: false; reason: string; error: string }>;
  destroySessionNode(
    agentName: string,
    sessionId: string,
    reason: "sealed" | "interrupted" | "error",
  ): Promise<void>;
  retireOnCounterpartyAbandon(agentName: string, sessionId: string, correlationId?: string): Promise<boolean>;
}
