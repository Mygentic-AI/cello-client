/**
 * CELLO Daemon — THE BLIND WITNESS, AND STAYING REACHABLE THROUGH IT
 *
 * Split out of `session-node-manager.ts`. A relay countersigns the ORDER of a conversation and is
 * given only hashes, never plaintext — so what lives here is everything about talking to one:
 * connecting a session to its witness, proving key possession to it, holding a circuit reservation
 * open so a counterparty behind a NAT can still reach us, watching that reservation decay and
 * renewing it, quarantining a relay that misbehaves, and detaching cleanly when a session ends.
 *
 * **Moved verbatim, comments included.**
 *
 * ⚠️ **A RELAY IS NOT TRUSTED, AND THE CODE HERE IS WHERE THAT IS ENFORCED.** It authenticates to
 * us as much as we authenticate to it; it is quarantined rather than believed when it misbehaves;
 * and the one thing it must never learn — the operator's own address — is why the circuit-dial
 * authorisation below is narrow rather than convenient. Anything added here that widens what a
 * relay can see or do is a protocol change, not a refactor.
 */
import { randomUUID } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import type { Stream } from "@libp2p/interface";
import { NodeAutoNatService, isValidMultiaddr, type CelloNode } from "@cello-protocol/transport";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { contentHashFor } from "./wire-content-hash.js";
import { extractErrorMessage } from "./error-message.js";
import { type QuarantineFrameMeta } from "./quarantine-framing.js";
import type { Logger } from "./types.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import { RelayReceiptStore, type RelayReceipt } from "./relay-receipt-store.js";
import { SessionSealLeafStore } from "./session-seal-leaf-store.js";
import type { SessionOwnChainStore } from "./session-own-chain-store.js";
import type { SessionRecords } from "./session-records.js";
import type { SessionQueries } from "./session-queries.js";
import type { ParkRecovery } from "./park-recovery.js";
import type { InboundRefusals } from "./inbound-refusals.js";
import type { SessionLeafRecords } from "./session-leaf-records.js";
import type { StandingReceivers } from "./standing-receivers.js";
import type { WitnessAlerts } from "./witness-alerts.js";
import type { SessionContentIngest } from "./session-content-ingest.js";
import { AgentRelayClient, type RelayAuthRefusal } from "./session-relay-client.js";
import {
  RELAY_QUARANTINE_MS,
  SR_RESERVATION_MAX_RETRIES,
  heldRelayIdsOf,
  relayPeerIdOf,
  type ActiveSessionEntry,
  type QuarantinedRecord,
  type RelayConnectParams,
} from "./session-node-types.js";

/** What the relay path needs from the manager. */
export interface SessionRelayContext {
  readonly logger: Logger;

  readonly records: SessionRecords;
  readonly queries: SessionQueries;
  readonly park: ParkRecovery;
  readonly refusals: InboundRefusals;
  readonly leafRecords: SessionLeafRecords;
  readonly receivers: StandingReceivers;
  readonly witness: WitnessAlerts;
  readonly contentIn: SessionContentIngest;

  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;

  // ── Shared in-memory state: ONE object each, never a copy ───────────────────────────────────
  readonly activeNodes: Map<string, ActiveSessionEntry>;
  readonly relayClients: Map<string, AgentRelayClient>;
  /** The same shape `standing-receivers.ts` declares — one map, two files naming it identically. */
  readonly standingReceivers: Map<string, {
    node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService;
    seed: Uint8Array; relayPeerIds: string[];
  }>;
  readonly agentsWantingReceiver: Set<string>;
  readonly directoryRelayEndpoints: Map<string, Array<{ relayPeerId: string; relayAddrs: string[] }>>;
  /** Agent → relay peer id → the moment the quarantine lifts. NESTED, one inner map per agent. */
  readonly relayQuarantine: Map<string, Map<string, number>>;
  /**
   * ⚠️ NOT A TIMESTAMP — the retry STATE. It carries the attempt count and the correlation id as
   * well as when to try next, because a retry that forgets which attempt it is on cannot back off
   * and a retry that mints a fresh correlation id cannot be followed through the log.
   */
  readonly srReservationRetry: Map<string, { attempts: number; nextAt: number; correlationId: string; lastReason?: string }>;
  readonly srLastRejectionReason: Map<string, string>;
  readonly srLastRespreadAt: Map<string, number>;
  /**
   * ⚠️ THE REFUSAL OBJECT, not a reason string. It carries WHICH relay refused alongside why, and
   * dropping the peer id would leave an operator with "a relay refused your key" and no way to know
   * which of several to look at.
   */
  readonly srRelayRefusal: Map<string, RelayAuthRefusal & { relayPeerId: string }>;

  // ── Settings and flags the manager may change after construction ────────────────────────────
  readonly shuttingDown: boolean;
  readonly srReservationRetryMs: number;
  readonly srWatchdogIntervalMs: number;
  readonly ownChainStore: SessionOwnChainStore | null;

  /**
   * ⚠️ READ-WRITE, all three. The two stores are opened LAZILY — on first use, because they need a
   * database that does not exist when the manager is constructed — and every side must end up
   * holding the SAME instance, or a second store writes the same rows and the two agree only by
   * luck. The watchdog handle is written when the timer is armed and read to avoid arming a second.
   */
  relayReceiptStore: RelayReceiptStore | null;
  sealLeafStore: SessionSealLeafStore | null;
  reservationWatchdog: ReturnType<typeof setInterval> | null;

  readonly detachedRelayClientBuilder:
    | ((
        agentName: string,
        relayPeerId: string,
        relayAddrs: string[],
        stores: {
          receiptStore?: RelayReceiptStore;
          sealLeafStore?: SessionSealLeafStore;
          ownChainStore?: SessionOwnChainStore;
          onlineToken: () => Uint8Array | undefined;
        },
      ) => AgentRelayClient | undefined)
    | null;

  // ── Calls back into the manager ─────────────────────────────────────────────────────────────
  /** DOD-LOOP-1: (agentName, sessionId), never sessionId alone — see the manager's own note. */
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  getDirectoryOnlineToken(agentName: string): Uint8Array | undefined;
  /**
   * ⚠️ IT TAKES A REFUSAL AND RETURNS ONE — it is not a generic wrapper. It attributes a relay's
   * refusal to the directory that named the relay, so the operator is pointed at the party that
   * can actually fix it. A `<T>(reason, fn)` shape would have type-checked and lost that entirely.
   */
  withDirectoryCause(agentName: string, refusal: RelayAuthRefusal): RelayAuthRefusal;
  /**
   * ⚠️ `source` IS AN ENUM, NOT A FREE STRING, and it is written to the row an operator reads days
   * later — labelling a key-authentication refusal as a stream close sends them to the relay fleet
   * for a fault in the payload. And it answers `boolean`, not `void`: whether the row actually
   * moved.
   */
  markInterruptedWithDetails(
    agentName: string,
    sessionId: string,
    messageCount: number,
    source: "relay_frame" | "stream_close" | "key_refused",
  ): Promise<boolean>;
}

export class SessionRelay {
  readonly #ctx: SessionRelayContext;

  constructor(ctx: SessionRelayContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * DOD-M15-RELAYAUTH-1: authenticate a fresh standing receiver to its reservation relay over the
   * CELLO relay protocol — proof of K_local key possession, not a session. Reuses the SAME
   * `#relayClients` cache `connectSessionRelay`/`#resolveSealTransport` read from, keyed
   * identically (`${agentName}::${relayPeerId}`), so a session created moments later on this same
   * relay finds an already-authenticated client instead of dialing and authenticating twice.
   *
   * The manager holds no K_local (M12-P15's own rationale for `#detachedRelayClientBuilder`) —
   * without a builder wired (a narrow startup race, or a test harness that never wires one), this
   * is a no-op and the relay's own grace-window revoke is the backstop, not a defect in this path.
   */
  async authenticateStandingReceiver(
    agentName: string,
    node: CelloNode,
    relayPeerId: string,
    heldCircuitAddr: string,
    correlationId: string,
  ): Promise<void> {
    const clientKey = `${agentName}::${relayPeerId}`;
    let client = this.#ctx.relayClients.get(clientKey);
    if (!client) {
      if (!this.#ctx.relayReceiptStore && this.#db) this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
      if (!this.#ctx.sealLeafStore && this.#db) this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
      /**
       * ⚠️ SPLIT, NOT AN ANCHORED STRIP. The held address is
       * `/ip4/…/tcp/…/p2p/<relay>/p2p-circuit/p2p/<self>` — the `/p2p-circuit` marker is in the
       * MIDDLE, not at the end, so a `/\/p2p-circuit$/` replace matches nothing and silently
       * hands the relay client a circuit address as its DIAL address. Measured, not assumed:
       * that first version failed this file's own test because the client could not dial.
       */
      const baseRelayAddr = heldCircuitAddr.split("/p2p-circuit")[0] ?? heldCircuitAddr;
      client = this.#ctx.detachedRelayClientBuilder?.(agentName, relayPeerId, [baseRelayAddr], {
        receiptStore: this.#ctx.relayReceiptStore ?? undefined,
        sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
        ownChainStore: this.#ctx.ownChainStore ?? undefined,
        // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
        onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
      });
      if (!client) {
        /**
         * Review M5: this was a `debug` line, and it is not a debug-level event.
         *
         * If no builder is wired we return without proving key possession, the relay revokes this
         * receiver's reservation about fifteen seconds later, and the agent stops being reachable
         * from behind NAT — while reporting itself perfectly healthy. Calling that "a narrow startup
         * race" in a comment concedes it happens in production, and a system that is unreachable
         * must not be quieter about it than a system that is merely slow.
         */
        this.#ctx.logger.warn("session.standing_receiver.relay_auth.no_builder", {
          agentName,
          relayPeerId,
          correlationId,
          impact:
            "this receiver cannot prove key possession, so the relay will revoke its reservation and " +
            "the agent becomes unreachable from behind NAT — nobody can start a session with it — " +
            "even though it still reports itself online.",
        });
        return;
      }
      this.#ctx.relayClients.set(clientKey, client);
    }
    /**
     * ⚠️ `proveReservation`, NOT `connect`. Review HIGH-1: `connect()` short-circuits on the
     * client's cached stream, which belongs to whichever node connected FIRST — so every
     * REPLACEMENT standing receiver (the one built behind each new session) sent nothing, the relay
     * never saw its transport identity, and its reservation was revoked ~15s later. The agent then
     * churned reserve→revoke→rebuild for the life of the conversation, holding no usable circuit
     * address, so while you were talking to one person nobody else could reach you.
     *
     * `proveReservation` always opens its own stream from THIS node, and marks it so the relay
     * proves possession without rebinding the agent's delivery target away from the live session.
     */
    const proven = await client.proveReservation(node);
    /**
     * DOD-M15-RELAYSLOTS-1: keep the relay's refusal where the OPERATOR can reach it.
     *
     * The log line below is a good log line and it is not an answer to "why is my agent
     * unreachable?" — nobody opens the file. The relay now refuses for reasons a person can act on
     * (no token yet, too many sessions still open, this relay is misconfigured), each with its own
     * next step, and every one of them is useless if it stops at a log.
     */
    if (!proven) {
      const refusal = client.getLastAuthRefusal();
      /**
       * Review L2: the `else` is not symmetry for its own sake. `proveReservation` also fails for
       * transport reasons, which leave `getLastAuthRefusal()` null — and without this branch the
       * PREVIOUS refusal stayed in the map, so `cello_status` went on showing a cause and an
       * affordance for something that was no longer what was wrong.
       */
      if (refusal) this.#ctx.srRelayRefusal.set(agentName, { ...this.#ctx.withDirectoryCause(agentName, refusal), relayPeerId });
      else this.#ctx.srRelayRefusal.delete(agentName);
      /**
       * DOD-M15-RELAYSLOTS-1 clause 9 — **ACT on the classification, do not merely record it.**
       * A relay-side fault means a different relay will work now, so quarantine this one and
       * rebuild the receiver against the rest of the pool. Everything else stays put: a token
       * problem reproduces on every relay, and walking the fleet would turn one client fault into
       * what looks like a fleet-wide outage.
       */
      if (refusal?.tryAnotherRelay && !this.#ctx.shuttingDown) {
        this.#quarantineRelay(agentName, relayPeerId, refusal.reason);
        void this.#ctx.receivers.rebuildStandingReceiver(agentName);
      }
    } else {
      this.#ctx.srRelayRefusal.delete(agentName);
    }
    this.#ctx.logger.info("session.standing_receiver.relay_auth.result", {
      agentName,
      relayPeerId,
      // The node that actually proved itself — without this, HIGH-1 was invisible in the logs: the
      // line said `connected: true` for a receiver that had sent nothing.
      nodePeerId: node.getPeerId(),
      proven,
      ...(proven ? {} : {
        refusalReason: client.getLastAuthRefusal()?.reason ?? "no_relay_verdict",
        tryAnotherRelay: client.getLastAuthRefusal()?.tryAnotherRelay ?? false,
      }),
      correlationId,
    });
  }

  /**
   * RELAYSIG-1: the durably-stored, signature-verified relay ordering-record receipts for an agent
   * (optionally a single session). Empty when no receipts have been recorded yet. Read-only.
   */
  getRelayReceipts(agentPubkeyHex: string, sessionIdHex?: string): RelayReceipt[] {
    if (!this.#ctx.relayReceiptStore && this.#db) {
      this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
    }
    return this.#ctx.relayReceiptStore?.getAll(agentPubkeyHex, sessionIdHex) ?? [];
  }

  /**
   * DOD-M15-REFUSEDEVIDENCE-1 — retain a message refused OUTSIDE `ingestReceivedContent`
   * (`session-content-ingest.ts`).
   *
   * Review F6. The park drain terminally-blocks a message that arrived for an already-committed
   * session, then confirm-deletes the relay copy — the one other route in the tree that discarded
   * refused content, and the highest-suspicion combination in the product: hostile bytes aimed at a
   * conversation somebody has already sealed. Shipped guidance now tells every operator that
   * refused messages are kept, so this is made true rather than the promise narrowed.
   *
   * A thin delegate, not a second implementation: the bound, the dedup, the sequence allocation and
   * the logging are the ones every other refusal uses.
   */
  quarantineRefusedInbound(
    agentName: string,
    sessionId: string,
    reason: string,
    content: Uint8Array,
    contentHashHex: string,
    senderPubkeyHex: string | null,
    correlationId?: string,
  ): number | null {
    return this.#ctx.refusals.quarantineRefusedContent(agentName, sessionId, reason, content, contentHashHex, {
      senderPubkeyHex, correlationId,
    });
  }

  /** The metadata half of a framed quarantine read — everything known ABOUT the message, none of it
   *  taken from the message. Split out so the framing module never touches the database. */
  quarantineFrameMeta(agentName: string, sessionId: string, rec: QuarantinedRecord): QuarantineFrameMeta {
    return {
      reason: rec.reason,
      senderPubkeyHex: rec.senderPubkeyHex,
      senderLabel: rec.senderPubkeyHex === null ? null : this.#ctx.records.getContactMoniker(agentName, rec.senderPubkeyHex),
      // `attribution` is the column that exists to answer exactly this, so it is read rather than
      // inferred from `sender_sig` being non-null — a stored signature that was never checked
      // against the sender's key would otherwise be reported as VERIFIED.
      signature: rec.attribution === "verified_signature" ? "VERIFIED" : "NOT SIGNED",
      sessionId,
      position: rec.sequence,
      arrivedAtMs: rec.createdAt,
      /**
       * The hash OF THE RETAINED BYTES, recomputed here — not the hash the sender committed to.
       *
       * On the highest-value case in the whole unit those two differ ON PURPOSE:
       * `content_hash_mismatch` means the sender's committed hash does not describe these bytes.
       * Printing their claim over our bytes would label the payload with a hash it does not have,
       * which is the one thing a reader would use this line to check.
       */
      contentHashHex: Buffer.from(contentHashFor(rec.content, { alg: "sha256", salt: null })).toString("hex"),
    };
  }

  /**
   * The current standing receiver node's session-transport coordinates (peer id +
   * listen multiaddrs), or null if it is not ready. These are the addresses a local
   * SessionNegotiator advertises as this node's counterparty endpoint so the initiator
   * can dial it, and the value an inbound session_assignment carries in its
   * counterparty_session_* fields. Read-only — does NOT consume the standing receiver
   * (unlike acceptSession, which hands it off).
   */
  /**
   * 032-RELAYSPREAD — would this receiver ADMIT an inbound dial from this relay?
   *
   * The gater's inbound carve-out is the security-sensitive half of the spread: only relays whose
   * own reservation is confirmed held earn it, so a directory that merely NAMES a relay cannot dial
   * in behind the gate. Nothing could observe that from outside the manager, and the review found
   * the consequence: substituting the CANDIDATE list for the held list at the `setReservedRelayPeers`
   * call kept every test in the unit green while shipping exactly that hole. A guard whose wiring
   * cannot be observed is a guard nothing can test.
   *
   * Reads the live gater rather than a copy, so it cannot drift from what the gate actually does.
   */
  isRelayCarvedOutInbound(agentName: string, relayPeerId: string): boolean {
    return this.#ctx.standingReceivers.get(agentName)?.gater.holdsInboundCarveOut(relayPeerId) ?? false;
  }

  /**
   * M7 DOD-SPINE-6 / MSG-001-3b: connect a session node to the relay witness and
   * store the client on the active entry. Best-effort: a connect/auth failure logs
   * and leaves relayClient undefined — the session is NOT destroyed and the direct
   * content path keeps working (the relay-park/recovery path is MSG-001-3b's domain).
   *
   * ⚠️ THIS BLOCK SPENT TWO MILESTONES ABOVE THE WRONG METHOD. It sat stacked on top of
   * `relayLeafHandler`'s own docblock, so the file showed two descriptions in a row and the first
   * one described a method further down the page. The content split then carried it verbatim into
   * `session-content-ingest.ts`, where `connectSessionRelay` does not exist at all and the
   * misattribution could no longer be worked out from context. Returned to the method it describes.
   */
  async connectSessionRelay(
    sessionId: string,
    node: CelloNode,
    agentName: string,
    relay: RelayConnectParams,
    correlationId: string,
  ): Promise<void> {
    try {
      // The session node's gater admits only the counterparty; the relay witness is a
      // third peer. Permit it OUTBOUND so the dial isn't denied — inbound stays
      // counterparty-only (INV-5). The relay peer id comes from the signed assignment.
      this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId))?.gater.setAllowedOutboundPeer(relay.relayPeerId);

      // One relay client per (AGENT, RELAY NODE). The relay keys by agent pubkey, so the
      // collision H1 addresses is per relay; CELLO is federated, so a different session for
      // the same agent may be assigned a DIFFERENT relay — that needs its own client.
      const clientKey = `${agentName}::${relay.relayPeerId}`;
      let client = this.#ctx.relayClients.get(clientKey);
      if (!client) {
        // RELAYSIG-1: one shared receipt store (keyed by agent_pubkey, so a single instance serves all
        // agents + relays). Lazy — the encrypted DB is open by the time sessions are active.
        if (!this.#ctx.relayReceiptStore && this.#db) {
          this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
        }
        // FED-OPTIONB-SEAL-001: one shared seal-leaf log (keyed by agent_pubkey), same lazy lifecycle.
        if (!this.#ctx.sealLeafStore && this.#db) {
          this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
        }
        client = new AgentRelayClient({
          relayPeerId: relay.relayPeerId,
          relayAddrs: relay.relayAddrs,
          keyProvider: relay.keyProvider,
          senderPubkey: relay.senderPubkey,
          logger: this.#ctx.logger,
          receiptStore: this.#ctx.relayReceiptStore ?? undefined,
          sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
          // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
          onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
          // DOD-M15-CORROBORATE-1: a relay's witness alert reaches the operator's inbox from here.
          // The DETACHED clients get the same callback from the builder in daemon.ts.
          onWitnessAlert: (alert) => { this.#ctx.witness.recordRelayWitnessAlert(agentName, alert); },
          onWitnessUnreadable: (relayPeerId, why) => { this.#ctx.records.recordRelayWitnessUnreadable(agentName, relayPeerId, why); },
        });
        this.#ctx.relayClients.set(clientKey, client);
      }
      const sessionIdHexForRelay = Buffer.from(relay.sessionIdBytes).toString("hex");
      /**
       * ⚠️ THE GENESIS IS WRITTEN BEFORE THE REGISTRATION, NOT AFTER — review F10.
       *
       * `#leafRecords.sessionGenesisPrevRoot` reads the entry's assignment first and the column second,
       * and BOTH were still unset at this line: the entry's assignment is set below and the column
       * is written below that. So the argument was always `undefined` here on a first attach, and
       * the seed only survived because `registerSession` falls back to deriving one from the
       * assignment it is handed. That is a dead argument standing next to a live fallback, which
       * reads as deliberate and is the shape a later edit removes the wrong half of.
       */
      const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
      if (entry) entry.relayAssignment = relay.assignment;
      if (relay.assignment) this.#ctx.leafRecords.persistGenesisPrevRoot(agentName, sessionId, relay.assignment);
      client.registerSession(sessionIdHexForRelay, node, this.#ctx.contentIn.relayLeafHandler(agentName, sessionId, correlationId), relay.assignment, this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId));

      if (entry) {
        entry.relayClient = client;
        entry.relaySessionIdBytes = relay.sessionIdBytes;
        entry.relayClientKey = clientKey;
        // 2b: remember the relay endpoint so the content-park backstop deposits to the SAME relay.
        entry.relayPeerId = relay.relayPeerId;
        entry.relayAddrs = relay.relayAddrs;
        // Review H1: the dial path needs the credential in hand, not just the endpoint.
        // (Set above, before `registerSession`, so the genesis lookup it does has something to
        // find — see the note there.)
        // MSG-2 startup-flush: also PERSIST it, so a restart's crash-backstop flush (which runs
        // before the in-memory entry exists) can deposit un-acked content to the same relay.
        try {
          this.#db
            ?.prepare("UPDATE sessions SET relay_peer_id = ?, relay_addrs = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
            .run(relay.relayPeerId, JSON.stringify(relay.relayAddrs), Date.now(), this.#ctx.requireAgentId(agentName), sessionId);
        } catch (err: unknown) {
          this.#ctx.logger.warn("session.relay.endpoint.persist.failed", {
            sessionId,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      } else {
        // The session was torn down while we were wiring — undo the registration.
        client.unregisterSession(sessionIdHexForRelay);
        if (!client.hasSessions() && this.#ctx.relayClients.get(clientKey) === client) {
          client.close();
          this.#ctx.relayClients.delete(clientKey);
        }
        return;
      }

      // Proactively connect so the relay has this agent's stream to deliver leaves to
      // (the RECEIVER must be connected before the counterparty submits). Best-effort.
      await client.connect(node);

      // DOD-M15-RELAYAUTH-1 review HIGH-2 — see below. Best-effort and non-blocking: a session must
      // never fail to come up because a SECOND relay could not be told about it.
      //
      // Review M1: `.catch()` is not decoration. This is an unawaited promise, so a throw it does not
      // handle is an unhandled rejection — and this file already carries a comment elsewhere about an
      // absent `await` that became a remote process kill. The method's own try/catch does not cover
      // its prologue, so the catch here is the only thing standing between a torn-down node and the
      // daemon dying.
      void this.#presentAssignmentToReservationRelay(agentName, node, relay, sessionIdHexForRelay, correlationId, entry)
        .catch((err: unknown) => {
          this.#ctx.logger.warn("session.relay.assignment.reservation_relay_failed", {
            agentName,
            sessionId: sessionIdHexForRelay.slice(0, 16),
            error: extractErrorMessage(err),
            impact: "inbound relayed dials to this node may be refused by its reservation relay; the session still works over the direct path and the park backstop",
            correlationId,
          });
        });
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.relay.connect.error", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
  }

  /**
   * DOD-M15-RELAYAUTH-1 review HIGH-2 — **THE RELAY THAT GATES THE DIAL IS NOT ALWAYS THE RELAY
   * THAT HOLDS THE ASSIGNMENT, AND THE GATE DENIES WHEN THEY DIFFER.**
   *
   * Two relays are in play for one session, chosen by unrelated rules:
   *   - the WITNESS relay, `assignment.relay_endpoint`, picked by the directory. Both parties
   *     present `client_record_assignment` to it and to nowhere else.
   *   - the RESERVATION relay, whichever one this node's circuit address is held on — the first
   *     candidate that granted when it was a standing receiver.
   *
   * The counterparty dials our CIRCUIT address, so it is the RESERVATION relay whose gater is asked
   * `denyOutboundRelayedConnection(them, us)`. With no assignment recorded there it finds no binding
   * and refuses a completely legitimate dial. Two relays run in production and the client's own
   * logs show the fall-through to the second candidate is frequent, so this is the ordinary case,
   * not a corner: the session still opens, but every message falls to the store-and-forward park
   * path, and the only trace is a denial on a relay nobody is tailing.
   *
   * So the node that will be DIALLED presents the same assignment to the relay that will be asked
   * to allow it. Safe by construction: the assignment is self-authenticating (a per-node directory
   * signature the relay verifies against its consortium set), so presenting it more widely grants
   * nothing that forging it would not already require. No directory change, no new frame.
   */
  async #presentAssignmentToReservationRelay(
    agentName: string,
    node: CelloNode,
    relay: RelayConnectParams,
    sessionIdHex: string,
    correlationId: string,
    entry?: ActiveSessionEntry,
  ): Promise<void> {
    // Review M1: the prologue below lives INSIDE the try. `listenAddresses()` on a node torn down
    // while we were wiring is exactly the case handled 30 lines above at the caller, and out here it
    // would have escaped both this method's catch and (before the caller's `.catch`) the process.
    let reservationRelayPeerId: string | undefined;
    try {
      if (!relay.assignment) return; // direct/legacy/persisted-reconnect: nothing to present anywhere
      const heldCircuitAddr = node.listenAddresses().find((a) => a.includes("/p2p-circuit"));
      if (!heldCircuitAddr) return; // no reservation held → nobody will gate a dial to us
      reservationRelayPeerId = /\/p2p\/([^/]+)\/p2p-circuit/.exec(heldCircuitAddr)?.[1];
      if (!reservationRelayPeerId || reservationRelayPeerId === relay.relayPeerId) return; // same relay — already recorded
      const clientKey = `${agentName}::${reservationRelayPeerId}`;
      let client = this.#ctx.relayClients.get(clientKey);
      if (!client) {
        if (!this.#ctx.relayReceiptStore && this.#db) this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
        if (!this.#ctx.sealLeafStore && this.#db) this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
        // Split on the marker, not an anchored strip: the held address is
        // `…/p2p/<relay>/p2p-circuit/p2p/<self>`, so the marker is in the MIDDLE.
        const baseRelayAddr = heldCircuitAddr.split("/p2p-circuit")[0] ?? heldCircuitAddr;
        client = this.#ctx.detachedRelayClientBuilder?.(agentName, reservationRelayPeerId, [baseRelayAddr], {
          receiptStore: this.#ctx.relayReceiptStore ?? undefined,
          sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
          // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
          onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
        });
        if (!client) return;
        this.#ctx.relayClients.set(clientKey, client);
        // Review M4: record the key so teardown releases this client too — `relayClientKey` names
        // only the witness relay, so before this the client and its session registration leaked.
        if (entry) entry.extraRelayClientKeys = [...(entry.extraRelayClientKeys ?? []), clientKey];
      }
      // registerSession presents the assignment eagerly (see its own comment). No leaf handler: this
      // relay is not witnessing the session, it only needs the binding that authorizes the dial.
      // 033-ACKEMIT: no genesis is passed and none is needed. This client is not witnessing the
      // session — it never submits — and `registerSession` derives a seed from the assignment
      // anyway. Reaching into the session record for one here would also be reaching with the RELAY
      // session id, which is not the key that record is stored under.
      client.registerSession(sessionIdHex, node, undefined, relay.assignment);
      this.#ctx.logger.info("session.relay.assignment.presented_to_reservation_relay", {
        agentName,
        sessionId: sessionIdHex.slice(0, 16),
        witnessRelayPeerId: relay.relayPeerId,
        reservationRelayPeerId,
        impact: "the relay that will be asked to allow inbound circuit dials to this node now holds the assignment authorizing them",
        correlationId,
      });
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.relay.assignment.reservation_relay_failed", {
        agentName,
        sessionId: sessionIdHex.slice(0, 16),
        reservationRelayPeerId,
        error: extractErrorMessage(err),
        impact: "inbound relayed dials to this node may be refused by its reservation relay; the session still works over the direct path and the park backstop",
        correlationId,
      });
    }
  }

  /**
   * M7 DOD-SPINE-6 / MSG-001-3b: detach a session from its (agent, relay) client and
   * close the client when it has no remaining sessions. Idempotent and identity-guarded:
   * the map delete only fires if the map still holds THIS client (a racing teardown of a
   * sibling session must not close a freshly-created replacement client for the same key).
   */
  detachSessionRelay(entry: ActiveSessionEntry): void {
    const client = entry.relayClient;
    const key = entry.relayClientKey;
    if (!entry.relaySessionIdBytes) return;
    const sidHex = Buffer.from(entry.relaySessionIdBytes).toString("hex");

    /**
     * Review M4: release the EXTRA relay clients first — the ones opened to relays that gate circuit
     * dials. `relayClientKey` above names only the witness relay, so these were registered and never
     * unregistered: an authenticated relay stream and a `#sessions` entry leaked per session, and
     * relay-side the dial-through binding they hold is then cleared only by the idle timer, which is
     * now 24h. Runs before the early return below so it happens even for a session that never got a
     * witness client.
     */
    for (const extraKey of entry.extraRelayClientKeys ?? []) {
      const extra = this.#ctx.relayClients.get(extraKey);
      if (!extra) continue;
      extra.unregisterSession(sidHex);
      if (!extra.hasSessions()) {
        extra.close();
        this.#ctx.relayClients.delete(extraKey);
      }
    }
    entry.extraRelayClientKeys = undefined;

    if (!client) return;
    // Idempotent: clear the entry's reference so a second teardown of the same entry no-ops.
    entry.relayClient = undefined;
    client.unregisterSession(sidHex);
    if (!client.hasSessions() && key && this.#ctx.relayClients.get(key) === client) {
      client.close();
      this.#ctx.relayClients.delete(key);
    }
  }

  /**
   * DOD-M15-RELAYAUTH-1 review H1 — **THE GATE WAS DENYING THE LEGITIMATE DIAL, AND USUALLY.**
   *
   * With the gater installed, a relay refuses a circuit dial unless it already holds a
   * directory-signed assignment naming both transport peer ids. Both parties get that assignment
   * from the directory independently, and until this method existed, each only presented it to
   * relays IT had chosen — so whether a dial was allowed came down to which of two independent
   * network races finished first:
   *
   *   1. WE connect to the witness relay, then dial the counterparty's circuit address. ~2 RTT.
   *   2. THEY connect to their witness relay, then — unawaited, on a fresh dial + auth + record —
   *      tell their RESERVATION relay about the session. ~3–4 RTT.
   *
   * Nothing sequenced (1) against (2), and (1) is shorter, so we usually arrived first and were
   * refused. The session still opened and reported `transportMode: "relay"`, so the failure was
   * invisible: every message for the life of that conversation quietly took the store-and-forward
   * park path, and the only trace was a denial logged on a third machine nobody tails.
   *
   * The fix is to stop racing. Whoever is about to dial presents the assignment to the relay that
   * will gate that dial, and WAITS for the relay to confirm it recorded it. The ordering becomes
   * local to one thread of execution, so there is nothing left to lose.
   *
   * Safe by construction: we are a participant the assignment names, so the relay's own participant
   * check passes; and the assignment is self-authenticating (a directory signature the relay
   * verifies against its consortium set), so presenting it more widely grants nothing that forging
   * it would not already require.
   *
   * Best-effort by design — a relay we cannot reach must not stop us from dialling. If the record
   * fails we dial anyway: a dial that might be refused is strictly better than no dial.
   */
  async authorizeCircuitDialsToCounterparty(
    agentName: string,
    sessionId: string,
    entry: ActiveSessionEntry,
    addrs: string[],
  ): Promise<void> {
    const assignment = entry.relayAssignment;
    if (!assignment || !entry.relaySessionIdBytes) return; // direct/legacy/persisted: no credential to present
    const sessionIdHex = Buffer.from(entry.relaySessionIdBytes).toString("hex");

    // One presentation per distinct relay, not per address: a counterparty commonly advertises
    // several circuit addresses on the SAME relay.
    const seen = new Set<string>();
    for (const addr of addrs) {
      const relayPeerId = /\/p2p\/([^/]+)\/p2p-circuit/.exec(addr)?.[1];
      if (!relayPeerId || seen.has(relayPeerId)) continue;
      seen.add(relayPeerId);
      // The witness relay already has it — registerSession presented it when the session was wired.
      if (relayPeerId === entry.relayPeerId) continue;

      const baseRelayAddr = addr.split("/p2p-circuit")[0] ?? addr;
      try {
        const clientKey = `${agentName}::${relayPeerId}`;
        let client = this.#ctx.relayClients.get(clientKey);
        if (!client) {
          if (!this.#ctx.relayReceiptStore && this.#db) this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
          if (!this.#ctx.sealLeafStore && this.#db) this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
          client = this.#ctx.detachedRelayClientBuilder?.(agentName, relayPeerId, [baseRelayAddr], {
            receiptStore: this.#ctx.relayReceiptStore ?? undefined,
            sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
            // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
            onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
          });
          if (!client) {
            this.#ctx.logger.warn("session.transport.dial_authorization.no_builder", {
              sessionId,
              relayPeerId,
              impact: "cannot present the assignment to the relay that gates this dial; if the counterparty has not presented it either, the dial will be refused and every message will fall to the park path",
              correlationId: entry.correlationId,
            });
            continue;
          }
          this.#ctx.relayClients.set(clientKey, client);
          // Review M4: remember it so teardown releases it — this is a SECOND client for the
          // session, and detach only knows about the witness one.
          entry.extraRelayClientKeys = [...(entry.extraRelayClientKeys ?? []), clientKey];
        }
        // No leaf handler: this relay is not witnessing the session, it only needs the binding.
        client.registerSession(sessionIdHex, entry.node, undefined, assignment, this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId));
        const recorded = await client.recordAssignmentAndWait(entry.node, sessionIdHex);
        if (recorded) {
          this.#ctx.logger.info("session.transport.dial_authorized", {
            sessionId,
            relayPeerId,
            impact: "the relay that gates this circuit dial now holds the assignment authorizing it",
            correlationId: entry.correlationId,
          });
        } else {
          this.#ctx.logger.warn("session.transport.dial_authorization.not_recorded", {
            sessionId,
            relayPeerId,
            impact: "the relay did not confirm the assignment; the dial below may be refused and messages would fall to the park path",
            correlationId: entry.correlationId,
          });
        }
      } catch (err: unknown) {
        this.#ctx.logger.warn("session.transport.dial_authorization.failed", {
          sessionId,
          relayPeerId,
          error: extractErrorMessage(err),
          impact: "could not tell the relay that gates this dial about the session; the dial is attempted anyway",
          correlationId: entry.correlationId,
        });
      }
    }
  }

  /**
   * TEST-ONLY (M8C-INBOX-1 reviewer F1): buffer a received message + persist its transcript row,
   * exactly as the real inbound path (appendVerifiedContent, in `session-content-ingest.ts`) does,
   * WITHOUT standing up a session
   * tree — so a test can drive a live cello_receive that advances the read watermark (the N3
   * "delivery marks read" coupling). Only reachable via the CELLO_ENV=test IPC hook.
   */
  /** CELLO_ENV=test only: patch a relay client and session-id bytes onto an existing active node entry
   *  so submitSealLeaf succeeds without a real relay handshake (used by the oneshot relay-path test). */
  patchRelayClientForTest(agentName: string, sessionId: string, relayClient: AgentRelayClient, relaySessionIdBytes: Uint8Array): void {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) throw new Error(`patchRelayClientForTest: no active node for (${agentName}, ${sessionId})`);
    entry.relayClient = relayClient;
    entry.relaySessionIdBytes = relaySessionIdBytes;
    /**
     * ⚠️ REGISTER THE SESSION TOO — the seam must leave the state production leaves.
     *
     * A relay client that has never been told about a session holds no starting point for it, and
     * since `DOD-M15-SELFCHAIN-1` every submit on such a session is refused: there is nothing for
     * the chain links to anchor to. Production always registers, because attaching a relay is what
     * registration IS. A seam that attached the client and skipped the registration left fixtures
     * exercising a refusal path, and the failure surfaced as "the seal never happened" in a test
     * about away-mode replies.
     */
    relayClient.registerSession(
      Buffer.from(relaySessionIdBytes).toString("hex"),
      entry.node,
      undefined,
      entry.relayAssignment,
      this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId),
    );
  }

  /**
   * M7-SESSION-001 AC-004/AC-005: Register a relay stream for an active session.
   * Starts a background reader that watches for session_interrupted frames and
   * stream close events. Both detection paths call markInterruptedWithDetails().
   *
   * The reader runs for the lifetime of the relay stream. If the stream closes
   * without delivering a session_interrupted frame (AC-005 / 'stream_close' path),
   * the session is still marked interrupted.
   *
   * @param sessionId The hex session ID
   * @param stream The relay stream to monitor
   * @param messageCount Number of message leaves at the time of registration
   *   (used as the count at interruption — best effort since exact count at frame
   *   receipt may differ, but this is the value available at stream setup time)
   */
  registerRelayStream(agentName: string, sessionId: string, stream: Stream, messageCount: number = 0): void {
    void this.#watchRelayStream(agentName, sessionId, stream, messageCount);
  }

  /**
   * Background relay stream watcher.
   * Pseudocode:
   *   1. Create LP-framed iterator over the stream
   *   2. For each frame:
   *      a. If type === 'session_interrupted':
   *         - Record receivedInterruptFrame = true
   *         - Call markInterruptedWithDetails(sessionId, messageCount, 'relay_frame')
   *         - Break (no more frames expected)
   *   3. On stream close (loop ends normally or with error):
   *      a. If !receivedInterruptFrame:
   *         - Call markInterruptedWithDetails(sessionId, messageCount, 'stream_close')
   */
  async #watchRelayStream(agentName: string, sessionId: string, stream: Stream, messageCount: number): Promise<void> {
    let receivedInterruptFrame = false;
    // CELLO-M7-TRANSPORT-001: cast the stream input to lp.decode. Adding the
    // @libp2p/autonat service (interface@3.2.2 / uint8arraylist v2) to the
    // transport package surfaced a benign mixed-version split between the Stream
    // type (now v2) and it-length-prefixed's expected Uint8ArrayList (v3). The two
    // are structurally identical at runtime — this is a build-time-only artifact.
    const lpSource = stream as unknown as AsyncIterable<Uint8Array>;
    const source = (lp.decode(lpSource) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
    try {
      while (true) {
        let result: IteratorResult<Uint8Array>;
        try {
          result = await source.next();
        } catch {
          // Stream error (e.g. stream aborted) — treat as stream close
          break;
        }
        if (result.done || result.value === undefined) break;

        let frame: Record<string, unknown>;
        try {
          const bytes = result.value instanceof Uint8Array ? result.value
            : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
            : (result.value as { slice(): Uint8Array }).slice();
          frame = decode(bytes) as Record<string, unknown>;
        } catch {
          continue;
        }

        if (frame["type"] === "session_interrupted") {
          // H-3 SECURITY: this stream is registered (bound) to a specific
          // sessionId. A malicious or buggy relay could put a DIFFERENT session_id
          // in the frame body to target a session this stream is not authorized
          // for (cross-session targeting). Never trust the frame's id: if the frame
          // names a different session, reject it and keep watching the bound one.
          const frameSessionId = typeof frame["session_id"] === "string"
            ? frame["session_id"]
            : (frame["session_id"] instanceof Uint8Array
              ? Buffer.from(frame["session_id"]).toString("hex")
              : null);
          if (frameSessionId !== null && frameSessionId !== sessionId) {
            this.#ctx.logger.warn("session.interrupt.frame.session_mismatch", {
              boundSessionId: sessionId,
              frameSessionId,
              reason: "cross_session_frame_rejected",
            });
            continue; // ignore the hostile/mismatched frame; keep reading
          }
          receivedInterruptFrame = true;
          // Always mark the BOUND sessionId — never the id carried in the frame.
          await this.#ctx.markInterruptedWithDetails(agentName, sessionId, messageCount, "relay_frame");
          break; // No more relay frames expected after session_interrupted
        }
      }
    } catch {
      // Stream read loop ended — fall through to stream_close check
    }

    // AC-005: stream closed without a session_interrupted frame
    if (!receivedInterruptFrame) {
      // Only mark interrupted if this session is still active in SQLite
      const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
      if (record && record.status === "active") {
        await this.#ctx.markInterruptedWithDetails(agentName, sessionId, messageCount, "stream_close");
      }
    }
  }

  /**
   * DOD-NAT-REACHABILITY-1 (Phase 2): accept the directory's relay-pool endpoints
   * for an agent (arrives with signaling_auth_ok, i.e. on every connect AND every
   * reconnect). If the agent's standing receiver is up but holds NO reservation —
   * the agent-online ensure raced ahead of auth_ok, or every relay was down at
   * create time — rebuild it now so the agent becomes dialable without waiting
   * for a session handoff that (being unreachable) would never come.
   */
  setDirectoryRelayEndpoints(agentName: string, endpoints: Array<{ relayPeerId: string; relayAddrs: string[] }>): void {
    // DOD-M12B-RESERVATION-RETRY-1: a DIFFERENT relay pool re-arms the retry budget; the same one
    // does not. This fires on every signaling connect AND reconnect, so clearing unconditionally
    // would reset the bound on a short grid and defeat the whole point of having one. But once the
    // budget is spent, `getStandingReceiverReachability` reports `unreachable` for the rest of the
    // online episode — including while this path is actively re-attempting against relays we have
    // never tried. A new relay is new information; a repeat of the same list is not.
    const previous = this.#ctx.directoryRelayEndpoints.get(agentName);
    const poolChanged =
      previous === undefined ||
      previous.length !== endpoints.length ||
      endpoints.some((e, i) => e.relayPeerId !== previous[i]?.relayPeerId);
    this.#ctx.directoryRelayEndpoints.set(agentName, endpoints);
    if (poolChanged) {
      this.#ctx.srReservationRetry.delete(agentName);
      this.#ctx.srLastRejectionReason.delete(agentName);
    }
    if (endpoints.length === 0 || this.#ctx.shuttingDown) return;
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr) return; // not ensured yet — the coming ensure reads the map
    if (sr.node.listenAddresses().some((a) => a.includes("/p2p-circuit"))) return; // already reserved
    this.#ctx.logger.info("session.standing_receiver.reservation.rebuild", {
      agentName,
      relayPeerIds: endpoints.map((e) => e.relayPeerId),
    });
    void this.#ctx.receivers.rebuildStandingReceiver(agentName);
  }

  /**
   * Is this agent currently skipping this relay? The observable half of the failover decision — a
   * test that asserts only on the classifier's boolean proves nothing about what the daemon does.
   */
  isRelayQuarantined(agentName: string, relayPeerId: string): boolean {
    return this.#relayQuarantineFor(agentName).has(relayPeerId);
  }

  /** Live quarantine entries for an agent, expired ones swept on read. */
  #relayQuarantineFor(agentName: string): Set<string> {
    const byRelay = this.#ctx.relayQuarantine.get(agentName);
    if (!byRelay) return new Set();
    const now = Date.now();
    for (const [relayPeerId, expiresAt] of byRelay) {
      if (now >= expiresAt) byRelay.delete(relayPeerId);
    }
    if (byRelay.size === 0) this.#ctx.relayQuarantine.delete(agentName);
    return new Set(byRelay.keys());
  }

  /**
   * Skip this relay for this agent for a while. Called only for refusals the classifier marks
   * `tryAnotherRelay` — a fault of the relay's, not one that would follow us to the next one.
   */
  #quarantineRelay(agentName: string, relayPeerId: string, reason: string): void {
    let byRelay = this.#ctx.relayQuarantine.get(agentName);
    if (!byRelay) { byRelay = new Map(); this.#ctx.relayQuarantine.set(agentName, byRelay); }
    byRelay.set(relayPeerId, Date.now() + RELAY_QUARANTINE_MS);
    this.#ctx.logger.warn("session.standing_receiver.relay_quarantined", {
      agentName,
      relayPeerId,
      reason,
      forMs: RELAY_QUARANTINE_MS,
      impact: "this relay refused this agent for a fault of its own, so the agent will ask a " +
        "different relay for its reservation until the quarantine lapses. Its inbound reachability " +
        "is restored by moving, not by waiting for someone to fix that relay.",
    });
  }

  reservationCircuitAddrs(agentName: string): { addrs: string[]; relayPeerIds: string[] } {
    let persisted: Array<{ relayPeerId: string; relayAddrs: string[] }>;
    try {
      persisted = this.#ctx.queries.getAgentRelayEndpoints(agentName);
    } catch (err: unknown) {
      // No DB / unknown agent — persisted source unavailable. The directory
      // source may still serve; reachability degrades only if both are empty.
      // Logged (not swallowed): a genuine DB failure must be distinguishable
      // from "fresh agent, no history" in the reachability trail.
      this.#ctx.logger.debug("session.standing_receiver.persisted_relays.unavailable", {
        agentName,
        error: extractErrorMessage(err),
      });
      persisted = [];
    }
    const merged = new Map<string, { relayPeerId: string; relayAddrs: string[] }>();
    for (const ep of [...(this.#ctx.directoryRelayEndpoints.get(agentName) ?? []), ...persisted]) {
      if (!merged.has(ep.relayPeerId)) merged.set(ep.relayPeerId, ep);
    }
    /**
     * DOD-M15-RELAYSLOTS-1 — **THE FAILOVER.** Skip relays that refused this agent for a fault of
     * their own (today: a relay holding no directory public key, which can verify nobody and is
     * refusing everyone). We run several relays precisely so one being broken is survivable.
     *
     * ⚠️ NEVER TO THE POINT OF HAVING NO RELAY AT ALL. If the quarantine would empty the candidate
     * list it is ignored wholesale: a relay that refuses is strictly better than no relay, because
     * the refusal at least has a cause the operator can read, while an agent with no candidates is
     * simply unreachable with nothing to show for it. This is the same "refusing too eagerly is the
     * failure mode" rule, applied to the client's own choice of where to ask.
     */
    const quarantined = this.#relayQuarantineFor(agentName);
    const eligible = [...merged.values()].filter((ep) => !quarantined.has(ep.relayPeerId));
    const usable = eligible.length > 0 ? eligible : [...merged.values()];
    if (eligible.length === 0 && quarantined.size > 0 && merged.size > 0) {
      this.#ctx.logger.warn("session.standing_receiver.relay_quarantine.ignored", {
        agentName,
        quarantined: [...quarantined],
        impact: "every known relay has refused this agent for a relay-side fault, so the quarantine " +
          "is being ignored and they are all being tried again. A relay that refuses with a cause " +
          "is better than no relay at all — but if this persists, every relay this agent knows " +
          "about is misconfigured, and that is the thing to look at.",
      });
    }
    const addrs: string[] = [];
    const relayPeerIds: string[] = [];
    for (const ep of usable) {
      const base = ep.relayAddrs[0];
      if (!base) continue;
      const candidate = base.includes("/p2p/")
        ? `${base}/p2p-circuit`
        : `${base}/p2p/${ep.relayPeerId}/p2p-circuit`;
      // These addresses are built from DIRECTORY-supplied endpoints — data from off
      // this machine. A malformed one throws inside libp2p node construction, which
      // would take the standing receiver down entirely and leave the agent deaf to
      // ALL inbound (worse than the defect this fixes). A bad endpoint must cost one
      // relay, never the receiver.
      if (!isValidMultiaddr(candidate)) {
        this.#ctx.logger.warn("session.standing_receiver.relay_endpoint.invalid", {
          agentName,
          relayPeerId: ep.relayPeerId,
          addr: candidate,
        });
        continue;
      }
      addrs.push(candidate);
      relayPeerIds.push(ep.relayPeerId);
    }
    return { addrs, relayPeerIds };
  }

  /**
   * DOD-NAT-REACHABILITY-1: notice when a standing receiver has SILENTLY LOST its
   * reservation, and get it another one.
   *
   * libp2p refreshes a circuit reservation before it expires. If the relay has died,
   * that refresh fails and the /p2p-circuit address simply DISAPPEARS from the node's
   * addresses. Nothing throws. The receiver is still up, still directly dialable, and
   * still looks perfectly healthy — but no NAT'd peer can reach the agent any more.
   * That is precisely the silent-loss-of-inbound failure this whole story exists to
   * kill, so it cannot be left to chance: we watch for it and re-pick a relay.
   *
   * Only receivers that HAD a reservation are watched. One that never got one is
   * already degraded and already loud (reservation.none / reservation.timeout);
   * rebuilding it on a timer would just thrash against relays we know are refusing.
   */
  /**
   * DOD-M12B-RESERVATION-RETRY-1 — ask again for a reservation the relay refused.
   *
   * The rebuild is the re-attempt: a circuit listener is fixed at node creation, so the only way to
   * obtain a reservation is to build a new node asking for one.
   */
  #retryReservationIfDue(agentName: string): void {
    const now = Date.now();
    const state = this.#ctx.srReservationRetry.get(agentName)
      ?? { attempts: 0, nextAt: now + this.#ctx.srReservationRetryMs, correlationId: randomUUID() };
    // The reason the LAST attempt was refused, captured where it is actually known.
    const lastReason = this.#ctx.srLastRejectionReason.get(agentName);
    if (lastReason !== undefined) state.lastReason = lastReason;
    if (state.attempts === 0 && !this.#ctx.srReservationRetry.has(agentName)) {
      // First sighting — schedule, do not fire. The creation attempt just happened.
      this.#ctx.srReservationRetry.set(agentName, state);
      return;
    }
    if (now < state.nextAt) return;

    if (state.attempts >= SR_RESERVATION_MAX_RETRIES) {
      if (state.attempts === SR_RESERVATION_MAX_RETRIES) {
        state.attempts += 1; // mark as reported, so this fires exactly once
        this.#ctx.srReservationRetry.set(agentName, state);
        this.#ctx.logger.error("session.standing_receiver.reservation.gave_up", {
          agentName,
          attempts: SR_RESERVATION_MAX_RETRIES,
          correlationId: state.correlationId,
          // WHY, not just the consequence. Three different problems reach this one message and they
          // need three different responses: `relay_granted_no_reservation` is relay CAPACITY (and a
          // trustless-cello problem), `relay_unreachable` is the NETWORK, and
          // `reservation_did_not_complete_in_time` is LATENCY — and the only one of the three that
          // can pin a slot it never uses, so its appearance is also the signal that this retry
          // budget needs tightening.
          ...(state.lastReason !== undefined ? { lastRejectionReason: state.lastReason } : {}),
          // "No relay would grant" and "there was no relay to ask" are different facts and lead to
          // different places — the first at relay capacity, the second at this agent's directory
          // connection. Without this they are the same sentence.
          //
          // 032-RELAYSPREAD: this was also called `reservationsRequested` — the same mis-naming as
          // the reachability events, in its worst form, because here the value is a BOOLEAN under a
          // name that reads as a count. It is NOT `relaysOffered`: that field counts the merged
          // candidate list the walk actually asks (directory pool + persisted endpoints, minus
          // quarantine), and this reads the directory pool alone. Two populations must not share
          // one field name, so this one is named for what it measures.
          hadRelayToAsk: (this.#ctx.directoryRelayEndpoints.get(agentName)?.length ?? 0) > 0,
          // …and HOW MANY the walk actually asks, so this event stands on its own instead of
          // needing the last reachability line to be read beside it. Same population and same
          // meaning as `relaysOffered` everywhere else: the merged, quarantine-filtered candidate
          // list.
          relaysOffered: this.reservationCircuitAddrs(agentName).addrs.length,
          impact:
            "no relay would grant this agent a circuit reservation, so anyone behind NAT cannot reach or dial it — inbound sessions will only arrive from peers that can connect directly, and everything else falls back to the relay's store-and-forward",
        });
      }
      return;
    }

    state.attempts += 1;
    // The FINAL attempt gets a fixed settle window rather than another doubled wait: at the top of
    // the ladder that would be 80 minutes of silence after the last thing we did, which is a long
    // time to tell an operator nothing. Every earlier attempt doubles, which is what keeps a fleet
    // off a scarce relay.
    state.nextAt = now + (state.attempts >= SR_RESERVATION_MAX_RETRIES
      ? this.#ctx.srReservationRetryMs
      : this.#ctx.srReservationRetryMs * 2 ** (state.attempts - 1));
    this.#ctx.srReservationRetry.set(agentName, state);
    this.#ctx.logger.warn("session.standing_receiver.reservation.retry", {
      agentName,
      attempt: state.attempts,
      maxAttempts: SR_RESERVATION_MAX_RETRIES,
      correlationId: state.correlationId,
      ...(state.lastReason !== undefined ? { lastRejectionReason: state.lastReason } : {}),
      impact: "this agent currently holds no circuit reservation, so a NAT'd peer cannot dial it",
    });
    void this.#ctx.receivers.rebuildStandingReceiver(agentName);
  }

  #reservationWatchdogTick(): void {
    if (this.#ctx.shuttingDown) return;
    for (const [agentName, sr] of this.#ctx.standingReceivers) {
      if (!this.#ctx.agentsWantingReceiver.has(agentName)) continue;        // agent went offline

      // DOD-M12B-RESERVATION-RETRY-1 — NEVER HAD ONE IS NOT "NOTHING TO DO".
      //
      // This used to `continue` unconditionally, on the grounds that a receiver with no reservation
      // is "already degraded and already loud". Measured over 17 days: `reservation.none` fired 481
      // times and `relay.rejected` 2,215 — every one of the latter `relay_granted_no_reservation`,
      // a relay out of slots completing the handshake and granting nothing. Nothing ever acted on
      // the noise, and each of those receivers is a plain TCP node with no circuit address: behind
      // NAT, dialable by NOBODY, for its whole life. That is the silent loss of inbound this file
      // says three lines below it exists to kill.
      //
      // A relay out of slots at boot may have one minutes later, so re-attempt — on a BACKOFF and
      // BOUNDED, never on this 30-second grid. A reservation is scarce: the relay holds it for its
      // full TTL even after the client disconnects, and churning attempts across a fleet is how a
      // relay is exhausted (`#startReceiverNode` records that hazard).
      if (sr.relayPeerIds.length === 0) {
        // …unless one has arrived since. Review F4, same class as the recompute below: the
        // slow-start path installs a receiver before every circuit has bound, so "held nothing at
        // install" is not the same fact as "holds nothing now". Adopting it here is what stops the
        // retry ladder rebuilding a receiver that is already reachable.
        const arrived = heldRelayIdsOf(sr.node)
          .filter((id) => sr.node.getConnections().some((c) => c.peerId === id && c.status === "open"));
        if (arrived.length === 0) {
          this.#retryReservationIfDue(agentName);
          continue;
        }
        sr.relayPeerIds = arrived;
        sr.gater.setReservedRelayPeers(arrived);
        this.#ctx.logger.info("session.standing_receiver.reservation.gained", {
          agentName,
          relayPeerIds: arrived,
          reservationsHeld: arrived.length,
        });
      }
      // It has at least one — any earlier retry budget, and the reason the last attempt failed, are
      // stale.
      this.#ctx.srReservationRetry.delete(agentName);
      this.#ctx.srLastRejectionReason.delete(agentName);

      // Watch the CONNECTION to the relay, not the circuit address.
      //
      // Killing the relay does NOT make the /p2p-circuit address disappear: libp2p
      // keeps the listen address until the reservation's own refresh, up to two hours
      // away. Watching the address would therefore miss a dead relay for hours — the
      // agent would advertise a circuit address that routes through a relay that no
      // longer exists, which is exactly the silent unreachability we are hunting. The
      // live connection to the relay is the honest signal: no connection, no relay,
      // no reservation.
      //
      // AND IT MUST BE OPEN. `getConnections()` returns libp2p's registry, which keeps a connection
      // listed while it is closing and after its muxer has died — the state the whole M12 Tier P5
      // investigation turned on. Without the status check a registered corpse reads as "still
      // connected", the rebuild never fires, and the agent silently stops being reachable while
      // this loop reports it healthy. The comment above claimed liveness; only this tests it.
      // 032-RELAYSPREAD — PER RELAY, and the health question is now a COUNT.
      //
      // This used to evaluate one peer id and rebuild the entire standing receiver when it went
      // false. With a pool of one that was the only thing it could do; with a pool of three it is
      // the churn engine — every relay is another watchdog subject, and a full rebuild per loss
      // multiplies the 30-second grid by the size of the pool while throwing away reservations that
      // are perfectly healthy.
      /**
       * RECOMPUTED FROM THE NODE, never filtered down from the stored list. Review F4: filtering
       * `sr.relayPeerIds` makes it SHRINK-ONLY, and a list that can only shrink cannot see a
       * circuit arrive. Three things went wrong with that, and the first one happens routinely:
       *   - the slow-start path installs the receiver before every circuit has bound, so a relay
       *     that binds four seconds later was invisible to this watchdog and absent from the
       *     gater's carve-out set FOREVER — its AutoNAT probe reply refused by our own gate;
       *   - shrinking to zero then rebuilt a receiver that was announcing live circuits, which is
       *     the exact defect this unit is against;
       *   - anything that ever restores a circuit could not be counted.
       * Reading the node's own addresses costs the same and has none of that.
       */
      const open = sr.node.getConnections().filter((c) => c.status === "open").map((c) => c.peerId);
      const stillHeld = heldRelayIdsOf(sr.node).filter((id) => open.includes(id));
      const lost = sr.relayPeerIds.filter((id) => !stillHeld.includes(id));
      const gained = stillHeld.filter((id) => !sr.relayPeerIds.includes(id));
      sr.relayPeerIds = stillHeld;
      if (gained.length > 0) {
        // A circuit this receiver did not have at install. Said out loud because it is the visible
        // half of the slow-start case, and because it is the moment that relay earns its inbound
        // carve-out — a silent widening of the gate is not something to do without a line.
        this.#ctx.logger.info("session.standing_receiver.reservation.gained", {
          agentName,
          relayPeerIds: gained,
          reservationsHeld: stillHeld.length,
        });
      }
      if (lost.length === 0) {
        // Nothing lost. The gater still gets the current set, because `gained` may have widened it.
        if (gained.length > 0) sr.gater.setReservedRelayPeers(stillHeld);
        continue;
      }
      // REVOKE FIRST. A relay whose reservation is gone must lose its inbound carve-out in the same
      // breath as the loss is noticed, or the gater's bound quietly becomes "granted one once".
      sr.gater.setReservedRelayPeers(stillHeld);
      for (const relayPeerId of lost) {
        // DOD-RELAY-KEEPALIVE-1 (review F4): carry the CAUSE, not just the exit point.
        // `relay_connection_gone` says where this was noticed — a poll of getConnections() — by
        // which time the abort reason that actually killed the link is long discarded. The relay
        // client for this (agent, relay) pair kept the error that ended its reader; that is the
        // nearest thing to an upstream cause available here, and its absence is how 2,061 of these
        // went untraced.
        const upstreamReason = this.#ctx.relayClients.get(`${agentName}::${relayPeerId}`)?.getLastReaderError();
        this.#ctx.logger.warn("session.standing_receiver.reservation.lost", {
          agentName,
          relayPeerId,
          reason: open.includes(relayPeerId) ? "circuit_address_vanished" : "relay_connection_gone",
          ...(upstreamReason ? { upstreamReason } : {}),
          reservationsHeld: stillHeld.length,
          // The line an operator reads, and the two cases are not the same event at all.
          impact: stillHeld.length > 0
            ? "this agent still holds " + stillHeld.length + " other circuit reservation(s), so it "
              + "stays dialable from behind NAT and the receiver is NOT rebuilt. Losing one relay "
              + "costs this agent nothing it can feel."
            : "this agent now holds NO circuit reservation, so nobody behind a home router can "
              + "reach it. The receiver is being rebuilt against the rest of the pool.",
        });
      }
      if (stillHeld.length === 0) {
        // ZERO HELD IS STILL THE LOUD, STRUCTURAL CASE — the agent is unreachable behind NAT and
        // only a new node can take a new reservation, because a circuit listener is fixed at node
        // creation.
        void this.#ctx.receivers.rebuildStandingReceiver(agentName);
        continue;
      }
      /**
       * STILL REACHABLE, SO THE RECEIVER STANDS, AND NOTHING ELSE HAPPENS HERE. That second half is
       * the part worth reading, because the obvious next line is wrong twice over.
       *
       * **A LOST CONFIGURED CIRCUIT CANNOT BE RETAKEN BY THIS NODE.** Read out of
       * `@libp2p/circuit-relay-v2@4.2.5`, not assumed: for an explicit relay address
       * `transport/listener.js#listen()` is a ONE-SHOT — it reserves once and nothing calls it
       * again; `reservation-store.js#removeReservation()` clears the refresh timeout and deletes
       * the entry; and the listener's `_onAddRelayPeer` returns early for `type === 'configured'`,
       * so even a later reservation would not be announced. A circuit listener is fixed at node
       * creation, and the only thing that takes a new one is a NEW NODE — which is exactly the
       * rebuild this branch exists to refuse.
       *
       * **AND RE-PROVING TO THE LOST RELAY WOULD REBUILD THE RECEIVER ANYWAY.** Review F3: an
       * earlier version called `authenticateStandingReceiver` here to "remove the relay-side
       * reason for the revocation". That function ends with `if (refusal?.tryAnotherRelay) { …
       * void this.#ctx.receivers.rebuildStandingReceiver(agentName); }` — and a dead or misconfigured relay is
       * precisely the one that answers that way. So the common case was: lose relay A while
       * holding B, decline to rebuild, prove to A, A refuses, rebuild the whole receiver and throw
       * B's healthy reservation away. The churn engine, re-entered through the back door.
       *
       * **THE BOUND, STATED PLAINLY BECAUSE IT IS A REAL SHORTFALL AGAINST THE DoD:** a lost
       * circuit is gone until the receiver is next rebuilt for another reason. What the agent buys
       * is that it never STOPS BEING REACHABLE while that is true — the surviving relays carry it,
       * the loss is named in the log with its cause, and the lost relay's inbound carve-out is
       * revoked above. That is availability, not restoration in place.
       *
       * WHICH LEAVES A RATCHET, and `#respreadIfDecayed` below is what stops it: relays are only
       * ever lost between rebuilds, never regained, so an agent nobody talks to walks itself back
       * down to one relay — the exact state this unit exists to get it out of.
       */
    }
    for (const agentName of this.#ctx.standingReceivers.keys()) {
      if (this.#ctx.agentsWantingReceiver.has(agentName)) this.#respreadIfDecayed(agentName);
    }
  }

  /**
   * 032-RELAYSPREAD — **AN IDLE AGENT MUST NOT RATCHET ITSELF BACK DOWN TO ONE RELAY.**
   *
   * Spreading happens when a receiver is BUILT, and between builds the count only falls: a lost
   * circuit cannot be retaken by a running node (a circuit listener is fixed at node creation), and
   * a relay the directory announces later is skipped while any circuit is held. An agent in
   * conversation re-spreads constantly — the receiver is handed into each session and a fresh one
   * is built behind it — so this is about the agent nobody has talked to for a day. It loses relays
   * one at a time, nothing pulls it back up, and it ends up exactly where this unit found it:
   * reachable through one relay, one relay away from being reachable through none.
   *
   * **THE COST OF FIXING IT IS A NEW PEER ID**, which is why it is fenced three ways rather than
   * simply rebuilding on sight:
   *   - **ONLY WHEN IDLE.** A rebuild replaces the receiver's transport identity, and a counterparty
   *     may be holding the old one from a `session_offer_accept`. With a live session for this agent
   *     we leave it alone — a degraded spread costs redundancy, a changed peer id mid-conversation
   *     costs the conversation.
   *   - **ONLY WHEN THERE IS SOMETHING TO GAIN.** Holding every relay that was offered is not decay.
   *   - **ON ITS OWN SLOW CLOCK**, never the watchdog's 30-second grid. A reservation is scarce —
   *     the relay holds it for its full TTL even after we disconnect — so this reuses the
   *     reservation retry interval rather than inventing a faster one.
   */
  #respreadIfDecayed(agentName: string): void {
    if (this.#ctx.shuttingDown) return;
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr || sr.relayPeerIds.length === 0) return;                    // zero held is the loud path
    for (const entry of this.#ctx.activeNodes.values()) {
      if (entry.agentName === agentName) return;                        // in conversation — hands off
    }
    const offered = this.reservationCircuitAddrs(agentName).addrs.length;
    if (sr.relayPeerIds.length >= offered) return;                      // nothing to gain
    const now = Date.now();
    const last = this.#ctx.srLastRespreadAt.get(agentName) ?? 0;
    if (now - last < this.#ctx.srReservationRetryMs) return;
    this.#ctx.srLastRespreadAt.set(agentName, now);
    this.#ctx.logger.info("session.standing_receiver.respread", {
      agentName,
      reservationsHeld: sr.relayPeerIds.length,
      relaysOffered: offered,
      impact: "this agent is idle and holds fewer relay reservations than it was offered, so its " +
        "receiver is being rebuilt to take the rest. Without this it can only lose relays between " +
        "rebuilds, and an agent nobody talks to drifts back down to a single relay — one relay " +
        "away from being unreachable behind NAT, which is the state this whole mechanism exists " +
        "to keep it out of.",
    });
    void this.#ctx.receivers.rebuildStandingReceiver(agentName);
  }

  /** Start the reservation watchdog (idempotent). Stopped by gracefulShutdown. */
  startReservationWatchdog(): void {
    if (this.#ctx.reservationWatchdog !== null) return;
    // Arm the backstop clock from the START of watching, not from the epoch — otherwise the first
    // tick always fires a sweep on top of the install drain that just ran.
    this.#ctx.park.armBackstopClock(Date.now());
    this.#ctx.reservationWatchdog = setInterval(() => {
      try {
        this.#reservationWatchdogTick();
        this.#ctx.park.parkedDrainBackstopTick(Date.now());
      } catch (err: unknown) {
        this.#ctx.logger.warn("session.standing_receiver.watchdog.failed", { error: extractErrorMessage(err) });
      }
    }, this.#ctx.srWatchdogIntervalMs);
    // Never hold the process open on account of the watchdog.
    this.#ctx.reservationWatchdog.unref?.();
  }

  /**
   * Start the standing receiver's libp2p node, holding a circuit-relay reservation
   * if one can be had — and WITHOUT one if it cannot.
   *
   * THE INVARIANT, learned live: **standing-receiver creation must NEVER be gated on
   * a relay.** libp2p's circuit listener awaits a live connection to its relay before
   * start() resolves, and it does not time out. A relay that does not answer parks
   * start() forever: no created event, no failure, no retry, no alarm — the agent
   * simply has no receiver and is deaf to ALL inbound, including the direct path that
   * worked before reservations existed. Strictly worse than the NAT defect this whole
   * line exists to fix. So every attempt is raced against a deadline, and failure
   * ALWAYS falls through to a plain TCP receiver.
   *
   * ONE relay, tried on the REAL node — not a probe.
   *
   * A relay reservation is a scarce resource: the relay holds it for its full TTL
   * even after the client disconnects, and it has a finite number of slots. An
   * earlier design probed each relay on a throwaway node and then reserved AGAIN on
   * the receiver — burning TWO slots per agent to get one, and leaving the throwaway's
   * slot pinned for hours. That is how a fleet exhausts a relay. Here the receiver
   * itself makes the attempt: if the relay grants the reservation, we KEEP that node.
   * One slot per agent, which is the true cost.
   *
   * Candidates are tried in order (directory pool first). The first that actually
   * grants a reservation wins; the rest are never touched.
   */
  /**
   * DOD-M15-RELAYSLOTS-1 — tell the relay this transport identity belongs to a registered agent, so
   * the reservation it just refused is granted on the next attempt.
   *
   * Returns `"proven"` on success, or the shape of the failure so the candidate loop can act on it.
   * It never throws: throwing would turn one unreachable relay into a failure to build a receiver
   * at all.
   *
   * ─── Why this returns a verdict instead of a boolean ──────────────────────────────────────────
   *
   * Review HIGH-1/HIGH-2. Putting the reservation behind a proof MOVED THE FIRST REFUSAL onto this
   * path. `authenticateStandingReceiver` does everything right with a refusal — records it where
   * `cello_status` can read it, and quarantines a relay whose fault is its own — but it runs only
   * on a receiver that ALREADY HAS a reservation, so under the new gate a total failure never
   * reaches it. This method was logging `proven: false` and returning.
   *
   * What that cost the operator: an expired token, or an agent at its slot cap, refused by every
   * relay in the pool. `cello_status` shows an agent that is online and reachable by nobody, with
   * no cause anywhere the person will look — while the relay had computed the cause, the count, and
   * the next step, and put them on the wire. And `slot_cap_exceeded` is classified
   * `tryAnotherRelay: false` precisely so the client STOPS walking the fleet; without the verdict,
   * the loop walked it anyway, turning one client-side fault into what reads as a fleet outage.
   */
  async proveToRelay(
    agentName: string,
    circuitAddr: string,
    node: CelloNode,
    correlationId: string,
    /**
     * Whether this proof is the STANDING RECEIVER's, and may therefore write the surface
     * `cello_status` reads as "your standing receiver was refused".
     *
     * A revival proves itself too, and its refusal is real — but it is not evidence about the
     * receiver. A receiver that proved thirty seconds ago and holds a slot, plus a revival refused
     * with `slot_cap_exceeded`, would otherwise have `cello_status` report a front door as refused
     * while it is open. The refusal is still logged and still steers the candidate loop; what it
     * does not do is claim to be about something it did not measure.
     */
    surfaceAsReceiverRefusal: boolean,
  ): Promise<"proven" | "refused_try_another_relay" | "refused_this_agent" | "unavailable"> {
    const relayPeerId = relayPeerIdOf(circuitAddr);
    const baseRelayAddr = circuitAddr.split("/p2p-circuit")[0];
    if (!relayPeerId || !baseRelayAddr) {
      this.#ctx.logger.warn("session.standing_receiver.prove.address_unreadable", {
        agentName,
        circuitAddr,
        correlationId,
        impact: "this candidate's circuit address does not name a relay peer, so there is nothing " +
          "to prove to and its reservation will stay refused. Skipped silently before — which made " +
          "a malformed address look identical to a relay that simply said no.",
      });
      return "unavailable";
    }
    /**
     * Declared out here so the `finally` can close it. Scoped inside the `try` before, so a throw
     * from `proveReservation` skipped the close and left the stream and its pending settles behind.
     */
    let client: AgentRelayClient | undefined;
    try {
      client = this.#ctx.detachedRelayClientBuilder?.(agentName, relayPeerId, [baseRelayAddr], {
        receiptStore: this.#ctx.relayReceiptStore ?? undefined,
        sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
        onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
      });
      if (!client) {
        this.#ctx.logger.warn("session.standing_receiver.prove.no_builder", {
          agentName,
          relayPeerId,
          correlationId,
          impact: "no relay client could be built, so this receiver cannot prove itself and the " +
            "relay will refuse its reservation again. The agent is reachable only over a direct " +
            "connection until this is wired.",
        });
        return "unavailable";
      }
      const proven = await client.proveReservation(node);
      if (proven) {
        if (surfaceAsReceiverRefusal) this.#ctx.srRelayRefusal.delete(agentName);
        this.#ctx.logger.info("session.standing_receiver.prove.result", {
          agentName, relayPeerId, peerId: node.getPeerId(), proven: true, correlationId,
        });
        return "proven";
      }

      /**
       * The same two lines `authenticateStandingReceiver` runs, for the same reason. The `else`
       * matters as much as the `if`: `proveReservation` also fails for transport reasons, which
       * leave `getLastAuthRefusal()` null, and leaving a PREVIOUS refusal in the map would have
       * `cello_status` explaining a cause that is no longer what is wrong.
       */
      const refusal = client.getLastAuthRefusal();
      if (surfaceAsReceiverRefusal) {
        if (refusal) {
          this.#ctx.srRelayRefusal.set(agentName, { ...this.#ctx.withDirectoryCause(agentName, refusal), relayPeerId });
        } else {
          this.#ctx.srRelayRefusal.delete(agentName);
        }
      }
      this.#ctx.logger.warn("session.standing_receiver.prove.result", {
        agentName,
        relayPeerId,
        peerId: node.getPeerId(),
        proven: false,
        refusalReason: refusal?.reason ?? "no_relay_verdict",
        tryAnotherRelay: refusal?.tryAnotherRelay ?? true,
        correlationId,
        impact: refusal?.advice ??
          "the relay would not accept this agent's proof and said nothing about why, which is what " +
          "a transport failure mid-handshake looks like. The candidate loop moves on to the next relay.",
      });
      if (refusal && !refusal.tryAnotherRelay) return "refused_this_agent";
      if (refusal?.tryAnotherRelay && !this.#ctx.shuttingDown) {
        this.#quarantineRelay(agentName, relayPeerId, refusal.reason);
      }
      return "refused_try_another_relay";
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.standing_receiver.prove.failed", {
        agentName,
        correlationId,
        error: extractErrorMessage(err),
        impact: "this receiver could not prove itself, so its retry will be refused and the " +
          "candidate loop will try the next relay.",
      });
      return "unavailable";
    } finally {
      client?.close();
    }
  }

  /**
   * DOD-M12B-REVIVE-RELAY-1 — reconnect the session's relay WITNESS, which revival never did.
   *
   * THE FIRST-PRINCIPLES DEFECT, and the one that explains every symptom chased separately before
   * it. Establishment does five things: build the node, register the content handler, wire liveness,
   * **connect the relay**, and dial the counterparty. Revival did the first three. A revived session
   * was therefore not a session — it looked live, reported `active`, and had no live inbound path at
   * all.
   *
   * MEASURED 2026-08-18 with two real agents: a message on a reconnected session took **three
   * minutes**, against seconds on a fresh one, because only the five-minute mailbox backstop ever
   * found it. Doorbells stopped firing for the same reason — the relay stream is what rings them.
   * And `#parkContent` refuses without `entry.relayClient`, so sends could not park either.
   *
   * NO ASSIGNMENT IS PRESENTED, and that is by design rather than omission: `RelayConnectParams`
   * documents the reconnect mode itself — *"absent … on the restart/persisted reconnect path (the
   * relay already recorded the session at first establishment) — the client then just reconnects
   * without re-recording."* A revival is exactly that path.
   *
   * Best-effort and non-fatal: a session that comes back without its witness is still better than
   * one that does not come back, and the failure is named rather than silent.
   */
  async reconnectRevivedSessionRelay(
    agentName: string,
    sessionId: string,
    node: CelloNode,
    gater: SessionConnectionGater,
    correlationId: string,
    ep: { relayPeerId: string; relayAddrs: string[] } | null,
  ): Promise<void> {
    if (!ep) {
      this.#ctx.logger.warn("session.revive.relay.absent", {
        agentName,
        sessionId,
        impact: "no relay is recorded for this session, so it comes back with no live inbound path — "
          + "messages arrive only on the periodic mailbox poll, and a failed send cannot park and is "
          + "reported lost",
      });
      return;
    }
    try {
      // The gater admits only the counterparty inbound; the relay is a third peer and must be
      // permitted OUTBOUND or our own gate refuses the dial (INV-5 keeps inbound counterparty-only).
      gater.setAllowedOutboundPeer(ep.relayPeerId);

      const clientKey = `${agentName}::${ep.relayPeerId}`;
      let client = this.#ctx.relayClients.get(clientKey);
      if (!client) {
        if (!this.#ctx.relayReceiptStore && this.#db) this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
        if (!this.#ctx.sealLeafStore && this.#db) this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
        client = this.#ctx.detachedRelayClientBuilder?.(agentName, ep.relayPeerId, [...ep.relayAddrs], {
          receiptStore: this.#ctx.relayReceiptStore ?? undefined,
          sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
          // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
          onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
        });
        if (!client) {
          this.#ctx.logger.warn("session.revive.relay.builder_absent", {
            agentName,
            sessionId,
            impact: "no relay client could be built, so this revived session has no live inbound path",
          });
          return;
        }
        this.#ctx.relayClients.set(clientKey, client);
      }

      // 033-ACKEMIT: a revived session re-registers with no assignment in hand, so the genesis comes
      // from the entry that was just restored above.
      client.registerSession(sessionId, node, this.#ctx.contentIn.relayLeafHandler(agentName, sessionId, correlationId), undefined, this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId));

      const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
      if (entry) {
        entry.relayClient = client;
        entry.relaySessionIdBytes = Uint8Array.from(Buffer.from(sessionId, "hex"));
        entry.relayClientKey = clientKey;
      }

      /**
       * THE STEP THIS METHOD IS NAMED AFTER, and the first version did not take it (review HIGH-2).
       *
       * `registerSession` files a handler in a Map. It opens nothing — no dial, no auth, no reader
       * loop. `connectSessionRelay` ends with exactly this line and the reconnect ended without it,
       * so a revived session registered a handler on a client whose stream was `null` and then
       * logged that its live inbound path was back. It was not: the counterparty's leaves queued at
       * the relay, no doorbell fired, and delivery fell back to the five-minute mailbox poll — the
       * three-minutes-versus-seconds symptom the whole unit exists to remove.
       *
       * Worse, the client is usually BRAND NEW here: `markInterruptedWithDetails` closes and drops
       * the client for the last session on a relay, so a single-session agent always lands in the
       * build branch above with a fresh, unconnected client.
       *
       * `#ensureConnected` is idempotent, so this also repairs the cached-but-dead-stream case.
       */
      await client.connect(node);

      this.#ctx.logger.info("session.revive.relay.connected", {
        agentName,
        sessionId,
        relayPeerId: ep.relayPeerId,
        impact: "the revived session has its live inbound path back — messages arrive promptly "
          + "instead of waiting for the periodic mailbox poll",
      });
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.revive.relay.failed", {
        agentName,
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact: "the session is back but without its witness — delivery falls back to the periodic poll",
      });
    }
  }

  /** DOD-M12B-REVIVE-PARK-1 test seam: the relay the live entry will park to. Not otherwise
   *  observable — `#activeNodes` is private and the park's own refusal is silent about which of its
   *  four preconditions was missing. */
  getSessionRelayForTest(agentName: string, sessionId: string): { relayPeerId?: string; relayAddrs?: string[] } | null {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) return null;
    return {
      ...(entry.relayPeerId !== undefined ? { relayPeerId: entry.relayPeerId } : {}),
      ...(entry.relayAddrs !== undefined ? { relayAddrs: entry.relayAddrs } : {}),
    };
  }
}
