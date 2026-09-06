/**
 * CELLO Daemon — CLOSING A CONVERSATION, AND PROVING IT CLOSED
 *
 * Split out of `session-node-manager.ts`. The seal is the artefact the whole product exists to
 * produce: when both parties close, each holds a notarized root over the same transcript, and
 * either can later show a third party that the conversation happened and was not altered.
 *
 * What is here: deciding whether a session is ready to seal and telling the operator when it is
 * not, submitting our own SEAL leaf, carrying the counterparty's, persisting the commitment when a
 * close is interrupted, recording the certificate, verifying a certified root against our own tree,
 * and the auto-acknowledgement gate that lets a seal complete without a human on both ends.
 *
 * **Moved verbatim, comments included.**
 *
 * ⚠️ **THE TWO STORES BELOW ARE OPENED LAZILY, and that is why they are read-write on the context
 * rather than passed in.** Both are created on first use, because they need the database and the
 * database is opened long after the manager is constructed. The manager and this file must see the
 * SAME instance — a second `SessionSealLeafStore` over the same rows is two writers that agree only
 * by luck.
 */
import { createHash } from "node:crypto";
import { buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { encodeSealPayload, decodeStructure1 } from "@cello-protocol/protocol-types";
import { AUTOACK_BROKER_GRACE_MS, carryContentHashInputs } from "./session-node-types.js";
import type { SealUpgradeReadiness } from "./seal-upgrade.js";
import type { Logger, SealReadinessView } from "./types.js";
import type { SessionTree } from "./session-tree.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { CelloNode } from "@cello-protocol/transport";
import { LEAF_KIND_CTRL, type AgentRelayClient } from "./session-relay-client.js";
import { RelayReceiptStore } from "./relay-receipt-store.js";
import { SessionSealLeafStore, type SealCarryLeaf } from "./session-seal-leaf-store.js";
import type { SessionOwnChainStore } from "./session-own-chain-store.js";
import type { SessionRecords } from "./session-records.js";
import type { SessionQueries } from "./session-queries.js";
import type { ParkRecovery } from "./park-recovery.js";
import type { HeldContent, HeldEntry } from "./held-content.js";
import type { SessionLeafRecords } from "./session-leaf-records.js";
import type { StandingReceivers } from "./standing-receivers.js";
import type { ActiveSessionEntry } from "./session-node-types.js";

/** What the seal path needs from the manager. */
export interface SessionSealContext {
  readonly logger: Logger;

  readonly records: SessionRecords;
  readonly queries: SessionQueries;
  readonly park: ParkRecovery;
  readonly held: HeldContent;
  readonly leafRecords: SessionLeafRecords;
  readonly receivers: StandingReceivers;

  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;

  // ── Shared in-memory session state: ONE Map object each, never a copy ───────────────────────
  readonly activeNodes: Map<string, ActiveSessionEntry>;
  readonly heldContent: Map<string, Map<number, HeldEntry>>;
  readonly witnessedSeq: Map<string, Map<string, number>>;
  readonly highWaterSeq: Map<string, number>;
  readonly orderingObserved: Set<string>;
  readonly contentDesynced: Map<string, "tampered" | "unverifiable">;
  readonly responderSealSubmitted: Map<string, { reportedRootHex: string; sequenceNumber: number } | null>;
  readonly relayClients: Map<string, AgentRelayClient>;

  /**
   * ⚠️ READ-WRITE, both of them, and deliberately so — see the file header. They are `null` until
   * something needs them, and whichever side reaches for one first is the side that opens it. A
   * read-only view here would have meant this file opening its own second instance over the same
   * rows the manager writes.
   */
  relayReceiptStore: RelayReceiptStore | null;
  sealLeafStore: SessionSealLeafStore | null;

  /**
   * Assigned by `setEnsureSealBroker`, which lives here; the manager only forwards to it.
   *
   * ⚠️ `undefined`, not `null` — matching the manager's field exactly rather than tidying it. The
   * broker returns a HANDLE with a `stop`, not a boolean: it is the thing keeping a seal ceremony
   * alive, and a caller has to be able to end it. Simplifying that to a success flag here would
   * have compiled against a wrapper and lost the only way to cancel.
   */
  ensureSealBroker:
    | ((agentName: string, sessionId: string) => Promise<{ stop: (reason: string) => Promise<void> } | null>)
    | undefined;

  /**
   * ⚠️ FOUR PARAMETERS. The last two — the state name and the counterparty key — are what the
   * notification carries to the operator's channel; a two-parameter version would have type-checked
   * at the call site and delivered a state change with no state in it.
   */
  readonly onSessionStateChanged:
    | ((agentName: string, sessionId: string, state: string, counterpartyPubkey: string | null) => void)
    | null;
  readonly ownChainStore: SessionOwnChainStore | null;
  /**
   * ⚠️ THE `stores` ARGUMENT IS NOT OPTIONAL DECORATION. A client built without it has no receipt
   * store and no seal-leaf store, so `#captureReceipt` silently returns false: the submit reports
   * ok while the relay's signed receipt — the evidence the seal rests on — is never written.
   */
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
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  getSessionTreeRootHex(agentName: string, sessionId: string): string;
  getDirectoryOnlineToken(agentName: string): Uint8Array | undefined;
  destroySessionSeed(agentName: string, sessionId: string): void;
  updateSessionStatus(
    agentName: string,
    sessionId: string,
    status: "active" | "sealed" | "interrupted" | "abandoned",
    interruptedBy?: "local",
  ): boolean;
}

export class SessionSeal {
  readonly #ctx: SessionSealContext;

  constructor(ctx: SessionSealContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * M12-P15: what a seal leaf actually needs, resolved from a LIVE node when there is one and from
   * durable state when there is not.
   *
   * `submitSealLeaf` used to hard-require an `#activeNodes` entry. But it is reachable — by design —
   * for an `interrupted` session, and EVERY producer of that status deletes the entry. So the guard
   * refused 100% of the calls the seal-interrupted path could ever make, which is what made M12-P15's
   * first fix inert. `submitLeaf(node, sessionId, contentHash, leafKind)` takes everything
   * explicitly; nothing about it needs a per-session node.
   *
   * The fallback is the same shape `startupParkFn` already uses for content: the persisted relay
   * endpoint (`relay_peer_id`/`relay_addrs`, columns that exist for exactly this reason) plus the
   * owning agent's standing receiver. Every failure is named for its own cause rather than collapsed
   * into "no node", because that collapse is what sent this investigation at the session lifecycle
   * instead of at the endpoint.
   */
  #resolveSealTransport(agentName: string, sessionId: string):
    | { node: CelloNode; relayClient: AgentRelayClient; relaySessionIdBytes: Uint8Array; releaseOnDone?: true }
    | { error: string } {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (entry) {
      // The live path is unchanged and takes precedence — a session with its own registered client
      // must never seal through a rebuilt one.
      if (!entry.relayClient || !entry.relaySessionIdBytes) return { error: "relay_unavailable" };
      return { node: entry.node, relayClient: entry.relayClient, relaySessionIdBytes: entry.relaySessionIdBytes };
    }
    const ep = this.#ctx.queries.getPersistedRelayEndpoint(agentName, sessionId);
    if (!ep) return { error: "no_persisted_relay_endpoint" };
    const node = this.#ctx.receivers.getStandingReceiverNode(agentName);
    if (!node) return { error: "standing_receiver_unavailable" };
    // Reuse the agent's existing client for this relay when the process still has one; otherwise ask
    // the composition root to build one. Without the builder this path would work only within the
    // lifetime that created the session — and the case that matters most is precisely a daemon that
    // RESTARTED, which is what marked the session interrupted in the first place.
    const clientKey = `${agentName}::${ep.relayPeerId}`;
    let client = this.#ctx.relayClients.get(clientKey);
    if (!client) {
      // Review HIGH-1: the stores are NOT optional here. Without them `#captureReceipt` silently
      // `return false`s — the submit still reports ok while the relay's signed receipt and our OWN
      // 0x02 ctrl leaf are never persisted. That drops the unilateral-escalation carry chain AND
      // defeats this very unit's ceremony discriminator, which reads `session_seal_leaves`: a seal
      // sent through here would later read as "ceremony unknown" and the peer would decline to
      // sign. The fix would have broken the fix.
      if (!this.#ctx.relayReceiptStore && this.#db) this.#ctx.relayReceiptStore = new RelayReceiptStore(this.#db, this.#ctx.logger);
      if (!this.#ctx.sealLeafStore && this.#db) this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
      client = this.#ctx.detachedRelayClientBuilder?.(agentName, ep.relayPeerId, [...ep.relayAddrs], {
        receiptStore: this.#ctx.relayReceiptStore ?? undefined,
        sealLeafStore: this.#ctx.sealLeafStore ?? undefined,
        ownChainStore: this.#ctx.ownChainStore ?? undefined,
        // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
        onlineToken: () => this.#ctx.getDirectoryOnlineToken(agentName),
      });
      if (!client) return { error: "relay_client_unavailable" };
      // Review MEDIUM-4: cache it, so a retry loop does not leak one authenticated relay stream per
      // attempt. Safe ONLY because the client above now carries the stores — a store-less client
      // cached under this key would be picked up by the live `#connectSessionRelay` path and poison
      // it for the rest of the process.
      this.#ctx.relayClients.set(clientKey, client);
    }
    // Review HIGH-2: register the session (no assignment — there is nothing to re-present) so the
    // relay's `session_not_found` is interpreted honestly. Unregistered, `recordedBefore` is false,
    // the retry loop runs pointlessly, and the `recordedBefore && session_not_found ->
    // relay_session_gone` branch — which exists to tell "the relay never had it" apart from "the
    // relay swept or sealed it" — can never fire, so the operator is handed a first-message-race
    // label for a swept session.
    /**
     * DOD-M15-RELAYLEAK-1 — **RE-REGISTERING A SESSION THAT IS ALREADY REGISTERED BLINDS IT.**
     *
     * `registerSession` REPLACES the entry's `onLeafDeliver` with `onLeafDeliver ?? (() => {})`, and
     * unlike `assignment` / `recorded` it does NOT carry the existing handler forward. **This path
     * passes no handler.** So a detached seal on a session that still holds a live registration
     * would swap that session's inbound leaf delivery for a no-op: the counterparty's leaves keep
     * arriving at the relay client and are dropped on the floor, while the operator sees a healthy
     * session that has simply gone quiet.
     *
     * A call that finds the session already registered is therefore a PASSENGER: it uses the client
     * and touches nothing. It also does not release — ownership is never inferred, only claimed.
     *
     * ⚠️ **This is NOT justified by a concurrency race, and an earlier version of this comment said
     * it was.** Review checked: `#resolveSealTransport` and everything above the first `await` are
     * synchronous, and a second caller plants/hits `#responderSealSubmitted` and returns
     * `responder_seal_already_submitted` before ever reaching `submitLeaf`. Two callers cannot be in
     * the client at once through the only caller, so "the second one closes the client the first is
     * awaiting" **cannot happen**. The wrong reason mattered: it invites a future reader to delete
     * this guard as defensive clutter once they notice the race is impossible — taking the
     * handler-clobbering protection with it.
     */
    const claimedRegistration = !client.hasSession(sessionId);
    if (claimedRegistration) {
      // 033-ACKEMIT: the seal transport submits a ctrl leaf like any other, so it needs the same
      // acknowledgement seed. It carries no assignment of its own, so the genesis is supplied here
      // from the session's own active entry rather than derived inside the client.
      client.registerSession(sessionId, node, undefined, undefined, this.#ctx.leafRecords.sessionGenesisPrevRoot(agentName, sessionId));
    } else {
      /**
       * Review MEDIUM-1 — **A PATH THAT DECLINES TO FIX A LEAK MUST SAY SO.**
       *
       * Reaching here means the session is registered on this client while `#activeNodes` holds no
       * entry for it — and the ways that happens are all orphans: a previous `releaseDetached()`
       * that threw (loud once, then silent forever after), or a revival that registered and then
       * failed to hang the client on an entry. Declining to unregister is right — we cannot prove
       * no live session owns it — but without this line the orphan is invisible, which is the exact
       * shape this whole line exists to remove.
       */
      this.#ctx.logger.info("session.seal.transport.registration_shared", {
        agentName,
        sessionId,
        impact:
          "this seal is using a relay registration it did not create, so it will not release it. If " +
          "no live session owns that registration the client is held until process exit.",
      });
    }
    /**
     * DOD-M15-RELAYLEAK-1 — **`releaseOnDone` IS THE RELEASE SIGNAL, and its absence was the leak.**
     *
     * This branch (no `#activeNodes` entry) CACHES a relay client and registers a session on it, and
     * nothing ever unregistered. `#detachSessionRelay` closes a client only when
     * `!client.hasSessions()`, so a registration that is never removed keeps that predicate false
     * **forever** — the client, its authenticated stream and its reader survive for the process
     * lifetime. The LIVE branch above registers nothing here, so only this one needs releasing, and
     * marking it is what lets the caller tell them apart without guessing.
     */
    return {
      node,
      relayClient: client,
      relaySessionIdBytes: new Uint8Array(Buffer.from(sessionId, "hex")),
      // Not `true` unconditionally: a passenger call must not release a registration it did not
      // claim — see the note above `claimedRegistration`.
      ...(claimedRegistration ? { releaseOnDone: true as const } : {}),
    };
  }

  /**
   * REBUILD THE CERTIFIED ROOT FROM THIS DAEMON'S OWN LEAVES — `DOD-M15-SEALWIRE-1` bullet 2.
   *
   * The receipt used to prove only that the directory signed SOMETHING: the client took the sealed
   * root off the wire, confirmed the directory's signature over those bytes, stored it, and threw
   * away the root it had computed a step earlier. At co-signing time that means **your key signs a
   * root you never checked.**
   *
   * Bullet 1 moved the certified root into the content-hash domain, which is the domain this daemon
   * can actually rebuild — each carry leaf's `content_hash` is the leaf hash (RFC 6962 §2.1 "hash"
   * leaves are used as-is), and the carry is ordered by the relay's canonical `sequence_number`,
   * which is the order the directory rebuilds in.
   *
   * ─── Why this returns "cannot judge" instead of always answering ───────────────────────────
   *
   * A root comparison that is WRONG makes every session unsealable, and force-abandon — no receipt —
   * becomes the only exit. That failure is worse than the one being guarded, and this file already
   * carries two comments saying so about other gates.
   *
   * The carry is this daemon's view, and it is not guaranteed complete at the instant a certificate
   * arrives: the counterparty's SEAL ctrl leaf is what TRIGGERS the seal, so it may not have been
   * witnessed here yet. So completeness is checked FIRST, against the certificate's own leaf count.
   * A short carry means this daemon cannot judge — which is a different answer from "the roots
   * disagree", and conflating them would turn a local timing gap into an accusation.
   */
  verifyCertifiedRoot(
    agentPubkeyHex: string,
    sessionIdHex: string,
    certifiedRoot: Uint8Array,
    certifiedLeafCount: number,
  ): { verdict: "match" } | { verdict: "mismatch"; ownRootHex: string | null; detail: string } | { verdict: "cannot_judge"; reason: string } {
    const carry = this.getSealCarry(agentPubkeyHex, sessionIdHex);
    if (carry.length === 0) return { verdict: "cannot_judge", reason: "no_carry" };

    /**
     * COMPLETENESS IS ESTABLISHED FROM THE CARRY'S OWN EVIDENCE, NEVER FROM THE CERTIFICATE.
     *
     * Review F3, and the first cut had this exactly backwards. It gated on
     * `carry.length !== certifiedLeafCount`, where `certifiedLeafCount` is a field the DIRECTORY
     * chooses and signs — so the party being checked controlled whether it was checked. A directory
     * certifying a root over a different conversation had only to state a `leaf_count` that did not
     * match, and the client answered "cannot judge" and accepted. The signature still verified,
     * because the count is signed inside the same TBS.
     *
     * That is the hole §2b names in as many words: *"an attacker who wants to evade a mismatch check
     * simply never supplies a checkable proof. Treating 'we could not tell' as harmless is the
     * hole."* I defended against a false POSITIVE and left the false NEGATIVE one field away.
     *
     * The carry can answer the question by itself. A complete bilateral leaf set is:
     *   - sequences contiguous from 1 — no gap where a leaf this daemon never saw would sit; and
     *   - exactly two SEAL ctrl leaves, from two DISTINCT senders — which is what a bilateral seal
     *     is, and is the condition that says the counterparty's closing leaf has landed here.
     * Both predicates already exist in `seal-escalation.ts`; this reuses their shape rather than
     * inventing a second opinion about the same question.
     *
     * When the carry IS self-evidently complete, a `leaf_count` that disagrees is no longer "I
     * cannot tell" — it is the certificate describing a different leaf set, which is a MISMATCH.
     */
    const sequences = carry.map((l) => l.sequenceNumber).sort((a, b) => a - b);
    const contiguousFromOne = sequences.every((n, i) => n === i + 1);
    const ctrlSenders = new Set(
      carry.filter((l) => l.leafKind === LEAF_KIND_CTRL).map((l) => l.senderPubkeyHex),
    );
    const selfEvidentlyComplete = contiguousFromOne && ctrlSenders.size === 2;

    /**
     * 🚨 THE CERTIFICATE MAY COVER EXACTLY WHAT THIS SIDE HOLDS — ASK THAT FIRST.
     *
     * `DOD-M15-UNILATERAL-1`. The completeness predicate below describes a BILATERAL leaf set: two
     * SEAL ctrl leaves, from two distinct senders. **A solo seal can never satisfy it**, because the
     * counterparty is gone and never posts one — that is the entire premise. So on the solo path
     * this returned `cannot_judge` every time, `session-ceremony.ts` refuses to co-sign on anything
     * that is not `match`, and **the sealing party refused to co-sign its own unilateral seal.** The
     * FROST ceremony never reached threshold, the directory never completed, and the close came back
     * `seal_unilateral_timeout` — the label that names our own wait. Measured against the real
     * binaries: `j-unilateral` failed on exactly this, with the directory having already verified the
     * chain and recorded the counterparty ABSENT.
     *
     * Completeness was only ever needed to tell TWO KINDS OF DISAGREEMENT apart — "the roots differ
     * because my carry is behind" (cannot judge) from "the roots differ because the directory
     * certified something else" (mismatch). It answers nothing when the roots AGREE: a certificate
     * whose root and leaf count are exactly what this daemon holds is, by construction, over this
     * daemon's own leaves. Nothing is taken on trust — both values are recomputed here from the
     * carry, and an adversary who could satisfy them would have to have produced this leaf set.
     *
     * Deliberately BOTH values. A count that disagreed while the root matched would be a certificate
     * contradicting itself, and this is not the place to wave that through.
     */
    const carryInputs = carryContentHashInputs(carry);
    if (
      carryInputs !== null &&
      carry.length === certifiedLeafCount &&
      Buffer.compare(Buffer.from(merkleRoot(buildMerkleTree(carryInputs))), Buffer.from(certifiedRoot)) === 0
    ) {
      return { verdict: "match" };
    }

    if (!selfEvidentlyComplete) {
      return {
        verdict: "cannot_judge",
        reason: contiguousFromOne
          ? `carry_incomplete: ${ctrlSenders.size} of 2 SEAL ctrl leaves witnessed here`
          : `carry_noncontiguous: hold ${carry.length} leaves with a gap in the relay sequence`,
      };
    }
    if (carry.length !== certifiedLeafCount) {
      // The carry proves itself complete and the certificate claims a different size, so the
      // certificate is over a different leaf set. Accusing is correct here.
      return {
        verdict: "mismatch",
        ownRootHex: null, // no root computed — the sets differ in SIZE, which is decisive on its own
        detail: `leaf_count_disagrees: this daemon holds a provably complete ${carry.length}-leaf set, the certificate claims ${certifiedLeafCount}`,
      };
    }
    if (carryInputs === null) {
      // A leaf this daemon cannot decode is a leaf it cannot judge. Never an accusation.
      return { verdict: "cannot_judge", reason: "structure1_content_hash_unreadable" };
    }
    const ownRoot = merkleRoot(buildMerkleTree(carryInputs));
    const ownRootHex = Buffer.from(ownRoot).toString("hex");
    return Buffer.compare(Buffer.from(ownRoot), Buffer.from(certifiedRoot)) === 0
      ? { verdict: "match" }
      : { verdict: "mismatch", ownRootHex, detail: "root_disagrees: same leaf count, different leaves or different order" };
  }

  /**
   * FED-OPTIONB-SEAL-001: the complete ordered leaf chain (both parties) a UNILATERAL seal carries to the
   * directory for the OFFLINE tree rebuild. Empty when no leaves were logged (e.g. a direct-only session
   * with no relay witness) — the caller then has nothing to carry and the seal stays bilateral/pending.
   *
   * ⚠️ Stranded on `verifyCertifiedRoot` before this split — the third block found doing that, and the
   * reason the rule is now written down: a method reduced to a delegator leaves its documentation
   * behind, and the block below it ends up carrying two descriptions of which the first is a stranger.
   */
  getSealCarry(agentPubkeyHex: string, sessionIdHex: string): SealCarryLeaf[] {
    if (!this.#ctx.sealLeafStore && this.#db) {
      this.#ctx.sealLeafStore = new SessionSealLeafStore(this.#db, this.#ctx.logger);
    }
    return this.#ctx.sealLeafStore?.getCarry(agentPubkeyHex, sessionIdHex) ?? [];
  }

  /** Fix #1 EXTENSION: inject the broker-connection opener. Setter injection, same construction-order reason. */
  setEnsureSealBroker(
    cb: (agentName: string, sessionId: string) => Promise<{ stop: (reason: string) => Promise<void> } | null>,
  ): void {
    this.#ctx.ensureSealBroker = cb;
  }

  /**
   * DOD-M12B-INTERRUPTED-ESCALATE-1 — flip a session to `sealed`, synchronously, without needing a
   * live node.
   *
   * **`destroySessionNode(…, "sealed")` cannot be relied on to do this.** It returns early at
   * `if (!entry) return`, and the status write lives 26 lines BELOW that guard — so it flips the
   * status only for a session that still has an `#activeNodes` entry. An interrupted session has
   * none by construction: every producer of that status deletes the entry. Before this method, a
   * unilateral seal on an interrupted session stored the notarized root and the certificate and
   * left the row saying `interrupted` — the receipt landed and nothing that represents it moved.
   * `cello_sessions` still showed it stuck, `cello_close_session` still refused it by name, and the
   * restart-seal resolver re-selected it on the next boot to run the whole ceremony again against a
   * session that already held a receipt.
   *
   * STATUS FIRST AND SYNCHRONOUS, teardown second — the order `abandonSession` uses and the one
   * `retireSession` documents. The flip is the load-bearing half; the teardown makes memory agree
   * with it. `#updateSessionStatus` also runs the terminal disposition hooks (held content is
   * annexed, not stranded), which the early return skipped entirely.
   */
  markSealed(agentName: string, sessionId: string): boolean {
    // The terminal guard (abandoned/sealed must not be overwritten) lives in #updateSessionStatus,
    // so it holds for destroySessionNode and retireSession too — not only for callers of this
    // wrapper.
    return this.#ctx.updateSessionStatus(agentName, sessionId, "sealed");
  }

  /**
   * M8B FINDING-6 (cascade-2): persist a seal certificate for a session that may have NO local
   * `sessions` row. recordSealCertificate (a manager delegator onto `session-queries.ts`) is an `UPDATE ... WHERE` — a SILENT no-op when the
   * row is absent (the exact trap the cascade-2 reviewer flagged). The ABSENT party (B), learning of
   * a seal on reconnect via seal_unilateral_notification, may never have persisted a row for this
   * session. This ensures a minimal stub row first (INSERT OR IGNORE — a no-op if a row already
   * exists, e.g. an 'interrupted' row after a restart) so B's receipt is actually durable + retrievable
   * via cello_get_sealed_receipt. The counterparty pubkey is required by the schema (NOT NULL); B
   * derives it from the notification's present_pubkey.
   */
  recordSealCertificateEnsuringRow(
    agentName: string,
    sessionId: string,
    counterpartyPubkeyHex: string,
    sealedRootHex: string,
    legibilityJson: string,
  ): void {
    if (!this.#db) return;
    const now = Date.now();
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO sessions
           (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(sessionId, this.#ctx.requireAgentId(agentName), counterpartyPubkeyHex, "sealed", now, now);
    this.#ctx.queries.recordSealCertificate(agentName, sessionId, sealedRootHex, legibilityJson);
  }

  /**
   * M7-SESSION-001 (H-1): persist a verified bilateral SEAL-INTERRUPTED
   * commitment and transition the session to 'seal_interrupted_pending'.
   *
   * This is NOT a seal. It records that both parties produced and exchanged
   * K_local-signed SEAL-INTERRUPTED leaves over the same {leafCount, merkleRoot}.
   * The FROST threshold notarization is a separate, currently-unwired step (see
   * daemon.ts handleSealInterruptedFlow H-1 note), which is precisely why the
   * status is 'seal_interrupted_pending' and never 'sealed'.
   *
   * The status update is guarded so it only advances a session out of the
   * 'interrupted' state — it will not overwrite a 'sealed' row.
   *
   * @returns true if the session row was advanced to seal_interrupted_pending.
   */
  persistSealInterruptedCommitment(opts: {
    agentName: string;
    sessionId: string;
    role: "initiator" | "responder";
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  }): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          `INSERT OR REPLACE INTO seal_interrupted_artifacts
           (agent_id, session_id, role, own_leaf, counterparty_leaf, merkle_root, nonce, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          this.#ctx.requireAgentId(opts.agentName),
          opts.sessionId,
          opts.role,
          JSON.stringify(opts.ownLeaf),
          JSON.stringify(opts.counterpartyLeaf),
          opts.merkleRoot,
          opts.nonce,
          now,
        );
    } catch (err: unknown) {
      this.#ctx.logger.error("session.interrupted.db.write.failed", {
        sessionId: opts.sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }

    // DAEMON-004: the bilateral commitment advances a session out of either
    // 'interrupted' (SESSION-001 interrupted-seal flow) OR 'active' (DAEMON-004
    // active-session seal). The guard still refuses to overwrite a terminal
    // 'sealed' row or an already-pending one.
    const result = this.#db
      .prepare(
        "UPDATE sessions SET status = 'seal_interrupted_pending', updated_at = ? WHERE agent_id = ? AND session_id = ? AND status IN ('active', 'interrupted')",
      )
      .run(now, this.#ctx.requireAgentId(opts.agentName), opts.sessionId);
    const landed = Number(result.changes) > 0;
    if (landed) {
      // DOD-M12B-SESSION-SEED-1 (review F3): `seal_interrupted_pending` is NOT a state revival
      // exists for, and the first build's comment wrongly grouped it with `interrupted`.
      // `ingestReceivedContent` (in `session-content-ingest.ts`) refuses it outright, and BOTH
      // sweeps that could otherwise close a
      // session — `listRestartOrphanedSessions` and `listExpiredUnrevivableSessions` — filter
      // `status = 'interrupted'`, so a pending-seal session is unrevivable AND unswept. Keeping its
      // identity meant holding it until the process exited. Entry 42's own measurement is that 59%
      // of seals that start never finish, so that is the common path, not a corner.
      this.#ctx.destroySessionSeed(opts.agentName, opts.sessionId);
    }
    return landed;
  }

  /**
   * M7 DOD-SPINE-7: submit THIS party's SEAL ctrl leaf (0x02) to the relay witness.
   * Structure: content_hash = SHA-256(0x02 || encodeSealPayload({session_id, final_root,
   * close_timestamp, "PENDING"})), where final_root is the daemon's OWN tree root. Two
   * distinct-sender SEAL leaves in the relay's log trigger the relay's #maybeProcessSeal
   * → directory processSeal (rebuild + verify the signed chain) → FROST notarization →
   * session_sealed. Requires an active relay client; the caller falls back to the
   * directory-mediated path when this returns relay_unavailable.
   */
  async submitSealLeaf(
    agentName: string,
    sessionId: string,
    correlationId?: string,
  ): Promise<
    | { ok: true; sequenceNumber: number; reportedRootHex: string }
    | { ok: false; reason: string; reportedRootHex?: string; sequenceNumber?: number }
  > {
    const sealKey = this.#ctx.sessionKey(agentName, sessionId);
    // M12-P15: resolved, not required. See #resolveSealTransport — an interrupted session has no
    // in-memory node BY CONSTRUCTION, and refusing here is what made the first fix inert.
    const transport = this.#resolveSealTransport(agentName, sessionId);
    if ("error" in transport) return { ok: false, reason: transport.error };
    const entry = transport;
    /**
     * DOD-M15-RELAYLEAK-1 — release a DETACHED seal transport when this submission is done.
     *
     * Only the detached branch registers a session here, so this can never remove a live one. The
     * client is closed only when it has no sessions left and the cache still holds THIS client —
     * the same two guards `#detachSessionRelay` uses, and for the same reason: a racing teardown
     * must not close a freshly-built replacement for the same key.
     */
    const releaseDetached = (): void => {
      if (transport.releaseOnDone !== true) return;
      try {
        entry.relayClient.unregisterSession(sessionId);
        if (!entry.relayClient.hasSessions()) {
          for (const [key, cached] of this.#ctx.relayClients) {
            if (cached === entry.relayClient) {
              cached.close();
              this.#ctx.relayClients.delete(key);
              break;
            }
          }
        }
      } catch (err: unknown) {
        this.#ctx.logger.warn("session.seal.transport.release_failed", {
          agentName,
          sessionId,
          reason: err instanceof Error ? err.message : String(err),
          impact: "a detached seal relay client could not be released; it is held until process exit",
        });
      }
    };
    /**
     * ⚠️ try/finally, NOT a call at each return. There are three exits today and adding a release
     * to each would be a hand-kept list — the shape this milestone has been bitten by repeatedly,
     * where the FOURTH exit added later quietly leaks. Here the release cannot be bypassed by a new
     * return, and it runs on the throw path too, which is where a leak matters most.
     */
    try {

      // M7-UPGRADE-002 idempotency: this party submits its responder SEAL leaf AT MOST ONCE per
      // session. BOTH cello_close_session and the auto-acknowledge path call here; the first to reach
      // this point wins, the second short-circuits. The check+set is SYNCHRONOUS (before any await) so
      // two near-simultaneous triggers (e.g. B's own close racing A's delivered SEAL ctrl leaf) cannot
      // both submit. Cleared below on a relay submit failure so a genuine retry can proceed.
      // DOD-M12B-INTERRUPTED-ESCALATE-1 — THE MARK MUST SURVIVE A RESTART, or one automatic retry
      // permanently forfeits the receipt.
      //
      // `#responderSealSubmitted` is in memory. A session whose close was in flight when the daemon
      // stopped already has our SEAL ctrl leaf in the relay log — and on the next boot the mark is
      // empty, so the restart-seal resolver's automatic close would submit a SECOND one. The
      // directory requires exactly one ctrl leaf (`ctrlLeaves.length !== 1 → unilateral_seal_leaf_invalid`)
      // and the carry is durable, so every future attempt would carry both and be refused forever.
      //
      // The durable evidence already exists and was simply not consulted: our own ctrl leaf is in
      // `session_seal_leaves`. Recover the escalation values from it instead of submitting again.
      if (!this.#ctx.responderSealSubmitted.has(sealKey)) {
        const durable = this.#ctx.park.recoverOwnSealCtrlLeaf(agentName, sessionId);
        if (durable === "unknown") {
          // REFUSE, do not submit. A second ctrl leaf makes the session unsealable forever, and the
          // question "is one already there?" just failed to answer. Refusing costs this close; a
          // second leaf costs the receipt permanently.
          return { ok: false, reason: "seal_leaf_recovery_unavailable" };
        }
        if (durable !== "none") {
          this.#ctx.logger.info("session.seal.leaf.already_submitted.recovered", {
            sessionId, agentName, sequenceNumber: durable.sequenceNumber,
            impact: "our SEAL ctrl leaf is already in the relay log from a previous run; submitting a second would make this session unsealable forever",
          });
          this.#ctx.responderSealSubmitted.set(sealKey, durable);
        }
      }
      if (this.#ctx.responderSealSubmitted.has(sealKey)) {
        // M8B FINDING-1: carry the FIRST submit's reported root/sequence so a retry close can
        // still escalate to a unilateral seal. A null value means that submit is still in
        // flight — return the bare reason and let the caller fall back to the pending path.
        const prior = this.#ctx.responderSealSubmitted.get(sealKey);
        return prior
          ? {
              ok: false,
              reason: "responder_seal_already_submitted",
              reportedRootHex: prior.reportedRootHex,
              sequenceNumber: prior.sequenceNumber,
            }
          : { ok: false, reason: "responder_seal_already_submitted" };
      }
      this.#ctx.responderSealSubmitted.set(sealKey, null);

      // A throw anywhere before the mark is finalized would strand the null in-flight marker
      // and lock every future close out of escalation (a FINDING-1-shaped deadlock via a
      // different trigger) — clear the mark on any unexpected exception.
      try {
        const finalRootHex = this.#ctx.getSessionTreeRootHex(agentName, sessionId);
        const sealPayload = encodeSealPayload({
          session_id: entry.relaySessionIdBytes,
          final_root: new Uint8Array(Buffer.from(finalRootHex, "hex")),
          close_timestamp: Date.now(),
          attestation: "PENDING",
        });
        // content_hash = SHA-256(0x02 || seal_payload) — the ctrl leaf kind byte is 0x02.
        const contentHash = new Uint8Array(
          createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(sealPayload).digest(),
        );
        /**
         * ⚠️ `sealPayload` IS PASSED, AND ITS ABSENCE WAS THE WHOLE DEFECT — `DOD-M15-SEALWIRE-1`
         * bullets 3+4, review pass 1, F1.
         *
         * These exact bytes were computed two lines above, hashed, and then dropped: `submitLeaf` had
         * no parameter for them. So the directory received a SHA-256 pre-image nobody transmitted, and
         * the client's SIGNED `final_root` — the one value in the seal the relay cannot produce — was
         * unrecoverable. Four legs of this line shipped and were reviewed green while the head of the
         * chain did not exist.
         *
         * The payload and the hash MUST come from the same derivation. If they ever diverge the
         * directory reports `seal_payload_unbound`, whose guidance says *"someone between them and here
         * altered or fabricated the payload — the relay is the only party on that path"* — a correct
         * relay accused by name, in an error written to sound like an attack, for a mismatch made here.
         */
        const result = await entry.relayClient.submitLeaf(entry.node, entry.relaySessionIdBytes, contentHash, LEAF_KIND_CTRL, sealPayload);
        if (!result.ok) {
          // Clear the idempotency mark so a genuine retry (agent close / reconnect) can proceed (DB-001).
          this.#ctx.responderSealSubmitted.delete(sealKey);
          this.#ctx.logger.warn("session.seal.leaf.submit.failed", { sessionId, reason: result.reason, correlationId });
          return { ok: false, reason: result.reason };
        }
        // SESSION-002: the reported_root for a unilateral seal is the content-hash root the
        // local tree WOULD have with this SEAL ctrl leaf appended — the same root the directory
        // rebuilds from the relay's content-hash chain (the relay records the identical
        // content_hash for this ctrl leaf). Computed without mutating the durable tree /
        // message_count, so the bilateral + interrupted seal paths are unaffected.
        const contentHashHex = Buffer.from(contentHash).toString("hex");
        const reportedRootHex = this.#ctx.getSessionTree(agentName, sessionId).rootWithAppendedHex(contentHashHex);
        // M8B FINDING-1: durably associate the submit's escalation values with the idempotency
        // mark, so any LATER close call can retrieve them via the already-submitted result.
        this.#ctx.responderSealSubmitted.set(sealKey, { reportedRootHex, sequenceNumber: result.sequence_number });
        this.#ctx.logger.info("session.seal.leaf.submitted", {
          sessionId,
          sequenceNumber: result.sequence_number,
          correlationId,
        });
        // M7-UPGRADE-002: #responderSealSubmitted was set synchronously at the top of this method —
        // the guard now blocks any second submit (auto-ack OR a redelivered counterparty SEAL ctrl leaf).
        return { ok: true, sequenceNumber: result.sequence_number, reportedRootHex };
      } catch (err: unknown) {
        this.#ctx.responderSealSubmitted.delete(sealKey);
        throw err;
      }
    } finally {
      releaseDetached();
    }
  }

  /**
   * CELLO-M7-UPGRADE-001 (DOD-UP-1): readiness of a session for B to RATIFY a unilateral seal
   * (the returning absent party). This is the SAME verifiability bar as the UP-2 auto-ack gate:
   *
   *  - `known`: the session exists locally with its content (B has a transcript to ratify). After a
   *    restart B reloads it from SQLite, and autoRecoverForAgent re-pulls any parked content first.
   *  - `tampered`: the content cross-check flagged a content_hash mismatch (#contentDesynced) — B
   *    must NEVER ratify content it could not integrity-verify (the KERNEL refusal, AC-003).
   *
   * The directory separately verifies B's ack signature is genuine; B separately verifies the
   * unilateral cert signature (R1 is authentic). NOTE: a full "B's frontier covers R1's tail"
   * completeness check (the `desynced` reason) requires the deferred MSG-001-3b canonical-sequence
   * reconciliation — same documented limitation as the UP-2 gate above.
   */
  getSealUpgradeReadiness(agentName: string, sessionId: string): SealUpgradeReadiness {
    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    return {
      known: !!record,
      /**
       * THE REASON TRAVELS WITH THE VERDICT — review F-A, correcting review F1's fix.
       *
       * F1 made the gate binary and moved the label into the log, and I did that in ONE consumer.
       * This struct feeds a second one (`evaluateSealUpgrade`), which had only a boolean to read and
       * therefore called every cause `content_tamper` — at ERROR, with no guidance. An honest peer on
       * a newer build raised a security alarm on B's reconnect: exactly the harm the F1 fix was
       * written to remove, reached through the consumer it did not check.
       *
       * Returning the LABEL rather than a boolean is what makes that impossible to reintroduce: a
       * caller cannot flatten what it never receives flat.
       */
      unverifiable: this.#ctx.contentDesynced.get(this.#ctx.sessionKey(agentName, sessionId)) ?? null,
    };
  }

  /**
   * M7-UPGRADE-002: auto-acknowledge close (POSTMORTEM Workstream E / C-5). When B's daemon
   * ingests the COUNTERPARTY's SEAL control leaf and B has verified the content, B's OWN node
   * auto-co-signs + submits its responder SEAL leaf WITHOUT waiting for B's agent to call
   * cello_close_session — so a bilateral seal completes promptly instead of degrading to
   * unilateral on a slow/busy/crashed agent.
   *
   * SI-001 (non-negotiable): B's signature is ALWAYS produced by B's own node — submitSealLeaf
   * signs the responder SEAL leaf with B's K_local. We remove the agent PROMPT, never the SIGNER;
   * nothing here lets the directory or the peer synthesize B's acknowledgement.
   *
   * SI-002 (verifiability gate): auto-ack ONLY content B has verified. A session whose content
   * cross-check failed (content_hash_mismatch = tamper, recorded in #contentDesynced) is NEVER
   * auto-signed — it surfaces to the agent as a genuine decision point. DISAGREEMENT with the
   * content is NOT a gate failure (C-6): the gate is "can I verify integrity?", never "do I agree?"
   * — a verified-but-disliked tail is auto-sealed and the transcript speaks for B.
   *
   * Idempotent + non-throwing: marks #responderSealSubmitted BEFORE the async submit so a
   * redelivered ctrl leaf cannot double-submit; clears the mark on submit failure so a later
   * agent close / reconnect can still complete the seal (DB-001 — never a silent half-seal).
   */
  maybeAutoAcknowledgeSeal(agentName: string, sessionId: string, correlationId: string): void {
    const ackKey = this.#ctx.sessionKey(agentName, sessionId);
    // Idempotency: at most one responder seal per session (auto-ack or agent close).
    if (this.#ctx.responderSealSubmitted.has(ackKey)) return;
    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    // Only an ACTIVE session auto-acks. A committed/sealing/sealed/interrupted session is out of
    // scope (already sealing, or needs the interrupted/upgrade path), not an auto-ack candidate.
    if (!record || record.status !== "active") return;
    /**
     * SI-002 verifiability gate: never auto-sign a session whose content we could not verify.
     *
     * ⚠️ THIS COMMENT SAID THE OPPOSITE UNTIL `DOD-M15-SEALWIRE-1` part B1 (review F-C). It read
     * *"Today the ONLY tracked unverifiable cause is a content_hash mismatch = TAMPER"*, which was
     * true when a mismatch was the only way to fail the cross-check and is false now: B1 added an
     * unreadable algorithm name and a salted frame with no salt, and **both are ordinary**.
     *
     * Genuine tamper is a SECURITY event — ERROR, reason `content_tamper`, which is what the AC-008
     * alarm keys on. The other two must NOT wear that name, or the alarm fires on an honest peer
     * running a newer build and the operator learns to dismiss it.
     *
     * 🚨 AND `content_unverifiable` IS RESERVED — DO NOT REUSE IT HERE. It is specced for *parked
     * content unrecoverable*, one of the two reasons (with `desynced`, B's tree behind the canonical
     * sealed tail) awaiting the deferred MSG-001-3b canonical-sequence reconciliation. B1's first
     * attempt emitted exactly that string for a different condition, which would have made the two
     * indistinguishable in the log the day the follow-on landed. Hence
     * `content_verification_unavailable`, deliberately distinct.
     */
    const unverifiable = this.#ctx.contentDesynced.get(ackKey);
    if (unverifiable) {
      /**
       * DOD-M15-SEALWIRE-1 part B1 (review F1) — THE GATE FIRES FOR BOTH, THE ALARM ONLY FOR ONE.
       *
       * `content_tamper` is what the AC-008 alarm keys on, and it must keep meaning what it says. A
       * frame we could not verify because the peer named an algorithm this build cannot read is an
       * ordinary version difference; raising a tamper alarm for it would train an operator to
       * dismiss the alarm, which costs more than the skew.
       *
       * But the REFUSAL TO AUTO-SIGN is identical in both cases and non-negotiable: SI-002 is "never
       * auto-sign a session whose content we could not verify", and "could not" covers both.
       */
      this.#ctx.logger.error("session.seal.autoack.skipped", {
        sessionId,
        reason: unverifiable === "tampered" ? "content_tamper" : "content_verification_unavailable",
        correlationId,
      });
      // AC-002: the verifiability gate refused — surface counterparty_closing to B's agent as a
      // GENUINE decision point (the seal will not auto-complete; B must decide). Uses the existing
      // session-state push to the live MCP clients; best-effort (never throws out of this gate).
      try {
        this.#ctx.onSessionStateChanged?.(record.agent_name, sessionId, "counterparty_closing", record.counterparty_pubkey);
      } catch (err: unknown) {
        this.#ctx.logger.debug("session.state.notify.failed", {
          sessionId,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      return;
    }
    const entry = this.#ctx.activeNodes.get(ackKey);
    const responderPubkey = entry?.relayClient?.senderPubkeyHex ?? "unknown";
    // submitSealLeaf owns the #responderSealSubmitted idempotency mark (set synchronously at its
    // top), so the auto-ack does not pre-mark — it just reacts to the result.
    // Establish the broker visiting connection BEFORE submitting, not after. The directory acts on
    // the leaf in ~60ms and pushes `seal_verified` straight back; if the stream is not up by then it
    // defers the frame and the seal stalls. Proven on GCP: leaf submitted 18:41:56.555, directory
    // deferred at 18:41:56.615 (initiator_stream_absent), the explicit-close path opened the
    // connection at 18:42:01.529 — five seconds too late.
    void (async () => {
      let sealBrokerConn: { stop: (reason: string) => Promise<void> } | null = null;
      try {
        sealBrokerConn = (await this.#ctx.ensureSealBroker?.(agentName, sessionId)) ?? null;
      } catch (err: unknown) {
        // Best-effort: a same-node session needs no visiting connection, and a failure here must not
        // suppress the seal leaf — losing the leaf is strictly worse than racing the push.
        this.#ctx.logger.warn("session.seal.autoack.broker.failed", {
          sessionId,
          correlationId,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      const submitted = await this.submitSealLeaf(agentName, sessionId, correlationId);
      // RELEASE AFTER A GRACE WINDOW, not when the submit resolves.
      //
      // `submitSealLeaf` settles at the relay ack plus a local root computation — milliseconds — while
      // the frame this connection exists to catch arrives ~60ms LATER (the timeline in the comment
      // above is the measurement). Releasing on submit therefore closed the stream before the push it
      // was opened for, which is the stall it was written to prevent.
      //
      // It is worse than a lost race. The directory drains its DURABLE notification queue on ANY
      // stream that authenticates — visiting included — and DELETES each row once sent. So a visiting
      // stream that authenticates and dies milliseconds later invites the directory to send-and-delete
      // queued seal frames into a closing stream: the receipt is gone from the queue and never
      // arrived. That is permanent loss, not a retry.
      //
      // The close path holds its connection around the entire bilateral wait; this path has no waiter
      // to hang off, so it uses a bounded grace instead — generous against a ~60ms push, and bounded
      // so a stalled seal cannot leak the connection. Unref'd: it must never hold the process open.
      if (sealBrokerConn) {
        const conn = sealBrokerConn;
        const t = setTimeout(() => { void conn.stop("autoack-seal-grace-elapsed").catch(() => {}); }, AUTOACK_BROKER_GRACE_MS);
        t.unref?.();
      }
      return submitted;
    })()
      .then((result) => {
        if (result.ok) {
          // SI-001: the responder SEAL leaf was signed by B's OWN node (K_local) in submitSealLeaf.
          this.#ctx.logger.info("session.seal.autoacknowledged", {
            sessionId,
            responderPubkey,
            correlationId,
          });
        } else if (result.reason === "responder_seal_already_submitted") {
          // B's agent close already submitted the responder seal (it won the race) — nothing to do.
          return;
        } else {
          // Submission failed (e.g. relay path down) — the agent close / reconnect can still
          // complete the seal; never a silent half-seal (DB-001).
          this.#ctx.logger.warn("session.seal.autoack.skipped", {
            sessionId,
            reason: result.reason,
            correlationId,
          });
        }
      })
      .catch((err: unknown) => {
        this.#ctx.logger.warn("session.seal.autoack.skipped", {
          sessionId,
          reason: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      });
  }

  /**
   * M12-P14: is this side's chain COMPLETE enough to be sealed?
   *
   * A seal is a bilateral signature over the same conversation, so a side that is missing a leaf
   * cannot produce a signable one — the counterparty compares frontiers and refuses with
   * `leaf_count_mismatch`. That refusal is correct and it is also terminal: there is no backfill
   * request in the protocol, so the only exit is a force-abandon, which yields NO notarized receipt.
   * Measured 2026-08-05 on two sessions that died exactly this way (initiator 2 leaves, responder 3).
   *
   * The cheap prevention is to notice BEFORE asking. Two local signals already exist and, until now,
   * nothing read either of them at close time:
   *  - `#highWaterSeq` — the largest canonical sequence the RELAY has witnessed for this session.
   *    The relay is the ordering authority, so a high-water above our own frontier is proof that a
   *    leaf exists which we have not appended. (Its own doc comment called it "reserved … NOT yet
   *    consumed by the gate" — this is that consumer.)
   *  - `#heldContent` — content we HAVE received and verified but cannot append because it sits
   *    behind a gap. Holding content and sealing anyway would seal a chain we know is short.
   *
   * Deliberately NOT a network call: it must work when the counterparty is unreachable, which is
   * the whole situation a seal-interrupted exists for.
   *
   * KNOWN LIMIT, stated rather than hidden: both maps are in-memory and cleared on teardown, so
   * after a daemon restart this returns ready for a session whose gap predates the restart — which
   * is the shape of the 2026-08-05 incident itself. Closing that needs the mailbox drained (or the
   * high-water persisted) before the check; tracked with M12-P14, not claimed here.
   */
  sealReadiness(agentName: string, sessionId: string): {
    ready: boolean; treeSize: number; highWaterSeq: number; heldCount: number; missingLeaves: number;
    /** DOD-M12B-INDEX-1: of `heldCount`, how many are THIS side's own sends versus the
     *  counterparty's. They block a seal identically and mean completely different things. */
    heldOwn: number; heldReceived: number;
    /**
     * DOD-M15-DIVERGE-1 — this tree and the relay's counter have PROVABLY parted.
     *
     * The other two counters both measure the same direction: positions the relay committed that
     * this tree has not appended. This is the OPPOSITE direction — this tree holds a leaf at a
     * position the relay assigned to something else — and it is the direction an injected or forged
     * leaf appears in. Without it `ready` was asymmetric, and a diverged session read as perfectly
     * sealable right up until the counterparty answered `leaf_count_mismatch`, which is terminal.
     */
    diverged: boolean;
  } {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    // DOD-M12B-STRAND-1: hydrate first. An under-counted `heldCount` reports a gapped session as
    // READY, and this gate's whole purpose is to stop a short chain being signed — the counterparty
    // answers `leaf_count_mismatch`, which is TERMINAL and costs the receipt permanently. Failing
    // open here is the one outcome worse than refusing a healthy close.
    //
    // Hydrate WITHOUT releasing: this is a read path now — the status surface asks it for every
    // active session — and a read that appends leaves, advances the root and rings the doorbell is
    // a diagnostic command that delivers messages. The release still runs on every path that was
    // going to mutate anyway.
    this.#ctx.held.ensureHeldRestored(agentName, sessionId, { release: false });
    const treeSize = this.#ctx.getSessionTree(agentName, sessionId).size();
    const highWaterSeq = this.#ctx.highWaterSeq.get(key) ?? -1;
    const heldCount = this.#ctx.heldContent.get(key)?.size ?? 0;
    // Review HIGH-2: NOT `(highWaterSeq + 1) - treeSize`. That subtraction silently assumes the
    // relay's sequence space and this tree's index space count the same things, and they do not:
    // `relay-node.ts` increments seq_counter for EVERY accepted leaf including CTRL (0x02), while
    // NOTHING APPENDS A CTRL LEAF TO THIS TREE — `submitSealLeaf` deliberately computes its root
    // without mutating the durable tree. So one seal ctrl leaf offsets the two spaces permanently,
    // and any msg witnessed afterwards would read as a missing leaf FOREVER. That is a false
    // positive, and a false positive here is worse than the bug it guards: it makes a healthy
    // session unsealable, leaving force-abandon (no receipt) as the only exit. `seal-upgrade.ts`
    //
    // ⚠️ THIS SENTENCE USED TO READ *"`appendSessionLeaf` is only ever called with 'msg'"*, AND THAT
    // WAS FALSE WHEN IT WAS WRITTEN — corrected, not deleted, per review pass 1 F8. Line ~7730
    // appends "doc", and `WritableSessionTreeLeafKind` permits "ctrl" outright, so the type does not
    // enforce it either. Doc leaves are harmless to this subtraction because they are witnessed by
    // the relay too (LEAF_KIND_DOC) and counted in BOTH spaces; the load-bearing property is only
    // ever about CTRL. Stating it as "msg only" made a narrower claim than the code supports and a
    // stronger one than it holds — so a reader checking it would find a counter-example, conclude
    // the reasoning was stale, and be one step from "fixing" the subtraction back.
    // already documents the same `leaf_count - 1` offset.
    //
    // `#witnessedSeq` answers the question directly instead of inferring it. It gains an entry when
    // the relay witnesses a COUNTERPARTY msg leaf (ctrl leaves are excluded at the call site) and
    // loses it the moment that leaf is appended. So its remaining size IS the count of leaves the
    // ordering authority has committed and this tree has not — no arithmetic, no space mismatch,
    // and it cannot go negative.
    const missingLeaves = this.#ctx.witnessedSeq.get(key)?.size ?? 0;
    // DOD-M12B-INDEX-1: our OWN held sends are counted separately. They block a seal just as a
    // received hold does, but they are not "a message from the counterparty that has not arrived" —
    // and a refusal that calls them that tells the operator to wait for something already in hand,
    // which is how a close-retry loop ends at force-abandon and no receipt.
    let heldOwn = 0;
    for (const e of this.#ctx.heldContent.get(key)?.values() ?? []) if (e.origin === "sent") heldOwn++;
    // DOD-M15-DIVERGE-1: the third term, and the one that closes the asymmetry. `#diverged` is set
    // only where the parting is PROVEN — an ack came back behind our frontier — never where it is
    // merely suspected, because a gate that refuses a healthy session forever is worse than the bug
    // it guards: force-abandon, with no receipt, becomes the only exit.
    const diverged = this.#ctx.records.isSessionDiverged(agentName, sessionId);
    return {
      ready: missingLeaves === 0 && heldCount === 0 && !diverged,
      treeSize, highWaterSeq, heldCount, missingLeaves,
      heldOwn, heldReceived: heldCount - heldOwn,
      diverged,
    };
  }

  /**
   * DOD-M12B-SEAL-STUCK-1 — the operator-facing answer to "can this session be closed?".
   *
   * THREE STATES, because there are three answers. `sealReadiness` above returns a boolean plus raw
   * counters, and both of its counters are easy to misread on a surface:
   *
   *  - `missingLeaves` is `#witnessedSeq.size`, which is every position the relay witnessed that
   *    this tree has not appended — and a HELD frame keeps its witness entry. So it INCLUDES the
   *    held ones. Reporting it beside `heldCount` counts the same message twice and labels one copy
   *    "never received" when it is sitting on our own disk. Split here into what each actually is.
   *  - Neither counter survives a restart on its own: `#witnessedSeq` is memory-only. Held content
   *    is durable since DOD-M12B-STRAND-1, but a position the relay witnessed for content that
   *    never arrived leaves no trace. So for a session carrying leaves this process did not watch
   *    arrive, "clean" is unknowable — and saying `ready` there invites a close that gets
   *    `leaf_count_mismatch` back, which is terminal and costs the receipt for good.
   */
  sealReadinessView(agentName: string, sessionId: string): SealReadinessView {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const r = this.sealReadiness(agentName, sessionId);
    // DOD-M15-DIVERGE-1: READ THIS BEFORE THE `!ready` BRANCH, and the order is load-bearing.
    // `diverged` is now a term in `ready`, so a diverged session reaches `!ready` — where it would
    // report `blocked` with awaitingArrival and heldBehindGap both ZERO, replacing an accurate,
    // specific answer with one that describes nothing and invites a retry that can never work.
    // Divergence is permanent and has its own state; the gap cases below are the ones that resolve.
    if (r.diverged) {
      // NOT `ready`. The tree is ahead of the relay's counter for good, so a close here signs a root
      // the counterparty answers `leaf_count_mismatch` to — terminal, and the receipt is gone. The
      // raw counters cannot see this: nothing is missing and nothing is held.
      return { state: "unknown", reason: "record_diverged_from_relay" };
    }
    if (!r.ready) {
      const oldestHeldMs = this.#ctx.queries.oldestHeldMs(agentName, sessionId);
      return {
        state: "blocked",
        // The witness map counts a held frame until it is appended, so subtract the RECEIVED holds
        // to avoid reporting one message twice. NOT the own-sends: the witness map only ever
        // carries counterparty leaves, so subtracting ours would push this count below the truth.
        awaitingArrival: Math.max(0, r.missingLeaves - r.heldReceived),
        heldBehindGap: r.heldCount,
        oldestHeldMs,
      };
    }
    if (r.treeSize > 0 && !this.#ctx.orderingObserved.has(key)) {
      return {
        state: "unknown",
        reason: "witness_state_predates_daemon_start",
      };
    }
    return { state: "ready" };
  }

  /**
   * WHERE THE MUTUALLY-SIGNED PREFIX ENDS, DERIVED FROM THIS DAEMON'S OWN LEAVES —
   * `DOD-M15-UNILATERAL-1`, review F2.
   *
   * ⚠️ **THE FIRST VERSION COMPUTED THIS FROM THE CERTIFICATE'S OWN PARTICIPANT LIST, AND CALLED
   * THAT "recomputed, cannot be steered".** It could be steered. On the SOLO path the certificate's
   * TBS binds no legibility at all, and the client verifies only the *live* party's frontier — so
   * the absent party's `content_frontier_seq` and every `last_authored_seq` arrived unchecked. One
   * directory node could publish the absent party's frontier as 3 and the receipt would say
   * "mutually signed through 3" over a transcript that party never signed for. That is the precise
   * conflation this field exists to prevent, reintroduced by the field itself.
   *
   * The carry answers it without trusting anybody. This daemon holds the counterparty's own leaves,
   * each carrying, inside the bytes THEY signed, both the sequence they authored and the
   * `last_seen_seq` they acknowledged. So a party's commitment reaches
   * `max(highest sequence they authored, highest sequence they acknowledged)`, and the transcript is
   * mutually signed only as far as the LEAST-committed party reaches.
   *
   * Fewer than two distinct authors ⇒ `0`: nobody countersigned anything, which is the honest floor
   * for a conversation where the other side only ever received. `null` when the carry is empty or
   * unreadable — the caller must then publish NO boundary rather than fall back to a number
   * somebody else supplied.
   */
  countersignedThroughSeqFromCarry(agentPubkeyHex: string, sessionIdHex: string): number | null {
    const carry = this.getSealCarry(agentPubkeyHex, sessionIdHex);
    if (carry.length === 0) return null;
    const reach = new Map<string, number>();
    for (const leaf of carry) {
      // Structure 1 = [version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp],
      // plus last_seen_hash at 6 on a v2 claim. `last_seen_seq` is index 4 in both — 020-ACKHASH
      // APPENDS, so this read did not move. The hash is not consulted here: this derives a
      // POSITIONAL boundary, which is the job last_seen_seq keeps doing alongside the new field.
      const s1 = decodeStructure1(leaf.structure1Cbor);
      // Unreadable, or a layout this build cannot name: publish no boundary rather than a
      // half-derived one somebody else could have shaped.
      if (!s1.ok) return null;
      const signedLastSeen = Number.isFinite(Number(s1.fields.lastSeenSeq))
        ? Number(s1.fields.lastSeenSeq)
        : 0;
      const prior = reach.get(leaf.senderPubkeyHex) ?? 0;
      reach.set(leaf.senderPubkeyHex, Math.max(prior, leaf.sequenceNumber, signedLastSeen));
    }
    if (reach.size < 2) return 0;
    return Math.min(...reach.values());
  }
}
