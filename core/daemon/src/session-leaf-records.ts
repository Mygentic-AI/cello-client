/**
 * CELLO Daemon — THE TWO DURABLE FACTS ABOUT A SESSION'S LEAVES
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. Both are read at seal time and both
 * outlive the process, which is why they are here together rather than with the in-memory tree:
 *
 *   - the GENESIS prev-root — where this two-party chain starts. It is a defined 32 bytes derived
 *     from both keys, the session id and the session timestamp, NOT 32 zeros: a constant identical
 *     across every session is one an attacker could present for any session, which would make the
 *     one position most exposed to a forged acknowledgement the only one nobody could check.
 *   - the CERTIFIED LEAF SET — which leaves the directory actually attested, and the state of that
 *     answer when it could not be obtained.
 *
 * Moved verbatim, comments included.
 */
import type { Logger } from "./types.js";
import type { SessionQueries } from "./session-queries.js";
import type { ActiveSessionEntry } from "./session-node-types.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { RelayAssignmentCarry } from "./session-relay-client.js";
import type { SealFrontierLeaf } from "./seal-frontier-verify.js";
import { computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import { extractErrorMessage } from "./error-message.js";
import { certifiedLeafSetFrom } from "./sealed-leaf-set.js";

/** What the leaf records need from the manager. */
export interface SessionLeafRecordContext {
  readonly logger: Logger;
  readonly queries: SessionQueries;
  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  activeEntry(key: string): ActiveSessionEntry | undefined;
}

export class SessionLeafRecords {
  readonly #ctx: SessionLeafRecordContext;

  constructor(ctx: SessionLeafRecordContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * The starting point of each live session's chain, in memory.
   *
   * ⚠️ NOT A CACHE OF THE DATABASE — it is the only copy that exists at the moment the value is
   * first needed. It is recorded before the session node is built, and the session ROW does not
   * exist until that build inserts it (`#insertSessionRow` writes the column from here). The row is
   * what survives a restart; this is what the session open itself reads.
   */
  readonly #sessionGenesis = new Map<string, Uint8Array>();
  /**
   * Return the daemon-owned Merkle tree for a session, loading it from SQLite
   * on first access (so it survives a restart — AC-007). Never returns null;
   * an unknown session yields an empty tree.
   */
  /**
   * The session's genesis prev_root — what its FIRST message acknowledges, before anything has been
   * received (033-ACKEMIT).
   *
   * DERIVED FIRST, STORED SECOND — and this docblock used to say "derived, never stored", which
   * stopped being true inside this same unit. Rewritten rather than deleted: a reader who believed
   * the first sentence would delete the column read below as redundant, and take the restart case
   * with it.
   *
   * The live assignment is authoritative, because it is the thing the value is defined by. The
   * stored column covers the one case the derivation cannot: a session restored after a restart
   * re-registers with no assignment, and the session TIMESTAMP the genesis needs lives nowhere
   * else.
   *
   * `undefined` when neither is available. The callers do not paper over that — they say, in the
   * log and in the claim itself, that this session acknowledges nothing yet.
   */
  sessionGenesisPrevRoot(agentName: string, sessionId: string): Uint8Array | undefined {
    const assignment = this.#ctx.activeEntry(this.#ctx.sessionKey(agentName, sessionId))?.relayAssignment;
    if (assignment) {
      return computeGenesisPrevRoot(
        assignment.participantA,
        assignment.participantB,
        Uint8Array.from(Buffer.from(sessionId, "hex")),
        assignment.sessionTimestamp,
      );
    }
    /**
     * ⚠️ THE IN-MEMORY RECORD, READ BEFORE THE DATABASE — and this ordering is the fix, not a
     * cache.
     *
     * `recordSessionGenesis` is called BEFORE the session node exists, because registering the
     * session is what seeds the relay client's acknowledgement state and the seed has to be
     * available by then. At that moment there is no session ROW to write to — `createSessionNode`
     * inserts it — so a database-only record would still be empty at the one moment it is read.
     * The row is written from this map when the insert happens, and read back after a restart.
     */
    const recorded = this.#sessionGenesis.get(this.#ctx.sessionKey(agentName, sessionId));
    if (recorded) return recorded;
    /**
     * THE RESTART CASE. A session restored from the database re-registers with no assignment, so
     * the derivation above has nothing to work from and the stored copy is the only answer. Read
     * second, never first: the live assignment is authoritative, and a stored value that ever
     * disagreed with it would be the more dangerous of the two to prefer.
     */
    const row = this.#db
      ?.prepare("SELECT genesis_prev_root FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { genesis_prev_root?: unknown } | undefined;
    const stored = row?.genesis_prev_root;
    const bytes = stored instanceof Uint8Array ? stored : Buffer.isBuffer(stored) ? new Uint8Array(stored) : null;
    // A stored value of the wrong width is not a genesis. Refusing it here sends the caller down its
    // own named refusal, which is a better outcome than signing an acknowledgement of 17 bytes.
    if (bytes && bytes.length === 32) return bytes;
    return undefined;
  }
  persistGenesisPrevRoot(agentName: string, sessionId: string, assignment: RelayAssignmentCarry): void {
    let genesis: Uint8Array;
    try {
      genesis = computeGenesisPrevRoot(
        assignment.participantA,
        assignment.participantB,
        Uint8Array.from(Buffer.from(sessionId, "hex")),
        assignment.sessionTimestamp,
      );
    } catch (err: unknown) {
      /**
       * The DERIVATION failed, which is a different failure from the write below and must not be
       * reported as one. It means the assignment's own fields are not what this function needs, and
       * no amount of database health would help.
       */
      this.#ctx.logger.error("session.genesis.derive.failed", {
        agentName, sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact:
          "this session's starting point could not be computed from its assignment, so nothing " +
          "sent on it can be chained and every send will be refused by name. The session open " +
          "continues; the conversation cannot.",
      });
      return;
    }
    // The in-memory record FIRST, and unconditionally: it is what the session open reads, and it
    // must not depend on a database write that may not have anywhere to land yet.
    this.#sessionGenesis.set(this.#ctx.sessionKey(agentName, sessionId), genesis);
    if (!this.#db) return;
    try {
      this.#db
        .prepare("UPDATE sessions SET genesis_prev_root = ? WHERE agent_id = ? AND session_id = ? AND genesis_prev_root IS NULL")
        .run(Buffer.from(genesis), this.#ctx.requireAgentId(agentName), sessionId);
    } catch (err: unknown) {
      /**
       * LOUD, AND IT DOES NOT BLOCK. Losing this row costs the session its acknowledgements after a
       * restart — sends are then refused by name until the counterparty speaks — and that is a far
       * smaller harm than failing the session open that is in progress. Reported at ERROR because
       * the failure is invisible until a restart that may be days away.
       */
      this.#ctx.logger.error("session.genesis.persist.failed", {
        agentName, sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact:
          "this session's starting point was not written to the database. Everything works until " +
          "this daemon restarts; after that, a send on this session is refused until the " +
          "counterparty has sent something, because the daemon cannot say what its first message " +
          "acknowledges.",
      });
    }
  }
  /**
   * Persist the session's genesis prev_root, once, at the moment the assignment arrives.
   *
   * `WHERE genesis_prev_root IS NULL` rather than a plain update: the value cannot legitimately
   * change for the life of a session, so the second writer is either redundant or wrong, and the
   * first write is the one derived closest to the assignment that opened the session.
   */
  /**
   * Record the session's starting point from the ASSIGNMENT — `DOD-M15-SELFCHAIN-1`.
   *
   * ⚠️ **CALL THIS BEFORE `createSessionNode` / `acceptSession`, NOT AFTER.** Registering the
   * session is what seeds the relay client's acknowledgement state, so the value has to exist by
   * then; recorded afterwards, the first message of the session has nothing to chain to and is
   * refused. Both the initiator and the responder derive this from the same FROST-signed assignment
   * before they build anything.
   *
   * ⚠️ THE ANCHOR BELONGS TO THE SESSION, NOT TO THE RELAY, and treating it as the relay's was a
   * real gap. It was derived only when a relay assignment CARRY was present — and that carry is
   * built only for a relay-mode assignment that also carries a per-node relay signature. So a
   * direct-mode session, brokered and FROST-signed exactly like any other, recorded no starting
   * point at all, and every message on it had nothing to chain to.
   *
   * Both transport modes get their assignment from the same ceremony and derive the same value from
   * it. The relay is how the conversation travels; it is not what makes the conversation provable.
   */
  recordSessionGenesis(
    agentName: string,
    sessionId: string,
    participantA: Uint8Array,
    participantB: Uint8Array,
    sessionTimestamp: number,
  ): void {
    this.persistGenesisPrevRoot(agentName, sessionId, {
      participantA, participantB, sessionTimestamp,
    } as RelayAssignmentCarry);
  }
  /**
   * Test seam: put the session's genesis prev_root where a completed session open leaves it —
   * 033-ACKEMIT.
   *
   * ⚠️ THE STATE IS THE PRODUCTION ONE; ONLY HOW IT GOT THERE IS SHORT-CIRCUITED, exactly as
   * `setSessionContentKeyForTest` short-circuits the key exchange next door.
   *
   * In production this value is derived from the directory-signed relay assignment and written to
   * the session row the moment the session learns it, so every real session has one. A fixture that
   * builds a session node directly never sees an assignment — so without this seam every content
   * test built on the fixture would be exercising the "no starting point" REFUSAL path instead of
   * the thing it was written for, and would report that as a pass or a mysterious failure depending
   * on which side of the send it sat on.
   */
  setSessionGenesisForTest(agentName: string, sessionId: string, genesis: Uint8Array): void {
    /**
     * ⚠️ WRITES THE SAME MAP PRODUCTION WRITES, deliberately — `DOD-M15-SELFCHAIN-1`.
     *
     * This seam exists because a fixture builds a session below the paths that derive a starting
     * point from a directory assignment; it does NOT exist to install a second, quieter source of
     * the value. Sharing the map means a fixture and a real session read through exactly the same
     * lookup, so a change to that lookup cannot pass the tests while breaking production.
     *
     * ⚠️ CALL IT BEFORE `createSessionNode`, the same rule production follows: registering the
     * session is what seeds the relay client's acknowledgement state, and a value recorded after
     * that leaves the first send with nothing to chain to.
     */
    this.#sessionGenesis.set(this.#ctx.sessionKey(agentName, sessionId), Uint8Array.from(genesis));
    /**
     * The durable half is BEST EFFORT. Some fixtures run against a database whose schema was never
     * created, and a seam that threw there would turn "this fixture has no sessions table" into a
     * failure of whatever it was actually testing. Harmless when the row does not exist yet either:
     * `#insertSessionRow` writes the column from the map above.
     */
    try {
      this.#db
        ?.prepare("UPDATE sessions SET genesis_prev_root = ? WHERE agent_id = ? AND session_id = ?")
        .run(Buffer.from(genesis), this.#ctx.requireAgentId(agentName), sessionId);
    } catch { /* see above — the in-memory half is the load-bearing one */ }
  }
  /**
   * DOD-M15-INCLUSION-1: keep the leaf set the certificate is signed over, so one message can later
   * be proved to sit under it.
   *
   * REFUSES unless the hashes reproduce `sealedRootHex` — `certifiedLeafSetFrom` does that check and
   * this method never bypasses it. That is what separates "the leaves the directory sent" from "the
   * leaves the consortium signed", and only the second is worth storing: a proof built on the first
   * would inherit whatever the directory chose to say.
   *
   * Idempotent (INSERT OR REPLACE keyed on leaf_index) so a re-delivered seal frame, or a unilateral
   * seal later upgraded to bilateral, rewrites the same rows instead of failing or doubling them.
   *
   * @returns whether the set was accepted and stored.
   */
  recordCertifiedLeafSet(
    agentName: string,
    sessionId: string,
    signedLeaves: readonly SealFrontierLeaf[],
    sealedRootHex: string,
    correlationId?: string,
  ): boolean {
    if (!this.#db) return false;
    const resolved = certifiedLeafSetFrom(signedLeaves, sealedRootHex);
    if (!resolved.ok) {
      // The CAUSE is written where the proof surface can read it — fallback-finder finding 1. Without
      // this row, `sealed_leaves_root_disagrees` (a directory contradicting its own FROST signature)
      // and "this side was simply absent" are the same `null` downstream, and the operator is told
      // the second.
      this.#ctx.queries.noteCertifiedLeafState(agentName, sessionId, resolved.reason, resolved.detail);
      // LOUD, and it names which of the two it is. `sealed_leaves_root_disagrees` in particular is
      // the directory shipping a leaf set that is not the one it signed — the receipt still stands
      // (its own signature is checked elsewhere), but nothing in this session can be proved at
      // message granularity until a set that reproduces the root arrives.
      this.#ctx.logger.error("seal.certified_leaves.refused", {
        agentName,
        sessionId,
        reason: resolved.reason,
        detail: resolved.detail,
        correlationId,
        impact:
          "the leaf set shipped with this seal is not the one the certificate is signed over, so no " +
          "inclusion proof can be issued for this session; the sealed receipt itself is unaffected",
        guidance:
          "cello_get_inclusion_proof will refuse this session by name (certified_leaves_unavailable). " +
          "Nothing local repairs it — the set has to arrive with a seal frame that reproduces the " +
          "signed root.",
      });
      return false;
    }
    const now = Date.now();
    try {
      const agentId = this.#ctx.requireAgentId(agentName);
      /**
       * DELETE THEN INSERT, INSIDE A TRANSACTION — fallback-finder finding 5.
       *
       * `INSERT OR REPLACE` alone is idempotent only for a set of the SAME length: a shorter
       * re-delivery overwrites 0..k-1 and leaves stale rows at k..n-1, and an un-transacted loop that
       * throws halfway leaves a truncated set that `getCertifiedLeafSet` still returns (it tests
       * `rows.length > 0`, not completeness). Both produce a set that no longer hashes to the
       * certified root — caught on read, but reported to the operator as *"the local copy has
       * changed since the seal"*, which points at tampering for a write that never finished.
       */
      // `BEGIN` / `COMMIT` / `ROLLBACK` via exec — this file's and `db-identity-store.ts`'s idiom.
      // `DaemonDatabase` has no `transaction()` helper (node:sqlite's handle does not provide one),
      // and reaching for better-sqlite3's would compile against the adapter and fail on the other.
      this.#db.exec("BEGIN");
      try {
        this.#db.prepare("DELETE FROM session_certified_leaves WHERE agent_id = ? AND session_id = ?")
          .run(agentId, sessionId);
        const stmt = this.#db.prepare(
          `INSERT INTO session_certified_leaves
             (agent_id, session_id, leaf_index, content_hash_hex, recorded_at)
           VALUES (?, ?, ?, ?, ?)`,
        );
        for (let i = 0; i < resolved.leafHashes.length; i++) {
          stmt.run(agentId, sessionId, i, resolved.leafHashes[i], now);
        }
        this.#db.exec("COMMIT");
      } catch (err: unknown) {
        try { this.#db.exec("ROLLBACK"); } catch { /* the failing statement may have aborted it already */ }
        throw err;
      }
    } catch (err: unknown) {
      this.#ctx.queries.noteCertifiedLeafState(agentName, sessionId, "persist_failed", extractErrorMessage(err));
      this.#ctx.logger.error("seal.certified_leaves.persist.failed", {
        agentName,
        sessionId,
        reason: extractErrorMessage(err),
        correlationId,
        impact:
          "this session's certified leaf set was verified but not written, so cello_get_inclusion_proof " +
          "will refuse it by name until a later seal frame re-delivers the set",
      });
      return false;
    }
    this.#ctx.queries.noteCertifiedLeafState(agentName, sessionId, "stored", null);
    this.#ctx.logger.info("seal.certified_leaves.recorded", {
      agentName,
      sessionId,
      leafCount: resolved.leafHashes.length,
      sealedRoot: sealedRootHex,
      correlationId,
    });
    return true;
  }
  /**
   * Record WHY this session does or does not have a certified leaf set.
   *
   * Public for the one case the manager cannot see: a seal frame that carried no signed leaves at
   * all never reaches `recordCertifiedLeafSet`, and that absence is a permanent fact about the
   * session for the party that observed it.
   */
  noteCertifiedLeafSetUnavailable(
    agentName: string,
    sessionId: string,
    state: "not_carried_absent_party" | "not_carried_present_party",
    detail: string,
  ): void {
    this.#ctx.queries.noteCertifiedLeafState(agentName, sessionId, state, detail);
  }
  getCertifiedLeafSet(agentName: string, sessionId: string): string[] | null { return this.#ctx.queries.getCertifiedLeafSet(agentName, sessionId); }
  getCertifiedLeafSetState(agentName: string, sessionId: string): { state: string; detail: string | null } | null { return this.#ctx.queries.getCertifiedLeafSetState(agentName, sessionId); }

  /** The in-memory genesis prev-root for a session, when one has been recorded. */
  genesisFor(agentName: string, sessionId: string): Uint8Array | undefined {
    return this.#sessionGenesis.get(this.#ctx.sessionKey(agentName, sessionId));
  }
}
