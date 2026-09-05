/**
 * `DOD-M15-SELFCHAIN-1` — what THIS agent last said in a session, so the next thing it says can
 * link to it.
 *
 * ─── Why this exists at all ───────────────────────────────────────────────────────────────────
 *
 * A sender signs `last_seen_hash`: the hash of the last message they RECEIVED. That chains across
 * the two parties and never chains a sender to themselves — so when one party sends twice in a
 * row, both of their messages carry the same acknowledgement, because nothing arrived in between.
 * Nothing in the signed bytes tells them apart.
 *
 * The relay-assigned position cannot fill the gap: it is assigned AFTER the sender signs, so a
 * sender can never sign their own position. The relay's receipt does pin it — but the receipt goes
 * to the SENDER, so whoever hands a conversation to a new relay holds no receipt for the
 * counterparty's messages and can reorder any run of them.
 *
 * `prev_own_hash` closes it, and this store is the thing that can answer what to put in it.
 *
 * ─── Why a dedicated table rather than reading one that exists ────────────────────────────────
 *
 * Three candidates were examined and each fails for a different reason:
 *
 *   - **`SessionTree`** stores leaf hashes and no authorship, so it cannot say which leaves are
 *     ours.
 *   - **`transcript`** knows `direction` but carries no content hash column.
 *   - **`session_seal_leaves`** knows the sender and the signed bytes, and is keyed by the RELAY's
 *     `sequence_number` — so it holds nothing for a message that was never witnessed. `033-ACKEMIT`
 *     Part 0b measured exactly that gap and it is still open.
 *
 * The self link must hold on the unwitnessed path too — a conversation that ran while the relay was
 * down is precisely the one whose order gets disputed later — so the producer cannot depend on a
 * relay having been there. One row per (agent, session), written wherever this daemon signs.
 *
 * ⚠️ PERSISTED, because the chain must survive a restart. An in-memory tracker would silently start
 * a new chain after a daemon restart mid-conversation, and the counterparty would refuse every
 * message after it with no way to tell that from tampering.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS session_own_chain (
    agent_pubkey   TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    last_own_hash  TEXT NOT NULL,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (agent_pubkey, session_id)
  );
`;

export class SessionOwnChainStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_SQL);
  }

  /**
   * The content hash of this agent's own previous message in this session, or `null` when it has
   * not sent one yet.
   *
   * ⚠️ `null` MEANS "I HAVE NOT SPOKEN HERE", AND THE CALLER MUST NOT TREAT IT AS "SKIP THE LINK".
   * The first message of a session carries the session GENESIS as its self link — a defined value,
   * derived per session. Substituting an absent field, or a shared constant like 32 zero bytes,
   * would give a first message a link that is presentable for any conversation.
   */
  lastOwnHash(agentPubkeyHex: string, sessionIdHex: string): Uint8Array | null {
    const row = this.#db
      .prepare(`SELECT last_own_hash FROM session_own_chain WHERE agent_pubkey = ? AND session_id = ?`)
      .get(agentPubkeyHex, sessionIdHex) as { last_own_hash?: string } | undefined;
    if (!row || typeof row.last_own_hash !== "string") return null;
    const bytes = Buffer.from(row.last_own_hash, "hex");
    if (bytes.length !== 32) {
      /**
       * A stored value that is not a hash is a corrupt local record, and the honest answer is to say
       * so and behave as if nothing were stored — the next message then chains to the session
       * genesis, which the counterparty will refuse, which is the correct loud outcome. Returning
       * the malformed bytes would sign a link nobody can check; returning null silently would hide
       * a corrupt database behind a first-message claim.
       */
      this.#logger.error("session.selfchain.stored_hash_malformed", {
        session: sessionIdHex,
        storedWidth: bytes.length,
        impact:
          "this agent's own chain record for this session is corrupt, so the next message it sends " +
          "will not link to the previous one and the counterparty will refuse it. The conversation " +
          "cannot continue on this machine until the session is restarted.",
      });
      return null;
    }
    return new Uint8Array(bytes);
  }

  /**
   * Record what this agent just sent, so the next message links to it.
   *
   * ⚠️ CALLED AFTER THE SEND SUCCEEDS, NEVER BEFORE. Recording first and failing to send would skip
   * a link over a message that never existed, and every later message would be refused by the
   * counterparty for a reason that names tampering. Recording after means a retry re-uses the same
   * predecessor, which is exactly right — a retransmission is the same message.
   */
  record(agentPubkeyHex: string, sessionIdHex: string, contentHash: Uint8Array, atMs: number): void {
    this.#db
      .prepare(
        `INSERT INTO session_own_chain (agent_pubkey, session_id, last_own_hash, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(agent_pubkey, session_id) DO UPDATE SET last_own_hash = excluded.last_own_hash, updated_at = excluded.updated_at`,
      )
      .run(agentPubkeyHex, sessionIdHex, Buffer.from(contentHash).toString("hex"), atMs);
  }

  /** Drop a session's chain record. Called when the session is destroyed. */
  forget(agentPubkeyHex: string, sessionIdHex: string): void {
    this.#db
      .prepare(`DELETE FROM session_own_chain WHERE agent_pubkey = ? AND session_id = ?`)
      .run(agentPubkeyHex, sessionIdHex);
  }
}
