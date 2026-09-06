/**
 * CELLO Daemon — THE SESSION DATABASE SCHEMA
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. Every CREATE TABLE and every additive
 * ALTER TABLE the daemon's session store needs, in the order they must run.
 *
 * Moved verbatim, comments included — and in this file the comments carry more than usual. Several
 * columns exist because of a specific defect, and the prose beside them is the only record of which
 * one: the transcript's `attribution` column is NOT NULL precisely so that a row without authorship
 * proof cannot look like a row that has one, and the `⚠️` blocks on `sender_sig` correct two earlier
 * sentences that sent auditors looking for Structure-2 bytes that do not exist on a relay-degraded
 * message.
 *
 * ⚠️ THIS IS CLIENT-SIDE MIGRATION CODE AND IT RUNS ON OPERATORS' MACHINES. A migration that fails
 * here is not a failed deploy that can be rolled back — it is a daemon that will not start on
 * somebody's laptop, with their key shares and transcript inside the database it could not open.
 * Additive columns only; never rewrite an applied statement, and never reorder the list.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { addColumnIfMissing } from "./column-birth.js";
import { migrateSessionTablesToAgentId } from "./agent-id-migration.js";
import { migrateContactsAddTierMetadata } from "./contacts-tier-migration.js";
import { migrateCborBlobsToCanonical } from "./cbor-blob-migration.js";
import { foldContactPubkeyCase } from "./contact-pubkey-case.js";
import { ensureTrustSignalSchema } from "./trust-signal-store.js";

/**
 * Create every session-store table and apply every additive migration.
 *
 * `loadDivergedFromDb` is a CALLBACK rather than an import: the divergence memo is rehydrated part
 * way through this sequence — after the agent-id migration that gives it rows to read — and the
 * store that owns it lives elsewhere. Passing it keeps the ordering visible here, where the reason
 * for it is, instead of leaving a second caller to remember it.
 */
export function ensureSessionSchema(
  db: DaemonDatabase,
  logger: Logger,
  loadDivergedFromDb: () => void,
): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      counterparty_pubkey TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      -- DOD-LOOP-1: composite key so two of the operator's agents can hold both ends of the
      -- SAME session_id on ONE daemon (the loopback case). A bare session_id PK would reject
      -- the second end's row.
      -- DOD-AGENT-ID-JOINKEY-1: keyed on the STABLE agent_id, never the mutable, reuse-freed
      -- agent_name. The display name lives on the agents table and is joined in for reads.
      PRIMARY KEY (agent_id, session_id)
    )
  `);

  // M7-SESSION-001: idempotent schema extension — add message_count and interrupted_at
  // columns if they do not exist. ALTER TABLE IF NOT EXISTS COLUMN is not supported by
  // older SQLite; we use a try/catch per column as the idempotent approach.
  for (const ddl of [
    "ALTER TABLE sessions ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE sessions ADD COLUMN interrupted_at TEXT",
    /**
     * Decisions Carried #8 — THE SESSION SALT, persisted.
     *
     * Agreed once at session open from BOTH sides' random contributions, and unchanged for the
     * life of the session. It is NOT a key: it decrypts nothing, and it is what lets this
     * operator's own transcript stay verifiable — the content hash is recomputed from stored
     * plaintext on the receive path and again for any later check, and salted it is underivable
     * without this value.
     *
     * PERSISTED because the alternative is silent corruption. ⚠️ FUTURE TENSE, deliberately
     * (review F10): NOTHING WRITES OR READS THIS COLUMN YET. `DOD-M15-SEALWIRE-1` will add the
     * contribution exchange and the lookup — "does this session already have a salt? yes → use it,
     * no → agree one" — and without the column that lookup would fail after a restart, mint a
     * fresh salt, and split the transcript at the crash: every leaf before it unverifiable, with
     * nothing saying so. The column lands now because it must exist before the code that needs it.
     *
     * NULL for every session opened before this column existed; those keep the unsalted hash.
     */
    "ALTER TABLE sessions ADD COLUMN content_salt BLOB",
    /**
     * DOD-M15-FREEZE-STATUS-1 — carried here for the OTHER LANE (`CELLO_Support`), agreed in
     * session `e3adcaa7…`. Two lanes must not both edit this file (§2e, one file two branches), so
     * the columns land in one migration and every line of behaviour stays on their side. Nothing
     * in this lane reads or writes them.
     *
     *   `frozen_at`     epoch-ms when `#freezeOnIdentityFailure` fired. NULL = never frozen.
     *   `frozen_reason` the `reason` already passed to that method. NULL iff `frozen_at` is NULL.
     *
     * ⚠️ THE WRITE MUST LAND BEFORE `destroySessionNode`, NOT AFTER — FRAME-1 review F1's
     * ordering, and the reason the in-memory `#frozenSessions.add` already sits before the
     * teardown. `destroySessionNode` writes `interrupted`, which is the REVIVABLE status, so a
     * durable mark landing after it lets a read race the teardown and revive the session out from
     * under the freeze — the disk reproducing the bug the memory mark was moved early to fix.
     *
     * Why it earns a slot rather than waiting: `#frozenSessions` is memory-only today, so a
     * restart UN-FREEZES a session that was frozen because a party signed with a key that was not
     * the counterparty's. The next read revives it and re-admits that peer, while the log still
     * says the session will not be revived.
     */
    "ALTER TABLE sessions ADD COLUMN frozen_at INTEGER",
    "ALTER TABLE sessions ADD COLUMN frozen_reason TEXT",
    // MSG-001-3b (MSG-2 startup-flush): persist the session's relay endpoint so the
    // crash-backstop flush can deposit un-acked content after a restart, when the
    // in-memory entry is gone. relay_addrs is a JSON array of multiaddr strings.
    "ALTER TABLE sessions ADD COLUMN relay_peer_id TEXT",
    "ALTER TABLE sessions ADD COLUMN relay_addrs TEXT",
    // M7-SESSION-004 (AC-005): persist the seal certificate's legibility object with the
    // sealed record so it survives a daemon restart and is readable on the cert-read surface
    // (cello_get_sealed_receipt). JSON string with hex-encoded pubkeys; NULL until sealed.
    // Inline idempotent migration (NOT Flyway — this is the client-side SQLite, AC-011).
    /**
     * 033-ACKEMIT — THE SESSION'S GENESIS PREV_ROOT, and it is persisted for ONE reason: a
     * restart.
     *
     * It is a pure function of the two participant keys, the session id and the SESSION
     * TIMESTAMP — and the timestamp arrives on the directory-signed relay assignment and lives
     * nowhere else. A session restored from this table after a daemon restart re-registers with
     * no assignment in hand, so without this column the daemon could not say what the first
     * message of that session acknowledges, and every send on it would be refused rather than
     * signed. Deriving is still preferred where the assignment IS in memory; this is what makes
     * the derivation survive the process.
     *
     * NULL for every session opened before this column existed. Those sessions acknowledge
     * nothing until the counterparty has sent something — they claim position 0 with no hash,
     * which asserts nothing rather than asserting a position they cannot back — and from the
     * first leaf they receive they acknowledge content like any other session.
     */
    "ALTER TABLE sessions ADD COLUMN genesis_prev_root BLOB",
    "ALTER TABLE sessions ADD COLUMN seal_legibility TEXT",
    "ALTER TABLE sessions ADD COLUMN sealed_root_hex TEXT",
    // M7 legibility-TBS-binding (responder verify): the counterparty's FROST primary (group)
    // pubkey, taken from the FROST-signed SessionAssignment's signer_pubkey. The responder uses
    // it to VERIFY the bilateral seal signature locally (the seal is signed by the initiator's
    // primary), not just accept it. NULL when this party initiated (it uses its own primary).
    "ALTER TABLE sessions ADD COLUMN counterparty_primary_pubkey TEXT",
    // DOD-SESSION-NAME-1: the operator's own human-readable label for this session. LOCAL AND
    // COSMETIC — it is never sent to the relay or directory, never in a wire frame, never in the
    // transcript, never in the seal or a Merkle leaf, and the counterparty never sees it. It
    // cannot influence protocol behaviour.
    // NULL MEANS SOMETHING: a session closed through an agent usually carries a name, so an
    // unnamed closed session is a hint it did not close cleanly. Never auto-generate a default —
    // a fabricated name destroys that signal.
    "ALTER TABLE sessions ADD COLUMN session_name TEXT",
    // DOD-SEALED-INBOX-1: local-only housekeeping flag — epoch-ms timestamp set by cello_dismiss.
    // Never propagated, never part of the seal ceremony or hash chain. A dismissed terminal
    // session is excluded from cello_inbox's ended_unread section. Distinct from the read
    // watermark: this records "operator acknowledged via dismiss", not "operator received via
    // cello_receive". NULL = not yet dismissed.
    "ALTER TABLE sessions ADD COLUMN read_at INTEGER",
    // DOD-M12B-ABANDON-NOTIFY-1: epoch-ms when the counterparty told us they force-abandoned.
    // Deliberately NOT a status — the session stays sealable, so the operator can still take a
    // unilateral receipt. It stops this side calling them, nothing more.
    "ALTER TABLE sessions ADD COLUMN counterparty_abandoned_at INTEGER",
    // DOD-CAP-SELF-HEAL-1: WHO caused this session to be interrupted — 'counterparty' when their
    // stream dropped, 'local' when OUR daemon stopped or started. Only theirs counts against the
    // acceptance bound. Without this the bound is all-time rather than concurrent: every restart
    // flips every live session to `interrupted`, nothing ever resolves them, and a pair of agents
    // that has talked three times can never talk again. NULL means "not recorded" and is treated
    // as the counterparty's, because the safe default for an anti-abuse bound is to count it.
    "ALTER TABLE sessions ADD COLUMN interrupted_by TEXT",
    // DOD-M12B-RESTART-SEAL-1: when automatic sealing exhausted this session, and why. Durable
    // because the resolver's attempt budget is in memory — without it a machine that restarts
    // several times a day re-runs the whole budget against a hopeless session on every boot.
    "ALTER TABLE sessions ADD COLUMN restart_seal_gave_up_at INTEGER",
    "ALTER TABLE sessions ADD COLUMN restart_seal_gave_up_reason TEXT",
    // DOD-M15-DIVERGE-DURABLE-1: epoch-ms when this session's tree and the relay's counter
    // provably parted, so it can never seal bilaterally. NULL = not diverged.
    //
    // DURABLE, and the reason is that the read site cannot tell "not diverged" from "forgotten":
    // both are false and both read READY. `#diverged` was in memory, so a restart turned a
    // session that provably cannot seal into one the gate was happy to close.
    //
    // NOT the trade `frontier-mismatch.ts` makes on purpose. A frontier mismatch is re-detected
    // by the very next close, so losing it costs a recomputation. Divergence is re-detected only
    // by the next send that gets an ack behind the frontier — which on a finished conversation
    // never comes. Losing it costs a WRONG ANSWER.
    "ALTER TABLE sessions ADD COLUMN diverged_at INTEGER",
  ]) {
    try {
      db.exec(ddl);
    } catch (err: unknown) {
      // Only swallow the idempotent "duplicate column name" case (the column
      // already exists from a prior init). Any other failure — disk full,
      // SQLITE_LOCKED, corruption — must propagate, otherwise the daemon would
      // run without these columns and later silently read undefined.
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes("duplicate column name")) throw err;
    }
  }

  // M12-P18: sessions this agent REFUSED (abuse cap etc.). DURABLE and separate from the in-memory
  // refusedSessionRequests inbox list, for one reason: content parked for a refused session arrives
  // AFTER the refusal and often after a restart, and at drain time `counterparty_unknown` cannot
  // tell "content for a session I declined" from "content I might still want". This table is that
  // missing memory. Deleting parked content matched here judges NOTHING about the content — it acts
  // on OUR OWN refusal, so it does not violate the SEC-1 rule that a forgery must not evict itself.
  // Bounded by pruning on write (keep the most recent N per agent); a refused session id is never
  // reused (directory-assigned, unique), so forgetting an old one only means its stale parked
  // content is not proactively swept — the relay TTL backstop still applies.
  db.exec(`
    CREATE TABLE IF NOT EXISTS refused_sessions (
      agent_id   TEXT NOT NULL,
      session_id TEXT NOT NULL,
      reason     TEXT NOT NULL,
      refused_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id)
    )
  `);

  // M12-P17: the POST-SEAL ANNEX — verified content that arrived for a session which had already
  // ended. It cannot join the sealed chain (that would change `sealed_root` and invalidate the
  // notarization), and it must not be thrown away: it is a real message, provably sent to this
  // operator, that no one would otherwise ever read.
  //
  // A SEPARATE TABLE is the point, not an implementation detail. Inertness has to be structural:
  // nothing here is joined by `getUnreadSummary`, `getEndedUnread`, any inbox count or any wake
  // path, so this content CANNOT ring a doorbell or reach agent context no matter what a future
  // caller does. If it lived in `transcript` behind a flag, the next reader would key on the row
  // and not the flag — which is exactly how an agent came to obey an instruction out of a sealed
  // conversation.
  //
  // Keyed on (agent_id, content_hash): `session_id` is recorded for display but is NOT part of the
  // key, because the sibling case this design must also serve — content we cannot attribute to a
  // session at all — has no session to key on.
  db.exec(`
    CREATE TABLE IF NOT EXISTS sealed_session_annex (
      agent_id      TEXT NOT NULL,
      content_hash  TEXT NOT NULL,
      session_id    TEXT NOT NULL,
      sender_pubkey TEXT,
      content       BLOB NOT NULL,
      arrived_at    INTEGER NOT NULL,
      PRIMARY KEY (agent_id, content_hash)
    )
  `);

  // M7-SESSION-001 (H-1): side table holding the verified bilateral
  // SEAL-INTERRUPTED commitment artifacts. A side table (CREATE TABLE IF NOT
  // EXISTS) is inherently idempotent — no ALTER TABLE / duplicate-column
  // handling required. We keep BOTH parties' signed leaves and the agreed
  // Merkle root so the achieved commitment is never discarded.
  db.exec(`
    CREATE TABLE IF NOT EXISTS seal_interrupted_artifacts (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      role TEXT NOT NULL,
      own_leaf TEXT NOT NULL,
      counterparty_leaf TEXT NOT NULL,
      merkle_root TEXT NOT NULL,
      nonce TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      -- DOD-LOOP-1: composite key (per-agent end of a loopback session).
      PRIMARY KEY (agent_id, session_id)
    )
  `);

  // DAEMON-004 (AC-007 / SI-001): the daemon-owned per-session Merkle tree,
  // persisted as an ordered list of leaf hashes. The (session_id, leaf_index)
  // primary key enforces append-order uniqueness; a fresh daemon reconstructs
  // each tree from these rows so the transcript survives a restart. Querying
  // by session_id ORDER BY leaf_index is the only read pattern.
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_tree_leaves (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      leaf_index INTEGER NOT NULL,
      leaf_kind TEXT NOT NULL,
      leaf_hash_hex TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      -- DOD-LOOP-1: composite key so each agent's end has its own append-ordered tree.
      PRIMARY KEY (agent_id, session_id, leaf_index)
    )
  `);

  // DOD-M15-INCLUSION-1: the leaf set the DIRECTORY certified — a different tree from the one
  // above, and the distinction is the whole reason this table exists.
  //
  // `session_tree_leaves` holds this agent's CONTENT leaves. The certified root covers every leaf
  // the relay ordered, CONTROL leaves included, and nothing appends a ctrl leaf to the local tree
  // (`submitSealLeaf` computes its root without mutating it). So an audit path built from
  // `session_tree_leaves` lands on a root no certificate names — it proves this machine agrees
  // with itself, which is worth nothing to the third party a proof is FOR.
  //
  // Rows land only after the Merkle root over them reproduces the FROST-signed `sealed_root`
  // (`certifiedLeafSetFrom`), so what is stored here is the consortium's leaf set and not the
  // directory's word for it. Written once at seal time; read only by the inclusion-proof surface,
  // ORDER BY leaf_index.
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_certified_leaves (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      leaf_index INTEGER NOT NULL,
      content_hash_hex TEXT NOT NULL,
      recorded_at INTEGER NOT NULL,
      -- DOD-LOOP-1: composite key so each agent's end of a loopback session keeps its own set.
      PRIMARY KEY (agent_id, session_id, leaf_index)
    )
  `);

  // WHY a session has no certified leaf set — fallback-finder finding 1, and the reason it is a
  // TABLE rather than a log line.
  //
  // `getCertifiedLeafSet` returns null for four different situations: no seal frame ever carried
  // the leaves, the directory shipped a set that does not reproduce the root it signed, a leaf was
  // malformed, or the write failed. The worst of those — a directory contradicting its own FROST
  // signature — is the strongest misbehaviour signal this client can produce, and it was going to
  // one ERROR line while the operator was told the most benign of the four: "normal for the party
  // that was absent at seal time." A detection whose only consumer is a log is not a control.
  //
  // One row per session, replaced on every attempt, so the state is the LAST thing that happened
  // rather than a history. Read only by the inclusion-proof surface, to name the cause.
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_certified_leaves_state (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      state TEXT NOT NULL,
      detail TEXT,
      recorded_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id)
    )
  `);

  // DOD-M12B-STRAND-1 — content we RECEIVED and VERIFIED but cannot append yet.
  //
  // Held content used to live only in `#heldContent`, a Map that died with the session node. The
  // teardown path said so itself: "the content is unrecoverable by the time we are here."
  // Measured on one daemon in one morning: 367 held, 8 released, **24 destroyed**. Each
  // destruction is permanent and one-sided — the sender was never acknowledged, so it believes
  // the message is merely pending, while the only copy the receiver will ever see is gone and
  // every later message in that session is stuck behind a gap nothing can fill.
  //
  // `canonical_seq` is the RELAY's position, not a local counter, and it is part of the key: that
  // is what lets a frame come back after a restart and land at its OWN index rather than the next
  // free slot. Appending it anywhere else would change the root the seal signs over.
  //
  // Keyed on agent_id, never agent_name — agent_name is a mutable display label (see the repo
  // guide). `content_blob` is the SCREENED copy that gets delivered; `original_blob` is the peer's
  // raw bytes, which the release path needs because classification reads byte 0 and the screened
  // copy is no longer a CBOR map header for a document frame.
  db.exec(`
    CREATE TABLE IF NOT EXISTS held_content (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      canonical_seq INTEGER NOT NULL,
      content_blob BLOB NOT NULL,
      original_blob BLOB,
      content_hash_hex TEXT NOT NULL,
      screened_out INTEGER NOT NULL DEFAULT 0,
      correlation_id TEXT,
      held_at INTEGER NOT NULL,
      -- DOD-M12B-INDEX-1: 'received' (default) or 'sent'. A held frame of OUR OWN must be
      -- released down the sent path — appended and transcribed as sent — never down the received
      -- path, which would put our words in the counterparty's mouth in the sealed record and hand
      -- them back to our own agent through cello_receive as though they had just arrived.
      origin TEXT NOT NULL DEFAULT 'received',
      -- DOD-M12B-INDEX-1: 'msg' or 'doc'. A held document leaf must come back as a document leaf.
      leaf_kind TEXT NOT NULL DEFAULT 'msg',
      PRIMARY KEY (agent_id, session_id, canonical_seq)
    )
  `);

  // DOD-M12B-INDEX-1: `CREATE TABLE IF NOT EXISTS` is a NO-OP against a table that already
  // exists, so a database created between DOD-M12B-STRAND-1 and this change has `held_content`
  // WITHOUT `origin`. On those every insert throws and every restore throws — holds go back to
  // memory-only, silently at the surface, and that now includes our own sent messages, which
  // nobody else holds a copy of. Loud in the log is not the same as visible.
  try {
    db.exec("ALTER TABLE held_content ADD COLUMN origin TEXT NOT NULL DEFAULT 'received'");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!/duplicate column name/i.test(msg)) throw err;
  }
  // DOD-M12B-INDEX-1: and the LEAF KIND. `#releaseHeld` used to append every held frame as "msg",
  // so a document leaf that had to wait for its position came back as a conversation message —
  // the distinction survived the immediate append and was destroyed by the hold, unrecoverably
  // after a restart.
  try {
    db.exec("ALTER TABLE held_content ADD COLUMN leaf_kind TEXT NOT NULL DEFAULT 'msg'");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!/duplicate column name/i.test(msg)) throw err;
  }

  // DOD-LOG-1 (PERSIST-LOG-001) / PERSIST-002 (AC-010): the durable, ENCRYPTED-at-rest readable
  // transcript. Each row is keyed by the canonical leaf `sequence`, so it JOINS to
  // session_tree_leaves(leaf_index) — a stored message is provably behind a committed hash-chain
  // leaf, not a loose dump. `blob` holds the readable plaintext bytes; encryption at rest is now
  // provided by whole-DB SQLCipher, not a per-column cipher (relay/directory never see it — INV-3).
  db.exec(`
    CREATE TABLE IF NOT EXISTS transcript (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      direction TEXT NOT NULL,        -- 'sent' | 'received'
      blob BLOB NOT NULL,             -- readable plaintext bytes (whole-DB SQLCipher-encrypted at rest)
      created_at INTEGER NOT NULL,
      -- ─── DOD-M15-SEALWIRE-1 bullet 5: the row proves AUTHORSHIP, or says it cannot ──────────
      --
      -- Before this, a row was (message, direction) and attribution came entirely from local
      -- session state: "this arrived on the socket I believed was Bob's". That is fine while the
      -- transcript is only ever read by its owner, and worthless the moment it is shown to anyone
      -- else — which is the whole point of a notarized record.
      --
      -- sender_sig holds one of TWO things, and which one is told by direction:
      --   RECEIVED row -> the sender's signature over their own Structure-1 bytes, carried on the
      --                   content frame BESIDE those bytes, stored ONLY after the receiver
      --                   verified it against the pubkey inside them (#verifyAuthorshipClaim).
      --                   Verified, never claimed.
      --                   ⚠️ THIS USED TO READ "the Structure-2 signature ... (#recordFrameOrdering)"
      --                   and it named a real place: until DOD-M15-AUTHORSHIP-ABSENT-1 the only
      --                   copy of that signature this side ever saw was the one the RELAY had
      --                   committed at Structure-2 index 3, so a message with no relay record had
      --                   no checkable author at all. Rewritten rather than deleted: an auditor
      --                   reading the old sentence goes looking for Structure-2 bytes that, on a
      --                   relay-degraded message, do not exist.
      --   SENT row     -> OUR OWN signature over the Structure-1 bytes we put on the wire, taken
      --                   from the submit result. Produced, not verified — there was no
      --                   counterparty in the act, so it must NEVER be labelled verified_signature.
      --
      -- ⚠️ self_authored COVERS TWO PROVENANCES, and sender_sig IS NOT NULL is the discriminator.
      -- Named here because it is the same shape this column exists to prevent, one level up: a
      -- provable sent row and an unprovable one share a label, so a reader keying on attribution
      -- alone cannot tell them apart.
      --   self_authored + sender_sig NOT NULL -> we wrote it and can prove we did
      --   self_authored + sender_sig NULL     -> we wrote it; no proof was stored for this row
      --
      -- ⚠️ THE NULL CASE USED TO READ "the relay never witnessed it", and DOD-M15-AUTHORSHIP-ABSENT-1
      -- made that false. Every content frame now carries this side's signature over its own
      -- Structure 1 whether or not a relay witnessed the leaf, so an unwitnessed send is provable
      -- too. Rewritten rather than deleted: the old sentence is why a NULL here was read as
      -- ordinary. It is not ordinary now — it means this machine could not sign at all, or the row
      -- came by a path that carries no proof, and both are worth a second look.
      --
      -- attribution is NOT NULL ON PURPOSE, and it is the load-bearing column. There is a soft
      -- path — session.content.ordering.decode_failed falls back to hash-dedup — that ingests a
      -- message with no verified signature, so rows legitimately without one WILL exist. A
      -- nullable signature column and nothing else would rebuild the defect this bullet exists to
      -- fix: a table that IMPLIES every row carries authorship proof, where some carry none and
      -- nothing distinguishes them. Forcing every writer to name which it is makes silent NULL
      -- impossible rather than merely discouraged.
      sender_pubkey TEXT,             -- from INSIDE the sender's signed bytes; NULL unless verified
      sender_sig BLOB,                -- the VERIFIED sender signature over structure1_cbor (see above); NULL unless verified
      attribution TEXT NOT NULL DEFAULT 'local_session_state',  -- verified_signature | self_authored | local_session_state
      PRIMARY KEY (agent_id, session_id, sequence, direction)
    )
  `);

  /**
   * DOD-M15-REFUSEDEVIDENCE-1 — the refusal reason on a QUARANTINED row.
   *
   * `direction` takes a third value, `'quarantined'`: a message that was received and REFUSED. It
   * is stored the same way a delivered one is — plaintext blob, sender key, sender signature,
   * attribution — because a hash with no original proves nothing, and the messages worth proving
   * (an injection, a probe, a tampered frame) are exactly the refused ones.
   *
   * ⚠️ THE DIRECTION VALUE IS THE FLAG, AND THAT IS WHY IT IS NOT A BOOLEAN COLUMN. `direction` is
   * in the primary key and every delivery and unread reader already filters it with an equality
   * literal (`findNextReceivedAfter`, `#UNREAD_RECEIVED_WHERE`, `countReceivedMessages`). A row
   * written `'quarantined'` therefore cannot be returned by `WHERE direction = 'received'` — it is
   * excluded BY CONSTRUCTION, with no query edited and none left to remember. A boolean column
   * alone would have been exclusion by EDIT, which rebuilds `DOD-UNREAD-1 D4a`'s phantom-session
   * residue the first time a new query forgets the predicate.
   *
   * `attribution` needs no new value: the expression in `recordTranscriptMessage` is
   * `direction === "sent" ? … : authorship ? "verified_signature" : "local_session_state"`, and
   * `'quarantined'` is not `'sent'` — so a verified frame lands `verified_signature` and an
   * unverified one `local_session_state`, which is the distinction the column exists for.
   */
  // Through `addColumnIfMissing`, not a hand-rolled try/catch — review F7. A bare `ADD COLUMN`
  // wrapped in a duplicate-name test had already been written twice in this codebase, which is
  // why the helper exists; a third copy rethrows correctly but emits no `db.column_birth.failed`,
  // so a failure on a fresh operator's database would name neither the table nor the column. That
  // is exactly the case — the FIRST run on a new machine — the helper was extracted for.
  addColumnIfMissing(db, logger, {
    table: "transcript",
    column: "quarantine_reason",
    sql: "ALTER TABLE transcript ADD COLUMN quarantine_reason TEXT",
  });

  // M8C-INBOX-1 (N2): per-agent, per-session read watermark. `last_delivered_seq` is the highest
  // RECEIVED transcript sequence the operator has been shown via cello_receive (delivery marks
  // read — no ack verb). Unread = received transcript rows with sequence > last_delivered_seq.
  // Persisted so a missed doorbell (fire-and-forget push) is reconcilable via cello_check_notifications
  // across daemon restarts, not just within one process (INV-PUSHPULL). Additive table.
  db.exec(`
    CREATE TABLE IF NOT EXISTS message_watermarks (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      last_delivered_seq INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id)
    )
  `);

  // M8C-CONTACT-1: binary per-agent contact whitelist. This is an ACCESS-CONTROL LIST, not a
  // setting — it belongs alongside message_watermarks/sessions as its own real subsystem, not
  // behind the parked M9-CFG-001 config store. Identity PINS to the pubkey at add time (never
  // re-resolved); known stays known until explicitly removed (no TTL/expiry on membership).
  db.exec(`
    CREATE TABLE IF NOT EXISTS contacts (
      agent_id TEXT NOT NULL,
      pubkey TEXT NOT NULL,
      added_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, pubkey)
    )
  `);
  // MONIKER-3 AC1: the receiver's own pet name for a pubkey — the top tier of whoLabel.
  // SQLite has no ADD COLUMN IF NOT EXISTS, so the ALTER is PRAGMA-guarded to stay
  // idempotent; existing rows → NULL, no data loss.
  // M10B / DOD-END-SURFACE-1 — per-counterparty presentation choice.
  //
  // `default_present` on the signal answers "show this by default"; this answers "show THIS signal
  // to THIS person", which is the finer question an operator actually has: an endorsement that is
  // right for a prospective client is not necessarily right for a competitor. Absent row = no
  // opinion → the signal's own default applies, so this table only ever holds explicit choices.
  //
  // Keys on `agent_id`, never `agent_name` — the name is a mutable display label that is reusable
  // after retirement, so keying on it would silently hand a NEW agent the retired one's
  // disclosure choices. Same key as `contacts`, which this is an extension of.
  db.exec(`
    CREATE TABLE IF NOT EXISTS contact_signal_prefs (
      agent_id TEXT NOT NULL,
      contact_pubkey TEXT NOT NULL,
      signal_hash TEXT NOT NULL,
      present INTEGER NOT NULL,
      set_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, contact_pubkey, signal_hash)
    )
  `);
  /**
   * DOD-M15-SEALWIRE-1 bullet 5: authorship columns on an EXISTING transcript.
   *
   * BEFORE `migrateSessionTablesToAgentId` — the rebuild copies the intersection of old and new
   * columns, so a column added after it would be dropped on the upgrade boot and re-added empty.
   * These have their second entry in that migration's pinned DDL; `DOD-M15-MIGRATION-GUARD-1`
   * fails the build if the two ever disagree.
   *
   * `addColumnIfMissing` rather than a bare try/catch: it swallows ONLY `duplicate column name`
   * and rethrows anything else, so broken DDL cannot be mistaken for "already applied".
   */
  // Written as three LITERAL statements rather than a loop over a column array. A loop needs its
  // own parser in the guard (as retry_queue does); literals are read by the guard's generic one,
  // so these are replayed automatically and cannot fall outside it.
  addColumnIfMissing(db, logger, {
    table: "transcript", column: "sender_pubkey",
    sql: "ALTER TABLE transcript ADD COLUMN sender_pubkey TEXT",
  });
  addColumnIfMissing(db, logger, {
    table: "transcript", column: "sender_sig",
    sql: "ALTER TABLE transcript ADD COLUMN sender_sig BLOB",
  });
  addColumnIfMissing(db, logger, {
    table: "transcript", column: "attribution",
    sql: "ALTER TABLE transcript ADD COLUMN attribution TEXT NOT NULL DEFAULT 'local_session_state'",
  });

  const contactCols = db.prepare("PRAGMA table_info(contacts)").all() as Array<{ name: string }>;
  if (!contactCols.some((c) => c.name === "moniker")) {
    db.exec("ALTER TABLE contacts ADD COLUMN moniker TEXT");
  }

  // DOD-AGENT-ID-JOINKEY-1: finish REMOVE-001. Re-key the seven child tables from the mutable,
  // reuse-freed `agent_name` to the stable `agent_id`, in ONE transaction. Runs AFTER every
  // CREATE/ALTER above, so an existing table has its full historical column set before it is
  // rebuilt, and BEFORE any read below touches it. A no-op once the tables carry `agent_id`.
  //
  // `retry_queue` (the seventh) is created later, by RetryQueue's constructor. On an existing
  // database it already exists here and is re-keyed in the same transaction; on a fresh one it is
  // absent, is skipped, and RetryQueue then creates it directly in the re-keyed shape.
  migrateSessionTablesToAgentId(db, logger);

  /**
   * DOD-M15-DIVERGE-DURABLE-1: rehydrate the divergence set from `sessions.diverged_at`.
   *
   * AFTER `migrateSessionTablesToAgentId`, not with the column migrations that create the field.
   * The query joins `sessions.agent_id` to `agents`, and on a database written before REMOVE-001
   * that column does not exist until this migration adds it — placing the load earlier failed
   * with `no such column: s.agent_id` on exactly those legacy databases, which are the ones a
   * restart matters most for.
   */
  loadDivergedFromDb();

  // DOD-TIER-1 (address-book Step 1): give `contacts` its tier metadata (tier / provenance /
  // last_offered_moniker / away_message). Pure ADD COLUMN, no rebuild — so it runs AFTER the
  // agent-id re-key above (it never needs to appear in that migration's pinned DDL) and BEFORE any
  // read below. Idempotent, no column DEFAULT, grandfathers existing contacts to WHITELISTED once.
  migrateContactsAddTierMetadata(db, logger);

  // §1.1: normalize frost_commitments / frost_verifying_shares to ONE CBOR encoding. Registration
  // wrote them with the shared encoder; the refresh path wrote them with cbor-x's bare `encode`,
  // so an agent's share blobs changed format the first time it ran `cello_refresh_shares` and both
  // formats are on disk. Both producers now use encodeCbor; this rewrites what is already stored.
  // Idempotent (a canonical blob re-encodes to itself and is skipped) and per-row fail-safe (an
  // undecodable share is LEFT ALONE, never dropped — losing key material is worse than an old
  // encoding cbor-x still reads).
  migrateCborBlobsToCanonical(db, logger);

  // M8C-TGDOOR-1: daemon-wide Telegram settings (bot token + allowlisted operator chat). A
  // NEW dedicated table — NOT folded into the parked M9-CFG-001 config store, because a bot
  // token has no sensible default (a required credential, unlike AWAY/TTL/CONTACT's real
  // defaults) and can't legitimately wait for M9. Singleton row (id=1) — "token = daemon
  // setting" (DoD), not per-agent.
  db.exec(`
    CREATE TABLE IF NOT EXISTS telegram_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      bot_token TEXT NOT NULL,
      allowlisted_chat_id TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `);

  // DOD-RENAME-1 (Option C): pending rename notices — one per (agent, contact). A notice is queued
  // when a peer the operator has PERSONALLY NAMED offers a self-declared name that differs from the
  // last one seen; it surfaces through cello_check_notifications (NOT a real-time push) and clears
  // when the operator adopts a name (cello_contact_set_moniker) or removes the contact. Keyed on
  // agent_id (the stable key); the offered name is charset-validated at the wire boundary but still
  // operator-untrusted, so surfaces render it as a quoted CLAIM.
  db.exec(`
    CREATE TABLE IF NOT EXISTS contact_rename_notices (
      agent_id TEXT NOT NULL,
      pubkey TEXT NOT NULL,
      offered_name TEXT NOT NULL,
      noticed_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, pubkey)
    )
  `);

  /**
   * A PUBLIC KEY IS BYTES; ITS HEX CASE IS NOT PART OF ITS IDENTITY.
   *
   * ⚠️ **PLACED HERE FOR TWO ORDERING REASONS, and getting either wrong is a crash at boot.** It
   * touches all three contact-keyed tables, so it runs after the LAST of them exists
   * (`contact_rename_notices`, directly above); and the merge it performs on a collision keeps the
   * more restrictive TIER, which it cannot read until `migrateContactsAddTierMetadata` has added
   * that column.
   *
   * Normalizing the accessors alone would be worse than the bug for anyone who already has a
   * mixed-case row: the row becomes UNREACHABLE rather than merely wrong, taking its block, its
   * away message and its pet name with it. Idempotent and silent on a clean database.
   */
  foldContactPubkeyCase(db, logger);

  // DOD-M15-NO-SILENT-REFUSAL-1: refusal notices — one per (agent, session, reason). Written every
  // time an inbound message is refused; read by cello_receive and by the cello_inbox pull. Modelled
  // on contact_rename_notices above and keyed the same way, on agent_id (the stable key) — the map
  // this replaced was keyed on agent_name, a mutable display label, which was its second bug.
  //
  // DURABLE because the case this exists for is NOBODY ATTENDING. A notice held only in memory is
  // lost to a restart and is only ever surfaced to whoever happens to call cello_receive on that
  // exact session, which is a log line with extra steps.
  //
  // `content_refusal_reads` is the part rename notices do not need: they clear on operator action,
  // these are read non-destructively PER CONSUMER. Two MCP windows attending one agent is ordinary,
  // and under a single surfaced flag the first reader consumed the notice and the second was told
  // nothing, permanently.
  db.exec(`
    CREATE TABLE IF NOT EXISTS content_refusal_notices (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      kind TEXT NOT NULL,
      impact TEXT NOT NULL,
      guidance TEXT NOT NULL,
      count INTEGER NOT NULL,
      first_at INTEGER NOT NULL,
      last_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id, reason)
    )
  `);
  /**
   * DOD-M15-REFUSALTERMINAL-1 — the lifetime refusal count, which `content_refusal_notices` is
   * NOT and never was.
   *
   * `cello_dismiss` DELETEs the notice row (`dismissContentRefusals`), so `notices.count` restarts
   * at 1 after every dismissal. That is correct for the notice — the operator said "I know" and
   * the next announcement should describe what happened since — and it is exactly why the number
   * shown beside it cannot be described as a lifetime figure. Live on 2026-09-04 an inbox reported
   * `times: 58` for a refusal that had fired tens of thousands of times.
   *
   * A separate table rather than a column, because the two have different lifetimes: this one is
   * never deleted by anything an operator does. Same key, so the read is one LEFT JOIN.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS content_refusal_totals (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      total INTEGER NOT NULL,
      first_at INTEGER NOT NULL,
      last_at INTEGER NOT NULL,
      -- 1 when this row was SEEDED from an existing notice at upgrade rather than counted from
      -- the first refusal. Its total is then a LOWER BOUND, not a figure, and the drain reports
      -- it under a different field name so a reader cannot mistake one for the other.
      seeded INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (agent_id, session_id, reason)
    )
  `);
  /**
   * ⚠️ **THE BACKFILL, and without it this unit ships the original lie with the new name on it.**
   *
   * Review finding 1. A new table is created EMPTY. Every daemon that already has refusal notices
   * — including the one that produced this incident, whose notice sat at 58 — would report
   * `times_since_dismissed: 59` beside a `times_total` of **1**, on the very field the guidance
   * tells an operator to judge severity by. Smaller than the number it exists to dwarf.
   *
   * `count` is the best figure available at upgrade and it is a LOWER BOUND: dismissals before
   * this build deleted history nothing can recover. So the row is marked `seeded` and reported as
   * "at least", never as a total. A lower bound is a true statement; `total = 1` is not.
   *
   * `INSERT OR IGNORE` makes it idempotent and self-healing — it fills only rows that do not
   * exist, so a real counted total is never overwritten by a seeded one, and running it at every
   * boot costs one indexed scan of a table bounded by (sessions × reasons).
   */
  /**
   * ⚠️ **AND `CREATE TABLE IF NOT EXISTS` IS A NO-OP AGAINST A TABLE THAT ALREADY EXISTS** —
   * review F1b, and it is the same hazard `DOD-M12B-INDEX-1` records for `held_content.origin`
   * three hundred lines above.
   *
   * The table shipped one commit earlier WITHOUT `seeded`, and that build ran on a real daemon to
   * take this unit's live measurement. On that machine the `CREATE` does nothing, the backfill
   * below names a column that is not there, and the throw comes out of schema init — **the daemon
   * does not open at all.** The one machine that most needs the backfill is the one it would have
   * bricked.
   */
  try {
    db.exec("ALTER TABLE content_refusal_totals ADD COLUMN seeded INTEGER NOT NULL DEFAULT 0");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!/duplicate column name/i.test(msg)) throw err;
  }
  db.exec(`
    INSERT OR IGNORE INTO content_refusal_totals
      (agent_id, session_id, reason, total, first_at, last_at, seeded)
    SELECT agent_id, session_id, reason, count, first_at, last_at, 1
      FROM content_refusal_notices
  `);
  /**
   * ⚠️ **THE INVARIANT: a lifetime total can never be SMALLER than a since-dismissal count.**
   * Caught on the live daemon, not by review — the inbox read
   * `times_since_dismissed: 78, times_total: 12`.
   *
   * `INSERT OR IGNORE` above only fills rows that are ABSENT. A row that already exists but began
   * counting AFTER the notice did — the totals table shipped one commit before `seeded`, so its
   * rows default to 0 and claim to be exact — is left alone, and then presents a partial tally as
   * a lifetime figure. Smaller than the number beside it, which is the tell.
   *
   * `count` resets on dismissal and `total` does not, so in healthy operation `total >= count`
   * always. `count > total` therefore means one thing only: this row's total did not start at the
   * beginning. Repaired to the best floor available and marked `seeded`, because that is what it
   * is. Runs at every boot — it is also the repair for a totals write that failed while the
   * notice's succeeded.
   */
  db.exec(`
    UPDATE content_refusal_totals
       SET total = (SELECT n.count FROM content_refusal_notices n
                     WHERE n.agent_id = content_refusal_totals.agent_id
                       AND n.session_id = content_refusal_totals.session_id
                       AND n.reason = content_refusal_totals.reason),
           seeded = 1
     WHERE EXISTS (SELECT 1 FROM content_refusal_notices n
                    WHERE n.agent_id = content_refusal_totals.agent_id
                      AND n.session_id = content_refusal_totals.session_id
                      AND n.reason = content_refusal_totals.reason
                      AND n.count > content_refusal_totals.total)
  `);
  /**
   * DOD-M15-REFUSALTERMINAL-1 — content this agent will never accept, so the daemon stops going
   * to fetch it.
   *
   * **DURABLE BECAUSE THE DEFECT CROSSED RESTARTS.** The 62-hour loop spanned several `cello
   * login` cycles; a marker held in a `Set` on the manager would have passed every test and
   * shipped nothing.
   *
   * NOT the `'quarantined'` transcript row, which is the natural candidate and does not work: it
   * is keyed on the BYTES, and the fetch scheduler is keyed on the content hash the sender
   * committed to. On the two refusals where those provably differ (a tamper, an algorithm we
   * cannot read) the row cannot answer the question this table is asked.
   *
   * Keyed on `agent_id` — the stable key. `agent_name` is a display label.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS terminal_content_refusals (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      reason TEXT NOT NULL,
      marked_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id, content_hash)
    )
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS content_refusal_reads (
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      consumer_id TEXT NOT NULL,
      seen_count INTEGER NOT NULL,
      seen_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id, reason, consumer_id)
    )
  `);

  // DOD-SETTINGS-1: a daemon-side per-agent settings store for REACHABILITY POLICY (the tier bounds
  // overrides and the per-tier/agent away messages). A generic key-value table on the stable
  // agent_id, in the same SQLCipher DB. Deliberately NOT M9-CFG-001's gateway config store: this is
  // daemon reachability policy, not gateway SCREENING config, and the M9 store is unwired + plaintext.
  // reconcile with DOD-CONFIG-1 later; this is daemon reachability policy, not gateway config.
  db.exec(`
    CREATE TABLE IF NOT EXISTS agent_settings (
      agent_id TEXT NOT NULL,
      key TEXT NOT NULL,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, key)
    )
  `);

  // M10 / DOD-STORE-CLIENT-1: the two trust-signal tables (wallet + received). Created HERE and
  // deliberately last: `contact_trust_signals` carries a composite FK to `contacts(agent_id,
  // pubkey)`, so its parent must exist and must already have been through the agent-id re-key
  // above. SQLite resolves an FK's parent at DML time, not DDL time — so getting this order wrong
  // would not fail here, it would fail on the first insert, which is a far worse place to find out.
  ensureTrustSignalSchema(db, logger);

}
