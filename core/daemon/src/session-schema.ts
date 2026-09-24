/**
 * CELLO Daemon — THE SESSION DATABASE SCHEMA
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. Every CREATE TABLE the daemon's
 * session store needs, each in its final shape.
 *
 * Several columns exist because of a specific defect, and the prose beside them is the only record
 * of which one: the transcript's `attribution` column is NOT NULL precisely so that a row without
 * authorship proof cannot look like a row that has one.
 *
 * NO MIGRATIONS (M9D purge). CELLO is alpha and every daemon starts from a fresh CELLO home at the
 * M9D roll, so there is no older database to upgrade. A column change is an edit to its CREATE.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { ensureTrustSignalSchema } from "./trust-signal-store.js";

/**
 * Create every session-store table.
 *
 * `loadDivergedFromDb` is a CALLBACK rather than an import: the store that owns the divergence memo
 * lives elsewhere, and it must run after `sessions` exists.
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
      message_count INTEGER NOT NULL DEFAULT 0,
      interrupted_at TEXT,
      -- Decisions Carried #8: the session salt, agreed once at open from both sides' random
      -- contributions. Not a key. Persisted because a restart that minted a fresh one would split
      -- the transcript at the crash, every earlier leaf unverifiable.
      content_salt BLOB,
      -- DOD-M15-FREEZE-STATUS-1: when and why #freezeOnIdentityFailure fired. Written BEFORE
      -- destroySessionNode, which writes the revivable 'interrupted' status. NULL = never frozen.
      frozen_at INTEGER,
      frozen_reason TEXT,
      -- MSG-001-3b: the relay endpoint, so the crash-backstop flush can deposit un-acked content
      -- after a restart. relay_addrs is a JSON array of multiaddr strings.
      relay_peer_id TEXT,
      relay_addrs TEXT,
      -- 033-ACKEMIT: the genesis prev_root. It depends on the session timestamp, which arrives only
      -- on the signed assignment; a session restored after a restart has no assignment in hand.
      genesis_prev_root BLOB,
      -- 069-ORDERPROOF: the ack-signing pubkey of the relay the directory assigned. NULL for a
      -- direct session, which has no relay.
      relay_anchor_hex TEXT,
      -- M7-SESSION-004: the seal certificate's legibility object (JSON) and sealed root. NULL until sealed.
      seal_legibility TEXT,
      sealed_root_hex TEXT,
      -- The counterparty's FROST primary, ML-DSA-44 and ML-KEM-768 public keys (hex), recorded
      -- together and only after their v2 key binding verified (M9D 002-PQKEYS). Read through
      -- counterpartyPqKeys, never directly.
      counterparty_primary_pubkey TEXT,
      counterparty_ml_dsa_pubkey TEXT,
      counterparty_ml_kem_pubkey TEXT,
      -- DOD-SESSION-NAME-1: the operator's own label. Local and cosmetic; never on the wire, in the
      -- transcript or in the seal. NULL means unnamed — never auto-generate one.
      session_name TEXT,
      -- DOD-SEALED-INBOX-1: epoch-ms set by cello_dismiss. Local housekeeping only.
      read_at INTEGER,
      -- DOD-M12B-ABANDON-NOTIFY-1: when the counterparty said they force-abandoned. Not a status:
      -- the session stays sealable.
      counterparty_abandoned_at INTEGER,
      -- DOD-CAP-SELF-HEAL-1: 'counterparty' or 'local'. Only the counterparty's counts against the
      -- acceptance bound.
      interrupted_by TEXT,
      -- DOD-M12B-RESTART-SEAL-1: when automatic sealing gave up, and why, so a restart does not
      -- re-run the whole budget against a hopeless session.
      restart_seal_gave_up_at INTEGER,
      restart_seal_gave_up_reason TEXT,
      -- DOD-M15-DIVERGE-DURABLE-1: when the tree and the relay's counter provably parted. Durable
      -- because "not diverged" and "forgotten" both read false.
      diverged_at INTEGER,
      -- DOD-LOOP-1: composite key so two of the operator's agents can hold both ends of the
      -- SAME session_id on ONE daemon (the loopback case).
      -- DOD-AGENT-ID-JOINKEY-1: keyed on the STABLE agent_id, never the mutable agent_name.
      PRIMARY KEY (agent_id, session_id)
    )
  `);

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

  /**
   * `DOD-M15-NOTACCEPTING-1` — THE COUNTERPARTY REFUSED A SESSION **WE** OPENED.
   *
   * The mirror of `refused_sessions` above, which records sessions WE declined. This one is the
   * caller's half, and it is durable for the same reason: the refusal arrives about a millisecond
   * after `cello_initiate_session` has already returned, so there is no call left to answer with it
   * — the operator learns of it on their next send, read or inbox, which may be after a restart.
   *
   * ⚠️ NO COUNTERPARTY PROSE IS STORED. Only the reason CODE crosses the wire into this table, and
   * the sentence shown to the operator is written locally from it (`counterparty-refusal.ts`).
   * Storing their `guidance` string would put an arbitrary peer's paragraph in front of the
   * operator's agent, which is an injection surface reachable by anyone who can refuse a session.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS counterparty_refusals (
      agent_id   TEXT NOT NULL,
      session_id TEXT NOT NULL,
      reason     TEXT NOT NULL,
      refused_at INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id)
    )
  `);

  /**
   * `DOD-M15-NOTACCEPTING-1` D10 — WHO knocked and was turned away, so the operator can whitelist
   * them or call them back.
   *
   * ⚠️ **KEYED ON THE CALLER, NOT ON THE SESSION, AND THAT IS THE ANTI-SPAM CONTROL.**
   * `refused_sessions` above is keyed on session id and every knock carries a fresh
   * directory-assigned one, so it writes one row per knock and prunes to the most recent N — which
   * means a flooder does not merely fill it, **they evict every genuine caller from it**, and the
   * list still looks complete afterwards. Here volume adds no rows: a thousand knocks from one key
   * is one row with `times` at a thousand, and nobody can be pushed off by someone else's traffic.
   * A row cap over the wrong key is a mute button with the operator's name on it.
   *
   * It carries nothing the CALLER chose — in particular not the name they offered for themselves,
   * which a peer refused at the gate must not get to put in front of the operator.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS refused_callers (
      agent_id            TEXT NOT NULL,
      counterparty_pubkey TEXT NOT NULL,
      first_refused_at    INTEGER NOT NULL,
      last_refused_at     INTEGER NOT NULL,
      times               INTEGER NOT NULL,
      last_reason         TEXT NOT NULL,
      PRIMARY KEY (agent_id, counterparty_pubkey)
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
      quarantine_reason TEXT,         -- DOD-M15-REFUSEDEVIDENCE-1; see below
      PRIMARY KEY (agent_id, session_id, sequence, direction)
    )
  `);

  /**
   * DOD-M15-REFUSEDEVIDENCE-1 — `quarantine_reason`, the refusal reason on a QUARANTINED row.
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

  /**
   * DOD-M15-DELIVERYACK-1 — the counterparty's SIGNATURE saying their machine received a message.
   *
   * One row per (agent, session, content hash), written only after the signature verified against
   * the session's RECORDED counterparty key. `INSERT OR IGNORE` on that key is the idempotence: a
   * replayed acknowledgement changes nothing, and the first one recorded stands.
   *
   * ⚠️ THIS IS NOT A CHAIN LEAF AND MUST NEVER BECOME ONE. Machine traffic does not enter the
   * tamper-evident record — an acknowledgement in the tree would double the length of every
   * conversation and make the daemon a participant in it. Nothing in the seal, the Merkle tree, the
   * transcript or `last_seen_seq` reads this table; it is read by the receipt surface only.
   *
   * ⚠️ AND ITS ABSENCE MEANS NOTHING. A message with no row here was very possibly delivered and
   * read: the acknowledgement may have been lost with the connection, the counterparty's daemon may
   * have had no identity key to sign with, or their build may predate this. Any surface that reads
   * a missing row as evasion — a score, a status, a counter that reads as fault — is a defect.
   *
   * Keyed on agent_id, never agent_name: agent_name is a mutable display label.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS delivery_acks (
      agent_id         TEXT    NOT NULL,
      session_id       TEXT    NOT NULL,
      content_hash_hex TEXT    NOT NULL,
      signer_pubkey    TEXT    NOT NULL,
      signature        BLOB    NOT NULL,
      recorded_at      INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id, content_hash_hex)
    )
  `);
  /**
   * The acknowledgements THIS side signed for messages it received — the other half of the seal
   * answer's `delivery_ack`. A separate table, not rows in `delivery_acks`: both sides can send
   * identical bytes, and a shared key on the hash would let our own signature stand in for theirs.
   */
  /**
   * The last acknowledgement the live path made per session: the RELAY position and the content
   * hash at it, exactly as signed into this side's claims. A resumed session starts from here, so a
   * restart cannot reset it to 0 (every close refused as stale) or guess it from the local leaf
   * index (which can drift one ahead of the relay). Forward-only.
   */
  /**
   * Where a MAILBOX-recovered message sits, as its sender's ordering record claims. Not seal
   * evidence and never carried to a seal: that record is not relay-signed. The seal answer uses it
   * only to place a message no relay acknowledgement reached, and the sealed root decides whether
   * the claimed positions were right.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_recovered_positions (
      agent_id   TEXT    NOT NULL,
      session_id TEXT    NOT NULL,
      relay_seq  INTEGER NOT NULL,
      hash_hex   TEXT    NOT NULL,
      sender_hex TEXT    NOT NULL,
      PRIMARY KEY (agent_id, session_id, relay_seq)
    )
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_last_ack (
      agent_id   TEXT    NOT NULL,
      session_id TEXT    NOT NULL,
      relay_seq  INTEGER NOT NULL,
      hash_hex   TEXT    NOT NULL,
      PRIMARY KEY (agent_id, session_id)
    )
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS delivery_acks_given (
      agent_id         TEXT    NOT NULL,
      session_id       TEXT    NOT NULL,
      content_hash_hex TEXT    NOT NULL,
      signer_pubkey    TEXT    NOT NULL,
      signature        BLOB    NOT NULL,
      recorded_at      INTEGER NOT NULL,
      PRIMARY KEY (agent_id, session_id, content_hash_hex)
    )
  `);

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
      -- MONIKER-3 AC1: the receiver's own pet name for a pubkey — the top tier of whoLabel.
      moniker TEXT,
      -- DOD-TIER-1: reachability tier (TIER in contact-tier.ts; NULL reads as UNKNOWN via
      -- normalizeTier), how the relationship began, the last self-declared name the peer offered
      -- (rename detection), and a per-contact away message.
      tier INTEGER,
      provenance TEXT,
      last_offered_moniker TEXT,
      away_message TEXT,
      PRIMARY KEY (agent_id, pubkey)
    )
  `);
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
  // DOD-M15-DIVERGE-DURABLE-1: rehydrate the divergence set from `sessions.diverged_at`.
  loadDivergedFromDb();

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
      PRIMARY KEY (agent_id, session_id, reason)
    )
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
  // pubkey)`, so its parent must exist. SQLite resolves an FK's parent at DML time, not DDL time — so getting this order wrong
  // would not fail here, it would fail on the first insert, which is a far worse place to find out.
  ensureTrustSignalSchema(db, logger);

}
