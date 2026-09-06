/**
 * CELLO Daemon — THE THINGS THIS DAEMON REMEMBERS ABOUT A CONVERSATION
 *
 * Split out of `session-node-manager.ts` by 036-GODFILE: contacts and their access tiers, per-agent
 * settings, the transcript (written, read, and counted as unread), and whether a session's local
 * chain has diverged from the relay's.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ EVERY QUERY IN HERE JOINS ON `agent_id`, NEVER `agent_name`. The name is a display label — it
 * is mutable and reusable after retirement — so joining on it silently attaches one agent's rows to
 * another's. `#requireAgentId` is the only way in.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { normalizeContactPubkey } from "./contact-pubkey-case.js";
import { TIER, normalizeTier, isKnownTierValue, tierBoundsFor } from "./contacts-tier-migration.js";
import { boundSettingKey, settableTierName, isValidSettingKey } from "./agent-settings-keys.js";
import { MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
import { type TranscriptEntry, UNREAD_RECEIVED_WHERE, TERMINAL_STATUSES } from "./session-node-types.js";
import { quarantineRedaction } from "./quarantine-framing.js";

/** What this module needs from the manager, stated explicitly rather than handed `this`. */
export interface SessionRecordsContext {
  readonly logger: Logger;
  /**
   * A FUNCTION, because the manager opens its database after construction — a value snapshotted at
   * wiring time would be null for the life of the process. Re-exposed below as a private getter so
   * the moved code still reads `this.#db` and still narrows exactly as it did.
   */
  db(): DaemonDatabase | null;
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  /** The relay-witness-unreadable memo, which the relay client also writes. */
  readonly witnessUnreadable: Map<string, Map<string, { why: string; count: number }>>;
}

export class SessionRecords {
  readonly #ctx: SessionRecordsContext;

  constructor(ctx: SessionRecordsContext) {
    this.#ctx = ctx;
  }

  /** See `SessionRecordsContext.db` — a getter so the moved queries are unchanged. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  #diverged = new Set<string>();
  /** M8C-CONTACT-1: is this pubkey a known contact of this agent? */
  isContact(agentName: string, pubkey: string): boolean {
    if (!this.#db) return false;
    const row = this.#db.prepare("SELECT 1 FROM contacts WHERE agent_id = ? AND pubkey = ?").get(this.#ctx.requireAgentId(agentName), normalizeContactPubkey(pubkey));
    return row !== undefined;
  }
  /** DOD-TIER-1: the reachability tier for a counterparty of this agent. The RESULT is total — an
   *  absent contact row (undefined), a NULL `tier`, or a corrupt out-of-range value all resolve to
   *  UNKNOWN via `normalizeTier`, so the return is always in 0..4 and guards the JS `null >= 0`/`0 ||
   *  1`/`grid[99]` traps. It is a SECURITY read (Step 2 gates inbound bounds on it), so it FAILS
   *  CLOSED, never open: an uninitialized DB throws (same contract as addContact) rather than
   *  silently returning UNKNOWN and admitting a BLOCKED sender; an unresolvable/retired agent name
   *  throws via #requireAgentId. Both are invariant violations a caller must surface, not swallow. */
  getTier(agentName: string, pubkey: string): number {
    // Fail CLOSED: a read that decides whether to admit a sender must not degrade to "unclassified"
    // when it cannot reach the ACL — that would admit a blocked contact. Throw as addContact does.
    if (!this.#db) throw new Error(`getTier('${agentName}'): database not initialized`);
    const row = this.#db
      .prepare("SELECT tier FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(this.#ctx.requireAgentId(agentName), normalizeContactPubkey(pubkey)) as { tier: number | null } | undefined;
    if (row && row.tier !== null && !isKnownTierValue(row.tier)) {
      // A stored tier outside 0..4 is corruption — surface it. normalizeTier still maps it to the
      // tighter UNKNOWN so the caller is safe, but a silent map would hide a broken row.
      this.#ctx.logger.warn("contact.tier.corrupt", { agentName, pubkey, storedTier: row.tier });
    }
    return normalizeTier(row?.tier);
  }
  /** DOD-TIER-BOUNDS-SETTINGS: the effective bound for (agent, tier, field) — a per-agent SETTINGS
   *  override if one is set and valid, else the hardcoded grid default (DEFAULT_TIER_BOUNDS). With no
   *  settings this is byte-identical to Step 2 (the daemon runs on defaults alone). A stored value
   *  that is somehow non-positive/non-finite (should be impossible — validated at SET time) falls back
   *  to the grid default rather than removing the bound (INV-TIER-BOUND, defensive). BLOCKED is never
   *  settable — it always returns the fixed grid value (0). */
  resolveTierBound(agentName: string, tier: number, field: "max_sessions" | "max_bytes"): number {
    const gridDefault = field === "max_sessions"
      ? tierBoundsFor(tier).maxSessionsPerSender
      : tierBoundsFor(tier).maxBytesPerSession;
    const name = settableTierName(tier);
    if (name === null) return gridDefault; // BLOCKED or out-of-range — fixed, not overridable
    const raw = this.getSetting(agentName, boundSettingKey(name, field));
    if (raw === null) return gridDefault; // unset → default
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      // Should be impossible (validated at SET time) → a config-integrity failure. Surface it: this
      // reverts a possibly-TIGHTENED bound to the looser default, so a silent revert would hide a real
      // problem. Still fail SAFE (grid default, never unbounded — INV-TIER-BOUND).
      this.#ctx.logger.warn("settings.bound.corrupt", { agentName, tier, field, raw });
      return gridDefault;
    }
    return parsed;
  }
  /** M8C-CONTACT-1: pin a contact at add time — idempotent (re-adding an existing contact is a
   *  no-op, never refreshes added_at; identity does not get re-resolved). MONIKER-3 AC2: an
   *  optional pet name; a NEW non-null moniker on re-add updates it, absence leaves it untouched.
   *  THROWS on an invalid moniker — callers validate first; this is the can-never-be-stored
   *  backstop (same contract as DbIdentityStore.setMoniker).
   *
   *  DOD-TIER-1/4: a NEW row is stamped `tier` (never NULL) and an optional `provenance`
   *  ('accepted' | 'initiated' | null). The `tier` defaults to the least-privilege UNKNOWN floor —
   *  a caller GRANTS trust by passing a higher tier explicitly. Every production creation path is a
   *  deliberate operator action and passes KNOWN (initiate, engage/reply, explicit cello_contact_add
   *  — DEC-AB-1). INSERT OR IGNORE means an EXISTING contact is untouched — tier and provenance pin
   *  at first add, exactly as `added_at`/`moniker` already do; re-adding never downgrades a contact
   *  the operator has since promoted. Raising the tier later is `cello_contact_set_tier`'s job. */
  addContact(agentName: string, pubkey: string, moniker?: string | null, provenance?: string | null, tier: number = TIER.UNKNOWN): void {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!pubkey) return;
    // Review F1: a missing DB handle must FAIL the write loudly — returning silently here let
    // the handler log contact.added and report ok:true for a row that never landed.
    if (!this.#db) throw new Error(`addContact('${agentName}'): database not initialized`);
    if (moniker !== undefined && moniker !== null && validateMoniker(moniker) === null) {
      throw new Error(`invalid contact moniker for agent '${agentName}': must match ${MONIKER_RE.source}`);
    }
    // DOD-TIER-4 (review F3): the stored tier must be a known 0..4 constant — a can-never-be-stored
    // backstop mirroring the moniker validation above. All callers pass a TIER constant; this catches
    // a future caller (or a bad refactor) that would otherwise persist a corrupt tier the read side
    // must then defensively normalize.
    if (!isKnownTierValue(tier)) {
      throw new Error(`invalid contact tier for agent '${agentName}': ${tier} (must be 0..4)`);
    }
    const agentId = this.#ctx.requireAgentId(agentName);
    this.#db
      .prepare("INSERT OR IGNORE INTO contacts (agent_id, pubkey, added_at, tier, provenance) VALUES (?, ?, ?, ?, ?)")
      .run(agentId, pubkey, Date.now(), tier, provenance ?? null);
    if (moniker !== undefined && moniker !== null) {
      this.#db
        .prepare("UPDATE contacts SET moniker = ? WHERE agent_id = ? AND pubkey = ?")
        .run(moniker, agentId, pubkey);
    }
  }
  /** MONIKER-3 AC3: rename (string) or clear (null) an EXISTING contact's pet name. Returns false
   *  when no such contact — fail-loud at the caller, never a silent no-op success. Same
   *  validate-throw backstop as addContact. */
  setContactMoniker(agentName: string, pubkey: string, moniker: string | null): boolean {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    // Review F2: false means exactly "no such contact" — a null DB handle throws instead, so the
    // operator is never sent chasing a nonexistent missing-contact problem.
    if (!this.#db) throw new Error(`setContactMoniker('${agentName}'): database not initialized`);
    if (moniker !== null && validateMoniker(moniker) === null) {
      throw new Error(`invalid contact moniker for agent '${agentName}': must match ${MONIKER_RE.source}`);
    }
    const res = this.#db
      .prepare("UPDATE contacts SET moniker = ? WHERE agent_id = ? AND pubkey = ?")
      .run(moniker, this.#ctx.requireAgentId(agentName), pubkey);
    // DOD-RENAME-1: setting the local pet name IS the operator acting on a rename — resolve any
    // pending notice for this contact (whether they adopted the offered name or chose their own).
    if (res.changes > 0) this.clearRenameNotice(agentName, pubkey);
    return res.changes > 0;
  }
  /**
   * M10B / DOD-END-SURFACE-1 — decide whether ONE signal is presented to ONE counterparty.
   *
   * `present: null` CLEARS the choice, which is not the same as `false`: cleared means "no opinion,
   * use the signal's own default", while false means "specifically not this person". Collapsing
   * them would make an operator unable to undo an omission without knowing what the default was.
   *
   * Deliberately does NOT require an existing contact row, unlike the tier/moniker/away setters. A
   * decision about what to disclose is meaningful before a relationship is established — indeed
   * that is when it matters most — and refusing here would force the operator to add someone as a
   * contact in order to withhold something from them.
   */
  setContactSignalPref(agentName: string, pubkey: string, signalHash: string, present: boolean | null): void {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) throw new Error(`setContactSignalPref('${agentName}'): database not initialized`);
    const agentId = this.#ctx.requireAgentId(agentName);
    if (present === null) {
      this.#db
        .prepare("DELETE FROM contact_signal_prefs WHERE agent_id = ? AND contact_pubkey = ? AND signal_hash = ?")
        .run(agentId, pubkey, signalHash);
      this.#ctx.logger.info("signal.presentation.pref.cleared", { agentName, pubkey: pubkey.slice(0, 16), signalHash: signalHash.slice(0, 16) });
      return;
    }
    this.#db
      .prepare(
        `INSERT INTO contact_signal_prefs (agent_id, contact_pubkey, signal_hash, present, set_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(agent_id, contact_pubkey, signal_hash) DO UPDATE SET present = excluded.present, set_at = excluded.set_at`,
      )
      .run(agentId, pubkey, signalHash, present ? 1 : 0, Date.now());
    this.#ctx.logger.info("signal.presentation.pref.set", {
      agentName, pubkey: pubkey.slice(0, 16), signalHash: signalHash.slice(0, 16), present,
    });
  }
  /**
   * The explicit per-counterparty choices for this contact: signal hash → present.
   *
   * A signal ABSENT from this map has no choice recorded and falls back to its own
   * `default_present`. Returns an EMPTY map on an uninitialised DB rather than throwing, because
   * this is a preference read on the presentation path and losing preferences must not break a
   * session — but note the direction that failure takes: with no preferences, `default_present`
   * decides, and consent still gates everything upstream in SQL. It can therefore only fall back to
   * the operator's standing default, never to disclosing something consent has not cleared.
   */
  getContactSignalPrefs(agentName: string, pubkey: string): Map<string, boolean> {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) return new Map();
    const rows = this.#db
      .prepare("SELECT signal_hash, present FROM contact_signal_prefs WHERE agent_id = ? AND contact_pubkey = ?")
      .all(this.#ctx.requireAgentId(agentName), pubkey) as Array<{ signal_hash: string; present: number }>;
    return new Map(rows.map((r) => [r.signal_hash, r.present !== 0]));
  }
  /** DOD-AWAY-TIER-1: set (or clear, with null) a contact's per-contact away message. Returns false
   *  when no such contact — fail-loud at the caller (same contract as setContactMoniker/setContactTier). */
  setContactAwayMessage(agentName: string, pubkey: string, message: string | null): boolean {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) throw new Error(`setContactAwayMessage('${agentName}'): database not initialized`);
    const res = this.#db
      .prepare("UPDATE contacts SET away_message = ? WHERE agent_id = ? AND pubkey = ?")
      .run(message, this.#ctx.requireAgentId(agentName), pubkey);
    return res.changes > 0;
  }
  /** DOD-CONTACT-VIEW-1: set an EXISTING contact's reachability tier. Returns false when no such
   *  contact — fail-loud at the caller, never a silent no-op success (same contract as
   *  setContactMoniker). The caller validates the tier is a known constant BEFORE calling; this
   *  stores whatever it is handed (the handler is the validation boundary). */
  setContactTier(agentName: string, pubkey: string, tier: number): boolean {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) throw new Error(`setContactTier('${agentName}'): database not initialized`);
    const res = this.#db
      .prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?")
      .run(tier, this.#ctx.requireAgentId(agentName), pubkey);
    return res.changes > 0;
  }
  /** DOD-RENAME-1 (Option C): record a self-declared name a peer offered, at the moment the offer is
   *  SEEN. The stored local pet name (contacts.moniker) is SACROSANCT — this only ever touches
   *  last_offered_moniker and the notice queue, never the moniker (AC2). A rename NOTICE is queued
   *  only when the peer is a contact the operator has PERSONALLY NAMED (moniker non-null), a name was
   *  seen BEFORE (last_offered_moniker non-null), and the new offer DIFFERS (AC3). The first-ever
   *  offer just records the baseline (no notice); a repeat of the same name is idempotent (AC4).
   *  Called only when a moniker WAS offered (caller-guarded), so silence never clears the baseline
   *  (AC5). Limitation: last_offered_moniker updates only on the RECEIVING side of an offer, so rename
   *  detection works only for peers who INITIATE to you — a property, not a bug. */
  recordOfferedMoniker(agentName: string, pubkey: string, offered: string): void {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    // Fail CLOSED like getTier/setContactTier: a silent skip here would drop a rename baseline update
    // (and any notice) while the daemon reports healthy — the inbound path always has an open DB.
    if (!this.#db) throw new Error(`recordOfferedMoniker('${agentName}'): database not initialized`);
    const agentId = this.#ctx.requireAgentId(agentName);
    const row = this.#db
      .prepare("SELECT last_offered_moniker, moniker FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(agentId, pubkey) as { last_offered_moniker: string | null; moniker: string | null } | undefined;
    if (!row) return; // not a contact — no row to hold a baseline or a notice
    if (offered === row.last_offered_moniker) return; // idempotent — same name already seen (AC4)
    // A genuine change from a previously-seen name, for a contact the operator has named → notice.
    if (row.last_offered_moniker !== null && row.moniker !== null) {
      this.#db
        .prepare("INSERT OR REPLACE INTO contact_rename_notices (agent_id, pubkey, offered_name, noticed_at) VALUES (?, ?, ?, ?)")
        .run(agentId, pubkey, offered, Date.now());
      // Observability: log the FACT, never the attacker-chosen name (same rule as moniker.rejected).
      this.#ctx.logger.info("contact.rename.noticed", { agentName, pubkey });
    }
    this.#db
      .prepare("UPDATE contacts SET last_offered_moniker = ? WHERE agent_id = ? AND pubkey = ?")
      .run(offered, agentId, pubkey);
  }
  /** M8C-CONTACT-1: known stays known until explicitly removed. */
  removeContact(agentName: string, pubkey: string): boolean {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) return false;
    const res = this.#db.prepare("DELETE FROM contacts WHERE agent_id = ? AND pubkey = ?").run(this.#ctx.requireAgentId(agentName), pubkey);
    // DOD-RENAME-1: a removed contact has no pending rename to resolve.
    if (res.changes > 0) this.clearRenameNotice(agentName, pubkey);
    /**
     * OUTSIDE the `changes > 0` guard — review N2, and inside it the F2 fix did nothing for the
     * case that matters.
     *
     * The pin is written on every ACCEPTED INBOUND session. A contact row is written only on an
     * outbound initiate, an explicit add, a reply, or a trust-signal presentation — and an inbound
     * requester is deliberately NOT auto-added. So a counterparty you never replied to (away-mode
     * auto-ack is exactly this) has a pin and no contact row.
     *
     * Guarded, `cello_contact_remove` for them returned `{ ok: true, removed: false }`, cleared
     * nothing, and the identity refusal stayed permanent — the original lockout, now wearing an
     * `ok: true`, which is harder to notice than the original.
     */
    const pinsCleared = this.clearPinnedCounterpartyPrimary(agentName, pubkey);
    return res.changes > 0 || pinsCleared > 0;
  }
  /** MONIKER-4: the operator's pet name for a pubkey (whoLabel's top tier), or null. Read-only
   *  and tolerant of a not-yet-open DB (a missing label degrades the doorbell, never blocks it). */
  getContactMoniker(agentName: string, pubkey: string): string | null {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) {
      // Review F2: the last fully-silent branch in the resolution chain — the label degrades to
      // fingerprint, which is correct, but say so rather than returning null wordlessly.
      this.#ctx.logger.debug("moniker.local.db_unavailable", { agentName, pubkey });
      return null;
    }
    const row = this.#db
      .prepare("SELECT moniker FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(this.#ctx.requireAgentId(agentName), pubkey) as { moniker: string | null } | undefined;
    return row?.moniker ?? null;
  }
  /** M8C-CONTACT-1 + DOD-CONTACT-VIEW-1: list an agent's contacts, oldest-added first, each with its
   *  pet name (MONIKER-3), tier + provenance (the address-book metadata), and a READ-side LEFT JOIN
   *  against `sessions` for how many SEALED sessions were shared and when they last spoke (MAX
   *  updated_at). No new stored data — a pure read. A contact with no sessions shows 0 / null (never),
   *  not an error. The JOIN is scoped by agent_id so one agent's sessions never bleed into another's. */
  listContacts(agentName: string): Array<{
    pubkey: string; added_at: number; moniker: string | null;
    tier: number | null; provenance: string | null; sealed_count: number; last_spoke: number | null;
  }> {
    if (!this.#db) return [];
    return this.#db
      .prepare(
        `SELECT c.pubkey, c.added_at, c.moniker, c.tier, c.provenance,
                COUNT(CASE WHEN s.status = 'sealed' THEN 1 END) AS sealed_count,
                MAX(s.updated_at) AS last_spoke
         FROM contacts c
         LEFT JOIN sessions s ON s.agent_id = c.agent_id AND s.counterparty_pubkey = c.pubkey
         WHERE c.agent_id = ?
         GROUP BY c.pubkey, c.added_at, c.moniker, c.tier, c.provenance
         ORDER BY c.added_at ASC`,
      )
      .all(this.#ctx.requireAgentId(agentName)) as Array<{
        pubkey: string; added_at: number; moniker: string | null;
        tier: number | null; provenance: string | null; sealed_count: number; last_spoke: number | null;
      }>;
  }
  /** DOD-RENAME-1: clear a pending rename notice — the operator acted (adopted a name or removed the
   *  contact). Idempotent (no notice → no-op). Fail-closed on a missing DB, like the writes above. */
  clearRenameNotice(agentName: string, pubkey: string): void {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) throw new Error(`clearRenameNotice('${agentName}'): database not initialized`);
    this.#db
      .prepare("DELETE FROM contact_rename_notices WHERE agent_id = ? AND pubkey = ?")
      .run(this.#ctx.requireAgentId(agentName), pubkey);
  }
  /**
   * Forget the pinned threshold group key for a counterparty, so the next session re-pins.
   *
   * DOD-M15-OFFER-SIGNED-1 review F2 — WITHOUT THIS THE REFUSAL WAS PERMANENT. The identity-change
   * check refuses a counterparty whose group key differs from the one recorded in an earlier
   * session, and its guidance told the operator to confirm out of band and then remove the contact
   * so the new identity is pinned afresh. `removeContact` deleted a row in `contacts`; the pin lives
   * in `sessions.counterparty_primary_pubkey`, and nothing in the daemon ever cleared it.
   *
   * So an operator who did exactly as instructed — called their counterparty, confirmed the
   * re-registration was genuine, removed the contact, retried — got the identical refusal, with no
   * way out short of editing the database. A security control that cannot be reset by the person it
   * protects is a lockout, and the printed remedy made it worse by reading as though it worked.
   *
   * Nulls the column rather than deleting the session rows: those rows are the transcript record,
   * and a re-pin is not a reason to lose them.
   */
  clearPinnedCounterpartyPrimary(agentName: string, counterpartyPubkeyHex: string): number {
    if (!this.#db) return 0;
    const res = this.#db
      .prepare(
        // NO `updated_at` BUMP — review N6. `CAP_COUNTS` counts an interrupted session only while
        // `updated_at` is inside the staleness window, so touching it here reset the clock on every
        // stale session with that counterparty, re-inflating their per-sender cap — while removing
        // the contact simultaneously dropped them to UNKNOWN tier, which LOWERS it. The operator
        // follows the printed remedy and their counterparty's next session is refused for cap,
        // through a reason string deliberately identical to every other refusal. A second lockout
        // that says nothing. Nothing needs the timestamp: every candidate row ends up NULL.
        "UPDATE sessions SET counterparty_primary_pubkey = NULL WHERE agent_id = ? AND counterparty_pubkey = ?",
      )
      .run(this.#ctx.requireAgentId(agentName), counterpartyPubkeyHex);
    return Number(res.changes);
  }
  /** M8C-TGDOOR-1: the daemon-wide Telegram bot settings, or null if never configured. */
  getTelegramSettings(): { botToken: string; allowlistedChatId: string } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT bot_token, allowlisted_chat_id FROM telegram_settings WHERE id = 1")
      .get() as { bot_token: string; allowlisted_chat_id: string } | undefined;
    return row ? { botToken: row.bot_token, allowlistedChatId: row.allowlisted_chat_id } : null;
  }
  /** M8C-TGDOOR-1: persist (or replace) the singleton Telegram settings row. */
  setTelegramSettings(botToken: string, allowlistedChatId: string): void {
    if (!this.#db) return;
    this.#db
      .prepare(
        `INSERT INTO telegram_settings (id, bot_token, allowlisted_chat_id, updated_at) VALUES (1, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET bot_token = excluded.bot_token, allowlisted_chat_id = excluded.allowlisted_chat_id, updated_at = excluded.updated_at`,
      )
      .run(botToken, allowlistedChatId, Date.now());
  }
  /** DOD-SETTINGS-1: read a per-agent setting, or null if unset. The get-with-default is the CALLER's
   *  job (an unset key falls back to the hardcoded grid/system default — the daemon runs correctly on
   *  defaults alone, AC3). Returns null on a missing DB (settings are always optional). */
  getSetting(agentName: string, key: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT value FROM agent_settings WHERE agent_id = ? AND key = ?")
      .get(this.#ctx.requireAgentId(agentName), key) as { value: string } | undefined;
    return row?.value ?? null;
  }
  /**
   * DOD-SETTINGS-1: DELETE a per-agent setting so the built-in default applies again.
   *
   * Deleting is NOT storing "". `getSetting` returns null for both, but the away-text resolver walks
   * per-contact → per-tier → agent-default → system default, and an empty string is a VALUE that
   * wins that walk and blanks the reply. Unsetting is the only way back to the default, and until
   * this existed there was no way back at all: `cello_settings_set` accepted a string, refused an
   * empty one, and told the caller to "pass null to clear" — a null it coerced to undefined and
   * rejected as missing_params. Following that guidance from the CLI set the literal text "null",
   * so an operator trying to remove their away message ended up broadcasting the word "null" to
   * every caller.
   *
   * Returns whether a row was actually removed, so the handler can report what it did rather than
   * claiming a clear it never performed.
   */
  deleteSetting(agentName: string, key: string): boolean {
    if (!this.#db) throw new Error(`deleteSetting('${agentName}'): database not initialized`);
    // Same dual-layer key check as setSetting — an unknown key here means a caller hand-typed one,
    // and silently reporting "cleared" for a key that never existed would be the same class of lie.
    if (!isValidSettingKey(key)) throw new Error(`invalid_key: '${key}' is not a known setting`);
    const res = this.#db
      .prepare("DELETE FROM agent_settings WHERE agent_id = ? AND key = ?")
      .run(this.#ctx.requireAgentId(agentName), key);
    return res.changes > 0;
  }
  /** DOD-SETTINGS-1: write a per-agent setting (upsert). Key VALIDATION is the handler's boundary
   *  (isValidSettingKey); value validation for typed settings (finite bounds, etc.) belongs to the
   *  specific consumer. Throws on a missing DB — a write that silently no-ops would be a lie. */
  setSetting(agentName: string, key: string, value: string): void {
    if (!this.#db) throw new Error(`setSetting('${agentName}'): database not initialized`);
    // Store-level backstop (review F2): the handler validates the key, but the dual-layer convention
    // (cf. MONIKER-1) means an unknown key can NEVER be stored — an internal caller that hand-typed a
    // key instead of using the builders would otherwise persist a setting that never takes effect.
    if (!isValidSettingKey(key)) throw new Error(`invalid_key: '${key}' is not a known setting`);
    this.#db
      .prepare(
        `INSERT INTO agent_settings (agent_id, key, value, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(agent_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      )
      .run(this.#ctx.requireAgentId(agentName), key, value, Date.now());
  }
  /** DOD-SETTINGS-1: all explicitly-set settings for an agent (the ones that OVERRIDE a default),
   *  key-sorted. Unset keys are absent — the operator sees only what they changed. */
  getAllSettings(agentName: string): Array<{ key: string; value: string }> {
    if (!this.#db) return [];
    return this.#db
      .prepare("SELECT key, value FROM agent_settings WHERE agent_id = ? ORDER BY key ASC")
      .all(this.#ctx.requireAgentId(agentName)) as Array<{ key: string; value: string }>;
  }
  /**
   * Review F7: a relay sent a witness alert this build could not read or could not verify.
   *
   * Recorded so a version skew that silently kills the witness layer is visible to the operator
   * instead of living only in a log file. Carries no session and no party by construction.
   */
  recordRelayWitnessUnreadable(agentName: string, relayPeerId: string, why: string): void {
    const byRelay = this.#ctx.witnessUnreadable.get(agentName) ?? new Map<string, { why: string; count: number }>();
    const prior = byRelay.get(relayPeerId);
    byRelay.set(relayPeerId, { why, count: (prior?.count ?? 0) + 1 });
    this.#ctx.witnessUnreadable.set(agentName, byRelay);
    this.#ctx.logger.error("session.witness.unreadable.recorded", {
      agentName, relayPeerId, why,
      impact: "this agent's witness layer is not working against that relay — no observation it " +
        "sends can be read, and nothing has been concluded about any participant",
    });
  }
  /** Relays whose witness alerts this build could not read, for the agent's inbox. */
  getWitnessUnreadable(agentName: string): ReadonlyArray<{ relayPeerId: string; why: string; count: number }> {
    return [...(this.#ctx.witnessUnreadable.get(agentName) ?? new Map()).entries()]
      .map(([relayPeerId, v]) => ({ relayPeerId, why: v.why, count: v.count }));
  }
  /**
   * DOD-LOG-1 / PERSIST-002 (AC-010): append one readable message to the durable transcript, keyed
   * by the canonical leaf `sequence` so it joins to the committed hash chain. The blob is stored as
   * plaintext bytes: the whole DB is SQLCipher-encrypted at rest, so there is no per-column cipher.
   * Idempotent on replay (INSERT OR IGNORE). Never throws into the caller's content path — but it
   * REPORTS: returns false when the row did not land, so a caller for whom the row is a delivery
   * precondition can fail instead of proceeding (review F2). Before Tier 1 the return value would
   * have been pointless, because `cello_receive` served content from the in-memory buffer and the
   * lost row only cost the unread count. Delivery reads the transcript now, so a swallowed received
   * row is TOTAL content loss and the caller has to know.
   */
  recordTranscriptMessage(
    agentName: string,
    sessionId: string,
    sequence: number,
    /**
     * DOD-M15-REFUSEDEVIDENCE-1 adds `'quarantined'` — received and REFUSED, kept as evidence and
     * never delivered. It goes through THIS writer rather than a second one so that the attribution
     * rule, the blob handling and the write-failure logging cannot drift between a delivered message
     * and a refused one. One store, one writer.
     */
    direction: "sent" | "received" | "quarantined",
    plaintext: Uint8Array,
    correlationId?: string,
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: the VERIFIED authorship proof, when there is one.
     *
     * Optional because there legitimately is not always one — the ordering decode can fail SOFT and
     * the message is still ingested via hash-dedup. Optional is NOT the same as unremarked: absence
     * is written into the row as `attribution = 'local_session_state'`, so a reader can tell a row
     * whose author was proven from one whose author was assumed. That distinction is the bullet.
     */
    authorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
    /** Required on a `'quarantined'` row and meaningless on any other: WHY it was refused. */
    quarantineReason?: string,
    /**
     * DOD-M15-REFUSEDEVIDENCE-1: the sender's key when there is one but no verified signature to go
     * with it. A refused frame often has an identified sender and an unusable proof — a tampered
     * message is still FROM someone — and dropping the key because the signature failed would throw
     * away the half of the attribution that survived.
     */
    senderPubkeyHexOverride?: string | null,
  ): boolean {
    if (!this.#db) return false;
    try {
      const agentId = this.#ctx.requireAgentId(agentName);
      const blob = Buffer.from(plaintext);
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO transcript
             (agent_id, session_id, sequence, direction, blob, created_at, sender_pubkey, sender_sig, attribution, quarantine_reason)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          agentId, sessionId, sequence, direction, blob, Date.now(),
          authorship
            ? Buffer.from(authorship.senderPubkey).toString("hex")
            : senderPubkeyHexOverride ?? null,
          authorship ? Buffer.from(authorship.senderSig) : null,
          /**
           * THREE values, not two — caught by CELLO_Coder_1 reviewing the first version, and it was
           * the same defect this column exists to prevent, surviving one layer up in the enum.
           *
           * `local_session_state` covered two OPPOSITE rows: one this agent AUTHORED (provenance
           * fully known, merely not third-party-provable) and one RECEIVED on the soft fallback
           * (provenance unknown — something arrived on a socket and was trusted). A reader shown the
           * transcript later could not separate "he wrote this himself" from "nobody checked".
           * Structurally identical rows with different trustworthiness is exactly what I refused to
           * ship when I rejected a nullable signature column.
           *
           * No plumbing needed: `direction` already carries the answer at write time.
           */
          /**
           * DIRECTION FIRST — DOD-M15-SEALWIRE-1 bullet 5, sent half.
           *
           * This used to read `authorship ? "verified_signature" : …`, which was right while only
           * RECEIVED rows could carry a signature. Now a SENT row carries one too — our own, over
           * the Structure-1 bytes we put on the wire — and labelling that `verified_signature` would
           * be false in the way this column exists to prevent: **we did not verify it, we produced
           * it.** Nobody checked a counterparty's key; there was no counterparty in the act.
           *
           * So the three values keep meaning three different things:
           *   `self_authored`      — this agent wrote it. Now PROVABLE when a signature is stored.
           *   `verified_signature` — someone else wrote it and we checked their key against it.
           *   `local_session_state`— someone else wrote it and nobody checked anything.
           */
          direction === "sent" ? "self_authored" : authorship ? "verified_signature" : "local_session_state",
          quarantineReason ?? null,
        );
      this.#ctx.logger.info("transcript.message.recorded", { sessionId, agentName, sequence, direction, correlationId });
      return true;
    } catch (err: unknown) {
      // M8C-INBOX-1 (reviewer F2): a RECEIVED-row write failure is not cosmetic — since INBOX-1 the
      // transcript is the AUTHORITY for unread (getUnreadSummary).
      //
      // UPDATED for DOD-COATTEND-1 (review F2). This comment used to end "...while cello_receive
      // still delivers it live from the in-memory buffer (masking the loss)", and that mitigation
      // was the whole reason a swallowed write was survivable. Tier 1 DELETED it: delivery reads
      // the transcript now, so a lost received row is not an undercount, it is the message never
      // reaching ANY session while the doorbell rings and the leaf sits in the hash chain. The
      // sentence is corrected rather than kept, because as written it reassured a reader about a
      // safety net that no longer exists. Sent-row failures stay a warning (they only affect the
      // durable readable transcript, not delivery).
      // A QUARANTINED row that fails to write is an ERROR for the same reason a received one is,
      // and a different one: nothing else holds these bytes. The message was refused, so it was
      // never delivered and never acked in a way that brings it back — a failed write here is the
      // evidence gap this unit exists to close, reopened by a disk fault.
      const level = direction === "sent" ? "warn" : "error";
      this.#ctx.logger[level]("transcript.message.record.failed", {
        sessionId, agentName, sequence, direction,
        reason: err instanceof Error ? err.message : String(err),
        correlationId,
        ...(direction === "received" ? { impact: "content_undeliverable_message_lost" } : {}),
        ...(direction === "quarantined" ? { impact: "refused_message_not_retained_no_other_copy_exists" } : {}),
      });
      return false;
    }
  }
  /**
   * DOD-LOG-1: read a session's durable transcript back (after a restart), decrypted and ordered by
   * canonical sequence then direction. A blob that fails to decrypt (tamper/wrong key) is skipped
   * with a loud log rather than crashing the read.
   */
  readTranscript(
    agentName: string,
    sessionId: string,
  ): { messages: TranscriptEntry[]; undecryptable: number } {
    if (!this.#db) return { messages: [], undecryptable: 0 };
    const rows = this.#db
      .prepare(
        `SELECT sequence, direction, blob, created_at, quarantine_reason FROM transcript
         WHERE agent_id = ? AND session_id = ? ORDER BY sequence ASC, direction ASC`,
      )
      .all(this.#ctx.requireAgentId(agentName), sessionId) as Array<{ sequence: number; direction: string; blob: Uint8Array; created_at: number; quarantine_reason: string | null }>;
    const messages: TranscriptEntry[] = [];
    // PERSIST-002 (AC-010): the blob is plaintext (whole-DB SQLCipher at rest), so there is no
    // per-row decrypt step that can fail — `undecryptable` stays 0 and is kept only for callers that
    // already read the field.
    for (const r of rows) {
      const blob = r.blob instanceof Uint8Array ? r.blob : new Uint8Array(r.blob);
      /**
       * DOD-M15-REFUSEDEVIDENCE-1 — THE READ IS REDACTED, THE STORAGE IS NOT.
       *
       * The entry stays at its position, because a hole where a message was is the evidence gap
       * this unit exists to close, one level up: the operator must be able to see that something
       * arrived here and was refused. What is withheld is the TEXT, and `text` carries the
       * withholding statement rather than being omitted — every existing renderer of this array
       * prints `text`, so a missing field would print nothing and an unfiltered one would print the
       * payload. The statement is the fail-safe value for both.
       *
       * ⚠️ THREE-WAY, not `!== "sent" ? "received"`. The old expression labelled anything that was
       * not `sent` as `received`, which would have handed a refused message to every reader as a
       * delivered one — with its text.
       */
      const direction: TranscriptEntry["direction"] =
        r.direction === "sent" ? "sent" : r.direction === "quarantined" ? "quarantined" : "received";
      if (direction === "quarantined") {
        // No `?? "refused"` default — review F11. See `readQuarantined` for why a generic label for
        // an impossible state is worse than an empty one.
        const reason = r.quarantine_reason as string;
        const redaction = quarantineRedaction(reason, sessionId, r.sequence);
        messages.push({
          sequence: r.sequence, direction, createdAt: r.created_at,
          text: redaction.text,
          // The key ENDS in `guidance` so `vocabulary.ts` rewrites the verb for a CLI reader — see
          // the note on `quarantineRedaction`.
          withheld_guidance: redaction.guidance,
          refusalReason: reason,
          withheld: true,
        });
        continue;
      }
      messages.push({ sequence: r.sequence, direction, text: new TextDecoder().decode(blob), createdAt: r.created_at });
    }
    return { messages, undecryptable: 0 };
  }
  /** INBOX-1 (N2): per-session unread summary for an agent — sessions that have RECEIVED transcript
   *  messages beyond the read watermark, excluding terminal sessions (sealed, abandoned,
   *  seal_interrupted_pending) which belong in getEndedUnread instead.
   *  Sessions with no sessions row are treated as non-terminal (LEFT JOIN).
   *  Content-free (counts + ids + last seq, never message text); a COUNT/MAX query, no decrypt. */
  getUnreadSummary(agentName: string): Array<{ session_id: string; unread_count: number; last_seq: number }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        `SELECT t.session_id AS session_id,
                COUNT(*)      AS unread_count,
                MAX(t.sequence) AS last_seq
         FROM transcript t
         LEFT JOIN message_watermarks w
           ON w.agent_id = t.agent_id AND w.session_id = t.session_id
         LEFT JOIN sessions s
           ON s.agent_id = t.agent_id AND s.session_id = t.session_id
         WHERE t.agent_id = ?
           AND ${UNREAD_RECEIVED_WHERE}
           AND (s.status IS NULL OR s.status NOT IN ${TERMINAL_STATUSES})
         GROUP BY t.session_id
         HAVING unread_count > 0
         ORDER BY t.session_id ASC`,
      )
      .all(this.#ctx.requireAgentId(agentName)) as Array<{ session_id: string; unread_count: number; last_seq: number }>;
    return rows;
  }
  /** DOD-SEALED-INBOX-1: terminal sessions with unread received messages that have not been
   *  dismissed. These are answering-machine style messages left in an ENDED session — the operator
   *  can read them via cello_transcript but cannot advance the watermark via cello_receive.
   *  Only returned when read_at IS NULL (not yet dismissed).
   *
   *  DOD-SEALED-INBOX-2: named `getEndedUnread`, not `getSealedUnread`, and it SELECTS `s.status`.
   *  All four #TERMINAL_STATUSES belong here — that part was always right — but only `sealed` is
   *  NOTARIZED. The old name and the caller's hardcoded `session_state: "sealed"` asserted a
   *  cryptographic receipt for `abandoned`, `interrupted` and `seal_interrupted_pending` sessions,
   *  which have none. Callers must render the row's own status; there is nothing to infer from
   *  membership in this list beyond "it ended". */
  getEndedUnread(agentName: string): Array<{ session_id: string; unread_count: number; last_seq: number; status: string }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        // M12-P17 (review F2): return the ACTUAL status. `#TERMINAL_STATUSES` spans four states and
        // they are NOT equivalent — an `interrupted` session is not committed, still accepts
        // appends, and may have a counterparty waiting to seal. Stamping "sealed" over all four
        // told an agent that live work was dead history: symptom B inverted.
        `SELECT t.session_id AS session_id,
                COUNT(*)      AS unread_count,
                MAX(t.sequence) AS last_seq,
                s.status      AS status
         FROM transcript t
         LEFT JOIN message_watermarks w
           ON w.agent_id = t.agent_id AND w.session_id = t.session_id
         JOIN sessions s
           ON s.agent_id = t.agent_id AND s.session_id = t.session_id
         WHERE t.agent_id = ?
           AND ${UNREAD_RECEIVED_WHERE}
           AND s.status IN ${TERMINAL_STATUSES}
           AND s.read_at IS NULL
         GROUP BY t.session_id
         HAVING unread_count > 0
         ORDER BY t.session_id ASC`,
      )
      .all(this.#ctx.requireAgentId(agentName)) as Array<{ session_id: string; unread_count: number; last_seq: number; status: string }>;
    return rows;
  }
  /**
   * DOD-CURSOR-DURABLE-1: how many RECEIVED messages in THIS session the agent has not read —
   * the durable half of the read-before-write gate. Same predicate as getUnreadSummary (shared
   * constant above), scoped to one session.
   *
   * This is DURABLE and PER-AGENT, where the send gate's other authority (the connection cursor) is
   * in-memory and per-connection. It is what lets a stateless client — the `cello` CLI, one process
   * per command — prove it has read the counterparty, which a dead socket's cursor never can.
   *
   * FAILS CLOSED: an uninitialized DB returns a positive count (treated as "unread"), never 0. A 0
   * here unblocks a send; guessing 0 from a broken DB would silently defeat the gate.
   */
  getUnreadReceivedCount(agentName: string, sessionId: string): number {
    if (!this.#db) return 1; // fail closed — never unblock a send because the DB is unavailable
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS unread_count
         FROM transcript t
         LEFT JOIN message_watermarks w
           ON w.agent_id = t.agent_id AND w.session_id = t.session_id
         WHERE t.agent_id = ?
           AND t.session_id = ?
           AND ${UNREAD_RECEIVED_WHERE}`,
      )
      .get(this.#ctx.requireAgentId(agentName), sessionId) as { unread_count: number } | undefined;
    // Absent row → "I cannot count", which is NOT "you are caught up". Answer the same way the
    // #db guard above does. Unreachable today (SELECT COUNT(*) with no GROUP BY always yields a
    // row), but a fail-OPEN default inside a fail-CLOSED gate is a defect that only needs the query
    // to change once. The two branches must never disagree about what "unknown" means.
    return row ? row.unread_count : 1;
  }
  /**
   * Rehydrate `#diverged` from `sessions.diverged_at` — `DOD-M15-DIVERGE-DURABLE-1`.
   *
   * The Set stays as the hot read (the seal gate consults it per close), and the column is the
   * truth. Loaded once at boot rather than queried per read so the gate's cost does not change.
   */
  loadDivergedFromDb(): void {
    if (!this.#db) return;
    const rows = this.#db
      .prepare(
        `SELECT s.session_id AS sid, a.agent_name AS agent
           FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
          WHERE s.diverged_at IS NOT NULL`,
      )
      .all() as Array<{ sid: string; agent: string }>;
    for (const r of rows) this.#diverged.add(this.#ctx.sessionKey(r.agent, r.sid));
    if (rows.length > 0) {
      this.#ctx.logger.info("session.diverged.restored", {
        count: rows.length,
        impact:
          "these sessions provably cannot seal bilaterally and are refused at the seal gate — before " +
          "this was durable, a restart made them read as healthy",
      });
    }
  }
  /**
   * Record that this session's tree and the relay's counter have provably parted.
   *
   * Idempotent, and deliberately does NOT touch `updated_at`: that column drives the inbox's
   * last-spoke ordering, and divergence is not activity.
   */
  markSessionDiverged(agentName: string, sessionId: string): void {
    this.#diverged.add(this.#ctx.sessionKey(agentName, sessionId));
    if (!this.#db) return;
    /**
     * KEYED ON (agent_id, session_id) — review F3, and the loopback case makes it concrete.
     *
     * This was `WHERE session_id = ?` alone. The table's PK is composite for a documented reason
     * (`DOD-LOOP-1`, on the CREATE TABLE above): **two of one operator's agents can hold both ends
     * of the SAME session_id on ONE daemon**, so `sessions` holds two rows. Unkeyed, marking one
     * side diverged marked BOTH, and the clear below wiped BOTH — so side B sealing its half
     * erased side A's divergence, and after a restart A's seal gate read healthy and signed a close
     * that could only be refused. The line's own defect, produced by the line's own clear.
     *
     * Every other per-session UPDATE in this file keys on both columns; these two were the
     * exceptions.
     */
    this.#db
      .prepare("UPDATE sessions SET diverged_at = ? WHERE agent_id = ? AND session_id = ? AND diverged_at IS NULL")
      .run(Date.now(), this.#ctx.requireAgentId(agentName), sessionId);
  }
  /** Whether this session has provably parted from the relay's ordering. */
  isSessionDiverged(agentName: string, sessionId: string): boolean {
    return this.#diverged.has(this.#ctx.sessionKey(agentName, sessionId));
  }

  /** Is this session's local chain known to have diverged from the relay's? In-memory memo only. */
  hasDivergedMemo(agentName: string, sessionId: string): boolean {
    return this.#diverged.has(this.#ctx.sessionKey(agentName, sessionId));
  }

  /**
   * Drop the in-memory divergence memo for a session.
   *
   * Called when the session reaches a TERMINAL status: no future close can be refused at that
   * point, so the flag has nothing left to protect. The DURABLE row is cleared by the caller —
   * otherwise a sealed session comes back after a restart still carrying a refusal for a close that
   * can no longer happen.
   */
  clearDivergedMemo(agentName: string, sessionId: string): void {
    this.#diverged.delete(this.#ctx.sessionKey(agentName, sessionId));
  }
}
