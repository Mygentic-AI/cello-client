/**
 * The address book: the contact / tier / moniker / settings / telegram-token IPC handlers.
 *
 * These ten handlers lived inside startDaemon's body, where they reached the daemon's state by
 * closing over it. Here they must NAME what they need — that is the whole point of the move, and
 * the list turns out to be short: the session store, the per-connection agent selection, a logger,
 * and one callback to restart the Telegram poller. Nothing about sessions, seals, transport or
 * ceremonies. The address book never needed any of it; you just couldn't tell from inside the
 * closure.
 *
 * Behavior is preserved exactly. The only type that changed is `connState`, widened to include
 * `clearedAgent` — it was always there at runtime (TS types are erased, and resolveCurrentAgent
 * reads it), so the old narrower type was a fiction, not a constraint.
 */
import { MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import { whoLabel } from "./who-label.js";
import { isKnownTierValue, TIER } from "./contacts-tier-migration.js";
import {
  isValidSettingKey,
  allSettingKeys,
  validateSettingValue,
  AWAY_MESSAGE_MAX_LEN,
} from "./agent-settings-keys.js";

/** The per-connection agent selection, as the address book needs to read it. */
export interface ConnState {
  currentAgent: string | null;
  clearedAgent?: string;
}

export interface ContactHandlerDeps {
  handlers: Map<string, IpcHandler>;
  sessionNodeManager: SessionNodeManager;
  /**
   * Read this connection's agent selection. The READ, not the container: these handlers only ever
   * `.get(connectionId)`, and injecting the whole Map would hand the address book the power to
   * mutate connection state it has no business touching.
   */
  getConnState: (connectionId: string) => ConnState | undefined;
  /** The daemon's single agent-selection rule. Injected, never re-implemented here. */
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  /**
   * Set (or clear, with null) an agent's outbound-name override. False when no such agent exists.
   *
   * Injected as a capability rather than reached for, because `cello_set_moniker` was the ONE
   * address-book handler that bypassed the store interface entirely and grabbed the raw SQLite
   * handle (`sessionNodeManager.getDb()`) to build a DbIdentityStore. Every other handler goes
   * through a store method. Inside the closure that asymmetry was invisible; the extraction made it
   * the single thing standing between this module and "needs no database". Same call, same
   * behavior — the daemon still constructs the DbIdentityStore. It just says so out loud now.
   */
  setAgentMoniker: (agentName: string, moniker: string | null) => boolean;
  logger: Logger;
  /** M8C-TGDOOR-1: restart the poller after a token change, with no daemon restart. */
  startTelegramPollerIfConfigured: () => void;
}

type Refusal = { ok: false; reason: string; guidance: string };

/**
 * Review finding 7 — a contact pubkey must LOOK like a pubkey, or the row can never work.
 *
 * The address-book handlers took `params.pubkey` as any string and stored it. So
 * `cello contact tier add` — a plausible slip under the `contact <pubkey> <op>` shape, where the
 * FIRST positional is the pubkey — persisted a contact whose pubkey is the literal text "tier",
 * and answered ok:true. Nothing would ever match it: it is not a key, so it can never be a
 * counterparty. The operator is told they added someone; they added a typo.
 *
 * A key is 32 bytes, hex: 64 characters. Anything else is refused, loudly, with the value echoed
 * so the slip is obvious. Returns null when the pubkey is absent — the caller's own missing_params
 * check owns that case and says something more useful.
 */
export function invalidPubkey(pubkey: string | undefined): Refusal | null {
  if (pubkey === undefined) return null; // absent → the caller's missing_params check owns it
  if (/^[0-9a-fA-F]{64}$/.test(pubkey)) return null;
  return {
    ok: false,
    reason: "invalid_pubkey",
    guidance: `'${pubkey}' is not a public key. A CELLO public key is 64 hex characters (32 bytes). Nothing was changed — storing it would create an address-book entry that can never match anyone. Note the argument order is 'cello contact <pubkey> <operation>'.`,
  };
}

export function registerContactHandlers(deps: ContactHandlerDeps): void {
  const {
    handlers, sessionNodeManager, getConnState, resolveCurrentAgent,
    setAgentMoniker, logger, startTelegramPollerIfConfigured,
  } = deps;

  // M8C-CONTACT-1: every address-book handler resolves the target agent the SAME way — an explicit
  // params.agent, else this connection's current/sole-online agent (F18) — so a CLI or AI operator
  // gets the same no_current_agent guidance INBOX already uses.
  function resolveContactAgent(
    connState: ConnState | undefined,
    params?: Record<string, unknown>,
  ): { ok: true; agent: string } | Refusal {
    const explicit = typeof params?.agent === "string" ? params.agent : undefined;
    if (explicit) return { ok: true, agent: explicit };
    const current = resolveCurrentAgent(connState);
    if (!current) {
      return {
        ok: false,
        reason: "no_current_agent",
        guidance: "No current agent for this connection. Pass --agent <name>, or call cello_use_agent to select one first.",
      };
    }
    return { ok: true, agent: current };
  }

  handlers.set("cello_contact_add", async (params, connectionId) => {
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey : undefined;
    const badPubkey = invalidPubkey(pubkey);
    if (badPubkey) return badPubkey;
    if (!pubkey) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'pubkey' (hex) — the contact to add." };
    }
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    // MONIKER-3 AC3: optional pet name. Invalid → reject the request WHOLE (no contact row
    // either) — a half-applied add would store trust without the name the operator asked for.
    let moniker: string | null | undefined;
    if (params && "moniker" in params && params.moniker !== undefined && params.moniker !== null) {
      moniker = validateMoniker(params.moniker);
      if (moniker === null) {
        return {
          ok: false,
          reason: "invalid_moniker",
          guidance: `A moniker is 1-64 chars: letters, digits, '-' or '_' (regex ${MONIKER_RE.source}).`,
        };
      }
    }
    // DOD-TIER-4 / DEC-AB-1: an explicit cello_contact_add is a deliberate operator vouch → KNOWN
    // (still not auto-accept; that is a separate cello_contact_set_tier to whitelisted). provenance
    // stays null — this relationship formed by neither initiating nor accepting a session (AC5).
    sessionNodeManager.addContact(resolved.agent, pubkey, moniker, null, TIER.KNOWN);
    logger.info("contact.added", { agent: resolved.agent, pubkey });
    if (moniker !== undefined) {
      logger.info("contact.moniker.set", { agentName: resolved.agent, pubkey });
    }
    // Review F3: echo the moniker ONLY when one rode this request — a re-add without a moniker
    // must not report null while an earlier pet name is still stored.
    return moniker !== undefined
      ? { ok: true, agent: resolved.agent, pubkey, moniker }
      : { ok: true, agent: resolved.agent, pubkey };
  });

  // MONIKER-3 AC3: rename (string) or clear (null) an existing contact's pet name. Absence of the
  // key is NOT a clear (Entry-66-F3): a request that omits it is malformed and rejected.
  handlers.set("cello_contact_set_moniker", async (params, connectionId) => {
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey : undefined;
    const badPubkey = invalidPubkey(pubkey);
    if (badPubkey) return badPubkey;
    if (!pubkey || !params || !("moniker" in params)) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'pubkey' (hex) and 'moniker' — a string to set the pet name, or null to clear it." };
    }
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    const raw = params.moniker ?? null;
    const moniker = raw === null ? null : validateMoniker(raw);
    if (raw !== null && moniker === null) {
      return {
        ok: false,
        reason: "invalid_moniker",
        guidance: `A moniker is 1-64 chars: letters, digits, '-' or '_' (regex ${MONIKER_RE.source}). Pass null to clear.`,
      };
    }
    if (!sessionNodeManager.setContactMoniker(resolved.agent, pubkey, moniker)) {
      return { ok: false, reason: "contact_not_found", guidance: `No contact ${pubkey.slice(0, 16)}… for agent '${resolved.agent}'. Add it first with cello_contact_add.` };
    }
    logger.info("contact.moniker.set", { agentName: resolved.agent, pubkey, cleared: moniker === null });
    return { ok: true, agent: resolved.agent, pubkey, moniker };
  });

  // DOD-CONTACT-VIEW-1 AC1: set a contact's reachability tier. Validates the tier is a known constant
  // (0..4) — an unknown value is REFUSED, never coerced. Emits contact.tier.changed (old→new).
  handlers.set("cello_contact_set_tier", async (params, connectionId) => {
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey : undefined;
    const badPubkey = invalidPubkey(pubkey);
    if (badPubkey) return badPubkey;
    const tier = typeof params?.tier === "number" ? params.tier : undefined;
    if (!pubkey || tier === undefined) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'pubkey' (hex) and 'tier' (0=blocked, 1=unknown, 2=known, 3=whitelisted, 4=vip)." };
    }
    if (!isKnownTierValue(tier)) {
      return { ok: false, reason: "invalid_tier", guidance: "tier must be one of 0 (blocked), 1 (unknown), 2 (known), 3 (whitelisted), 4 (vip)." };
    }
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    const oldTier = sessionNodeManager.getTier(resolved.agent, pubkey);
    if (!sessionNodeManager.setContactTier(resolved.agent, pubkey, tier)) {
      return { ok: false, reason: "contact_not_found", guidance: `No contact ${pubkey.slice(0, 16)}… for agent '${resolved.agent}'. Add it first with cello_contact_add.` };
    }
    // Only an actual change is an audit event — a no-op re-set must not pollute the trail (review F4).
    if (oldTier !== tier) {
      logger.info("contact.tier.changed", { agentName: resolved.agent, pubkey, oldTier, newTier: tier });
    }
    return { ok: true, agent: resolved.agent, pubkey, tier };
  });

  // DOD-AWAY-TIER-1 AC2: set (or clear, with null) a contact's per-contact away message — the most
  // specific level of the away-text resolution. Validated as a string-or-null; the text is screened
  // on the outbound path at send time (SI), never here.
  handlers.set("cello_contact_set_away", async (params, connectionId) => {
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey : undefined;
    const badPubkey = invalidPubkey(pubkey);
    if (badPubkey) return badPubkey;
    if (!pubkey || !params || !("message" in params)) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'pubkey' (hex) and 'message' — a string away text, or null to clear it." };
    }
    const rawMessage = params.message === null ? null : typeof params.message === "string" ? params.message : undefined;
    if (rawMessage === undefined) {
      return { ok: false, reason: "invalid_message", guidance: "'message' must be a string (the away text) or null (to clear)." };
    }
    // Review F2/F3: an empty / whitespace-only message CLEARS (consistent with the CLI + null), never
    // stores a blank away reply; a valid message is length-bounded.
    const message = rawMessage !== null && rawMessage.trim().length === 0 ? null : rawMessage;
    if (message !== null && message.length > AWAY_MESSAGE_MAX_LEN) {
      return { ok: false, reason: "invalid_message", guidance: `The away message must be <= ${AWAY_MESSAGE_MAX_LEN} characters.` };
    }
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    if (!sessionNodeManager.setContactAwayMessage(resolved.agent, pubkey, message)) {
      return { ok: false, reason: "contact_not_found", guidance: `No contact ${pubkey.slice(0, 16)}… for agent '${resolved.agent}'. Add it first with cello_contact_add.` };
    }
    logger.info("contact.away.set", { agentName: resolved.agent, pubkey, cleared: message === null });
    return { ok: true, agent: resolved.agent, pubkey };
  });

  handlers.set("cello_contact_remove", async (params, connectionId) => {
    // Deliberately NOT shape-gated. `remove` is the ESCAPE HATCH, and gating it would trap the very
    // rows the gate exists to prevent: a junk contact written by the older, unvalidated code (pubkey
    // = the literal text "tier") could never be deleted, because deleting it requires naming it.
    // Validation belongs on the paths that CREATE or MUTATE a row, never on the one that removes it.
    // Removing a key that was never stored is a harmless not_found.
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey : undefined;
    if (!pubkey) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'pubkey' (hex) — the contact to remove." };
    }
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    const removed = sessionNodeManager.removeContact(resolved.agent, pubkey);
    logger.info("contact.removed", { agent: resolved.agent, pubkey, removed });
    return { ok: true, agent: resolved.agent, pubkey, removed };
  });

  handlers.set("cello_contact_list", async (params, connectionId) => {
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    // MONIKER-5 AC1: each row shows the resolved who (a contact has no session, so the offered
    // tier doesn't apply — pet name ?? fingerprint).
    const contacts = sessionNodeManager.listContacts(resolved.agent).map((c) => ({
      ...c,
      ...whoLabel({ localMoniker: c.moniker, offeredMoniker: null, pubkeyHex: c.pubkey }),
    }));
    return { ok: true, agent: resolved.agent, contacts };
  });

  // DOD-SETTINGS-1 AC2: read a per-agent reachability-policy setting (or all set ones). An unset key
  // returns value:null — the CONSUMER applies the hardcoded default (the daemon runs on defaults alone).
  handlers.set("cello_settings_get", async (params, connectionId) => {
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    // A key was PROVIDED (present and non-null) → it must be a valid string key. Distinguish "key
    // absent" (list all) from "key present but malformed/unknown" (review F1/F3) — a typo'd read must
    // NOT masquerade as "unset", the exact invisibility this store exists to prevent.
    if (params && "key" in params && params.key !== undefined && params.key !== null) {
      if (typeof params.key !== "string") {
        return { ok: false, reason: "missing_params", guidance: "'key' must be a string setting key, or omit it to list every set value." };
      }
      if (!isValidSettingKey(params.key)) {
        return { ok: false, reason: "invalid_key", guidance: `Unknown setting key '${params.key}'. Valid keys: ${allSettingKeys().join(", ")}` };
      }
      return { ok: true, agent: resolved.agent, key: params.key, value: sessionNodeManager.getSetting(resolved.agent, params.key) };
    }
    return { ok: true, agent: resolved.agent, settings: sessionNodeManager.getAllSettings(resolved.agent) };
  });

  // DOD-SETTINGS-1 AC2: write a per-agent setting. The KEY is validated against the known namespace —
  // an unknown key is REFUSED (a typo'd key that persisted would be a setting that never takes effect,
  // invisible to the operator). Per-key VALUE validation (finite bounds, etc.) lives with the consumer.
  handlers.set("cello_settings_set", async (params, connectionId) => {
    const key = typeof params?.key === "string" ? params.key : undefined;
    const rawValue = params?.value;
    // NULL CLEARS THE SETTING, matching cello_contact_set_away, which has always taken
    // `string | null`. This handler's own guidance told callers to "pass null to clear" while
    // coercing null to undefined and rejecting it as missing_params — so there was NO way to unset a
    // setting from either surface. A caller following that advice from the CLI stored the literal
    // text "null", which for an away message meant the agent greeted every caller with "null".
    const isClear = rawValue === null;
    const value = typeof rawValue === "string" ? rawValue : typeof rawValue === "number" ? String(rawValue) : undefined;
    if (!key || (value === undefined && !isClear)) {
      return { ok: false, reason: "missing_params", guidance: `Provide 'key' and 'value' (string or number), or value null to clear the setting. Valid keys: ${allSettingKeys().join(", ")}` };
    }
    if (!isValidSettingKey(key)) {
      return { ok: false, reason: "invalid_key", guidance: `Unknown setting key '${key}'. Valid keys: ${allSettingKeys().join(", ")}` };
    }
    if (isClear) {
      // Reported honestly: `cleared` says whether a row actually went away, so clearing an already
      // unset key reads as the no-op it is instead of implying something was removed.
      const resolvedClear = resolveContactAgent(getConnState(connectionId), params);
      if (!resolvedClear.ok) return resolvedClear;
      const removed = sessionNodeManager.deleteSetting(resolvedClear.agent, key);
      logger.info("setting.cleared", { agentName: resolvedClear.agent, key, removed });
      return {
        ok: true,
        agent: resolvedClear.agent,
        key,
        value: null,
        cleared: removed,
        guidance: removed
          ? `'${key}' is unset — the built-in default applies again.`
          : `'${key}' was already unset; nothing to clear. The built-in default applies.`,
      };
    }
    // Past the clear branch, so this is a real set. The guard above already rejected an undefined
    // value on this path; re-check rather than assert, so a future edit to that guard cannot let an
    // undefined reach setSetting behind a cast that silently agreed with it.
    if (value === undefined) {
      return { ok: false, reason: "missing_params", guidance: `Provide 'value' (string or number), or null to clear. Valid keys: ${allSettingKeys().join(", ")}` };
    }
    // DOD-TIER-BOUNDS-SETTINGS AC2: a bound value must be a finite positive integer (INV-TIER-BOUND —
    // a setting cannot REMOVE a bound). Away-text values are free-form.
    const valueCheck = validateSettingValue(key, value);
    if (!valueCheck.ok) {
      return { ok: false, reason: "invalid_value", guidance: valueCheck.reason };
    }
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    sessionNodeManager.setSetting(resolved.agent, key, value);
    logger.info("setting.changed", { agentName: resolved.agent, key });
    return { ok: true, agent: resolved.agent, key, value };
  });

  // MONIKER-1 AC2/AC3: cello_set_moniker — set (or clear, via explicit null) an agent's outbound-name
  // override on the agents table. Validated at set-time with the shared MONIKER-0 rule; an invalid
  // value is rejected here AND at the store (backstop) — it can never be stored. Local-only: the
  // name is never sent to the directory (AC4).
  handlers.set("cello_set_moniker", async (params, connectionId) => {
    const resolved = resolveContactAgent(getConnState(connectionId), params);
    if (!resolved.ok) return resolved;
    // Absence is NOT a clear (review Finding 3): JSON preserves explicit null, so a request
    // that omits the key is malformed — rejecting it keeps a dropped field from silently
    // deleting a stored override while reporting success.
    if (!params || !("moniker" in params)) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'moniker' — a string to set the outbound name, or null to clear the override." };
    }
    const raw = params.moniker ?? null;
    const moniker = raw === null ? null : validateMoniker(raw);
    if (raw !== null && moniker === null) {
      return {
        ok: false,
        reason: "invalid_moniker",
        guidance: `A moniker is 1-64 chars: letters, digits, '-' or '_' (regex ${MONIKER_RE.source}). Pass null to clear the override.`,
      };
    }
    if (!setAgentMoniker(resolved.agent, moniker)) {
      return { ok: false, reason: "agent_not_found", guidance: `No active agent named '${resolved.agent}'. See cello_agents.` };
    }
    logger.info("agent.moniker.set", { agentName: resolved.agent, cleared: moniker === null });
    return { ok: true, agent: resolved.agent, moniker };
  });

  // M8C-TGDOOR-1: cello_telegram_set_token — persist the daemon-wide bot token + allowlisted
  // operator chat ID, then start the poller immediately (no restart needed).
  handlers.set("cello_telegram_set_token", async (params, _connectionId) => {
    const botToken = typeof params?.bot_token === "string" ? params.bot_token : undefined;
    const chatId = typeof params?.allowlisted_chat_id === "string" ? params.allowlisted_chat_id : undefined;
    if (!botToken || !chatId) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'bot_token' and 'allowlisted_chat_id'." };
    }
    sessionNodeManager.setTelegramSettings(botToken, chatId);
    startTelegramPollerIfConfigured(); // always bumps the generation — restarts even if already running
    logger.info("telegram.settings.updated", {});
    return { ok: true };
  });
}
