/**
 * M16 031-KEYSASKEYS — which 64-hex tokens in an OUTBOUND message the daemon knows to be PUBLIC keys.
 *
 * Outbound governance treats a 64-hex string as a secret (`generic-api-key`) or, chunked, as a phone
 * number, so an agent cannot send a channel key or any public key. The fix is scoped tightly: pass a
 * 64-hex token through the gateway's stages untouched ONLY when the daemon KNOWS it as a public key.
 * The daemon decides, because only it holds the four sources — its own agents' and channels' keys,
 * the sending agent's contacts, the channels the agent follows, and the session's counterparty.
 *
 * A private key in hex is 64 hex characters too, so a blanket exemption is ruled out. This module
 * NEVER puts private key material in the known set: the deps are strictly public-key queries.
 */
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";

/** A 64-hex token not run into surrounding hex (so it is a whole key, never a fragment or a longer run). */
const HEX64_TOKEN = /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g;
const IS_HEX64 = /^[0-9a-fA-F]{64}$/;
const DECODER = new TextDecoder("utf-8", { fatal: false });

/**
 * The four sources of KNOWN public keys. Each yields lowercase-or-any-case 64-hex public keys; the
 * extractor lowercases and validates. NONE of them may return private key material.
 */
export interface KnownPublicKeysDeps {
  /** Every public key of an agent loaded on this daemon (which includes the channels it created). */
  loadedAgentPubkeys: () => Iterable<string>;
  /** The public keys of the sending agent's contacts. */
  contactPubkeys: (agentName: string) => Iterable<string>;
  /** The public keys of the channels the sending agent follows. */
  followedChannelPubkeys: (agentName: string) => Iterable<string>;
  /** The counterparty's public key for this session, if any. */
  counterpartyPubkey: (agentName: string, sessionId: string) => string | undefined;
}

/**
 * Build the extractor the send path calls: given the message bytes, return the 64-hex tokens that
 * appear in it AND are in the known set, lowercased and de-duplicated. Only whole 64-hex tokens are
 * considered (a chunked key does not match, so it is screened as today — test 2).
 */
export function createKnownPublicKeysIn(
  deps: KnownPublicKeysDeps,
): (agentName: string, sessionId: string, content: Uint8Array) => string[] {
  return (agentName, sessionId, content) => {
    const known = new Set<string>();
    const add = (k: string | undefined): void => {
      if (k && IS_HEX64.test(k)) known.add(k.toLowerCase());
    };
    for (const k of deps.loadedAgentPubkeys()) add(k);
    for (const k of deps.contactPubkeys(agentName)) add(k);
    for (const k of deps.followedChannelPubkeys(agentName)) add(k);
    add(deps.counterpartyPubkey(agentName, sessionId));
    if (known.size === 0) return [];

    const out: string[] = [];
    const seen = new Set<string>();
    for (const m of DECODER.decode(content).matchAll(HEX64_TOKEN)) {
      const tok = m[0].toLowerCase();
      if (known.has(tok) && !seen.has(tok)) {
        seen.add(tok);
        out.push(tok);
      }
    }
    return out;
  };
}

/**
 * The production deps, built from the daemon's session manager and logger. Kept in this module (not
 * inline in `daemon.ts`, which is at its line cap) so the four queries live next to the extractor
 * they feed. Each is a public-key column read — no private key material is reachable here.
 */
export function knownPublicKeysDepsFromDaemon(snm: SessionNodeManager, logger: Logger): KnownPublicKeysDeps {
  const db = (): ReturnType<SessionNodeManager["getDb"]> => snm.getDb();
  return {
    loadedAgentPubkeys: () =>
      (db().prepare("SELECT k_local_pubkey FROM agents").all() as Array<{ k_local_pubkey: string }>).map(
        (r) => r.k_local_pubkey,
      ),
    contactPubkeys: (agentName) =>
      (db()
        .prepare("SELECT pubkey FROM contacts WHERE agent_id = ?")
        .all(snm.resolveAgentId(agentName)) as Array<{ pubkey: string }>).map((r) => r.pubkey),
    followedChannelPubkeys: (agentName) => {
      const agentId = snm.resolveAgentId(agentName);
      return new ChannelSubscriptionStore(db(), logger)
        .active()
        .filter((s) => s.agent_id === agentId)
        .map((s) => s.channel_pubkey);
    },
    counterpartyPubkey: (agentName, sessionId) => snm.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
  };
}
