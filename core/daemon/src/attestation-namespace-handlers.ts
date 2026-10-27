/**
 * M10E 003-NSCLIENT — the IPC verbs for attestation namespaces.
 *
 * Extracted from `signal-handlers.ts` only because that file is at its line cap; this is its
 * registerSignalHandlers block, wired by one call. Each verb resolves the selected agent and its
 * signing path exactly as `submitForAgent` does — an agent that is not started is NOT brought online
 * by a side effect of `getAgentSignaling`, and a missing key provider refuses by name. The namespace
 * owner is the selected agent's own pubkey, taken from the resolver, never a parameter.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager } from "@cello-protocol/transport";
import { createNamespace, closeNamespace, readIndex, type NamespaceDeps } from "./attestation-namespaces.js";
import { markServiceEvent, listRights, type ServiceEventDeps } from "./attestation-service-events.js";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";

type SelResult =
  | { ok: true; name: string; pubkey: string }
  | { ok: false; reason: string; guidance: string };

/** The minimum of the SQLCipher handle the service-event deps need (reads + stored-proof reads). */
interface HandlerDb {
  prepare(sql: string): { get(...p: unknown[]): unknown; all(...p: unknown[]): unknown[]; run(...p: unknown[]): unknown };
}

export function registerAttestationNamespaceHandlers(args: {
  handlers: Map<string, IpcHandler>;
  resolveSelectedAgent: (connectionId: string) => SelResult;
  onlineAgents: ReadonlySet<string>;
  keyProviders: Map<string, KeyProvider>;
  getAgentSignaling: (agentName: string, keyProvider: KeyProvider, pubkeyHex: string) => { signaling: SignalingManager };
  logger: Logger;
  getDb: () => HandlerDb;
  resolveAgentId: (agentName: string) => string;
}): void {
  const { handlers, resolveSelectedAgent, onlineAgents, keyProviders, getAgentSignaling, logger, getDb, resolveAgentId } = args;

  function resolveNamespaceDeps(connectionId: string): { ok: true; deps: NamespaceDeps; pubkey: string } | { ok: false; reason: string; guidance: string } {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    if (!onlineAgents.has(sel.name)) {
      return { ok: false, reason: "agent_offline", guidance: `Agent '${sel.name}' is not started. Run cello_start_agent and try again.` };
    }
    const kp = keyProviders.get(sel.name);
    if (!kp) {
      logger.warn("attestation.namespace.refused", { agentName: sel.name, reason: "key_provider_absent" });
      return { ok: false, reason: "key_provider_absent", guidance: `No signing key is loaded for '${sel.name}'.` };
    }
    const deps: NamespaceDeps = {
      signaling: getAgentSignaling(sel.name, kp, sel.pubkey).signaling,
      keyProvider: kp,
      ownerPubkeyHex: sel.pubkey.toLowerCase(),
      now: Date.now,
      logger,
    };
    return { ok: true, deps, pubkey: sel.pubkey.toLowerCase() };
  }

  // M10E 005-SVCCLIENT — the mark/rights deps add the two DB reads a service event needs: the proof
  // this agent kept for the session, and the hash of its last leaf. Keyed on agent_id throughout.
  function resolveServiceEventDeps(connectionId: string): { ok: true; deps: ServiceEventDeps } | { ok: false; reason: string; guidance: string } {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    if (!onlineAgents.has(sel.name)) {
      return { ok: false, reason: "agent_offline", guidance: `Agent '${sel.name}' is not started. Run cello_start_agent and try again.` };
    }
    const kp = keyProviders.get(sel.name);
    if (!kp) {
      logger.warn("attestation.service_event.refused", { agentName: sel.name, reason: "key_provider_absent" });
      return { ok: false, reason: "key_provider_absent", guidance: `No signing key is loaded for '${sel.name}'.` };
    }
    const agentId = resolveAgentId(sel.name);
    const deps: ServiceEventDeps = {
      signaling: getAgentSignaling(sel.name, kp, sel.pubkey).signaling,
      keyProvider: kp,
      ownerPubkeyHex: sel.pubkey.toLowerCase(),
      now: Date.now,
      logger,
      loadSessionProof: (sessionIdHex) => {
        const row = getDb().prepare("SELECT proof FROM session_proofs WHERE agent_id = ? AND session_id = ?").get(agentId, sessionIdHex) as { proof: Buffer } | undefined;
        return row ? new Uint8Array(row.proof) : null;
      },
      chainHeadHash: (sessionIdHex) => {
        const row = getDb().prepare("SELECT leaf_hash_hex FROM session_tree_leaves WHERE agent_id = ? AND session_id = ? ORDER BY leaf_index DESC LIMIT 1").get(agentId, sessionIdHex) as { leaf_hash_hex: string } | undefined;
        return row ? new Uint8Array(Buffer.from(row.leaf_hash_hex, "hex")) : new Uint8Array(32);
      },
    };
    return { ok: true, deps };
  }

  handlers.set("cello_attestations_mark", async (params, connectionId) => {
    const r = resolveServiceEventDeps(connectionId);
    if (!r.ok) return r;
    const session_id = typeof params?.session_id === "string" ? params.session_id : "";
    const namespace = typeof params?.namespace === "string" ? params.namespace : "";
    if (session_id.length === 0 || namespace.length === 0) {
      return { ok: false, reason: "invalid_input", guidance: "Pass the session id and the namespace, e.g. cello attestations mark <session-id> reviews.prop_8821." };
    }
    const origin_channel = typeof params?.origin_channel === "string" ? params.origin_channel : undefined;
    const res = await markServiceEvent(r.deps, { session_id, namespace, ...(origin_channel !== undefined ? { origin_channel } : {}) });
    if (!res.ok) return res;
    return {
      ok: true, status: res.status, session_id, namespace,
      guidance: res.status === "stored"
        ? `Service event marked in '${namespace}'. The counterparty now holds a right to review you, good for this namespace's window.`
        : `This session already carried that exact service event in '${namespace}'; nothing changed.`,
    };
  });

  handlers.set("cello_attestations_rights", async (params, connectionId) => {
    const r = resolveServiceEventDeps(connectionId);
    if (!r.ok) return r;
    const after = typeof params?.after === "string" ? params.after : undefined;
    const res = await listRights(r.deps, after);
    if (!res.ok) return res;
    return {
      ok: true, rights: res.rights, next: res.next,
      guidance: res.next
        ? `Showing ${res.rights.length}. More exist — call again with after='${res.next}'. An expired right is listed and flagged, never hidden.`
        : `An expired right is listed and flagged, never hidden.`,
    };
  });

  handlers.set("cello_attestations_namespace_create", async (params, connectionId) => {
    const r = resolveNamespaceDeps(connectionId);
    if (!r.ok) return r;
    const namespace = typeof params?.namespace === "string" ? params.namespace : "";
    const mode = params?.mode === "private" ? "private" : params?.mode === "public" ? "public" : null;
    if (!mode) {
      return { ok: false, reason: "invalid_mode", guidance: "mode must be 'public' (anyone can read the reviews) or 'private' (only chosen readers)." };
    }
    const condition = typeof params?.condition === "string" ? params.condition : "";
    if (condition.length === 0) {
      return { ok: false, reason: "empty_condition", guidance: "condition is the plain-words rule under which the right to review is granted — it cannot be blank." };
    }
    const scored = params?.scored === true;
    const ttlDays = typeof params?.ttl_days === "number" ? params.ttl_days : 30;
    const res = await createNamespace(r.deps, { namespace, mode, scored, right_ttl_days: ttlDays, condition });
    if (!res.ok) return res;
    return {
      ok: true, status: res.status, namespace, mode, scored,
      guidance: res.status === "stored"
        ? `Namespace '${namespace}' is recorded and listed in your public index. It is fixed — a new rule means a new namespace.`
        : `Namespace '${namespace}' was already recorded with these exact settings; nothing changed.`,
    };
  });

  handlers.set("cello_attestations_namespace_close", async (params, connectionId) => {
    const r = resolveNamespaceDeps(connectionId);
    if (!r.ok) return r;
    const namespace = typeof params?.namespace === "string" ? params.namespace : "";
    if (namespace.length === 0) {
      return { ok: false, reason: "invalid_namespace", guidance: "Pass the namespace to close, e.g. reviews.prop_8821." };
    }
    const res = await closeNamespace(r.deps, namespace);
    if (!res.ok) return res;
    return {
      ok: true, status: res.status, namespace,
      guidance: `Namespace '${namespace}' is closed — it grants no new rights, and it stays listed in your index.`,
    };
  });

  handlers.set("cello_attestations_index", async (params, connectionId) => {
    const r = resolveNamespaceDeps(connectionId);
    if (!r.ok) return r;
    // Default to the selected agent's own key — "show me my namespaces".
    const owner = typeof params?.owner_pubkey === "string" && /^[0-9a-f]{64}$/.test(params.owner_pubkey.toLowerCase())
      ? params.owner_pubkey.toLowerCase()
      : r.pubkey;
    const after = typeof params?.after === "string" ? params.after : undefined;
    const res = await readIndex(r.deps, owner, after);
    if (!res.ok) return res;
    return {
      ok: true, owner_pubkey: owner, entries: res.entries, next: res.next,
      guidance: res.next
        ? `Showing ${res.entries.length}. More exist — call again with after='${res.next}'. An entry flagged unverified failed its owner-signature check; it is shown, not hidden.`
        : `An entry flagged unverified failed its owner-signature check; it is shown, not hidden.`,
    };
  });
}
