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
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";

type SelResult =
  | { ok: true; name: string; pubkey: string }
  | { ok: false; reason: string; guidance: string };

export function registerAttestationNamespaceHandlers(args: {
  handlers: Map<string, IpcHandler>;
  resolveSelectedAgent: (connectionId: string) => SelResult;
  onlineAgents: ReadonlySet<string>;
  keyProviders: Map<string, KeyProvider>;
  getAgentSignaling: (agentName: string, keyProvider: KeyProvider, pubkeyHex: string) => { signaling: SignalingManager };
  logger: Logger;
}): void {
  const { handlers, resolveSelectedAgent, onlineAgents, keyProviders, getAgentSignaling, logger } = args;

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
