/**
 * Two verbs an operator runs ON an agent rather than through it: rotate its signing shares, and read
 * the relay's ordering receipts for it. Both resolve an agent by name and then reach the consortium
 * on that agent's own signaling connection, which is why they share a module.
 *
 * ⚠️ THE WORK ORDER PUT FOUR VERBS AND `cello_status` IN THIS UNIT. They are three modules, and the
 * split is a measurement rather than taste. Counting every member of each shipped interface,
 * `handlers` and `logger` included: one module for all of it needs **22**. Split by what each
 * surface touches — **12** here, **10** for `cello_status`, **3** for backup/restore, overlapping on
 * `handlers` and `logger` alone. 22 is the shape the order calls "the root with an extra hop".
 *
 * ⚠️ AND THIS MODULE IS AT THE BOUND, NOT UNDER IT. Twelve is exactly the order's ~12 ceiling. A
 * first draft of this note said eleven, which reads like room to spare; unit 7 calibrates against
 * these numbers, so the real one is written here. Anything else that wants to live in this file
 * needs a member it does not already have — which means it does not live in this file.
 */
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager } from "@cello-protocol/transport";
import type { LoadedAgent } from "./agent-loader.js";
import type { SealFailureStore } from "./seal-failure-store.js";
import { runAgentRefresh } from "./session-ceremony.js";

/** `runAgentRefresh`'s own parameter object — the source of truth for the types below, never a copy. */
type RefreshArgs = Parameters<typeof runAgentRefresh>[0];

/** The per-connection agent selection, as these verbs need to read it. */
export interface AdminConnState { currentAgent: string | null; clearedAgent?: string; }

export interface AgentAdminDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** Every agent this daemon has loaded — both verbs resolve a name through it. */
  loadedAgents: ReadonlyArray<LoadedAgent>;
  /** Read this connection's agent selection. The READ, not the container. */
  getConnState: (connectionId: string) => AdminConnState | undefined;
  /** The daemon's single agent-selection rule. Injected, never re-implemented here. */
  resolveCurrentAgent: (connState: AdminConnState | undefined, explicitAgent?: string) => string | null;
  getPersistence: (agentName: string) => RefreshArgs["persistence"];
  /** ⚠️ NOT a getter — for an agent with no manager this CONSTRUCTS one and dials. */
  getAgentSignaling: (
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
  ) => { signaling: SignalingManager; getNode: RefreshArgs["getNode"] };
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  resolveConsortiumRoster: RefreshArgs["getConsortiumEndpoints"];
  getFailoverEndpoint: RefreshArgs["getDirectoryEndpoint"];
  /** Where a dead seal ceremony leaves its mark, so a receipt can say it FAILED and why. */
  sealFailures: SealFailureStore;
}

export function registerAgentAdminHandlers(deps: AgentAdminDeps): void {
  const {
    handlers, logger, sessionNodeManager, loadedAgents, getConnState, resolveCurrentAgent,
    getPersistence, getAgentSignaling, waitForSignalingConnected, resolveConsortiumRoster,
    getFailoverEndpoint, sealFailures,
  } = deps;

  // ─── M8B DOD-REFRESH-1: cello_refresh_shares — proactive share refresh / epoch rollover ───
  handlers.set("cello_refresh_shares", async (params, connectionId) => {
    const connState = getConnState(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined); // M8C-AUTOSTART-1 F18: sole-online fallback
    if (!agentName) {
      // Not an MCP tool — the CLI is the only real caller, and its gesture is the POSITIONAL
      // `cello refresh <name>`, not a JSON param. The old text said "pass { name }", which stopped
      // working at the rename and never worked on this surface anyway. cello_use_agent stays: it is
      // the other real remedy, and renderForSurface rewrites it to `cello use-agent` for a CLI caller.
      return { ok: false, reason: "no_current_agent", guidance: "Name the agent: cello refresh <name>. Or select one for this connection with cello_use_agent." };
    }
    const loaded = loadedAgents.find((a) => a.name === agentName);
    if (!loaded) {
      return { ok: false, reason: "agent_not_found", guidance: `No agent named '${agentName}'. Create + register it first.` };
    }
    // The refresh ceremony reaches the consortium over the agent's signaling node — ensure it is up.
    const entry = getAgentSignaling(agentName, loaded.keyProvider, loaded.pubkey);
    const connected = await waitForSignalingConnected(entry.signaling, 15_000);
    if (!connected) {
      return { ok: false, reason: "directory_unreachable", guidance: "The agent's directory signaling is not connected; start the agent and retry." };
    }
    const result = await runAgentRefresh({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex: loaded.pubkey,
      // DOD-M15-SEALWIRE-1 bullet 2 (review F1): gate the co-signature on the root check.
      verifyCertifiedRoot: (pub, sid, root, leaves) => sessionNodeManager.verifyCertifiedRoot(pub, sid, root, leaves),
      keyProvider: loaded.keyProvider,
      getNode: entry.getNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: entry.signaling,
      logger,
      // DOD-M15-SEALPARTIES-1: where a dead seal ceremony leaves its mark, so `cello_sealed_receipt`
      // can say it FAILED and why instead of falling through to "no receipt yet".
      recordSealFailure: (name: string, sid: string, reason: string, kind: "unresolved" | "refused") =>
        sealFailures.record(name, sid, reason, new Date().toISOString(), kind),
    });
    if (!result.ok) {
      return { ok: false, reason: result.reason, guidance: "Share refresh did not complete — see the daemon log (refresh.ceremony.*) for the cause." };
    }
    return { ok: true, epoch: result.toEpochN, primary_pubkey: result.primaryPubkey, verifying_shares_digest: result.verifyingSharesDigest };
  });

  // ─── M8B DOD-RELAYSIG-1: cello_get_relay_receipts — the agent's stored relay ordering receipts ───
  handlers.set("cello_get_relay_receipts", async (params, connectionId) => {
    const connState = getConnState(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined); // M8C-AUTOSTART-1 F18: sole-online fallback
    if (!agentName) {
      // Not an MCP tool either — same reasoning as cello_refresh_shares above.
      return { ok: false, reason: "no_current_agent", guidance: "Name the agent: cello relay-receipts <name>. Or select one for this connection with cello_use_agent." };
    }
    const loaded = loadedAgents.find((a) => a.name === agentName);
    if (!loaded) {
      return { ok: false, reason: "agent_not_found", guidance: `No agent named '${agentName}'.` };
    }
    const sessionIdHex = typeof params?.session_id === "string" ? (params.session_id as string) : undefined;
    const receipts = sessionNodeManager.getRelayReceipts(loaded.pubkey, sessionIdHex).map((r) => ({
      hash_hex: r.hashHex,
      session_id: r.sessionIdHex,
      relay_id: r.relayId,
      sequence_number: r.sequenceNumber,
      timestamp: r.timestamp,
      signature_hex: r.signatureHex,
      // 069-ORDERPROOF: part of the signed statement, so a caller re-verifying the attestation from
      // the outside cannot rebuild the bytes without it. Absent on rows written before this order.
      running_root_hex: r.runningRootHex,
    }));
    return { ok: true, receipts };
  });
}
