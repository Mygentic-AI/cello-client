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
import { markServiceEvent, listRights, sendServiceClaim, getActivity, type ServiceEventDeps } from "./attestation-service-events.js";
import { claimRight, listClaimedAttestations, type ClaimSubmitResult, type ClaimedCopy } from "./attestation-claim.js";
import { fetchSubmissionResults } from "./signal-submission.js";
import type { SignalSubjectKind, SubmissionOp } from "@cello-protocol/protocol-types";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";

type SelResult =
  | { ok: true; name: string; pubkey: string }
  | { ok: false; reason: string; guidance: string };

/** The shared submission path (signal-handlers.ts `submitForAgent`), passed in so the claim verb
 *  signs and seals through the one audited composer rather than a second copy. */
export type SubmitForAgent = (opts: {
  connectionId: string;
  op: SubmissionOp;
  subjectKind: SignalSubjectKind;
  subject: string;
  body: string;
  context: string;
}) => Promise<ClaimSubmitResult>;

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
  /** The audited compose/sign/seal/send path — 011-CLAIM sends the `attest` op through it. */
  submitForAgent: SubmitForAgent;
}): void {
  const { handlers, resolveSelectedAgent, onlineAgents, keyProviders, getAgentSignaling, logger, getDb, resolveAgentId, submitForAgent } = args;

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
  function resolveServiceEventDeps(connectionId: string): { ok: true; deps: ServiceEventDeps; sel: { name: string; pubkey: string }; agentId: string; keyProvider: KeyProvider } | { ok: false; reason: string; guidance: string } {
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
    return { ok: true, deps, sel: { name: sel.name, pubkey: sel.pubkey }, agentId, keyProvider: kp };
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

  // M10E 011-CLAIM — the holder of a right writes the review; the daemon seals it as an `attest`
  // submission and keeps the author's own copy. The subject has no refuse step.
  handlers.set("cello_attestations_claim", async (params, connectionId) => {
    const r = resolveServiceEventDeps(connectionId);
    if (!r.ok) return r;
    const right_id = typeof params?.right_id === "string" ? params.right_id : "";
    const text = typeof params?.text === "string" ? params.text : "";
    if (!/^[0-9a-f]{64}$/i.test(right_id) || text.length === 0) {
      return { ok: false, reason: "invalid_input", guidance: "Pass the 64-hex right id and the review text, e.g. cello attestations claim <right-id> -- Great to work with." };
    }
    const rating = typeof params?.rating === "number" ? params.rating : undefined;
    const origin_channel = typeof params?.origin_channel === "string" ? params.origin_channel : null;
    const agentId = r.agentId;
    const res = await claimRight(
      {
        svc: r.deps,
        submitAttest: (subject, bodyHex) =>
          submitForAgent({ connectionId, op: "attest", subjectKind: "agent", subject, body: bodyHex, context: "The review was NOT submitted:" }),
        storeLocalCopy: (c) => {
          getDb().prepare(
            "INSERT OR REPLACE INTO claimed_attestations (agent_id, submission_id, right_id, subject_pubkey, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
          ).run(agentId, c.submissionId, c.rightId, c.subject, Buffer.from(c.payload), c.createdAt);
        },
        now: Date.now,
        logger,
      },
      { rightId: right_id, ...(rating !== undefined ? { rating } : {}), text, originChannel: origin_channel },
    );
    if (!res.ok) return res;
    return { ok: true, submission_id: res.submissionId, namespace: res.namespace, subject: res.subject, retrying: res.retrying, stored: res.stored, guidance: res.guidance };
  });

  // M10E 011-CLAIM — the reviews this agent has written, each with its submission outcome.
  handlers.set("cello_attestations_claimed", async (_params, connectionId) => {
    const r = resolveServiceEventDeps(connectionId);
    if (!r.ok) return r;
    const agentId = r.agentId;
    const opener = r.keyProvider as { openContentSeal?: (c: Uint8Array) => Promise<Uint8Array | null> };
    const res = await listClaimedAttestations({
      loadLocalCopies: () => {
        const rows = getDb().prepare(
          "SELECT submission_id, right_id, subject_pubkey, payload, created_at FROM claimed_attestations WHERE agent_id = ? ORDER BY created_at DESC",
        ).all(agentId) as Array<{ submission_id: string; right_id: string; subject_pubkey: string; payload: Buffer; created_at: number }>;
        return rows.map((row): ClaimedCopy => ({
          submissionId: row.submission_id,
          rightId: row.right_id,
          subject: row.subject_pubkey,
          payload: new Uint8Array(row.payload),
          createdAt: row.created_at,
        }));
      },
      fetchResults: () => fetchSubmissionResults({ signaling: r.deps.signaling, keyProvider: opener, logger }),
      logger,
    });
    return {
      ok: true, claimed: res.claimed,
      ...(res.results_unavailable ? { results_unavailable: res.results_unavailable } : {}),
      guidance: res.results_unavailable
        ? `Showing ${res.claimed.length} review(s). The directory could not return outcomes right now (${res.results_unavailable}), so those show 'pending'; your reviews are held and nothing is lost.`
        : `Showing ${res.claimed.length} review(s) you have written. A review the subject cannot refuse; 'pending' means no outcome has come back yet.`,
    };
  });

  // M10E 007-NOTICES — a customer files a service-received claim for a session that earned no right.
  handlers.set("cello_attestations_claim_service", async (params, connectionId) => {
    const r = resolveServiceEventDeps(connectionId);
    if (!r.ok) return r;
    const session_id = typeof params?.session_id === "string" ? params.session_id : "";
    const namespace = typeof params?.namespace === "string" ? params.namespace : "";
    if (session_id.length === 0 || namespace.length === 0) {
      return { ok: false, reason: "invalid_input", guidance: "Pass the session id and the namespace, e.g. cello attestations claim-service <session-id> reviews.prop_8821." };
    }
    const res = await sendServiceClaim(r.deps, { session_id, namespace });
    if (!res.ok) return res;
    return {
      ok: true, status: res.status, session_id, namespace,
      guidance: res.status === "stored"
        ? `Claim filed in '${namespace}'. It grants you NO right to review — it records that you say you received the service, and counts against the provider's namespace until they mark a service event for this session.`
        : `You had already filed this exact claim in '${namespace}'; nothing changed.`,
    };
  });

  // M10E 007-NOTICES — the public activity counts for a namespace (service events + unmarked claims).
  handlers.set("cello_attestations_activity", async (params, connectionId) => {
    const r = resolveServiceEventDeps(connectionId);
    if (!r.ok) return r;
    const owner_pubkey = typeof params?.owner_pubkey === "string" ? params.owner_pubkey : "";
    const namespace = typeof params?.namespace === "string" ? params.namespace : "";
    if (!/^[0-9a-f]{64}$/.test(owner_pubkey.toLowerCase()) || namespace.length === 0) {
      return { ok: false, reason: "invalid_input", guidance: "Pass the owner's 64-hex pubkey and the namespace, e.g. cello attestations activity <pubkey> reviews.prop_8821." };
    }
    const res = await getActivity(r.deps, { owner_pubkey, namespace });
    if (!res.ok) return res;
    return {
      ok: true, owner_pubkey: owner_pubkey.toLowerCase(), namespace,
      service_events: res.service_events, unmarked_claims: res.unmarked_claims,
      guidance: `'${namespace}': ${res.service_events} service event(s) marked, ${res.unmarked_claims} unmarked claim(s). An unmarked claim is a customer who says they got the service in a session the provider never marked.`,
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
