/**
 * M10E 007-NOTICES — the composition of the customer's attestation noticer, kept out of `daemon.ts`.
 *
 * `daemon.ts` is the composition root and is under a shrinking line cap; this file holds the deps
 * builders and the noticer construction so the root carries one call. The builders return null when
 * the agent is not online or not loaded, so a notice lookup for an agent this daemon cannot serve is
 * a debug skip, never a crash.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import { AttestationNotices, makeAttestationNoticer } from "./attestation-notices.js";
import { readIndex, type NamespaceDeps } from "./attestation-namespaces.js";
import type { ServiceEventDeps } from "./attestation-service-events.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import { extractErrorMessage } from "./error-message.js";
import type { Logger } from "./types.js";

/** Bounded so a mode lookup inside the pickup handler cannot wedge a stream teardown. */
const NAMESPACE_MODE_TIMEOUT_MS = 10_000;

export interface AttestationWiringCtx {
  logger: Logger;
  isOnline: (agentName: string) => boolean;
  keyProvider: (agentName: string) => KeyProvider | undefined;
  ownerPubkeyHex: (agentName: string) => string | undefined;
  signalingFor: (agentName: string, kp: KeyProvider, pubkeyHex: string) => NamespaceDeps["signaling"];
  db: () => DaemonDatabase | null | undefined;
  resolveAgentId: (agentName: string) => string;
  screenInbound: (text: string, agentName: string, sessionId: string) => Promise<{ disposition: string }>;
}

export function wireAttestationNoticer(ctx: AttestationWiringCtx): {
  store: AttestationNotices;
  noticer: ReturnType<typeof makeAttestationNoticer>;
  resolveNamespaceMode: (agentName: string, ownerPubkeyHex: string, namespace: string) => Promise<"public" | "private" | "unknown">;
} {
  const store = new AttestationNotices({ db: () => ctx.db() ?? null, logger: ctx.logger, now: Date.now });
  const namespaceDepsFor = (agentName: string): NamespaceDeps | null => {
    if (!ctx.isOnline(agentName)) return null;
    const kp = ctx.keyProvider(agentName);
    if (!kp) return null;
    const pub = ctx.ownerPubkeyHex(agentName)?.toLowerCase();
    if (!pub) return null;
    return { signaling: ctx.signalingFor(agentName, kp, pub), keyProvider: kp, ownerPubkeyHex: pub, now: Date.now, logger: ctx.logger };
  };
  const serviceEventDepsFor = (agentName: string): ServiceEventDeps | null => {
    const base = namespaceDepsFor(agentName);
    if (!base) return null;
    const agentId = ctx.resolveAgentId(agentName);
    return {
      ...base,
      loadSessionProof: (sid) => {
        const row = ctx.db()?.prepare("SELECT proof FROM session_proofs WHERE agent_id = ? AND session_id = ?").get(agentId, sid) as { proof: Buffer } | undefined;
        return row ? new Uint8Array(row.proof) : null;
      },
      chainHeadHash: (sid) => {
        const row = ctx.db()?.prepare("SELECT leaf_hash_hex FROM session_tree_leaves WHERE agent_id = ? AND session_id = ? ORDER BY leaf_index DESC LIMIT 1").get(agentId, sid) as { leaf_hash_hex: string } | undefined;
        return row ? new Uint8Array(Buffer.from(row.leaf_hash_hex, "hex")) : new Uint8Array(32);
      },
    };
  };
  const noticer = makeAttestationNoticer({
    store,
    namespaceDepsFor,
    serviceEventDepsFor,
    screen: ctx.screenInbound,
    resolveAgentId: ctx.resolveAgentId,
    logger: ctx.logger,
  });
  /**
   * M10E 016: read the MODE of `namespace` from `ownerPubkeyHex`'s public, append-only directory
   * index — the review subject owns the namespace and its mode is public even for a private one. Only
   * a VERIFIED entry's mode is trusted (a forged entry is shown `verified:false`, never as genuine).
   * Any failure — the agent not being online, the lookup not succeeding, the namespace being absent,
   * or the entry not verifying — returns "unknown", and the caller refuses rather than guesses.
   */
  const resolveNamespaceMode = async (agentName: string, ownerPubkeyHex: string, namespace: string): Promise<"public" | "private" | "unknown"> => {
    const deps = namespaceDepsFor(agentName);
    if (!deps) return "unknown";
    try {
      const res = await readIndex({ ...deps, timeoutMs: NAMESPACE_MODE_TIMEOUT_MS }, ownerPubkeyHex.toLowerCase());
      if (!res.ok) return "unknown";
      const entry = res.entries.find((e) => e.namespace === namespace && e.verified);
      return entry && entry.mode !== null ? entry.mode : "unknown";
    } catch (err: unknown) {
      ctx.logger.debug("attestation.mode.lookup_failed", { namespace, reason: extractErrorMessage(err) });
      return "unknown";
    }
  };
  return { store, noticer, resolveNamespaceMode };
}
