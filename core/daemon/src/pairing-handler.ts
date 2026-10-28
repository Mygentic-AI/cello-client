/**
 * cello_pair_start / cello_pair_await — pair this daemon with an account.
 *
 * The daemon opens a pairing on a directory, and a background poller in the daemon (not the CLI)
 * collects the approval, so an approval that lands after the terminal closed is still stored. The
 * credential is checked to name this daemon's key before it is stored. The directories enforce
 * everything that matters; this code only keeps an honest daemon from weakening it.
 */
import { randomUUID } from "node:crypto";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";
import type { DbPairingStore, PendingPairing } from "./pairing-store.js";
import { deviceFacts, openPairing, pollOnce, type DeviceFacts, type FetchFn } from "./pairing-client.js";

export const PAIRING_POLL_INTERVAL_MS = 3_000;
const GUIDANCE_NEW_CODE = "The code was not approved in time. Run 'cello register-agent <name>' again for a new code.";

export type PairingOutcome =
  | { ok: true; account_id: string }
  | { ok: false; reason: string; guidance: string };

export interface PairingHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  pairingStore: DbPairingStore;
  /** Directory HTTP bases, in the order to try them. */
  getBases: () => string[];
  fetchFn?: FetchFn;
  pollIntervalMs?: number;
  now?: () => number;
  facts?: () => DeviceFacts;
}

interface RunningPairing {
  pending: PendingPairing;
  /** Null for a pairing resumed after a restart: the link is not stored, so it cannot be shown again. */
  approveUrl: string | null;
  cancelled: boolean;
  outcome: Promise<PairingOutcome>;
}

export function registerPairingHandlers(deps: PairingHandlerDeps): void {
  const { handlers, logger, pairingStore, getBases } = deps;
  const fetchFn: FetchFn = deps.fetchFn ?? ((url, init) => fetch(url, init));
  const intervalMs = deps.pollIntervalMs ?? PAIRING_POLL_INTERVAL_MS;
  const now = deps.now ?? Date.now;
  const facts = deps.facts ?? deviceFacts;
  let running: RunningPairing | null = null;

  const end = (pending: PendingPairing, correlationId: string, outcome: PairingOutcome): PairingOutcome => {
    if (pairingStore.pending()?.code === pending.code) pairingStore.clearPending();
    logger.info("pairing.ended", { reason: outcome.ok ? "approved" : outcome.reason, correlationId });
    return outcome;
  };

  async function poll(run: RunningPairing, correlationId: string): Promise<PairingOutcome> {
    const { pending } = run;
    const { keyProvider, pubkeyHex } = pairingStore.daemonKey();
    const opener = pending.base;
    const others = getBases().filter((b) => b !== opener);
    let base = opener;
    let nextOther = 0;
    const moveOn = (): void => {
      if (others.length === 0) { base = opener; return; }
      base = base === opener ? others[nextOther++ % others.length]! : opener;
    };
    while (now() < pending.expiresAt) {
      const r = await pollOnce(base, pending.code, keyProvider, fetchFn, now);
      if (run.cancelled && r.kind !== "approved") {
        return end(pending, correlationId, { ok: false, reason: "pairing_replaced", guidance: "A newer pairing code replaced this one. Approve the code 'cello register-agent' showed most recently." });
      }
      if (r.kind === "approved") {
        if (r.credential.daemon_pubkey !== pubkeyHex) {
          logger.error("pairing.credential.mismatch", { base, correlationId });
          return end(pending, correlationId, {
            ok: false,
            reason: "pairing_credential_mismatch",
            guidance: "A directory returned a credential for a different device key, so it was not stored. Run 'cello register-agent <name>' again for a new code.",
          });
        }
        pairingStore.saveCredential(r.credential);
        logger.info("pairing.approved", { accountId: r.credential.account_id, correlationId });
        return end(pending, correlationId, { ok: true, account_id: r.credential.account_id });
      }
      if (r.kind === "unreachable") {
        logger.warn("pairing.poll.failed", { base, status: r.status ?? null, correlationId });
        moveOn();
      } else if (r.kind === "refused") {
        if (r.status === 404 && base !== opener) {
          // The request has not replicated to this directory yet; the opener is authoritative.
          logger.warn("pairing.poll.failed", { base, status: 404, correlationId });
          base = opener;
        } else {
          logger.warn("pairing.poll.failed", { base, status: r.status, correlationId });
          const reason = r.status === 410 ? "pairing_expired"
            : r.status === 429 ? "pairing_locked"
            : r.status === 404 ? "pairing_not_found"
            : "pairing_poll_refused";
          const fallback = reason === "pairing_poll_refused"
            ? `The directory refused this device's poll (HTTP ${r.status}). Check this machine's clock, then run 'cello register-agent <name>' again.`
            : GUIDANCE_NEW_CODE;
          return end(pending, correlationId, { ok: false, reason, guidance: r.guidance ?? fallback });
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    return end(pending, correlationId, { ok: false, reason: "pairing_expired", guidance: GUIDANCE_NEW_CODE });
  }

  function startPoller(pending: PendingPairing, approveUrl: string | null, correlationId: string): RunningPairing {
    if (running) running.cancelled = true;
    const run: RunningPairing = { pending, approveUrl, cancelled: false, outcome: Promise.resolve(null as never) };
    run.outcome = poll(run, correlationId)
      .catch((err: unknown) => end(pending, correlationId, {
        ok: false,
        reason: "pairing_failed",
        guidance: `Pairing stopped on a local error (${err instanceof Error ? err.message : String(err)}). Run 'cello register-agent <name>' again.`,
      }))
      .finally(() => { if (running === run) running = null; });
    running = run;
    return run;
  }

  // A pairing left open by a previous daemon run is resumed, so its approval is still collected.
  const leftOver = pairingStore.pending();
  if (leftOver && pairingStore.credential() === null && now() < leftOver.expiresAt) {
    startPoller(leftOver, null, randomUUID());
  }

  handlers.set("cello_pair_start", async () => {
    if (pairingStore.credential() !== null) return { ok: true, paired: true };
    const stored = pairingStore.pending();
    if (stored && now() < stored.expiresAt && running && running.pending.code === stored.code && running.approveUrl) {
      return { ok: true, paired: false, pairing_code: stored.code, approve_url: running.approveUrl, expires_at: stored.expiresAt };
    }
    const correlationId = randomUUID();
    const { pubkeyHex } = pairingStore.daemonKey();
    const opened = await openPairing(getBases(), pubkeyHex, facts(), fetchFn);
    if (!opened.ok) {
      for (const f of opened.failures) logger.warn("pairing.poll.failed", { base: f.base, status: f.status ?? null, correlationId });
      logger.info("pairing.ended", { reason: opened.reason, correlationId });
      return { ok: false, reason: opened.reason, guidance: opened.guidance };
    }
    pairingStore.savePending(opened.pairing_code, opened.base, opened.expires_at);
    logger.info("pairing.opened", { codePrefix: opened.pairing_code.slice(0, 4), base: opened.base, correlationId });
    const pending = { code: opened.pairing_code, base: opened.base, expiresAt: opened.expires_at };
    startPoller(pending, opened.approve_url, correlationId);
    return { ok: true, paired: false, pairing_code: opened.pairing_code, approve_url: opened.approve_url, expires_at: opened.expires_at };
  });

  handlers.set("cello_pair_await", async () => {
    if (running) return await running.outcome;
    const credential = pairingStore.credential();
    if (credential) return { ok: true, account_id: credential.account_id };
    return { ok: false, reason: "not_pairing", guidance: "Run 'cello register-agent <name>' to pair this device." };
  });
}
