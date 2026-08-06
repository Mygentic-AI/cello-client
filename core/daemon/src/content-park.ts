/**
 * The content park: relay store-and-forward, and recovery from it.
 *
 * When a counterparty is offline, content is PARKED on the relay — encrypted, so the relay never
 * sees plaintext — and pulled when they come back. autoRecoverForAgent is what runs on reconnect.
 *
 * TWO-PHASE ON PURPOSE, and this is the pattern that unblocks the rest of the daemon:
 *
 *   createContentPark(deps)      — constructed EARLY, because autoRecoverForAgent is called from
 *                                  BOOT-TIME paths (an agent's onConnected, and the seal upgrade's
 *                                  content gate) that run long before the IPC handler map exists.
 *   .registerHandlers(handlers)  — called LATER, once that map does exist.
 *
 * Fusing the two would force construction after the handler map, which puts autoRecoverForAgent in
 * the TEMPORAL DEAD ZONE for every boot-time caller — the daemon then dies at startup with "cannot
 * access before initialization". Separating construction from registration is what makes a module's
 * POSITION IN THE FILE stop mattering, which is the whole reason startDaemon could be taken apart.
 */
import { randomUUID, createHash } from "node:crypto";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { AgentInfo, Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import { ContentParkClient } from "./content-park-client.js";
import { extractErrorMessage } from "./session-relay-client.js";
import { decodeParkEnvelope } from "./park-envelope.js";

export interface ContentParkDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  agents: AgentInfo[];
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
}

export function createContentPark(deps: ContentParkDeps) {
  const { logger, sessionNodeManager, agents, getKeyProvider } = deps;

  // MSG-001-3b: content-park deposit/pull IPC handlers. These drive the daemon's
  // ContentParkClient directly so the daemon↔relay store-and-forward transport can be
  // proven (J-CONTENT increment 1) before the send/receive-path integration. The relay
  // multiaddr (with /p2p/<peerId>) comes from the session assignment's relay endpoint;
  // dials run from the standing receiver (open-gater) node.
  const parseRelayPeer = (multiaddr: string | undefined): { peerId: string; addr: string } | null => {
    if (!multiaddr) return null;
    const peerId = multiaddr.split("/p2p/")[1];
    return peerId ? { peerId, addr: multiaddr } : null;
  };



  // MSG-001-3b (increment 3): RECOVER parked content. Pulls the recipient's parked entries,
  // decrypts each IN-DAEMON (openContentSeal — the relay never sees plaintext), and routes the
  // plaintext through ingestReceivedContent — the SAME inbound chokepoint as a direct receive
  // (M9 single-funnel AC). The content completes the recipient's transcript view of an already-
  // witnessed message so it can be read (cello_receive) and the session bilaterally sealed
  // (DOD-INT-2). This is content-completion, NOT a resumption — the session stays interrupted.
  // DOD-MSG-4: pull a recipient agent's parked mailbox from ONE relay and recover each entry through
  // the inbound funnel (decode envelope → verify+order the signed Structure2 → ingest). Shared by the
  // explicit IPC handler and the auto-recover-on-reconnect trigger below.
  async function recoverParkedFromRelay(
    recipientAgent: { name: string; pubkey?: string },
    relayPeerId: string,
    relayAddrs: string[],
  ): Promise<
    | { ok: true; recovered: number; pulled: number; refused: number; refusals: Array<{ contentHash: string; sessionId: string; reason: string }> }
    | { ok: false; reason: string }
  > {
    const kp = getKeyProvider(recipientAgent.name);
    if (!kp) return { ok: false, reason: "signing_key_unavailable" };
    if (!kp.openContentSeal) return { ok: false, reason: "cannot_unseal" };
    const node = sessionNodeManager.getStandingReceiverNode();
    // Name the CAUSE, not the exit point (review F6): one label stood for "still building",
    // "agent never came online", "shutting down" and "none exists", and it is the label that
    // misdescribed this incident 102 times.
    if (!node) return { ok: false, reason: sessionNodeManager.standingReceiverAbsenceReason(recipientAgent.name) };
    const recipientPubkey = recipientAgent.pubkey ?? "";
    const client = new ContentParkClient({ relayPeerId, relayAddrs, logger });
    const entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
    let recovered = 0;
    // SEC-1 / review M2: a REFUSED entry must not vanish behind `ok:true`. Report it — an operator
    // seeing {ok:true, pulled:3, recovered:0} would otherwise have three messages evaporate with the
    // only explanation buried in the daemon log. This is both the injection signal and, given the
    // deliberate no-tolerant-window rollout, the lagging-peer signal.
    const refusals: Array<{ contentHash: string; sessionId: string; reason: string }> = [];
    // AC7: one correlationId per recover flow, threaded through every event it emits.
    const correlationId = randomUUID();
    for (const e of entries) {
      const unsealed = await kp.openContentSeal(e.ciphertext);
      if (!unsealed) {
        logger.warn("content.recover.unseal_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex });
        continue;
      }
      // SEC-1: authenticate THEN ingest — fused in recoverParkedEntry, which is now the ONLY way
      // parked content can enter the transcript. It verifies the sender's signature over
      // (session_id, recipient_pubkey, content_hash) and that the signer is this session's
      // counterparty, and it still verifies + records the DOD-MSG-4 ordering record when present.
      // Relay deposit is unauthenticated and the seal is anonymous, so WITHOUT this gate anyone
      // holding the recipient's public key — the relay above all — could inject content that gets
      // attributed to the honest counterparty and then notarized by the bilateral seal.
      const contentHashBytes = Buffer.from(e.contentHashHex, "hex");
      const ingest = await sessionNodeManager.recoverParkedEntry(
        recipientAgent.name,
        e.sessionIdHex,
        Buffer.from(recipientPubkey, "hex"),
        unsealed,
        contentHashBytes,
        correlationId,
      );
      if (ingest.ok && ingest.held) {
        // DOD-MSG-4 (review finding #4): a held entry is NOT yet an appended leaf — its sequence is
        // the FUTURE canonical index, not a completed recovery. Do not count it as recovered; log it
        // distinctly so the tally reflects leaves actually written, not content still queued in memory.
        logger.info("content.recover.held", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, canonicalSeq: ingest.sequenceNumber });
      } else if (ingest.ok && ingest.screenedOut) {
        // M9 (code-review LOW-3): a terminal-screened recovered entry IS durably leafed (so it must be
        // confirm-deleted, below) but was NEVER delivered to the agent — do not count it as a delivered
        // recovery, and log it distinctly so observability separates "delivered" from "leafed-but-screened".
        logger.info("content.recover.screened_out", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, sequenceNumber: ingest.sequenceNumber });
        try {
          await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
        } catch (err: unknown) {
          logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: extractErrorMessage(err) });
        }
      } else if (ingest.ok) {
        // DOD-MSG-4 (review #3): count leaves ACTUALLY written — the directly-ingested leaf PLUS any
        // held out-of-order entries this ingest unblocked (appendedCount), not just 1.
        recovered += ingest.appendedCount ?? 1;
        logger.info("content.recovered", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, sequenceNumber: ingest.sequenceNumber });
        // Delete-on-confirm (review #1): the entry is now durably ingested (a fresh leaf, or a dedup
        // of one already present), so confirm-delete it from the relay mailbox. The relay is
        // delete-on-CONFIRM, not delete-on-pull — without this the queue never drains and every
        // reconnect re-pulls the whole history. Held entries are deliberately NOT confirmed (not yet
        // durable). Best-effort: a failed confirm leaves the entry to be re-pulled + deduped next time.
        try {
          await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
        } catch (err: unknown) {
          logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: extractErrorMessage(err) });
        }
      } else if (ingest.reason === "session_committed") {
        // M12-P17: the session ENDED before this arrived. It can never join that chain — appending
        // would change `sealed_root` and invalidate the notarization — but it is VERIFIED content
        // (SEC-1 authenticated it above; that is what separates this branch from the one below), and
        // discarding it silently loses a real message the operator was actually sent.
        //
        // Without this branch the entry is refused and never confirm-deleted, so every drain pulls,
        // verifies and refuses it again — measured at ~120 repeats per message, forever, while the
        // operator never sees it once. Noisy invisible loss.
        //
        // ORDER IS LOAD-BEARING: annex FIRST, confirm-delete SECOND, and only if the annex committed.
        // A crash between them must lose nothing. Reversed, or delete-on-best-effort, converts the
        // loop into PERMANENT SILENT loss — strictly worse than the bug.
        // Review F1: annex `env.content`, NOT `unsealed`. `unsealed` is the whole CBOR park envelope
        // — every other consumer decodes it first (recoverParkedEntry does exactly this before
        // ingesting). Storing the envelope and then deleting the relay copy on the strength of it
        // would leave the operator an unreadable blob as the ONLY surviving copy: the loop stops,
        // the message is still never read, and now nothing else holds it. That is the permanent
        // silent loss the ordering above exists to prevent, arriving one line earlier.
        //
        // Review F5: the hash cross-check has to happen HERE too. `parkSig` covers
        // (session_id, recipient_pubkey, content_hash) — it does NOT cover the envelope's `content`
        // field, and this branch returns before `ingestReceivedContent`'s own check. Without it a
        // relay holding the ciphertext could substitute content under a genuine hash, have it
        // annexed, and have the real copy confirm-deleted. It also makes INSERT OR IGNORE sound:
        // identical hash now genuinely means identical bytes.
        let annexed = false;
        try {
          const env = decodeParkEnvelope(unsealed);
          const computed = createHash("sha256").update(new Uint8Array([0x00])).update(env.content).digest();
          if (Buffer.from(computed).toString("hex") !== e.contentHashHex) {
            logger.error("content.recover.annex.hash_mismatch", {
              sessionId: e.sessionIdHex, contentHash: e.contentHashHex, agentName: recipientAgent.name,
              impact: "content does not match its attested hash — NOT annexed, relay copy kept",
              correlationId,
            });
          } else {
            annexed = sessionNodeManager.recordSealedAnnex(
              recipientAgent.name, e.sessionIdHex, e.contentHashHex, env.content,
              env.senderPubkey ? Buffer.from(env.senderPubkey).toString("hex") : null,
            );
          }
        } catch (err: unknown) {
          logger.error("content.recover.annex.decode_failed", {
            sessionId: e.sessionIdHex, contentHash: e.contentHashHex,
            impact: "envelope could not be decoded — NOT annexed, relay copy kept",
            error: extractErrorMessage(err), correlationId,
          });
        }
        if (annexed) {
          // Review F6: named under `content.recover.*` like its five siblings in this loop, so a
          // grep for the recovery family does not miss the one branch you most want to count.
          logger.info("content.recover.annexed", {
            sessionId: e.sessionIdHex, contentHash: e.contentHashHex, agentName: recipientAgent.name,
            reason: "session_committed", correlationId,
          });
          try {
            await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
          } catch (err: unknown) {
            // The annex holds it, so the message is safe; the relay copy simply gets re-pulled and
            // deduped by the INSERT OR IGNORE next time. Not data loss.
            logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: extractErrorMessage(err) });
          }
        } else {
          // The annex failed and said so. Keep the relay copy — it is now the only one.
          // Review F7: name why the entry is STUCK, not why ingest refused it. Surfacing
          // `session_committed` here sends the operator to look at session state when the fault is
          // in the annex write.
          refusals.push({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, reason: "annex_write_failed" });
        }
      } else {
        // SEC-1 (M2): carry the refusal out to the caller, not just to the log. Deliberately still
        // NOT confirm-deleted — a forgery must not be able to evict itself from the mailbox, and a
        // genuine v1-peer message must not be destroyed by our refusing it.
        //
        // M12-P17: this is why `counterparty_unknown` is NOT annexed above. That reason comes from
        // the SEC-1 authentication step ("we cannot prove the signer") — the content is UNVERIFIED,
        // so deleting it would destroy exactly what this comment protects. Only verified content
        // whose session has ended is safe to move. The unverified backlog needs relay-side expiry,
        // not client-side deletion.
        refusals.push({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, reason: ingest.reason });
        logger.warn("content.recover.ingest_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, reason: ingest.reason, correlationId });
      }
    }
    return { ok: true, recovered, pulled: entries.length, refused: refusals.length, refusals };
  }

  // DOD-MSG-4 (auto-recover-on-reconnect): when an agent comes online, drain its parked mailbox from
  // every relay it has sessions on — symmetric to the SENDER's flushAwaitingContent. Without this,
  // nothing in production pulls a recipient's store-and-forward mailbox and parked content is never
  // delivered. Best-effort; a relay miss is retried on the next agent-online.

  /**
   * DOD-PARK-DRAIN-1 (review F1): one drain per agent at a time, and at most one re-run queued.
   *
   * The drain used to have two triggers; it now has five (agent start, receiver install, every
   * watchdog rebuild, signaling reconnect, the periodic backstop), and under the relay churn this
   * unit exists to survive, rebuilds arrive faster than a drain completes. Concurrent drains are
   * NOT safe by dedup alone: ingestReceivedContent decides "already present" synchronously from
   * the in-memory tree and then AWAITS the security gateway before appending, so two drains that
   * pull the same parked entry can both pass that check and both append — a duplicate leaf, the
   * frontier divergence the recovery path exists to avoid.
   *
   * Coalesced, not queued: a trigger that arrives mid-drain asks for exactly ONE more pass when
   * the current one finishes. Ten rebuilds during one slow pull cost one re-run, not ten.
   */
  const draining = new Set<string>();
  /** agentName → the trigger of the coalesced re-run owed to it (absent = none owed). */
  const drainRerunRequested = new Map<string, string>();

  async function autoRecoverForAgent(agentName: string, trigger = "unspecified"): Promise<void> {
    if (draining.has(agentName)) {
      drainRerunRequested.set(agentName, trigger);
      logger.debug("content.recover.auto.coalesced", { agentName, trigger });
      return;
    }
    draining.add(agentName);
    try {
      let pass = trigger;
      do {
        drainRerunRequested.delete(agentName);
        await drainOnce(agentName, pass);
        pass = drainRerunRequested.get(agentName) ?? pass;
      } while (drainRerunRequested.has(agentName));
    } finally {
      draining.delete(agentName);
      drainRerunRequested.delete(agentName);
    }
  }

  async function drainOnce(agentName: string, trigger: string): Promise<void> {
    const agent = agents.find((a) => a.name === agentName);
    if (!agent?.pubkey) return;
    const relays = sessionNodeManager.getAgentRelayEndpoints(agentName);
    if (relays.length === 0) return;
    let total = 0;
    let failed = 0;
    for (const r of relays) {
      try {
        const res = await recoverParkedFromRelay(agent, r.relayPeerId, r.relayAddrs);
        if (res.ok) {
          total += res.recovered;
        } else {
          // Review #2: a non-ok result (signing_key_unavailable / cannot_unseal / the precise
          // no-receiver cause) was previously silent — log the reason so a run where every relay
          // failed is distinguishable from "nothing was parked".
          failed++;
          logger.warn("content.recover.auto.relay_failed", { agentName, trigger, relayPeerId: r.relayPeerId, reason: res.reason });
        }
      } catch (err: unknown) {
        failed++;
        // extractErrorMessage, NOT String(err): libp2p and the transport reject with structured
        // plain objects, and String() renders every one of them "[object Object]". 102 of these
        // fired during the 2026-08-04 incident and not one was diagnosable from the log.
        logger.warn("content.recover.auto.failed", { agentName, trigger, stage: "relay", relayPeerId: r.relayPeerId, error: extractErrorMessage(err) });
      }
    }
    // Emit the completion event UNCONDITIONALLY — not only when total > 0 — so a clean "nothing
    // parked" run is observable, and distinct from an all-failed run.
    logger.info("content.recover.auto.completed", { agentName, trigger, recovered: total, relayCount: relays.length, failedRelays: failed });
  }


  /** Phase 2: register the IPC handlers, once the handler map exists. */
  function registerHandlers(handlers: Map<string, IpcHandler>): void {
    handlers.set("content_park_deposit", async (params, _connectionId) => {
      const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
      const recipientPubkey = params?.recipientPubkey as string | undefined;
      const contentHash = params?.contentHash as string | undefined;
      const sessionId = params?.sessionId as string | undefined;
      const ciphertext = params?.ciphertext as string | undefined;
      if (!relay || !recipientPubkey || !contentHash || !sessionId || !ciphertext) {
        return { ok: false, reason: "missing_params", guidance: "Provide relayMultiaddr (with /p2p/<peerId>), recipientPubkey, contentHash, sessionId, ciphertext — all hex." };
      }
      const node = sessionNodeManager.getStandingReceiverNode();
      if (!node) return { ok: false, reason: "standing_receiver_unavailable", guidance: "The daemon's standing receiver is not ready yet; retry after startup." };
      const client = new ContentParkClient({ relayPeerId: relay.peerId, relayAddrs: [relay.addr], logger });
      return await client.deposit(node, {
        recipientPubkey: Buffer.from(recipientPubkey, "hex"),
        contentHash: Buffer.from(contentHash, "hex"),
        sessionId: Buffer.from(sessionId, "hex"),
        ciphertext: Buffer.from(ciphertext, "hex"),
      });
    });

    handlers.set("content_park_pull", async (params, _connectionId) => {
      const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
      const recipientPubkey = params?.recipientPubkey as string | undefined;
      if (!relay || !recipientPubkey) {
        return { ok: false, reason: "missing_params", guidance: "Provide relayMultiaddr (with /p2p/<peerId>) and recipientPubkey (hex)." };
      }
      // The recipient must be a local agent — its K_local signs the relay's auth challenge.
      const recipientAgent = agents.find((a) => a.pubkey === recipientPubkey);
      if (!recipientAgent) return { ok: false, reason: "agent_not_found", guidance: "No local agent matches recipientPubkey; only the recipient can pull its own parked content." };
      const kp = getKeyProvider(recipientAgent.name);
      if (!kp) return { ok: false, reason: "signing_key_unavailable", guidance: `Signing key for '${recipientAgent.name}' is not loaded.` };
      const node = sessionNodeManager.getStandingReceiverNode();
      if (!node) return { ok: false, reason: "standing_receiver_unavailable", guidance: "The daemon's standing receiver is not ready yet; retry after startup." };
      const client = new ContentParkClient({ relayPeerId: relay.peerId, relayAddrs: [relay.addr], logger });
      const entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
      return {
        ok: true,
        entries: entries.map((e) => ({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, ciphertext: Buffer.from(e.ciphertext).toString("hex") })),
      };
    });

    handlers.set("content_park_recover", async (params, _connectionId) => {
      const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
      const recipientPubkey = params?.recipientPubkey as string | undefined;
      if (!relay || !recipientPubkey) {
        return { ok: false, reason: "missing_params", guidance: "Provide relayMultiaddr (with /p2p/<peerId>) and recipientPubkey (hex)." };
      }
      const recipientAgent = agents.find((a) => a.pubkey === recipientPubkey);
      if (!recipientAgent) return { ok: false, reason: "agent_not_found", guidance: "No local agent matches recipientPubkey." };
      const res = await recoverParkedFromRelay(recipientAgent, relay.peerId, [relay.addr]);
      if (!res.ok) {
        const guidanceByReason: Record<string, string> = {
          signing_key_unavailable: `Signing key for '${recipientAgent.name}' is not loaded.`,
          cannot_unseal: `Agent '${recipientAgent.name}' key provider cannot open content seals.`,
          standing_receiver_creating: "The daemon's standing receiver is still being built; retry in a few seconds.",
          agent_offline: `Agent '${recipientAgent.name}' is not online, so this daemon has no node to pull from. Start it with cello_start_agent.`,
          no_standing_receiver: "No agent on this daemon has a standing receiver; start an agent first.",
          daemon_shutting_down: "The daemon is shutting down.",
        };
        // The WIRE reason stays the documented contract string for every no-receiver cause
        // (types.ts STANDING_RECEIVER_UNAVAILABLE); the precise cause rides in the guidance,
        // where it helps the operator without breaking a consumer that branches on the reason.
        const noReceiver = new Set(["standing_receiver_creating", "agent_offline", "no_standing_receiver", "daemon_shutting_down"]);
        const wireReason = noReceiver.has(res.reason) ? "standing_receiver_unavailable" : res.reason;
        return { ok: false, reason: wireReason, guidance: guidanceByReason[res.reason] ?? "Recover failed." };
      }
      return { ok: true, recovered: res.recovered, pulled: res.pulled };
    });
  }

  return { autoRecoverForAgent, registerHandlers };
}
