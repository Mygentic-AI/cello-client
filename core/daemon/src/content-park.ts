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
// `createHash` is gone: the annex verifier's hardcoded `sha256(0x00 ‖ content)` became
// `contentHashFor`, so this file no longer computes a content hash without asking which algorithm
// the sender used (`DOD-M15-SEALWIRE-1` part B2a).
import { randomUUID } from "node:crypto";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { AgentInfo, Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SecurityGatewayClient } from "@cello-protocol/gateway";
import { ContentParkClient, ContentParkRefusedError, ContentParkUnreachableError } from "./content-park-client.js";
import { extractErrorMessage } from "./error-message.js";
import { decodeParkEnvelope, sealParkEnvelope } from "./park-envelope.js";
import { contentHashFor, resolveContentHashAlg, isKnownContentHashAlg, CONTENT_HASH_ALGS } from "./wire-content-hash.js";

export interface ContentParkDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  agents: AgentInfo[];
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  /**
   * M12-P17: the annex is the ONE durable store holding counterparty content that never passed the
   * inbound screen — `ingestReceivedContent` refuses a committed session before it reaches that
   * seam. Screening at WRITE makes every future reader safe, rather than leaving a guidance string
   * as the only thing between a stale instruction and an agent that acts on it.
   */
  securityGateway: SecurityGatewayClient;
  /**
   * M12-P17: seam for tests. Production leaves it undefined and gets the real client. Injecting it
   * is what makes the recover path's screening branches reachable — one of them DELETES the relay
   * copy, and an untested delete path is where this milestone's defects have consistently lived.
   */
  makeContentParkClient?: (opts: { relayPeerId: string; relayAddrs: string[]; logger: Logger }) => ContentParkClient;
}

export function createContentPark(deps: ContentParkDeps) {
  const { logger, sessionNodeManager, agents, getKeyProvider, securityGateway } = deps;
  const newParkClient = deps.makeContentParkClient ?? ((o) => new ContentParkClient(o));

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
    const client = newParkClient({ relayPeerId, relayAddrs, logger });
    let entries;
    try {
      entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
    } catch (err: unknown) {
      /**
       * DOD-M15-RELAYAUTH-1 review HIGH-3 — a REFUSAL is not an empty mailbox, and the distinction
       * is the whole point of this branch. Falling through with `[]` would report
       * `{ok:true, pulled:0, recovered:0}` — "nothing was waiting for you" — for a relay that
       * explicitly said it would not release this agent's content. Same defect shape as the
       * refused-entry comment directly below, one layer further out.
       */
      if (err instanceof ContentParkRefusedError) {
        logger.warn("content.recover.refused", { agentName: recipientAgent.name, relayPeerId, reason: err.reason });
        return { ok: false, reason: `relay_refused_pull:${err.reason}` };
      }
      throw err;
    }
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
        // All three verdict branches below are covered by m12-p17-annex-screening.test.ts, driven
        // through this real function with an injected park client and REAL sealed envelopes. The one
        // that matters is TRANSIENT: collapsing it into the terminal branch would delete a good
        // message because the screener was momentarily down — permanent loss caused by an outage.
        // That exact confusion was injected and the test goes red on it.
        let annexed = false;
        let screenedOut = false;
        let screenDeferred = false;
        /**
         * WHY the entry is stuck, for the caller — review B2a F5.
         *
         * Every non-annexing branch fell through to one `annex_write_failed`, at the very line whose
         * comment forbids exactly this: *"name why the entry is STUCK, not why ingest refused it."*
         * The annex write was never attempted in any of these cases. Four distinct causes shared a
         * label that named none of them, and the pre-existing hash-mismatch branch — a genuine
         * tamper — was one of the four.
         */
        let annexRefusal: string | null = null;
        try {
          const env = decodeParkEnvelope(unsealed);
          /**
           * ⚠️ THE SECOND CONTENT-HASH VERIFIER — `DOD-M15-SEALWIRE-1` part B1 review F3, closed by
           * part B2a.
           *
           * This check exists on its own (review F5: `parkSig` does not cover `env.content`, and
           * this branch returns before `ingestReceivedContent`'s own cross-check ever runs), so it
           * is NOT covered by B1's discriminator. Correct today and provably so — **no sender salts
           * in this build**, so every parked entry in existence was hashed `sha256(0x00 ‖ content)`.
           *
           * ✅ FIXED IN PART B2a. The envelope carries the algorithm from v3 onward and this check
           * now runs under it, so the re-pull loop it would otherwise have caused — refuse, keep the
           * relay copy, pull again, refuse again — cannot happen. The other site is
           * `session-node-manager.ts`'s `recoverParkedEntry`; both were changed together, because
           * fixing one and leaving the other is how this defect was created.
           */
          /**
           * TWO CAUSES, TWO REFUSALS — review B2a F2, and the first version collapsed them.
           *
           * "We cannot read the algorithm name" and "we hold no salt" are structurally different and
           * they send the operator to different places. One guidance string served both, and for the
           * salt case both halves of it were wrong: the counterparty's version is irrelevant, and
           * *"delivered once this daemon can verify it"* is a promise this daemon cannot keep — the
           * salt row is not coming back, so the entry loops on every drain forever.
           *
           * The DIRECT path already splits these (`content_hash_alg_unknown` vs
           * `content_hash_salt_unavailable`, B1 review F6). Collapsing them here undid, on the park
           * route, a distinction already paid for on the other one.
           *
           * It is not an edge case: `DOD-M15-SEALWIRE-1`'s own pass-1 F9 records that a park-only
           * session never agrees a salt, because the announcement hangs off `onPeerConnect`. So a
           * null salt is the DEFAULT for exactly the sessions whose content arrives this way.
           */
          const alg = resolveContentHashAlg(env.contentHashAlg);
          const sessionSalt = alg.ok
            ? sessionNodeManager.getSessionContentSalt(recipientAgent.name, e.sessionIdHex)
            : null;
          let computed: Uint8Array | null = null;
          // Discriminated BEFORE the call rather than recovered from a thrown string, so the two
          // causes are branches rather than message-matching.
          let algFailure: null | { reason: "annex_alg_unknown" | "annex_salt_unavailable"; detail: string } = null;
          if (!alg.ok) {
            // A name this build cannot read. NOT a hash mismatch: there is no value to compare
            // against, and reporting it as one would be a tamper claim for a version difference —
            // the same substitution `DOD-M15-SEALWIRE-1` part B1 removed on the direct path.
            algFailure = { reason: "annex_alg_unknown", detail: `the sender named "${alg.value}"` };
          } else if (alg.alg !== CONTENT_HASH_ALGS.SHA256 && !sessionSalt) {
            algFailure = {
              reason: "annex_salt_unavailable",
              detail: `the sender used ${alg.alg} and this side holds no salt for the session`,
            };
          } else {
            try {
              computed = contentHashFor(env.content, {
                alg: alg.alg,
                // OUR salt for the session. The envelope never carries one and could not be trusted
                // if it did — the salt is the shared secret that makes the hash unguessable.
                salt: sessionSalt,
              });
            } catch (err: unknown) {
              // Unreachable given the two checks above; kept so a future algorithm that throws for a
              // third reason cannot fall through into the mismatch branch and be called a tamper.
              algFailure = { reason: "annex_alg_unknown", detail: extractErrorMessage(err) };
            }
          }
          if (algFailure !== null) {
            annexRefusal = algFailure.reason;
            logger.error(
              algFailure.reason === "annex_salt_unavailable"
                ? "content.recover.annex.salt_unavailable"
                : "content.recover.annex.alg_unknown",
              {
                sessionId: e.sessionIdHex, contentHash: e.contentHashHex, agentName: recipientAgent.name,
                declaredAlg: env.contentHashAlg ?? "(absent)",
                detail: algFailure.detail,
                impact: "this parked message could not be CHECKED — not that it failed a check. It was not annexed and the relay copy is kept, so nothing is lost. Nothing here says the sender did anything wrong.",
                guidance: algFailure.reason === "annex_salt_unavailable"
                  // Lifted from the direct path's equivalent, because the operator needs the same
                  // answer wherever the message arrived. Deliberately does NOT promise delivery:
                  // without the salt this entry cannot be verified on any future drain either.
                  // DOD-M15-SALTSPLIT-1 review MEDIUM-3: "never completed" is now one of TWO ways to
                  // hold no salt. The discard undoes an agreement that DID complete, so an operator
                  // reading the old sentence would look for a failure that never happened.
                  ? "This side holds no salt for the session, for one of two reasons. If session.salt.discarded is in the log, the agreement completed and this side then dropped its salt on purpose because the counterparty said it could never hold one. Otherwise the agreement never completed — look for session.salt.read.failed or session.salt.persist.failed. Either way their build is NOT the problem; do not ask them to upgrade. This message will keep being re-pulled and re-refused until the session is closed, so close it and start a new one."
                  : "Their CELLO build is newer than this one: ask which version they run, and upgrade. The message stays on the relay and is delivered once this daemon can read that algorithm.",
                correlationId,
              },
            );
          } else if (Buffer.from(computed!).toString("hex") !== e.contentHashHex) {
            annexRefusal = "annex_hash_mismatch";
            logger.error("content.recover.annex.hash_mismatch", {
              sessionId: e.sessionIdHex, contentHash: e.contentHashHex, agentName: recipientAgent.name,
              // The algorithm the comparison RAN UNDER. Without it a mismatch is unfalsifiable from
              // the log: "the bytes were altered" and "we checked it the wrong way" look identical.
              declaredAlg: env.contentHashAlg ?? "(absent → sha256)",
              impact: "content does not match its attested hash — NOT annexed, relay copy kept",
              correlationId,
            });
          } else {
            // M12-P17 (review F4): screen before storing. Same terminal-vs-transient split the live
            // inbound funnel uses, because the consequences are the same shape.
            const verdict = await securityGateway.screenInbound(env.content, {
              direction: "inbound", agentName: recipientAgent.name, sessionId: e.sessionIdHex, correlationId,
            });
            const terminalBlock = verdict.disposition === "block" && verdict.terminal === true;
            if (verdict.disposition !== "allow" && verdict.disposition !== "redact" && !terminalBlock) {
              // TRANSIENT (gateway down / timeout): keep the relay copy and re-screen next drain.
              // Fail-closed — never store unscreened content because the screen was unreachable.
              logger.warn("content.recover.annex.screen_unavailable", {
                sessionId: e.sessionIdHex, contentHash: e.contentHashHex,
                disposition: verdict.disposition, correlationId,
              });
              screenDeferred = true;
            } else if (terminalBlock) {
              /**
               * TERMINAL: the detector rejected the CONTENT itself, so identical bytes would be
               * rejected identically forever — leaving it on the relay would restore the re-pull
               * loop this drain exists to end. It is still dropped from the relay and still never
               * annexed (the annex is a READABLE record of the conversation, and this was never part
               * of it).
               *
               * ⚠️ **BUT IT IS NO LONGER DISCARDED — review F6.** This comment used to end *"and do
               * NOT store it"*, and that was the last route in the tree that threw a refused message
               * away. `DOD-M15-REFUSEDEVIDENCE-1` retains every other one, and shipped guidance now
               * tells operators that refused messages are kept — so this branch falsified a promise
               * on the case with the most evidence value in the product: hostile bytes aimed at a
               * conversation that has already been sealed.
               *
               * Quarantined, not annexed. The two are different answers to different questions: the
               * annex is what arrived late and is readable, quarantine is what was refused and is
               * withheld. Bounded by the same tier cap and deduped by content, so the loop stays
               * closed.
               */
              const kept = sessionNodeManager.quarantineRefusedInbound(
                recipientAgent.name, e.sessionIdHex, verdict.reason ?? "inbound_screen_blocked",
                env.content, e.contentHashHex,
                env.senderPubkey ? Buffer.from(env.senderPubkey).toString("hex") : null,
                correlationId,
              );
              logger.warn("content.recover.annex.screened_out", {
                sessionId: e.sessionIdHex, contentHash: e.contentHashHex, agentName: recipientAgent.name,
                retained: kept !== null,
                impact: kept !== null
                  ? "content was terminally blocked by the inbound screen — NOT annexed, and RETAINED as quarantined evidence"
                  : "content was terminally blocked by the inbound screen and could NOT be retained — see session.content.quarantine.skipped or .failed",
                correlationId,
              });
              screenedOut = true;
            } else {
              // A redact verdict stores the ALTERED bytes, exactly as the live path delivers them.
              // Those no longer match `content_hash`, which is correct here: the annex is a readable
              // record, not chain content, and the hash column stays the entry's relay identity.
              const body = verdict.disposition === "redact" && verdict.content !== undefined
                ? new Uint8Array(verdict.content)
                : env.content;
              annexed = sessionNodeManager.recordSealedAnnex(
                recipientAgent.name, e.sessionIdHex, e.contentHashHex, body,
                env.senderPubkey ? Buffer.from(env.senderPubkey).toString("hex") : null,
              );
            }
          }
        } catch (err: unknown) {
          annexRefusal = "annex_decode_failed";
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
        } else if (screenedOut) {
          // Terminal block: nothing to keep and nothing to store. Delete so it stops being re-pulled.
          try {
            await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
          } catch (err: unknown) {
            logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: extractErrorMessage(err) });
          }
        } else if (screenDeferred) {
          refusals.push({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, reason: "annex_screen_unavailable" });
        } else {
          // Keep the relay copy — it is now the only one. Review F7: name why the entry is STUCK,
          // not why ingest refused it. `annexRefusal` carries the branch that actually stopped it;
          // the bare `annex_write_failed` fallback is now only what it says — the annex write ran
          // and failed.
          refusals.push({
            contentHash: e.contentHashHex, sessionId: e.sessionIdHex,
            reason: annexRefusal ?? "annex_write_failed",
          });
        }
      } else {
        // M12-P18: content for a session WE REFUSED can be swept — deleting it acts on our own
        // refusal decision, not on the content, so it does not violate the rule that a forgery must
        // not evict itself. This is the fix for the counterparty_unknown re-pull loop (78 of 121
        // stranded entries on one box): the abuse cap refused the session, no session row was ever
        // created, so every drain re-pulled and re-refused the parked content forever.
        if (sessionNodeManager.wasSessionRefused(recipientAgent.name, e.sessionIdHex)) {
          logger.info("content.recover.refused_session.swept", {
            sessionId: e.sessionIdHex, contentHash: e.contentHashHex, agentName: recipientAgent.name,
            reason: ingest.reason,
            impact: "content was parked for a session this agent refused — deleted from the relay, not re-pullable",
            correlationId,
          });
          try {
            await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
          } catch (err: unknown) {
            logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: extractErrorMessage(err) });
          }
        } else {
          // SEC-1 (M2): carry the refusal out to the caller, not just to the log. Deliberately still
          // NOT confirm-deleted for a session we did NOT ourselves refuse — a forgery must not be
          // able to evict itself, and a genuine message we simply have no row for yet must survive.
          // M12-P17: this is also why `counterparty_unknown` is NOT annexed above — the content is
          // UNVERIFIED. The residual (a stranger's stranded content we never refused) needs
          // relay-side TTL, not client-side deletion.
          refusals.push({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, reason: ingest.reason });
          logger.warn("content.recover.ingest_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, reason: ingest.reason, correlationId });
        }
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
    let refusedTotal = 0;
    const refusedReasons: Record<string, number> = {};
    let failed = 0;
    for (const r of relays) {
      try {
        const res = await recoverParkedFromRelay(agent, r.relayPeerId, r.relayAddrs);
        if (res.ok) {
          total += res.recovered;
          // F3: tally by reason so the unattended drain reports refusals it would otherwise swallow.
          refusedTotal += res.refused;
          for (const r2 of res.refusals) refusedReasons[r2.reason] = (refusedReasons[r2.reason] ?? 0) + 1;
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
    // `refusedReasons` for the same reason as above (F3): the drain is the path that runs
    // unattended, so if a refusal is invisible here it is invisible altogether. Counts by reason
    // rather than per-entry, so a mailbox full of one fault does not become a wall of log.
    logger.info("content.recover.auto.completed", {
      agentName, trigger, recovered: total, relayCount: relays.length, failedRelays: failed,
      refused: refusedTotal,
      ...(Object.keys(refusedReasons).length > 0 ? { refusedReasons } : {}),
    });
  }


  /** Phase 2: register the IPC handlers, once the handler map exists. */
  function registerHandlers(handlers: Map<string, IpcHandler>): void {
    /**
     * ⚠️ THIS HANDLER HAS NO PRODUCTION CALLER, AND THAT IS WHY IT DRIFTED.
     *
     * Production parks through `#parkContent` (`daemon.ts`), which seals a SIGNED envelope via
     * `sealParkEnvelope`. This IPC handler is reached only from the spine tests, and it deposited
     * whatever bytes it was handed — so the tests were parking a shape production stopped producing
     * when SEC-1 landed. `authenticateParkedEntry` then refused every one of them with
     * `unsigned_envelope`, which `park-envelope.ts` calls "the ATTACKER shape". Three j-content tests
     * were asserting downstream security properties — tamper detection, dedup, the post-seal
     * straggler guard — that the code never reached, because the entry was thrown out one step
     * earlier for a reason none of them mentioned.
     *
     * So `content` (plaintext hex) now parks the PRODUCTION way: same `sealParkEnvelope`, the sole
     * signer, no second copy of the encoder anywhere near a test.
     *
     * **`contentHash` stays a separate parameter on purpose — it is NOT derived from `content`.**
     * The signature covers `(sessionId, recipient, contentHash)` and deliberately does not bind the
     * content, so a sender CAN sign an entry whose claimed hash does not match what is inside. That
     * is a real malicious-sender case, it is what the recover path's hash cross-check exists to
     * catch, and a caller that wants to exercise it must be able to state the two independently.
     * Deriving the hash here would make that case unreachable and quietly hollow the tamper test.
     *
     * `ciphertext` (the raw path) is kept for the one caller that wants byte fidelity through the
     * relay rather than envelope semantics.
     */
    handlers.set("content_park_deposit", async (params, _connectionId) => {
      /**
       * `Buffer.from(x, "hex")` TRUNCATES at the first invalid pair instead of throwing — the trap
       * `park-envelope.ts` already documents. Unvalidated, a typo'd `content` is signed and sealed at
       * its truncated length and surfaces at the far end as `content_hash_mismatch`: a TAMPER verdict
       * on a local argument mistake. Review MEDIUM-4.
       */
      const hexOrNull = (v: unknown): string | null =>
        typeof v === "string" && v.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(v) ? v : null;

      const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
      const recipientPubkey = hexOrNull(params?.recipientPubkey);
      const contentHash = hexOrNull(params?.contentHash);
      const sessionId = hexOrNull(params?.sessionId);
      const senderAgentName = params?.senderAgentName as string | undefined;
      const hasCiphertext = params?.ciphertext !== undefined;
      const hasContent = params?.content !== undefined;

      if (!relay || !recipientPubkey || !contentHash || !sessionId) {
        const bad = [
          !relay ? "relayMultiaddr (needs /p2p/<peerId>)" : null,
          recipientPubkey === null ? "recipientPubkey" : null,
          contentHash === null ? "contentHash" : null,
          sessionId === null ? "sessionId" : null,
        ].filter(Boolean);
        return { ok: false, reason: "missing_params", guidance: `Missing or not even-length hex: ${bad.join(", ")}. Hex is validated here because Buffer.from truncates silently, and a truncated value is signed and refused at the far end as a content hash mismatch.` };
      }
      if (!hasCiphertext && !hasContent) {
        return { ok: false, reason: "missing_params", guidance: "Provide either `content` (plaintext hex — sealed and SIGNED here, the production shape) or `ciphertext` (hex — deposited verbatim, no envelope)." };
      }
      if (hasCiphertext && hasContent) {
        return { ok: false, reason: "conflicting_params", guidance: "Provide `content` OR `ciphertext`, not both — they are two different deposit shapes and honouring one would silently discard the other." };
      }

      /**
       * ⚠️ PARSED BEFORE THE BRANCH, and refused on the raw branch rather than dropped — review
       * HIGH-2, and it was the same defect this parameter exists to prevent, reintroduced one branch
       * over. It used to be read INSIDE the `content` branch, so `ciphertext` + `contentHashAlg`
       * discarded the algorithm in silence: the far end then resolves the absent field to `sha256`,
       * recomputes unsalted, and reports `content_hash_mismatch` — a tamper verdict on an honest
       * message, with nothing on the sender side logging anything at all.
       *
       * A raw deposit has nowhere to PUT the name (there is no envelope), so naming one is a
       * contradiction, not a preference. Refuse it.
       */
      let contentHashAlg: string | undefined;
      const rawAlg = params?.contentHashAlg;
      if (rawAlg !== undefined && rawAlg !== null) {
        if (typeof rawAlg !== "string" || !isKnownContentHashAlg(rawAlg)) {
          return { ok: false, reason: "unknown_content_hash_alg", guidance: `This daemon cannot compute "${typeof rawAlg === "string" ? rawAlg : `(${typeof rawAlg})`}". Known algorithms: ${Object.values(CONTENT_HASH_ALGS).join(", ")}. Omit the field to mean ${CONTENT_HASH_ALGS.SHA256}.` };
        }
        if (hasCiphertext) {
          return { ok: false, reason: "conflicting_params", guidance: "`contentHashAlg` cannot ride with `ciphertext`: a raw deposit carries no envelope, so there is nowhere to record the algorithm and the far end would recompute under sha256 and report a content hash mismatch on honest content. Use `content` to deposit under a named algorithm." };
        }
        contentHashAlg = rawAlg;
      }

      const node = sessionNodeManager.getStandingReceiverNode();
      if (!node) {
        /**
         * DOD-M15-PARKCONN-1 — **NAME THE CAUSE, NOT THE EXIT POINT** (Invariant 3).
         *
         * `standing_receiver_unavailable` is the label that already misnamed this incident 102
         * times, which is why `standingReceiverAbsenceReason()` exists — and `recoverParkedFromRelay`
         * has used it since M12-P12 while this handler kept returning the bare label. The four causes
         * demand opposite responses: `standing_receiver_creating` clears in seconds and a retry
         * works; `agent_offline` never clears until the agent is started; `daemon_shutting_down`
         * means stop.
         *
         * The wire reason is unchanged — a caller matching on it keeps working — and the cause rides
         * alongside, which is the same shape the send path settled on.
         */
        const namedAgent = senderAgentName ?? (agents.length === 1 ? agents[0]!.name : undefined);
        const cause = namedAgent ? sessionNodeManager.standingReceiverAbsenceReason(namedAgent) : "unknown_agent";
        const guidanceByCause: Record<string, string> = {
          standing_receiver_creating: "The standing receiver is still being built; retry this deposit in a few seconds.",
          agent_offline: `Agent '${namedAgent}' is not online, so this daemon has no node to deposit from. Start it with cello_start_agent.`,
          no_standing_receiver: "No agent on this daemon has a standing receiver; start an agent with cello_start_agent first.",
          daemon_shutting_down: "The daemon is shutting down — nothing was deposited, and retrying will not help until it is back up.",
          unknown_agent: "This daemon has no standing receiver and more than one agent, so it cannot say which; pass senderAgentName, or start an agent with cello_start_agent.",
        };
        logger.warn("content.park.deposit.ipc.result", { relayPeerId: relay.peerId, sessionId, contentHash, ok: false, reason: "standing_receiver_unavailable", cause });
        return { ok: false, reason: "standing_receiver_unavailable", cause, guidance: guidanceByCause[cause] ?? "The daemon's standing receiver is not ready yet; retry after startup." };
      }

      let payload: Uint8Array;
      if (hasContent) {
        const content = hexOrNull(params?.content);
        if (content === null) {
          return { ok: false, reason: "missing_params", guidance: "`content` is not even-length hex. It is validated because Buffer.from truncates silently, and a truncated body is sealed at the wrong length and refused at the far end as a content hash mismatch." };
        }
        /**
         * Which agent signs. Named explicitly when given; otherwise the only local agent that COULD
         * sign, and if there is more than one we REFUSE rather than pick — silently signing as the
         * wrong sender produces an entry the recipient authenticates against a pubkey nobody
         * expected, surfacing at recover time as a signature mismatch with no clue the wrong key was
         * chosen here.
         *
         * `load_failed` agents are excluded (review LOW-5): they hold no key provider, so listing
         * one as a candidate makes a daemon with one healthy agent report `ambiguous_sender` and
         * name a candidate that cannot sign.
         */
        const signable = agents.filter((a) => a.state !== "load_failed");
        const candidates = senderAgentName ? signable.filter((a) => a.name === senderAgentName) : signable;
        if (candidates.length === 0) {
          return { ok: false, reason: "agent_not_found", guidance: senderAgentName ? `No local agent named '${senderAgentName}' that can sign this deposit.` : "This daemon has no loadable local agent to sign the deposit." };
        }
        if (candidates.length > 1) {
          return { ok: false, reason: "ambiguous_sender", guidance: `This daemon has ${candidates.length} signable agents (${candidates.map((a) => a.name).join(", ")}); pass senderAgentName to say which one signs.` };
        }
        const signerAgent = candidates[0]!;

        /**
         * ⚠️ BIND THE SIGNATURE TO A SESSION THIS DAEMON ACTUALLY HOLDS — review HIGH-1.
         *
         * Both production producers derive `(sessionId, recipientPubkey)` from a session record;
         * this handler took them from the caller and signed whatever pair it was handed. A caller
         * passing the wrong session id or the wrong recipient therefore got a perfectly-formed
         * SIGNED entry, which the far end refuses as `bad_signature` / `signer_not_counterparty` —
         * **an attack verdict for a local argument mistake** — and a refused entry is deliberately
         * never confirm-deleted, so it re-pulls forever.
         *
         * `getSessionRecord` returns the row regardless of status, so a COMMITTED session still
         * resolves and the post-seal straggler case keeps working.
         */
        const record = sessionNodeManager.getSessionRecord(signerAgent.name, sessionId);
        if (!record) {
          return { ok: false, reason: "session_not_found", guidance: `Agent '${signerAgent.name}' holds no session ${sessionId.slice(0, 16)}…. Signing a park entry for a session this daemon does not hold produces bytes the recipient can only read as a forgery.` };
        }
        if ((record.counterparty_pubkey ?? "").toLowerCase() !== recipientPubkey.toLowerCase()) {
          return { ok: false, reason: "session_recipient_mismatch", guidance: `Session ${sessionId.slice(0, 16)}… has counterparty ${(record.counterparty_pubkey ?? "(none)").slice(0, 16)}…, not ${recipientPubkey.slice(0, 16)}…. Refused rather than signed: the entry would authenticate against a key the recipient never expects and be reported as a bad signature — an attack verdict for a wrong argument.` };
        }

        const signer = getKeyProvider(signerAgent.name);
        if (!signer) return { ok: false, reason: "signing_key_unavailable", guidance: `Signing key for '${signerAgent.name}' is not loaded.` };
        payload = await sealParkEnvelope({
          signer,
          sessionIdHex: sessionId,
          recipientPubkey: Buffer.from(recipientPubkey, "hex"),
          contentHash: Buffer.from(contentHash, "hex"),
          content: Buffer.from(content, "hex"),
          ...(contentHashAlg !== undefined ? { contentHashAlg } : {}),
        });
      } else {
        const ciphertext = hexOrNull(params?.ciphertext);
        if (ciphertext === null) {
          return { ok: false, reason: "missing_params", guidance: "`ciphertext` is not even-length hex." };
        }
        payload = Buffer.from(ciphertext, "hex");
      }

      /**
       * DOD-M15-PARKCONN-1 — **THE ODD HANDLER OUT NOW REFUSES LIKE ITS SIBLINGS, AND SAYS SO ONCE.**
       *
       * Every other exit above returns `{ ok: false, reason, guidance }`; this one ended in a bare
       * `return await client.deposit(...)` with no catch and no log. An unreachable relay — the
       * ordinary condition park exists for — therefore left the daemon as a THROW, which IPC shapes
       * into `internal_error` + "An unexpected error occurred. Check daemon logs for details." The
       * daemon logs held nothing either: this handler logged NOTHING AT ALL, which is why
       * `019-PARKERROR` went looking for a deposit line and found none.
       *
       * Only `ContentParkUnreachableError` is converted. Anything else still throws, because a
       * blanket catch here would turn a genuine defect into a tidy refusal — the failure this
       * milestone is named for.
       */
      const client = newParkClient({ relayPeerId: relay.peerId, relayAddrs: [relay.addr], logger });
      const logDepositResult = (r: { ok: boolean; reason?: string }): void => {
        // NOT `content.park.deposit.result` — the ContentParkClient already emits that name one
        // layer down, and two events from different layers under one name make an aggregated log
        // unreadable (the same review finding as `content.park.pull.refused_by_relay`).
        const line = { relayPeerId: relay.peerId, sessionId, contentHash, ok: r.ok, ...(r.reason !== undefined ? { reason: r.reason } : {}) };
        if (r.ok) logger.info("content.park.deposit.ipc.result", line);
        else logger.warn("content.park.deposit.ipc.result", line);
      };
      try {
        const res = await client.deposit(node, {
          recipientPubkey: Buffer.from(recipientPubkey, "hex"),
          contentHash: Buffer.from(contentHash, "hex"),
          sessionId: Buffer.from(sessionId, "hex"),
          ciphertext: payload,
        });
        logDepositResult(res);
        return res;
      } catch (err: unknown) {
        if (!(err instanceof ContentParkUnreachableError)) throw err;
        const reason = `relay_unreachable:${err.reason}`;
        logDepositResult({ ok: false, reason });
        return {
          ok: false,
          reason,
          // DoD 1: the per-address reasons are readable from the RESPONSE, not only the log — the
          // caller of this IPC has no daemon log in front of it.
          dialFailures: err.dialFailures,
          guidance:
            `Relay ${relay.peerId} could not be reached from this daemon (${err.reason}), so nothing was deposited and no content was lost. ` +
            (err.dialFailures.length > 0
              ? `Every address failed to dial: ${err.dialFailures.map((f) => `${f.addr} → ${f.error}`).join("; ")}. `
              : `No dial was refused, so the connection existed a moment ago and was gone by the time the stream opened. `) +
            `Retry this call once the relay is up. A conversation cannot be moved to a different relay from here — the park relay comes from the session assignment — so if this relay stays down, broker a new session with cello_initiate_session.`,
        };
      }
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
      let entries;
      try {
        entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
      } catch (err: unknown) {
        // DOD-M15-RELAYAUTH-1 review HIGH-3: a refusal must not be reported as an empty list.
        if (err instanceof ContentParkRefusedError) {
          return {
            ok: false,
            reason: `relay_refused_pull:${err.reason}`,
            guidance:
              "This relay refused to release parked content for this agent — it is NOT an empty mailbox, " +
              "and content may still be waiting. A relay only recognises agents named by a session " +
              "assignment it has recorded, and it forgets them when it restarts. Establish a session " +
              "with this relay (cello_initiate_session) and retry, or pull from the relay that " +
              "brokered the session the content belongs to.",
          };
        }
        throw err;
      }
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
      /**
       * `refusals` REACHES THE CALLER — review B2a pass-2 F3, "no consumer, no ship".
       *
       * `recoverParkedFromRelay` has always returned it and both callers dropped it: this handler
       * returned only `{recovered, pulled}`, and `drainOnce` reads only `res.recovered`. So every
       * refusal reason computed in that loop reached nothing but a vitest assertion — including the
       * four this milestone added to tell a version skew from a tamper from a storage fault.
       *
       * Which made the pass-1 F5 fix a label with no reader, and three of its tests assertions on a
       * channel nobody could observe. An operator seeing `{recovered: 0, pulled: 3}` had three
       * messages evaporate with the explanation only in the daemon log.
       */
      return { ok: true, recovered: res.recovered, pulled: res.pulled, refused: res.refused, refusals: res.refusals };
    });
  }

  // M12-P17: exported for the screening/annex tests. `autoRecoverForAgent` walks every relay the
  // agent has a session on and swallows per-relay errors by design, so it cannot assert what one
  // entry did; this is the single-relay drain the assertions need.
  return { autoRecoverForAgent, registerHandlers, recoverParkedFromRelay };
}
