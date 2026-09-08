/**
 * The trust-signal surface: listing, viewing, enabling, disabling and revoking an agent's signals,
 * issuing an attestation about someone else, the three consent verbs, and the results fetch that
 * asks every directory in the roster what it holds.
 *
 * Twelve handlers plus the two helpers only they use — the selected-agent resolver and
 * `submitForAgent`, the one path that composes, seals, sends and retries a submission. They lived
 * inside `startDaemonHoldingLock` and closed over the daemon's state; here they NAME what they need.
 *
 * ⚠️ FOURTEEN MEMBERS, TWO OVER THE ORDER'S BOUND, AND THERE *IS* A SEAM. Measured, because the
 * first version of this note asserted there was none — which is how a wrong comment survives. Four
 * members have one consumer between them: roster, visiting connection and `waitForSignalingConnected`
 * are `wallet_fetch_results` alone, the manifest is `submitForAgent` alone. Lift the results fetch
 * out and eleven remain, under the bound. It is NOT lifted: it calls `resolveSelectedAgent`, so the
 * split exports a deliberately-private helper or adds a third module, and each module costs the root
 * another ~15-line call site — the failure the order names in bold: extraction that makes the root
 * BIGGER. Two members are not worth that. Recorded so nobody has to re-measure it.
 *
 * Behavior is unchanged — bodies moved verbatim, comments included. The one edit: the per-connection
 * state Map became `getConnState`, since these handlers only ever read one entry and the Map would
 * hand this surface power to mutate connection state. Same narrowing as `contact-handlers.ts`.
 */
import { randomUUID } from "node:crypto";
import { decodeCbor } from "@cello-protocol/protocol-types";
import type { SignalSubjectKind, SubmissionOp, ConsortiumManifest } from "@cello-protocol/protocol-types";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager } from "@cello-protocol/transport";
import { CONSENT_ACCEPTED } from "./consent-migration.js";
import { revocabilityOf } from "./signal-revocability.js";
import { composeSealedSubmission, fetchSubmissionResults, sendSealedSubmission } from "./signal-submission.js";
import { DEFAULT_RETRY_WINDOW_MS, isRetryableSendFailure } from "./submission-retry.js";
import type { SubmissionRetryQueue } from "./submission-retry.js";
import { TrustSignalStore } from "./trust-signal-store.js";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { LoadedAgent } from "./agent-loader.js";
import { extractErrorMessage } from "./error-message.js";

/**
 * Cap on a refusal message (M10B-D4). Generous for prose — the point is not to police what the
 * operator writes, it is that an UNBOUNDED string reaches a signer, a sealer and a transport, and
 * fails in the transport where the error names the wrong subsystem.
 */
const MAX_SUBMISSION_BODY_CHARS = 4000;

/** The per-connection agent selection, as this surface needs to read it. */
export interface SignalConnState { currentAgent: string | null; }

export interface SignalHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** Signing keys by agent name. A missing entry is a refusal, never a silent skip. */
  keyProviders: Map<string, KeyProvider>;
  /** Read-only: a submission needs its agent ONLINE, and this surface must not change that. */
  onlineAgents: ReadonlySet<string>;
  /**
   * Every agent this daemon has loaded — resolves the selected agent's name to its pubkey. It no
   * longer gates attestations: a CO-OWNED subject is annotated by the portal, not refused here.
   */
  loadedAgents: ReadonlyArray<LoadedAgent>;
  /** Read this connection's agent selection. The READ, not the container. */
  getConnState: (connectionId: string) => SignalConnState | undefined;
  /**
   * ⚠️ NOT a getter — for an agent with no manager this CONSTRUCTS one. The comment at its use
   * site says so and moved with the code; it is repeated here because the name reads like a lookup.
   */
  getAgentSignaling: (
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
  ) => { signaling: SignalingManager };
  /** A transient connection to a directory that is not this agent's home node. */
  openVisitingConnection: (
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
    endpoint: { peerId: string; multiaddr: string },
    correlationId: string,
    nodeId: string,
  ) => { mgr: SignalingManager; stop: (reason: string) => Promise<void> };
  /** It returns synchronously and dials in the background; this is what makes it usable. */
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  /** Every directory in the verified consortium. Null when there is no roster at all. */
  resolveConsortiumRoster: () => Promise<Array<{ peerId: string; multiaddr: string; nodeId: string }> | null>;
  /** The verified manifest, for its intake key. Null on every path that verified nothing. */
  verifiedManifest: ConsortiumManifest | null;
  /** Held submissions that could not be sent, retried on a window. */
  submissionRetries: SubmissionRetryQueue;
  /** Record an issued submission against the agent's STABLE id, never its display name. */
  recordIssuedSubmission: (
    agentName: string,
    agentId: string,
    s: { submissionId: string; subject: string; op: SubmissionOp; intakeKeyId: string; stored: boolean },
  ) => void;
}

export function registerSignalHandlers(deps: SignalHandlerDeps): void {
  const {
    handlers,
    logger,
    sessionNodeManager,
    keyProviders,
    onlineAgents,
    loadedAgents,
    getConnState,
    getAgentSignaling,
    openVisitingConnection,
    waitForSignalingConnected,
    resolveConsortiumRoster,
    verifiedManifest,
    submissionRetries,
    recordIssuedSubmission,
  } = deps;

  handlers.set("wallet_list_signals", async (_params, _connectionId) => {
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const rows = store.listAllWalletSignals().map((r) => ({
      type: r.type,
      signal_hash: r.signalHash,
      subject_kind: r.subjectKind,
      subject: r.subject,
      issuer_kind: r.issuerKind,
      /**
       * DOD-M15-SAMEOP-FALSEPOS-1: WHO ISSUED IT. The listing carried `subject` — who the signal is
       * ABOUT — and never who SAID it, so an operator could see "someone endorsed me" and not see
       * who. For the decision this list exists to support (do I rely on this endorsement?) the
       * author is the primary fact, and an endorsement nobody can attribute is worth roughly
       * nothing.
       *
       * `issuer_kind` reads like it answers this and does not: it says `"agent"` or `"portal"`, a
       * category. Elsewhere a field literally named `issuer` holds `"peer-claimed"` /
       * `"platform-verified"` — also a category. Two fields whose names promise identity, neither
       * carrying it.
       *
       * It also unblocks an investigation this omission stalled: four endorsements in a wallet all
       * read `same_operator: true`, and **nothing in the response could say whether the stranger's
       * was among them** — so "a stranger is flagged as self-dealing" and "the stranger's
       * endorsement never arrived" were indistinguishable from the listing. Different bugs, in
       * different places, and the field that separates them was already in the row.
       *
       * Discloses nothing new: the issuer pubkey is inside the notarized envelope the recipient
       * already holds and can already present.
       */
      issuer_pubkey: r.issuerPubkey,
      status: r.status,
      issued_at: r.issuedAt,
      expires_at: r.expiresAt,
      supersedes_hash: r.supersedesHash,
      default_present: r.defaultPresent,
      // M10B / DOD-END-ACCEPT-1 review F4. Without this the operator cannot distinguish a signal
      // that will be presented from one awaiting their decision — or one they already refused —
      // because `default_present: true` looks identical in all three cases. `default_present`
      // answers "include it by default"; this answers the prior question, "may it be presented at
      // all".
      consent_state: r.consentState,
      // M10B / DOD-END-COUNT-1. The operator holds an endorsement whose worth is CAPPED — a
      // recipient's floor excludes it from `min_count` — and until now nothing told them so. Two
      // endorsements looked identical in this list while one could clear a counterparty's bar and the
      // other could not, which is the kind of invisible difference that reads as the protocol being
      // arbitrary. It is a portal-attested envelope field, so surfacing it discloses nothing the
      // recipient will not already see.
      same_operator: r.sameOperator,
    }));
    return { ok: true, signals: rows };
  });

  handlers.set("wallet_view_signal", async (params, _connectionId) => {
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(prefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: extractErrorMessage(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${prefix}'.` };
    }
    let payload: unknown;
    try {
      payload = decodeCbor(row.payload);
    } catch {
      payload = Buffer.from(row.payload).toString("hex");
    }
    return {
      ok: true,
      type: row.type,
      signal_hash: row.signalHash,
      subject_kind: row.subjectKind,
      subject: row.subject,
      issuer_kind: row.issuerKind,
      issuer_pubkey: row.issuerPubkey,
      schema_version: row.schemaVersion,
      status: row.status,
      default_present: row.defaultPresent,
      consent_state: row.consentState,  // review F4 — see wallet_list_signals
      issued_at: row.issuedAt,
      expires_at: row.expiresAt,
      supersedes_hash: row.supersedesHash,
      payload,
    };
  });

  handlers.set("wallet_enable_signal", async (params, _connectionId) => {
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(prefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: extractErrorMessage(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${prefix}'.` };
    }
    // M10B / DOD-END-ACCEPT-1 review F4. Enabling a signal the subject has not accepted returned
    // `{ok: true, default_present: true}` — the daemon affirming it will now be presented, when it
    // never will. `default_present` selects from what is ELIGIBLE, and an unconsented signal is not
    // eligible; saying yes here is a hollow success on the one verb that does respond.
    if (row.consentState !== CONSENT_ACCEPTED) {
      return {
        ok: false,
        reason: "consent_pending",
        guidance:
          `This signal is '${row.consentState ?? "unset"}', not accepted, so it cannot be presented ` +
          "regardless of the default-present flag. Accept it first; enabling it changes nothing until then.",
      };
    }
    store.setDefaultPresent(row.signalHash, true);
    return { ok: true, signal_hash: row.signalHash, default_present: true };
  });

  handlers.set("wallet_disable_signal", async (params, _connectionId) => {
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(prefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: extractErrorMessage(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${prefix}'.` };
    }
    store.setDefaultPresent(row.signalHash, false);
    return { ok: true, signal_hash: row.signalHash, default_present: false };
  });

  // ── M10B / DOD-END-SURFACE-1 — the consent verbs (D-23, M10B-D5) ───────────────────────────────
  //
  // SCOPED TO THE SELECTED AGENT, not to "the first loaded agent" the way wallet_revoke_signal is.
  // Consent is a decision the SUBJECT makes about an object a third party wrote concerning them, so
  // answering it on the wrong agent's behalf is not a cosmetic error — it is one agent deciding for
  // another. The presenting-agent pubkey is also what the store's queries scope on, and passing the
  // device-local agent_id instead now REFUSES rather than silently returning an empty queue.
  const resolveSelectedAgent = (connectionId: string):
    | { ok: true; name: string; pubkey: string }
    | { ok: false; reason: string; guidance: string } => {
    const name = getConnState(connectionId)?.currentAgent ?? null;
    if (!name) {
      return {
        ok: false,
        reason: "no_current_agent",
        // NOT "a consent decision belongs to…" — this resolver is shared with the attestation verbs
        // now, and `cello attestations issued` answered a plain "what happened to what I sent?" with
        // an explanation about consent. Guidance that describes a different verb is worse than none:
        // it sends the reader to fix something that was never wrong.
        guidance: "Select an agent first (cello_use_agent) — these act AS a specific agent, and the wrong one would answer on another agent's behalf.",
      };
    }
    const rec = loadedAgents.find((a) => a.name === name);
    if (!rec) {
      return { ok: false, reason: "agent_not_loaded", guidance: `Agent '${name}' is selected but not loaded on this daemon.` };
    }
    return { ok: true, name, pubkey: rec.pubkey };
  };


  /**
   * Compose → seal → send ONE submission on behalf of the selected agent, applying every guard that
   * must hold for any of them.
   *
   * Extracted because `refuse` and `issue` are the same journey with a different `op`, and a second
   * hand-written copy is how two paths that must agree stop agreeing. The guards are the point: an
   * agent that is not started must not be brought online by a side effect, an unbounded body must
   * not reach the transport, and the CAUSE of a refusal must survive to the operator. Duplicating
   * those means the next verb gets whichever subset its author remembered.
   *
   * INV-ATTRIBUTION holds BY CONSTRUCTION, and it did not before: this used to take the resolved
   * `sel` as a parameter, which is exactly a parameter through which a caller could name a different
   * identity. Both call sites happened to pass the right one, so the invariant held by CONVENTION
   * while the comment claimed structure — and the test that "pinned" it asserted the absence of two
   * identifiers that had never existed, so it could not fail. It now takes `connectionId` and
   * resolves the selection itself. There is no identity input left to get wrong.
   */
  async function submitForAgent(opts: {
    connectionId: string;
    op: SubmissionOp;
    subjectKind: SignalSubjectKind;
    subject: string;
    body: string;
    /** Prefixed onto every failure guidance so the operator knows what DID happen. */
    context: string;
  }): Promise<
    | { queued: true; retrying?: false; stored: boolean; submissionId: string; storedWarning?: string }
    /**
     * DOD-M15-ENDORSE-RETRY-1 — THE DAEMON HAS IT AND IS TRYING AGAIN. Deliberately a third
     * outcome and not a dressed-up failure: reporting this as failed sends the operator to re-run a
     * command whose whole point was that they should not have to, and reporting it as queued claims
     * a directory node accepted something no node has seen.
     */
    | { queued: false; retrying: true; submissionId: string; reason: string; guidance: string }
    | { queued: false; retrying?: false; reason: string; guidance: string }
  > {
    const { context } = opts;
    const resolved = resolveSelectedAgent(opts.connectionId);
    if (!resolved.ok) return { queued: false, reason: resolved.reason, guidance: `${context} ${resolved.guidance}` };
    const sel = resolved;
    if (opts.body.length > MAX_SUBMISSION_BODY_CHARS) {
      return { queued: false, reason: "message_too_long",
        guidance: `${context} it is ${opts.body.length} characters and the limit is ${MAX_SUBMISSION_BODY_CHARS}.` };
    }
    // `getAgentSignaling` is NOT a getter — for an agent with no manager it CONSTRUCTS one, which
    // dials and authenticates to the directory immediately and installs an unbounded reconnect loop.
    // Calling it on a stopped agent would silently bring it online: the directory would route
    // sessions to it while no standing receiver exists (`standing_receiver_unavailable`), and
    // `cello status` would still report it offline.
    if (!onlineAgents.has(sel.name)) {
      return { queued: false, reason: "agent_offline",
        guidance: `${context} agent '${sel.name}' is not started. Run cello_start_agent and try again — re-sending is safe, the submission id is derived from the content.` };
    }
    const kp = keyProviders.get(sel.name);
    if (!kp) {
      logger.warn("signal.submission.refused", { agentName: sel.name, reason: "key_provider_absent", op: opts.op });
      return { queued: false, reason: "key_provider_absent",
        guidance: `${context} no signing key is loaded for '${sel.name}'.` };
    }
    try {
      const composed = await composeSealedSubmission({
        manifest: verifiedManifest, keyProvider: kp, op: opts.op,
        subjectKind: opts.subjectKind, subject: opts.subject, body: opts.body,
        issuedAt: Math.floor(Date.now() / 1000), logger,
      });
      if (!composed.ok) {
        // ERRORS NAME THEIR CAUSE: manifest_unavailable / manifest_expired / intake_key_absent /
        // intake_key_malformed each say WHICH check refused, and that survives rather than
        // collapsing into a generic send failure that points at the network.
        return { queued: false, reason: composed.reason, guidance: `${context} ${composed.guidance}` };
      }
      // Resolved ONCE, and carried. `agent_name` is a display label and is reusable after a
      // retire; every row and every queue entry below keys on this stable id instead.
      const agentId = sessionNodeManager.resolveAgentId(sel.name);
      const sent = await sendSealedSubmission({
        signaling: getAgentSignaling(sel.name, kp, sel.pubkey).signaling,
        submissionId: composed.submissionId, intakeKeyId: composed.intakeKeyId,
        ciphertext: composed.ciphertext, logger,
      });
      if (!sent.ok) {
        // DOD-M15-ENDORSE-RETRY-1 — WORTH RETRYING, OR A VERDICT? The typed failure decides, never
        // a string match. `submission_refused_by_node` means a node decoded it, evaluated it and
        // said no, and it falls straight through to the plain failure below; everything else means
        // no node ever reached a decision, so the daemon keeps it and re-sends on the reconnect.
        /**
         * DO NOT HOLD A BLOB PAST ITS OWN INTAKE KEY (review M4).
         *
         * The sealed bytes are opened by the portal's intake key from THIS manifest. Holding them
         * across that key's expiry produces a submission the portal cannot open and cannot even
         * attribute — poison, with no reply possible — while the operator has been told it is held
         * and needs nothing from them. The plain failure is the better answer: they re-run it once
         * a current manifest is loaded, and they know to.
         *
         * The manifest is in hand here and nowhere inside the queue, which is why the check lives
         * at the call site rather than in the module that owns the window.
         */
        const manifestExpiresAt = verifiedManifest ? Date.parse(verifiedManifest.expires) : NaN;
        const keyOutlivesWindow =
          Number.isFinite(manifestExpiresAt) && manifestExpiresAt - Date.now() > DEFAULT_RETRY_WINDOW_MS;
        if (!keyOutlivesWindow) {
          logger.warn("signal.submission.retry.not_held", {
            agentName: sel.name,
            submissionId: composed.submissionId,
            reason: "intake_key_expires_within_retry_window",
            manifestExpires: verifiedManifest?.expires ?? null,
            impact: "the operator is told it failed rather than being told it is held",
          });
          return {
            queued: false,
            reason: sent.reason,
            guidance:
              `${context} it did not reach a directory node (${sent.reason}), and the daemon is NOT ` +
              "holding it to retry: the portal intake key it is sealed to expires too soon, and a " +
              "submission sent after that expires is one the portal cannot open or even attribute. " +
              "Load a current consortium manifest (cello_status shows its validity), then send it again.",
          };
        }
        if (isRetryableSendFailure(sent.reason)) {
          const held = submissionRetries.enqueue(
            {
              agentName: sel.name,
              agentId,
              submissionId: composed.submissionId,
              intakeKeyId: composed.intakeKeyId,
              // THE SAME SEALED BYTES, carried rather than re-derived. A re-seal is randomised and a
              // re-compose would take a new `issued_at` — which changes the content-derived id, and
              // a changed id is a second endorsement rather than a retry.
              ciphertext: composed.ciphertext,
              op: opts.op,
              subject: opts.subject,
            },
            sent.reason,
          );
          if (held) {
            return {
              queued: false,
              retrying: true,
              submissionId: composed.submissionId,
              reason: sent.reason,
              guidance:
                `${context.replace(/:$/, "")} — not yet. It did not reach a directory node ` +
                `(${sent.reason}), so the daemon is holding it and will send it as soon as the ` +
                "directory signaling stream is back, on whichever node that is. You do NOT need to " +
                "run this again. Run cello_attestations_issued to see where it got to. It is held IN " +
                "MEMORY, so if the daemon restarts before it lands you will have to write it again.",
            };
          }
          // The queue is full, so nothing is holding it and saying otherwise would be a lie the
          // operator acts on. They get the plain failure and the fact that re-sending is safe.
        }
        return { queued: false, reason: sent.reason, guidance: `${context} ${sent.guidance ?? sent.reason}` };
      }
      // F4: `sendSealedSubmission` ALREADY logs `signal.submission.queued` / `.duplicate`. Logging
      // `queued` again here doubled every count-based alarm and, worse, emitted `queued` right after
      // `duplicate` — partially erasing the very distinction the directory's queue repository exists
      // to preserve. A distinct name, only for what the send layer does not know (which agent, which
      // op).
      logger.info("signal.submission.attributed", {
        agentName: sel.name, op: opts.op, submissionId: composed.submissionId, stored: sent.stored,
      });
      // KEEP THE HANDLE, or a withdrawal has nothing to name. Recorded in the SHARED path so every
      // verb added after this one is covered by construction, which is the same reasoning as the
      // `storedWarning` below — and by the same helper the RETRY path uses, so the two cannot drift
      // about what a landed submission records.
      // A LANDED SEND RETIRES AN EARLIER GIVE-UP for the same submission. The id is content-derived,
      // so re-issuing the same words about the same subject produces the same id — this is the "I
      // wrote it again and it worked" case, and leaving the stale failure on the surface would show
      // the operator two contradictory states for one submission, forever.
      submissionRetries.clearGaveUp(agentId, composed.submissionId);
      recordIssuedSubmission(sel.name, agentId, {
        submissionId: composed.submissionId,
        subject: opts.subject,
        op: opts.op,
        intakeKeyId: composed.intakeKeyId,
        stored: sent.stored,
      });
      // F1: `stored: false` means a node reports it ALREADY HELD this submission id. That is either
      // a benign retry or single-node censorship — an operator pre-inserting garbage under a
      // clear-text id — and they are indistinguishable from here. Reporting it as unqualified
      // success is what makes the attack silent. The warning lives in the SHARED path, not at one
      // call site, because the refuse verb had it and the issue verb did not: the same omission
      // would otherwise be available to every verb added after this one.
      return {
        queued: true, stored: sent.stored, submissionId: composed.submissionId,
        ...(sent.stored ? {} : {
          storedWarning: "A directory node accepted it but reports it already held this submission id. If nothing arrives for the recipient, send it again — re-sending is safe, the submission id is derived from the content.",
        }),
      };
    } catch (err: unknown) {
      const reason = extractErrorMessage(err);
      logger.warn("signal.submission.refused", { agentName: sel.name, op: opts.op, reason });
      return { queued: false, reason, guidance: `${context} ${reason}` };
    }
  }

  /**
   * M10B / DOD-END-SURFACE-1 — issue a trust signal ABOUT a counterparty.
   *
   * NOTE WHAT IS NOT HERE: a `type` parameter, and the word "endorsement" anywhere in the path. The
   * submission wire carries no type field — the PORTAL decides what it mints from a submission — so
   * a second client-sourced type needs no new verb, no new parameter and no client change. That is
   * INV-ZEROBUMP holding by construction rather than by discipline, and it is what
   * `DOD-END-PLAYBOOK-1` has to prove with an empty diff.
   *
   * The subject is the counterparty's K_local pubkey: the only identifier a contact actually holds.
   * No account identifier crosses the wire — the portal resolves agent → account at intake, and the
   * directory is hash-only by design.
   */
  // M10B / DOD-END-SURFACE-1 — "see what I have submitted about others". The wallet list answers
  // "what do people say about ME"; this answers the other direction, and it is the prerequisite for
  // withdrawal: you cannot withdraw a submission you cannot name.
  // M10B / `M10B-D25r2` — collect this agent's outcomes from the directory and open any sealed
  // message with k_local. Separate from `wallet_list_issued` because it is a NETWORK call: listing
  // what you submitted must keep working when the directory is unreachable, and folding a fetch into
  // it would make a local read fail for a remote reason.
  handlers.set("wallet_fetch_results", async (_params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const kp = keyProviders.get(sel.name);
    if (!kp) {
      return { ok: false, reason: "agent_not_loaded",
        guidance: `Agent '${sel.name}' has no key loaded, so a sealed result could not be opened. Restart the daemon and select the agent again.` };
    }
    // ── ASK EVERY NODE, AND SAY WHICH ONES DID NOT ANSWER ─────────────────────────────────────────
    // An outcome is recorded on whichever node accepted the submission, and this agent is connected
    // to ONE node — routinely not the same one. Asking only home turns "your refusal is on another
    // node" into "you have no results", which is the answer that makes a counterparty look silent
    // when they were not.
    //
    // A NODE THAT DOES NOT ANSWER IS `unreachable`, NEVER an empty result. If a timeout collapsed
    // into "nothing here", a down node could silently produce a negative answer — the same lie in a
    // new place. The caller is told what was actually covered.
    const seen = new Map<string, ReturnType<typeof mapResult>>();
    const unreachable: string[] = [];
    function mapResult(r: { submissionId: string; outcome: string; reason: string | null; signalHash: string | null; message: string | null; createdAt: string }) {
      return {
        submission_id: r.submissionId,
        outcome: r.outcome,
        reason: r.reason,
        signal_hash: r.signalHash,
        message: r.message,
        created_at: r.createdAt,
      };
    }
    const opener = kp as { openContentSeal?: (c: Uint8Array) => Promise<Uint8Array | null> };

    // Home node first — it needs no connection and answers fastest.
    const home = await fetchSubmissionResults({
      signaling: getAgentSignaling(sel.name, kp, sel.pubkey).signaling,
      keyProvider: opener,
      logger,
    });
    if (home.ok) for (const r of home.results) seen.set(r.submissionId, mapResult(r));
    else unreachable.push("home");

    // Then every OTHER node in the consortium, over a transient visiting connection — the same
    // mechanism a cross-node session uses. Each is independent: one node refusing to answer must not
    // stop the others being asked.
    const roster = (await resolveConsortiumRoster().catch(() => null)) ?? [];
    for (const node of roster) {
      let visit: ReturnType<typeof openVisitingConnection> | null = null;
      try {
        visit = openVisitingConnection(
          sel.name, kp, sel.pubkey,
          { peerId: node.peerId, multiaddr: node.multiaddr },
          randomUUID(), node.nodeId,
        );
        // WAIT FOR THE CONNECTION BEFORE USING IT. openVisitingConnection returns SYNCHRONOUSLY and the
        // manager dials in the background, so asking it for results on the next line finds it still
        // connecting and gets `signaling_reconnecting` — every node, instantly. Observed live once the
        // environment was awake: three regions "unreachable" within 3ms of each other, which no real
        // network failure looks like. The seal-broker path above already does this; this one did not.
        if (!(await waitForSignalingConnected(visit.mgr, 10_000))) {
          logger.warn("signal.results.node.unreachable", { nodeId: node.nodeId, reason: "visiting_connect_timeout" });
          unreachable.push(node.nodeId);
          continue;
        }
        const r = await fetchSubmissionResults({ signaling: visit.mgr, keyProvider: opener, logger });
        if (r.ok) for (const x of r.results) { if (!seen.has(x.submissionId)) seen.set(x.submissionId, mapResult(x)); }
        else {
          // SAY WHY. `unreachable` is a list of node ids and nothing else, so a sweep that fails
          // everywhere reports "all three unreachable" with the cause discarded at the exact point it
          // was known — leaving the only evidence to be guessed at afterwards.
          logger.warn("signal.results.node.unreachable", { nodeId: node.nodeId, reason: r.reason });
          unreachable.push(node.nodeId);
        }
      } catch (err: unknown) {
        logger.warn("signal.results.node.unreachable", {
          nodeId: node.nodeId,
          reason: extractErrorMessage(err),
        });
        unreachable.push(node.nodeId);
      } finally {
        // ALWAYS torn down. A visiting connection left open holds a stream the directory will drain
        // its durable notification queue down — the bug this connection type has already caused once.
        await visit?.stop("results fetch complete").catch(() => {});
      }
    }

    if (seen.size === 0 && unreachable.length > 0 && unreachable.length >= roster.length) {
      // EVERY node we tried failed. Reporting an empty list here would be the exact lie this fan-out
      // exists to prevent.
      //
      // AN EMPTY ROSTER IS ITS OWN ANSWER. `resolveConsortiumRoster()` returns null when there is no
      // current manifest, and `?? []` turns "I do not know of any other nodes" into "there are no
      // other nodes" — so a daemon that cannot resolve the consortium at all reported "No directory
      // node answered (home)", which reads as one bad node rather than as no map. Chasing that cost
      // real time against a hibernated environment on 2026-07-31.
      const noRoster = roster.length === 0;
      return {
        ok: false,
        reason: noRoster ? "consortium_unresolved" : "results_unreachable",
        guidance: noRoster
          ? `This daemon cannot resolve any directory node right now, so there was nowhere to ask (${unreachable.join(", ")} also failed). Check that the directory is reachable — 'directory.consortium.node.unresolved' in the daemon log names each endpoint and why. Your outcomes are held until you collect them; nothing is lost.`
          : `No directory node answered (${unreachable.join(", ")}). Your outcomes are held until you collect them — nothing is lost. Retry when connectivity returns.`,
      };
    }
    return {
      ok: true,
      // WHAT WAS ACTUALLY COVERED. An empty list from a partial sweep means "nothing on the nodes we
      // reached", which is a different claim from "nothing exists".
      ...(unreachable.length > 0 ? { unreachable_nodes: unreachable } : {}),
      results: [...seen.values()],
    };
  });


  handlers.set("wallet_list_issued", async (_params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const agentId = sessionNodeManager.resolveAgentId(sel.name);
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const rows = store.listIssuedSubmissions(agentId).map((r) => ({
      submission_id: r.submissionId,
      subject_pubkey: r.subjectPubkey,
      op: r.op,
      intake_key_id: r.intakeKeyId,
      // Every row in this table reached a node. The in-flight ones below have not.
      delivery: "accepted" as const,
      // FALSE means a node already held this id — a benign retry, or single-node censorship. The
      // operator sees the distinction here rather than only in the moment they submitted.
      stored: r.stored,
      submitted_at: r.submittedAt,
    }));
    /**
     * DOD-M15-ENDORSE-RETRY-1 — THE SUBMISSIONS THAT REACHED NO NODE, listed here because this is
     * the verb whose whole question is "what happened to what I sent?".
     *
     * Without them a submission the daemon is retrying is INVISIBLE — the durable table only gets a
     * row once a node accepted one — so the honest answer to that question was silence, which reads
     * as "you sent nothing". And a give-up whose only consumer is a warn line in `daemon.log` is
     * indistinguishable from the submission never having existed.
     *
     * These are IN MEMORY and do not survive a daemon restart (see submission-retry.ts). That is
     * why they are a separate array rather than blended into `issued`: a caller must be able to
     * tell a durable fact from a live one.
     */
    const inFlight = submissionRetries.list(agentId).map((p) => ({
      submission_id: p.submissionId,
      subject_pubkey: p.subject,
      op: p.op,
      intake_key_id: p.intakeKeyId,
      delivery: p.delivery.state,
      attempts: p.delivery.attempts,
      last_reason: p.delivery.lastReason,
      ...(p.delivery.state === "gave_up" ? { gave_up_because: p.delivery.gaveUpBecause } : {}),
      guidance: p.delivery.guidance,
    }));
    return {
      ok: true,
      issued: rows,
      in_flight: inFlight,
      // NO BODY, and say so rather than letting its absence read as a bug. The text was the
      // operator's own words about a third party; keeping it on disk in the clear is exactly what
      // the sealed-submission path exists to prevent.
      note: "The text you wrote is NOT stored locally — only the handle, subject and verb. That is deliberate: your words about someone else are sealed to the portal and are not kept in the clear on this machine.",
    };
  });

  handlers.set("cello_attestations_issue", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const subject = typeof params?.subject_pubkey === "string" ? params.subject_pubkey.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(subject)) {
      return { ok: false, reason: "invalid_subject",
        guidance: "subject_pubkey must be the counterparty's 32-byte public key as 64 hex characters — run cello_contacts to see the peers you know." };
    }
    const body = typeof params?.body === "string" ? params.body.trim() : "";
    if (body.length === 0) {
      return { ok: false, reason: "empty_body",
        guidance: "An issued signal needs text — it is the claim you are making about them, in your own words." };
    }
    // AN AGENT ABOUT ITSELF IS REFUSED. Issuer and subject are one identity, so there is no fact
    // for a reader to weigh and no downstream annotation that rescues it.
    //
    // CO-OWNERSHIP IS NOT REFUSED — it is ANNOTATED. This guard used to reject ANY subject loaded on
    // this daemon, contradicting the portal, which decides the same question the other way and
    // deliberately (D-29, `submission-ingress.ts`): an agent-subject same-operator endorsement is
    // MINTED and FLAGGED `same_operator: true`, because "these two agents are the same operator" is
    // a true and useful fact for a recipient. The flag is a first-class field in the SIGNED envelope
    // for that purpose — it caps the claim at the endorser's own tier and keeps it out of any count
    // floor, which closes the farming hole. Minting it UNFLAGGED is the hole; refusing it discarded
    // the fact and guaranteed the flagged form could never exist. The daemon stops short of the
    // verdict because it cannot see account linkage (two agents under one account on different
    // machines are invisible here) and the portal can — and refusing here closed the path CELLO's
    // first wedge walks daily: solo multi-agent is the MOST likely way to hit this, not the least.
    if (subject === sel.pubkey.toLowerCase()) {
      return { ok: false, reason: "self_subject",
        guidance: "An agent cannot issue a trust signal about itself — standing has to come from somebody else." };
    }
    const res = await submitForAgent({
      connectionId,
      op: "submit", subjectKind: "agent", subject, body,
      context: "The signal was NOT submitted:",
    });
    // DOD-M15-ENDORSE-RETRY-1 — `ok: true` with `delivery: "retrying"`, and both halves are
    // deliberate. `ok: false` would send the agent to re-run a command the daemon is already
    // handling, which is the exact operator work this unit exists to remove; `queued: true` would
    // claim a directory node accepted something no node has seen. So: not a failure, not an
    // acceptance, and named.
    if (!res.queued && res.retrying) {
      return {
        ok: true, queued: false, delivery: "retrying" as const,
        submission_id: res.submissionId, reason: res.reason, guidance: res.guidance,
      };
    }
    if (!res.queued) return { ok: false, reason: res.reason, guidance: res.guidance };
    return {
      ok: true, queued: true, delivery: "accepted" as const, stored: res.stored, submission_id: res.submissionId,
      // Deliberately NOT "issued". Nothing is minted yet: the portal must still drain, authenticate,
      // scan and mint, and the subject must then ACCEPT it before anyone else can see it. Reporting
      // this as a completed endorsement would promise three steps that have not happened.
      guidance: res.storedWarning
        ? `Submitted for '${sel.name}'. ${res.storedWarning}`
        : `Submitted for '${sel.name}'. The portal will scan and mint it, and it stays invisible to everyone unless the subject ACCEPTS it — they are free to refuse, and a signal they have not accepted is inert. Nothing here is final until they decide.`,
    };
  });

  /**
   * M10B / DOD-END-SURFACE-1 — per-counterparty presentation choice.
   *
   * `present: null` CLEARS the choice rather than setting it false. Those are different states and
   * the surface must keep them apart: cleared means "no opinion, use the signal's default", false
   * means "specifically not this person". An operator who could only toggle true/false would be
   * unable to undo an omission without first knowing what the default had been.
   */
  handlers.set("cello_contact_set_signal", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(pubkey)) {
      return { ok: false, reason: "invalid_pubkey", guidance: "pubkey must be the counterparty's 32-byte public key as 64 hex characters." };
    }
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : "";
    if (prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters — see cello_trust_signals_list." };
    }
    const present = params?.present === null ? null : typeof params?.present === "boolean" ? params.present : undefined;
    if (present === undefined) {
      return { ok: false, reason: "invalid_present", guidance: "present must be true (show it to them), false (never show it to them), or null (clear the choice and fall back to the signal's default)." };
    }
    // Resolve the prefix against signals this agent actually holds, so a typo cannot silently write
    // a preference about a hash that does not exist and sit there doing nothing forever.
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const match = store.listAllWalletSignals().filter((r) => r.signalHash.startsWith(prefix));
    if (match.length === 0) {
      return { ok: false, reason: "signal_not_found", guidance: `No signal in this wallet starts with '${prefix}'.` };
    }
    if (match.length > 1) {
      return { ok: false, reason: "ambiguous_prefix", guidance: `'${prefix}' matches ${match.length} signals — use more characters.` };
    }
    sessionNodeManager.setContactSignalPref(sel.name, pubkey, match[0].signalHash, present);
    return {
      ok: true, signal_hash: match[0].signalHash, pubkey, present,
      guidance: present === null
        ? "Choice cleared — this signal now follows its own default for this contact."
        : present
          ? "This signal will be presented to this contact when a session forms, if you have accepted it."
          : "This signal will NOT be presented to this contact, whatever its default.",
    };
  });

  handlers.set("cello_attestation_consent_list", async (_params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const items = store.listPendingConsent(sel.pubkey).map((r) => {
      // THE PAYLOAD IS THE POINT OF THIS CALL. The operator is being asked to stand behind a claim
      // somebody else wrote about them, and they cannot make that decision from a byte count. An
      // earlier version returned `payload_bytes` while both surfaces instructed the operator to
      // "read the plaintext before accepting" — so following the instruction produced a number, and
      // accepting was necessarily blind. Decoded here, exactly as `wallet_view_signal` does it.
      //
      // Undecodable payloads fall back to hex rather than throwing: one unreadable item must not
      // make every other pending decision unreachable, and hex is honest about what it is.
      let payload: unknown;
      try {
        payload = decodeCbor(r.payload);
      } catch {
        payload = Buffer.from(r.payload).toString("hex");
      }
      return {
        signal_hash: r.signalHash,
        type: r.type,
        subject_kind: r.subjectKind,
        issuer_kind: r.issuerKind,
        issuer_pubkey: r.issuerPubkey,
        issued_at: r.issuedAt,
        // UNTRUSTED, and labelled as such on the way out. These are the issuer's own words, carried
        // verbatim and never restated in any other voice (INV-UNTRUSTED). A consuming model must
        // quote and attribute them — "<issuer> says: …" — never adopt them as its own statement.
        payload,
        payload_is_untrusted_text: true,
      };
    });
    // Seeing the list IS being told. Marking here rather than in cello_use_agent means the operator
    // is never marked notified about something they were not actually shown.
    store.markConsentNotified(sel.pubkey);
    return { ok: true, agent: sel.name, pending: items };
  });

  handlers.set("cello_attestation_consent_accept", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const item = store.listPendingConsent(sel.pubkey).find((r) => r.signalHash.startsWith(prefix));
    if (!item) {
      // Deliberately does NOT fall back to a wallet-wide lookup: a hash this agent has no pending
      // decision on is not this agent's to accept, and finding it anyway would be the cross-agent
      // decision this scoping exists to prevent.
      return { ok: false, reason: "not_pending_for_agent", guidance: `No pending consent item for '${sel.name}' with prefix '${prefix}'.` };
    }
    // The write RESULT is checked, not assumed. `setConsentState` returns false when zero rows
    // changed; reporting "accepted" regardless would tell the operator a decision was recorded that
    // was not, and the next presentation would silently omit it.
    if (!store.setConsentState(item.signalHash, "accepted")) {
      return { ok: false, reason: "consent_write_failed",
        guidance: `The acceptance was NOT recorded — the signal row changed underneath this call. Run cello_attestation_consent_list and retry.` };
    }
    return { ok: true, signal_hash: item.signalHash, consent_state: "accepted" };
  });

  handlers.set("cello_attestation_consent_refuse", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    // REFUSAL IS REACHABLE AFTER ACCEPTANCE, not only while pending.
    //
    // "I accepted this endorsement and now I want it gone" had NO path: refusal was pending-only and
    // revocation is the issuer's to perform, not the subject's. Refusing an accepted item is the
    // answer, and it is the better one — the decision is RECORDED rather than erased, so the trail
    // stays honest, and a refused signal is already inert everywhere it is checked.
    //
    // Peer-issued only (`issuer_kind <> 'portal'`, enforced in the store). Refusal makes a signal
    // inert, so allowing it on portal-issued signals would be a back door to suppressing a MANDATORY
    // track record — achieving by consent exactly what revocation is forbidden from doing.
    const item = store.findDecidableConsent(sel.pubkey, prefix);
    if (!item) {
      return {
        ok: false,
        reason: "not_decidable_for_agent",
        guidance:
          `No pending or accepted attestation for '${sel.name}' with prefix '${prefix}'. Refusal ` +
          `applies to attestations another party issued ABOUT you — signals the portal issued (your ` +
          `track record, verified email and phone, GitHub links, security factors) are not refused ` +
          `here. Run cello_attestation_consent_list to see what is decidable.`,
      };
    }
    const wasAccepted = item.consentState === "accepted";
    // ORDER IS LOAD-BEARING: the refusal is recorded FIRST and is never conditional on the message
    // getting out. A refusal that only takes effect if the network cooperates would leave a signal
    // Alice believes she rejected sitting in an unrefused state — the exact failure INV-CONSENT
    // exists to prevent. The message is a courtesy layered on top of a decision already made.
    //
    // And the write is CHECKED. The ordering above is worth nothing if nothing confirms the record
    // happened: without this, the code would go on to sign and send Bob a refusal message about a
    // decision that is not in the database.
    if (!store.setConsentState(item.signalHash, "refused")) {
      return { ok: false, reason: "consent_write_failed",
        guidance: `The refusal was NOT recorded — the signal row changed underneath this call. Run cello_attestation_consent_list and retry.` };
    }
    const refused = {
      ok: true as const,
      signal_hash: item.signalHash,
      consent_state: "refused" as const,
      // WITHDRAWN vs REFUSED, told apart in the response, because they are different acts and the
      // operator needs to know which one just happened. Also flags the supersession consequence:
      // accepting a re-issue supersedes what it replaced, and refusing it afterwards does NOT bring
      // the predecessor back. Withdrawing consent from a replacement can therefore leave you with
      // neither — surfaced rather than discovered.
      ...(wasAccepted
        ? {
            withdrawn_after_acceptance: true,
            guidance:
              `Consent WITHDRAWN — you had accepted this and it is now refused, so it stops being ` +
              `presented anywhere. The record of the decision remains, which is what keeps the trail ` +
              `honest. Note: if this attestation superseded an earlier one when you accepted it, the ` +
              `earlier one stays superseded — withdrawing from a replacement does not restore what it ` +
              `replaced.`,
          }
        : {}),
    };

    // M10B-D4: the message back to the issuer is the subject's CHOICE. Silence is the default, and a
    // silent refusal tells Bob NOTHING — which is what keeps D-24 intact for anyone who wants it.
    const message = typeof params?.message === "string" ? params.message.trim() : "";
    if (message.length === 0) return { ...refused, message_queued: false };

    // ACCOUNT-SUBJECT ITEMS DO NOT GET A MESSAGE YET, and this is a refusal, not an oversight.
    //
    // `listPendingConsent` scopes with `(subject_kind <> 'agent' OR lower(subject) = ?)`, so EVERY
    // agent on this daemon can see — and therefore refuse — an account-subject item. The refusal
    // itself is defensible (it is the account's own decision, and any of its agents speaks for it),
    // but the MESSAGE is signed with THIS agent's K_local, so the issuer would receive a signed
    // statement from an agent that was not the subject of anything. Which agent may speak for an
    // account is an open question this milestone has not answered, and signing is not the place to
    // guess at it. So the decision stands and the courtesy is withheld, with the reason named.
    if (item.subjectKind !== "agent") {
      return { ...refused, message_queued: false, message_error: "account_subject_message_unsupported",
        guidance: `The refusal is recorded. Your message was NOT sent: this signal is about the ACCOUNT rather than about '${sel.name}', and a message would be signed by this agent alone — which agent may speak for an account is not yet settled.` };
    }

    // Rides the submission queue as the `refuse` op. The SUBJECT is the target signal hash (as it is
    // for a withdrawal — both verbs act on an existing signal), and `subject_kind` is carried from
    // the row rather than hardcoded: it is inside the TBS, so a hardcoded value would be a SIGNED
    // field asserting something false.
    const res = await submitForAgent({
      connectionId,
      op: "refuse", subjectKind: item.subjectKind, subject: item.signalHash, body: message,
      context: "The refusal is recorded. Your message was NOT sent:",
    });
    // DOD-M15-ENDORSE-RETRY-1: the refusal itself is already recorded and unaffected either way —
    // what is in question is only the MESSAGE back to the issuer. `message_delivery: "retrying"` is
    // not `message_queued`, because no node has it yet, and it is not an error, because nothing is
    // asked of the operator.
    if (!res.queued && res.retrying) {
      return {
        ...refused, message_queued: false, message_delivery: "retrying" as const,
        submission_id: res.submissionId, guidance: `The refusal is recorded. ${res.guidance}`,
      };
    }
    if (!res.queued) {
      return { ...refused, message_queued: false, message_error: res.reason, guidance: res.guidance };
    }
    // `message_queued`, NOT `issuer_notified`. A directory node acked a sealed blob; the portal has
    // not drained it, scanned it, minted it, or delivered anything to the issuer.
    //
    // `stored` is carried through rather than collapsed into plain success: it is the ONE signal
    // separating a benign duplicate from single-node censorship (an operator pre-inserting garbage
    // under a clear-text submission_id), and folding them together destroys the only information
    // that could ever tell them apart.
    return {
      ...refused, message_queued: true, message_delivery: "accepted" as const,
      stored: res.stored, submission_id: res.submissionId,
      ...(res.storedWarning ? { guidance: `The refusal is recorded. ${res.storedWarning}` } : {}),
    };
  });

  handlers.set("wallet_revoke_signal", async (params, connectionId) => {
    const hashPrefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!hashPrefix || hashPrefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const resolvedAgent = resolveSelectedAgent(connectionId);
    if (!resolvedAgent.ok) return resolvedAgent;
    const sel = resolvedAgent;
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(hashPrefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: extractErrorMessage(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${hashPrefix}'.` };
    }
    const signalHash = row.signalHash;

    // ── CATEGORY CHECK, BEFORE ANYTHING IS DESTROYED ───────────────────────────────────────────
    //
    // This handler used to accept ANY signal in the wallet by hash and go — no type check at all.
    // The signal used in the 2026-08-10 live test was a `track_record`, and the tool accepted the
    // instruction to destroy it and deleted the local copy. Had the directory path been working,
    // an operator could have deleted their own behavioural history: precisely what the
    // mandatory-signal rule exists to prevent.
    //
    // Placed BEFORE the signing and before the local delete, because the local delete is
    // unconditional further down — a refusal that happens after it would still have destroyed the
    // operator's copy.
    //
    // This is a courtesy, NOT the enforcement: an operator can edit this file. The portal refuses
    // mandatory revocations server-side, and the directory already makes a non-issuer's tombstone
    // inert for attestations. See signal-revocability.ts.
    // M7: THE WALLET LOOKUP IS NOT AGENT-SCOPED, so refuse here rather than queue under the wrong
    // key. `getWalletSignalByPrefix` matches on hash alone, and several agents share this daemon's
    // database — so the SELECTED agent could sign a revocation for a signal that is another agent's.
    // The portal blocks it across accounts, but within one account it would silently succeed under
    // the wrong agent's key, and across accounts the operator waits for an async `not_authorized`
    // instead of being told immediately.
    if (row.subjectKind === "agent" && row.subject.toLowerCase() !== sel.pubkey.toLowerCase()) {
      return {
        ok: false,
        reason: "not_your_signal",
        guidance:
          `That signal is about a different agent, not '${sel.name}'. Select the agent it belongs to ` +
          `with cello_use_agent and retry.`,
      };
    }

    const revocability = revocabilityOf(row.type);
    if (!revocability.revocable) {
      return {
        ok: false,
        reason: revocability.category === "mandatory" ? "signal_not_revocable" : "revoke_via_portal",
        signal_type: row.type,
        guidance: revocability.guidance,
      };
    }

    // ── VIA THE PORTAL'S SUBMISSION QUEUE, NOT A DIRECT CALL TO A DIRECTORY ────────────────────
    //
    // What was here POSTed `/internal/signal/revoke` to port 9090 — the HEALTH port — took the 404
    // as an answer, returned `ok: true` regardless, and hard-deleted the local copy "regardless of
    // directory result". Measured 2026-08-10 against the live fleet: all three nodes unchanged, the
    // operator's copy gone, and the tool reporting success. It also asked ONE node under a comment
    // claiming it asked all three.
    //
    // The route is not the fix for a wrong port. The real route lives on the internal API, which is
    // firewalled to the VPC subnets and unreachable from an operator's machine by any URL. And the
    // deciding reason is ENFORCEMENT, not reachability: the directory deliberately cannot tell a
    // `track_record` from a `github_id` (opaque `type`, no enum, so a new signal type never needs a
    // directory deploy), and both are portal-issued, so `issuer_kind` does not separate them. A
    // direct verb would revoke a behavioural record on request with only an editable client in the
    // way. The PORTAL minted the signal and knows what it is, so the category rule can be real there
    // rather than advisory here.
    //
    // Rides the EXISTING sealed submission queue — same path as an endorsement, same results
    // channel. No new wire verb.
    const submitted = await submitForAgent({
      connectionId,
      op: "revoke",
      // The TARGET SIGNAL HASH, exactly as `refuse` and `withdraw` carry it — this acts on an
      // existing signal rather than asserting a fact about a party.
      subjectKind: row.subjectKind,
      subject: signalHash,
      body: "",
      context: "The revocation was NOT queued:",
    });
    // DOD-M15-ENDORSE-RETRY-1: the local copy survives either way (see below), so a retrying
    // revocation is a wait, not a loss — and the operator is told which it is rather than being
    // sent to re-run a retraction the daemon is already carrying.
    if (!submitted.queued && submitted.retrying) {
      return {
        ok: true, signal_hash: signalHash, submission_id: submitted.submissionId,
        revoked: false, queued: false, delivery: "retrying" as const,
        guidance:
          `Revocation for '${row.type}' is HELD, not yet at a directory. ${submitted.guidance} ` +
          "Your local copy is KEPT either way, deliberately, so nothing is lost while it waits.",
      };
    }
    if (!submitted.queued) {
      return { ok: false, reason: submitted.reason, guidance: submitted.guidance };
    }

    // THE LOCAL COPY SURVIVES. It used to be deleted unconditionally, so a failed retraction also
    // destroyed the ability to retry — and since the directory half never worked, that was every
    // retraction. The signal stays until the portal confirms the revocation; the operator can see
    // the outcome with cello_attestations_issued and the wallet reflects it on the next refresh.
    return {
      ok: true,
      signal_hash: signalHash,
      submission_id: submitted.submissionId,
      revoked: false,
      queued: true,
      delivery: "accepted" as const,
      // M5: CARRIED, not dropped. `submitForAgent`'s own comment says the warning lives in the
      // shared path "because the same omission would otherwise be available to every verb added
      // after this one" — and this was the next verb added. `stored:false` means a node already held
      // this id: usually a benign retry, but also what single-node censorship looks like, and
      // without it that reads as unqualified success.
      stored: submitted.stored,
      ...(submitted.storedWarning ? { stored_warning: submitted.storedWarning } : {}),
      guidance:
        `Revocation QUEUED for '${row.type}' — not yet revoked. The portal opens it, checks the ` +
        `signal is one you may retract, and revokes it at the directory; the outcome comes back on ` +
        `the results channel. Your local copy is KEPT — deliberately, so a failure leaves you able to ` +
        `retry. Nothing removes it automatically even on success: check the outcome with ` +
        `cello_attestations_issued.`,
    };
  });
}
