/**
 * M7 Keystone (Part 2) — production `signalingConnect` for the daemon.
 *
 * This is the daemon's directory-facing dialer. It establishes ONE authenticated
 * signaling stream to a directory node and returns it as a transport
 * `ConnectResult`. The transport `SignalingManager` owns everything after connect:
 * heartbeat, reconnect (it calls connect() again on a fresh attempt), the outbound
 * queue, and optional manifest polling.
 *
 * The 7-step handshake below is the wire protocol the directory speaks. It is not negotiable from
 * this side: change a step and registration, the DKG ceremony, and session sealing all break.
 *
 * Architecture note (2026-06-11 daemon-transport doc): this is the *directory-facing
 * node* — one per daemon, signaling only. A FRESH libp2p node (and therefore a fresh
 * transport key / Peer ID) is created on every connect, which is exactly the
 * reconnect-rotation behavior the architecture calls for. Per-session data exchange
 * uses separate ephemeral session nodes, not this node.
 *
 * Step-5/6 directory identity verification (the consortium-manifest "directory proves
 * itself back" hardening) is OPTIONAL here: it runs only when a `challengeVerifier`
 * is supplied. M6 ran with it off (challengeVerifier = null) and connected fine; the
 * hardening layers on later without changing this path.
 *
 * Crypto reference: agent→directory auth signs SHA-256(domain ‖ nonce ‖ pubkey) with
 * the agent's K_local Ed25519 key (RFC 8032). K_local never leaves the KeyProvider.
 */

import { createHash } from "node:crypto";
import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";
import type { Stream } from "@libp2p/interface";
import {
  createNode,
  buildStep5Tbs,
  type CelloNode,
  type ConnectResult,
  type SignalingStream,
  type IDirectoryChallengeVerifier,
} from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";

const SIGNALING_PROTOCOL_ID = "/cello/signaling/1.0.0";
const AUTH_DOMAIN_DIR = "CELLO-DIR-AUTH-v1";
const AUTH_TIMEOUT_MS = 5_000;

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (typeof (v as { slice?: unknown }).slice === "function") {
    return (v as { slice(): Uint8Array }).slice();
  }
  throw new Error(`expected bytes, got ${typeof v}`);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function nextWithTimeout<T>(iter: AsyncIterator<T>, timeoutMs: number): Promise<IteratorResult<T>> {
  return Promise.race([
    iter.next(),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("auth_timeout")), timeoutMs)),
  ]);
}

async function safeStop(node: CelloNode): Promise<void> {
  try {
    await node.stop();
  } catch {
    /* best-effort teardown */
  }
}

/** A directory node the daemon can dial, resolved from bootstrap config or a manifest. */
/**
 * DOD-M15-STEP6-REPLAY-1 — how far out of date a directory identity proof may be.
 *
 * ±5 minutes: wide enough for ordinary clock skew between an operator's machine and a directory
 * node without requiring either to be time-synced, narrow enough that a captured proof stops being
 * useful in minutes rather than never. An UNPARSEABLE timestamp is treated as out of window — the
 * NaN-comparison lesson from the manifest gate, where `new Date("nonsense") <= x` is false and a
 * garbage value sailed through a check that looked like it covered it.
 */
const IDENTITY_PROOF_MAX_SKEW_MS = 5 * 60_000;


export interface DirectoryEndpoint {
  peerId: string;
  /** A dialable multiaddr (e.g. /dns4/host/tcp/443/wss/p2p/<peerId>). Optional if already connected. */
  multiaddr?: string;
}

/** The agent identity that authenticates this signaling stream (steps 3-4). */
export interface SignalingAuthIdentity {
  keyProvider: KeyProvider;
  pubkeyHex: string;
}

export interface SignalingConnectDeps {
  /**
   * Resolve the directory node to dial. Returns null when no endpoint is known yet.
   * May be async — production re-resolves the bootstrap (GET /bootstrap) per connect
   * so a directory address change is picked up on the next reconnect.
   */
  getDirectoryEndpoint: () => DirectoryEndpoint | null | Promise<DirectoryEndpoint | null>;
  /** Resolve the agent identity to authenticate as. Returns null when no agent exists yet. */
  getAuthIdentity: () => SignalingAuthIdentity | null;
  logger: Logger;
  /**
   * Optional directory identity verifier (consortium-manifest step-6 hardening).
   * When absent, directory verification is skipped — the M6 backward-compat path.
   */
  challengeVerifier?: IDirectoryChallengeVerifier;
  /** Verified consortium manifest version, surfaced in ConnectResult. Defaults to 0 (no manifest). */
  getManifestVersion?: () => number;
  /**
   * Test seam: inject a node factory. Production uses `createNode` to mint a fresh
   * directory-facing node per connect.
   */
  createDirectoryNode?: (keyProvider: KeyProvider) => Promise<CelloNode>;
  /**
   * M7 Action 2: publish the live directory-facing node to the daemon so subsystems
   * that must reach the directory on the SAME node — registration's FROST DKG
   * (NetworkDirectoryNode), ceremonies, seal — can use it. Called with the node on a
   * successful connect, and with `null` when the stream closes. The daemon keeps the
   * latest reference and gates use on the signaling status being `connected`.
   */
  publishNode?: (node: CelloNode | null) => void;
  /**
   * Cross-node topology (item 3): mark this a VISITING connection. Set true ONLY for the transient
   * connection a client opens into a node that is NOT its home, to broker a cross-node session. The
   * flag rides in signaling_auth_response; the directory then gives this stream a #streams entry (so
   * the same-node session flow sees the agent) but writes NO presence — so the transient connection
   * never re-homes the agent or falsely marks it offline. Home connections omit it. Not signature-
   * bound (the auth TBS is unchanged) — the flag rides the encrypted libp2p channel.
   */
  visiting?: boolean;
  /**
   * DOD-NAT-REACHABILITY-1 (Phase 2): receives the directory's healthy relay-pool
   * endpoints when signaling_auth_ok carries `relay_endpoints`. Fires once per
   * successful connect (so every reconnect refreshes the set). The endpoints ride
   * the authenticated, directory-verified signaling channel — the same trust rail
   * as session_assignment frames. Absent field (old directory) → never called.
   */
  onRelayEndpoints?: (endpoints: Array<{ peerId: string; addrs: string[] }>) => void;
  /**
   * DOD-M15-RELAYSLOTS-1: receives the directory's online token — the credential the relays above
   * now require before they will let this agent hold a circuit reservation slot. Rides the same
   * frame and the same cadence as `relay_endpoints`: every connect and every reconnect, which is
   * what keeps a short-lived token current.
   *
   * Absent field → never called. That is the honest signal in two different situations, and the
   * daemon cannot tell them apart from here: an older directory that does not issue tokens, or a
   * key this directory does not know as a registered agent. Either way there is no slot.
   */
  onOnlineToken?: (token: Uint8Array) => void;
  /**
   * DOD-M15-RELAYSLOTS-1 review M1: fired instead of `onOnlineToken` when the directory issued
   * none, carrying WHICH absence it was. `undefined` means the directory stated no reason, i.e. it
   * predates the token — which is itself the third distinct answer and must not be folded into the
   * other two.
   */
  onOnlineTokenAbsent?: (reason: "not_registered_here" | "issue_failed" | undefined) => void;
}

/**
 * Parse signaling_auth_ok's optional `relay_endpoints` field. Per-entry strict:
 * a malformed entry is dropped (auth must never fail on a bad hint), a valid one
 * survives. Returns [] when the field is absent or not an array.
 */
function parseRelayEndpoints(raw: unknown): Array<{ peerId: string; addrs: string[] }> {
  if (!Array.isArray(raw)) return [];
  const out: Array<{ peerId: string; addrs: string[] }> = [];
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) continue;
    const e = entry as Record<string, unknown>;
    const peerId = e["peer_id"];
    const multiaddrs = e["multiaddrs"];
    if (typeof peerId !== "string" || peerId.length === 0) continue;
    if (!Array.isArray(multiaddrs) || multiaddrs.length === 0) continue;
    if (!multiaddrs.every((a): a is string => typeof a === "string" && a.length > 0)) continue;
    out.push({ peerId, addrs: multiaddrs });
  }
  return out;
}

/**
 * Build a production `signalingConnect` for `DaemonConfig.signalingConnect`.
 *
 * The returned function performs one full connect attempt. It throws on any failure
 * (no endpoint, no identity, dial failure, auth rejection, challenge failure); the
 * transport SignalingManager catches the throw and schedules a reconnect.
 */
export function createSignalingConnect(deps: SignalingConnectDeps): () => Promise<ConnectResult> {
  /**
   * DOD-M15-DIRAUTH-1 — directory peers already told about a skipped identity check.
   *
   * Mirrors `consortium-bootstrap`'s `lapsedMembershipReportedFor` idiom: the fact is about a PEER,
   * not about a connection, so reporting it per connection says the same true thing ~48 times an
   * hour forever. Keyed on the peer this daemon DIALLED — never on the peer's own claim about
   * itself, which on this path is precisely the thing that was not verified.
   *
   * ⚠️ SCOPED TO THE FACTORY, not the module. A module-level set is shared by every daemon wiring in
   * the process and never resets, which makes the suppression outlive the thing it describes and
   * makes test order load-bearing — my first version did exactly that and a later test silently lost
   * its warning to an earlier one.
   */
  const authSkipReportedFor = new Set<string>();
  return async function connect(): Promise<ConnectResult> {
    const endpoint = await deps.getDirectoryEndpoint();
    if (!endpoint) {
      throw new Error("directory_endpoint_unknown");
    }
    const identity = deps.getAuthIdentity();
    if (!identity) {
      throw new Error("no_agent_identity");
    }

    // Fresh directory-facing node per connect → fresh transport key / Peer ID.
    //
    // DOD-NAT-REACHABILITY-1: relayServer disabled, and the opt-out is NOT made redundant by this
    // node listening on nothing (see below). Leaving `nodeType` unset takes the service-node
    // default, which adds `circuitRelayServer` to the service map and advertises HOP — and HOP is
    // advertised over connections WE opened, not only over ones we accept. A node with no listener
    // still holds a live outbound connection to the directory.
    //
    // (This comment described the node as "bound on 0.0.0.0" until DOD-M15-SURFACE-1 removed the
    // binding. Rewritten rather than deleted: the constraint it records is still load-bearing, and
    // leaving it in past tense put two comments in one expression contradicting each other about
    // the exact fact this unit changed — which is how the binding gets "restored" by a later
    // session that stops reading at the first one.)
    const node = deps.createDirectoryNode
      ? await deps.createDirectoryNode(identity.keyProvider)
      : await createNode({
          keyProvider: identity.keyProvider,
          /**
           * DOD-M15-SURFACE-1 — LISTEN ON NOTHING. This node had a real open port on every
           * interface, for no reason.
           *
           * It bound `/ip4/0.0.0.0/tcp/0` while registering **no protocol handler at all**, and the
           * directory never dials a client — every directory connection is one this daemon opened.
           * So the port accepted connections that could reach no CELLO protocol, on an operator's
           * machine, for the life of the daemon. Not listening is strictly stronger than filtering
           * who may connect: there is no socket, nothing to scan, and nothing to gate. (A
           * `DirectoryConnectionGater` exists for the filtering approach and is constructed only in
           * tests — it is the consolation prize, not the fix.)
           *
           * FALSIFIED BEFORE REMOVING, because `listenAddresses()` IS sent to the directory at step
           * 7 below, in `peer_info_announce`, under a comment saying it is so the directory can
           * broker sessions. Traced to the consumer: the directory stores it and its own code says
           * this address is *"its per-agent DIRECTORY node, NOT its standing-receiver session node,
           * so it is NOT a valid content endpoint (using it yields 'could not negotiate
           * /cello/content')"*. A counterparty's session endpoint reaches the other side through the
           * `session_offer` → `session_offer_accept` round-trip, never through this announce. No
           * client reads `participant_a/b.multiaddrs` at all.
           *
           * The announce still matters and still happens: `#peerInfoAnnounced` gates `session_request`
           * on the directory side, and it is set by the frame ARRIVING, not by what is in it. The
           * peer id still goes with it, and a peer id needs no listener.
           *
           * INBOUND SESSIONS ARE UNAFFECTED. They arrive on the standing receiver, which is a
           * different node and keeps its socket deliberately (relay-audit Decision 2 — it is
           * load-bearing for same-machine and same-LAN sessions).
           */
          listenAddresses: [],
          relayServer: { enabled: false },
          // Same reason as relayServer above: this is a CLIENT node that leaves nodeType unset, so
          // the service-node default would leave the AutoNAT responder on -- and answering one
          // dial-back tears down this very connection, killing signaling mid-registration.
          autonatResponder: { enabled: false },
        });

    let sigStream: Stream;
    try {
      // L1: start() is inside the try so a start failure is caught and the
      // partially-started node is torn down (safeStop) rather than leaked.
      await node.start();
      if (endpoint.multiaddr) {
        // Best-effort dial; newStream below surfaces the real failure if unreachable.
        try {
          await node.dial(endpoint.multiaddr);
        } catch (dialErr: unknown) {
          // L2: non-fatal (dial-by-peerId may still work / already connected), but
          // keep the real reason — newStream's error is generic.
          deps.logger.debug("directory.dial.failed", {
            multiaddr: endpoint.multiaddr,
            error: errMsg(dialErr),
          });
        }
      }
      sigStream = await node.newStream(endpoint.peerId, SIGNALING_PROTOCOL_ID);
    } catch (err: unknown) {
      await safeStop(node);
      throw new Error(`directory_dial_failed: ${errMsg(err)}`);
    }

    const iter = (lp.decode(sigStream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;

    try {
      // ── Steps 1-2: receive the directory's auth challenge (32-byte nonce) ──
      const challenge = await nextWithTimeout(iter, AUTH_TIMEOUT_MS);
      if (challenge.done || challenge.value === undefined) throw new Error("directory_auth_no_challenge");
      const challengeFrame = decode(toU8(challenge.value)) as Record<string, unknown>;
      if (challengeFrame["type"] !== "signaling_auth_challenge") {
        throw new Error(`directory_auth_unexpected_frame: ${String(challengeFrame["type"])}`);
      }
      const nonce = toU8(challengeFrame["nonce"]);
      if (nonce.length !== 32) throw new Error("directory_auth_bad_nonce");

      // ── Steps 3-4: sign SHA-256(domain ‖ nonce ‖ pubkey), send auth response ──
      const myPubkey = Buffer.from(identity.pubkeyHex, "hex");
      const domain = Buffer.from(AUTH_DOMAIN_DIR, "utf8");
      const authMsg = new Uint8Array(Buffer.concat([domain, nonce, myPubkey]));
      const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
      const sig = await identity.keyProvider.sign(msgHash);
      const authResponse = encodeCbor({
        type: "signaling_auth_response",
        pubkey: myPubkey,
        signature: sig,
        // Cross-node item 3: only the transient visiting connection sets this; home connections omit it.
        ...(deps.visiting ? { visiting: true } : {}),
      }) as Uint8Array;
      sigStream.send(lp.encode.single(authResponse));

      // ── Step 5: receive signaling_auth_ok ──
      const ack = await nextWithTimeout(iter, AUTH_TIMEOUT_MS);
      if (ack.done || ack.value === undefined) throw new Error("directory_auth_no_ack");
      const ackFrame = decode(toU8(ack.value)) as Record<string, unknown>;
      if (ackFrame["type"] !== "signaling_auth_ok") {
        throw new Error(`directory_auth_rejected: ${String(ackFrame["type"])}`);
      }

      // ── Step 6 (optional hardening): verify the directory's identity proof ──
      // Runs only when a challengeVerifier is configured. M6 ran without one.
      let directoryNodeId = typeof ackFrame["nodeId"] === "string" ? (ackFrame["nodeId"] as string) : endpoint.peerId;
      const verifier = deps.challengeVerifier;
      if (!verifier) {
        /**
         * DOD-M15-DIRAUTH-1 — **A DISARMED CHECK MUST NOT LOOK LIKE A HEALTHY ONE.**
         *
         * With no verifier configured, step 6 does not run at all: this daemon takes the
         * directory's word for which directory it is. Until now the only trace of that was
         * `verified: false` — a boolean field inside the **info** line at the bottom of a successful
         * connect. Every other connect logged the same event at the same level, so the disarmed
         * state and the enforced state were distinguishable only by reading one field of one line,
         * which nothing alerts on and no operator reads.
         *
         * ⚠️ THIS IS NOT THE FIX AND MUST NOT BE MISTAKEN FOR ONE — this entry's own conclusion is
         * that **a log is not a control**, and a WARN is still a log. What it buys is that the
         * absence has a name and a level of its own, so "authentication is off" can be seen without
         * knowing to look for it. The control is `CELLO_REQUIRE_DIRECTORY_AUTH`, which refuses at
         * startup; this is what tells an operator who has not set it what they are running.
         */
        /**
         * ⚠️ ONCE PER DIRECTORY, NOT ONCE PER CONNECT — review F3, and the number is the argument.
         * The signaling stream turns over roughly every 70 seconds and reconnects forever, so a
         * per-connect WARN is ~48 an hour PER AGENT, indefinitely, and the daemon's stdout logger
         * has no level filtering. Three agents is ~3,400 identical lines a day. **A signal that
         * fires on the normal case is not a signal** — this repo's own rule — and it would bury the
         * public-directory case this exists to raise.
         *
         * ⚠️ AND THE FIELD IS NAMED FOR WHAT IT IS — review F4. On this path `directoryNodeId` is
         * `ackFrame["nodeId"]`: a string the REMOTE sent about itself, with nothing checked. Printing
         * it under that name inside a line whose whole subject is *"we did not check which directory
         * this is"* presents the peer's own answer as the answer. `dialedPeerId` sits beside it as
         * the thing this daemon actually chose.
         */
        const claimedNodeId = typeof ackFrame["nodeId"] === "string" ? (ackFrame["nodeId"] as string) : null;
        if (!authSkipReportedFor.has(endpoint.peerId)) {
          authSkipReportedFor.add(endpoint.peerId);
          deps.logger.warn("directory.auth.skipped", {
            dialedPeerId: endpoint.peerId,
            claimedNodeId,
            agentPubkey: identity.pubkeyHex,
            impact:
              "no directory identity verifier is configured, so this connection did NOT check which " +
              "directory it reached — the peer's claim of its own identity was accepted as given. " +
              "Set CELLO_CONSORTIUM_ROOT_KEYS (with CELLO_CONSORTIUM_THRESHOLD) to enable " +
              "verification, or CELLO_REQUIRE_DIRECTORY_AUTH=1 to refuse at startup instead of " +
              "connecting unverified. Reported ONCE per directory peer, not per reconnect.",
          });
        }
      }
      if (verifier) {
        const nodeId = ackFrame["nodeId"] as string | undefined;
        const signature = ackFrame["signature"] as string | undefined;
        const timestamp = ackFrame["timestamp"] as string | undefined;
        if (!nodeId || !signature || !timestamp) {
          deps.logger.error("directory.auth.challenge.failed", { reason: "no_identity_proof" });
          throw new Error("directory_challenge_no_identity_proof");
        }
        const tbsBytes = buildStep5Tbs({
          nodeId,
          agentPubkeyHex: identity.pubkeyHex,
          nonceHex: Buffer.from(nonce).toString("hex"),
          isoTimestamp: timestamp,
        });
        const result = verifier.verifyChallenge(nodeId, tbsBytes, signature);
        if (!result.valid) {
          deps.logger.error("directory.auth.challenge.failed", { directoryNodeId: nodeId, reason: result.reason });
          throw new Error(`directory_challenge_failed: ${result.reason}`);
        }
        /**
         * DOD-M15-STEP6-REPLAY-1 — A VALID SIGNATURE IS NOT A FRESH ONE.
         *
         * The TBS covers `nodeId ‖ agent pubkey ‖ nonce ‖ timestamp`, and until this check the
         * client verified the signature over that tuple and looked at **neither** the timestamp nor
         * the nonce. So **any party that once obtained a valid tuple for this agent could replay it
         * indefinitely.**
         *
         * ─── WHY THE NONCE CANNOT CARRY THE FRESHNESS, WHICH IS THE PART THAT SURPRISED ME ──────
         *
         * The obvious answer is "check the nonce is the one we just sent". **We did not send it.**
         * The nonce here is `challengeFrame["nonce"]` — the DIRECTORY's own, from step 1-2. The
         * client contributes no fresh value to this exchange at all, so it holds nothing of its own
         * to bind against. A replaying party simply replays the captured nonce in step 2 and the
         * captured ack in step 5, and both halves agree.
         *
         * **That leaves the timestamp as the only freshness anchor**, and it is a real one: it is
         * inside the signed bytes, so a replayer cannot move it without invalidating the signature
         * they are replaying.
         *
         * ─── AFTER the signature, deliberately ─────────────────────────────────────────────────
         *
         * A stale proof and a forged one are different facts and must not collapse into one
         * message. Checking freshness only once the signature verifies means `identity_proof_stale`
         * always describes a GENUINE proof that is too old — never a forgery — which is what makes
         * it diagnostic rather than another exit-point label.
         *
         * **The window, and what it does NOT fix.** ±5 minutes tolerates ordinary client/directory
         * clock skew without a time-sync dependency. It BOUNDS replay to that window; it does not
         * eliminate it, because with no client-chosen nonce there is nothing to make a proof
         * single-use. Closing the remainder needs either a client contribution in the challenge or a
         * seen-nonce cache — both wire or state changes, and neither is this line.
         */
        const proofMs = Date.parse(timestamp);
        const skewMs = Number.isFinite(proofMs) ? Math.abs(Date.now() - proofMs) : Number.NaN;
        if (!Number.isFinite(skewMs) || skewMs > IDENTITY_PROOF_MAX_SKEW_MS) {
          deps.logger.error("directory.auth.challenge.failed", {
            directoryNodeId: nodeId,
            reason: "identity_proof_stale",
            timestamp,
            skewMs: Number.isFinite(skewMs) ? Math.round(skewMs) : null,
            maxSkewMs: IDENTITY_PROOF_MAX_SKEW_MS,
            detail:
              "the directory's identity proof carries a valid signature over a timestamp outside the " +
              "freshness window — either a replayed proof, or a clock that is badly out on one side.",
          });
          throw new Error("directory_challenge_failed: identity_proof_stale");
        }
        directoryNodeId = nodeId;
        deps.logger.info("directory.auth.challenge.verified", { directoryNodeId, skewMs: Math.round(skewMs) });
      }

      // DOD-NAT-REACHABILITY-1 (Phase 2): the directory's relay pool rides
      // signaling_auth_ok so the standing receiver can reserve BEFORE any
      // session exists. Surfaced via callback; parse failures drop entries,
      // never the handshake.
      if (deps.onRelayEndpoints) {
        const endpoints = parseRelayEndpoints(ackFrame["relay_endpoints"]);
        if (endpoints.length > 0) {
          deps.logger.info("directory.relay_endpoints.received", {
            directoryNodeId,
            relayPeerIds: endpoints.map((e) => e.peerId),
          });
          deps.onRelayEndpoints(endpoints);
        }
      }

      /**
       * DOD-M15-RELAYSLOTS-1: the online token rides the same frame as the relay pool above, for
       * the same reason — a standing receiver needs both before any session exists: WHERE to ask
       * for a reservation slot, and the credential that lets it keep one.
       *
       * A field of the wrong type is dropped rather than failing the handshake, exactly as a
       * malformed relay endpoint is. The consequence is bounded and visible (this agent gets no
       * slot on any relay, and the relay names the reason when it refuses), whereas failing the
       * handshake would also cost session offers, which arrive on this same stream.
       */
      if (deps.onOnlineToken) {
        const raw = ackFrame["online_token"];
        const token = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw) : undefined;
        if (token && token.length > 0) {
          deps.logger.info("directory.online_token.received", { directoryNodeId, bytes: token.length });
          deps.onOnlineToken(token);
        } else {
          /**
           * Review M1: the directory names WHICH absence, so this is no longer one label for three
           * different problems. `not_registered_here` in particular is a payload fact, and reporting
           * it as a generic "no token" sent the operator to check a directory connection that is
           * working perfectly.
           */
          const raw = ackFrame["online_token_absent_reason"];
          const absentReason = raw === "not_registered_here" || raw === "issue_failed" ? raw : undefined;
          deps.onOnlineTokenAbsent?.(absentReason);
          deps.logger.warn("directory.online_token.absent", {
            directoryNodeId,
            agentPubkey: identity.pubkeyHex,
            reason: absentReason ?? "unstated",
            impact: absentReason === "not_registered_here"
              ? "this directory holds no agent profile for this key, so it issued no online token " +
                "and no relay will grant this agent a reservation. The directory connection is FINE " +
                "— either this agent registered against a different sovereign node and its profile " +
                "has not replicated here yet, or it is not registered at all."
              : absentReason === "issue_failed"
                ? "this directory could not issue an online token — its own lookup or signing failed. " +
                  "That is a fault on the directory, not on this agent or on any relay."
                : "this directory issued no online token, so no relay will let this agent hold a " +
                  "circuit reservation and it will be reachable only over a direct connection. It " +
                  "stated no reason, which means it predates the token.",
          });
        }
      }

      // ── Step 7: announce our peer info so the directory can broker sessions ──
      const peerInfo = encodeCbor({
        type: "peer_info_announce",
        peer_id: node.getPeerId(),
        multiaddrs: node.listenAddresses(),
      }) as Uint8Array;
      sigStream.send(lp.encode.single(peerInfo));

      deps.logger.info("directory.signaling.connected", {
        directoryNodeId,
        agentPubkey: identity.pubkeyHex,
        verified: !!verifier,
      });

      // Publish the live, directory-connected node so registration/FROST/seal can
      // open further streams to the directory on the same node.
      deps.publishNode?.(node);

      const stream = wrapSignalingStream(sigStream, iter, node, deps.logger, deps.publishNode);
      return {
        stream,
        directoryNodeId,
        manifestVersion: deps.getManifestVersion?.() ?? 0,
      };
    } catch (err: unknown) {
      // Symmetry with publishNode(node): if anything threw after we published (or in a
      // reconnect attempt), clear the daemon's reference so it never points at a node
      // we're about to stop. No-op when nothing was published this attempt.
      deps.publishNode?.(null);
      try {
        sigStream.abort(new Error("directory_auth_error"));
      } catch {
        /* stream may already be torn down */
      }
      await safeStop(node);
      throw err instanceof Error ? err : new Error(errMsg(err));
    }
  };
}

/**
 * Adapt the post-handshake libp2p stream to the transport `SignalingStream`
 * interface the SignalingManager drives. Frames are CBOR objects; the wire is
 * length-prefixed CBOR, matching the directory and the M6 client exactly.
 *
 * The read loop continues from the SAME iterator the handshake used, so no inbound
 * frame is dropped between auth_ok and the manager registering its handler.
 */
function wrapSignalingStream(
  sigStream: Stream,
  iter: AsyncIterator<Uint8Array>,
  node: CelloNode,
  logger: Logger,
  publishNode?: (node: CelloNode | null) => void,
): SignalingStream {
  let closed = false;
  return {
    async send(frame: unknown): Promise<void> {
      const encoded = encodeCbor(frame) as Uint8Array;
      sigStream.send(lp.encode.single(encoded));
    },
    onMessage(handler: (frame: unknown) => void): void {
      void (async () => {
        try {
          for (;;) {
            const { value, done } = await iter.next();
            if (done || value === undefined) break;
            let frame: unknown;
            try {
              frame = decode(toU8(value));
            } catch {
              // Skip undecodable frames rather than killing the whole stream.
              continue;
            }
            handler(frame);
          }
          logger.debug("directory.signaling.stream.ended", { expected: true });
        } catch (err: unknown) {
          // M8C-ONBOARD-LOGNOISE-1 (F11): routine reconnect churn (the reader loop ends when the
          // directory rotates/drops the stream, ~every 40–70 min, and the caller reconnects). At
          // `warn` a healthy daemon looked like it was failing. Log it quietly + marked expected; a
          // genuine SUSTAINED outage still stands out via the `reconnecting`→`lost` state escalation
          // (getAgentSignaling retry budget), which is unchanged.
          logger.debug("directory.signaling.reader.error", { error: errMsg(err), expected: true });
        }
      })();
    },
    close(): void {
      if (closed) return;
      closed = true;
      // Clear the daemon's reference before tearing the node down — registration/
      // FROST/seal must not use a node that is being stopped.
      publishNode?.(null);
      try {
        sigStream.abort(new Error("signaling_closed"));
      } catch {
        /* already closed */
      }
      void safeStop(node);
    },
  };
}
