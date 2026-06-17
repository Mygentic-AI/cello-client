/**
 * M7 Keystone (Part 2) — production `signalingConnect` for the daemon.
 *
 * This is the daemon's directory-facing dialer. It establishes ONE authenticated
 * signaling stream to a directory node and returns it as a transport
 * `ConnectResult`. The transport `SignalingManager` owns everything after connect:
 * heartbeat, reconnect (it calls connect() again on a fresh attempt), the outbound
 * queue, and optional manifest polling.
 *
 * It is a faithful port of the proven M6 client handshake in
 * `core/client/src/signaling-manager.ts` (`#doOpen`, ~lines 527-643). That path
 * connected the M6 client to the real directory, ran the full DKG ceremony, and
 * sealed sessions — so the 7-step handshake here is the known-good one, not new
 * protocol.
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
import { Encoder, decode } from "cbor-x";
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
// tagUint8Array:false — match the M6 client encoder so the directory decodes bytes
// fields (pubkey, signature, nonce) as raw byte strings, not CBOR-tagged values.
const CBOR_ENC = new Encoder({ tagUint8Array: false });

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
}

/**
 * Build a production `signalingConnect` for `DaemonConfig.signalingConnect`.
 *
 * The returned function performs one full connect attempt. It throws on any failure
 * (no endpoint, no identity, dial failure, auth rejection, challenge failure); the
 * transport SignalingManager catches the throw and schedules a reconnect.
 */
export function createSignalingConnect(deps: SignalingConnectDeps): () => Promise<ConnectResult> {
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
    const node = deps.createDirectoryNode
      ? await deps.createDirectoryNode(identity.keyProvider)
      : await createNode({ keyProvider: identity.keyProvider, listenAddresses: ["/ip4/0.0.0.0/tcp/0"] });
    await node.start();

    let sigStream: Stream;
    try {
      if (endpoint.multiaddr) {
        // Best-effort dial; newStream below surfaces the real failure if unreachable.
        try {
          await node.dial(endpoint.multiaddr);
        } catch {
          /* may already be connected, or dial-by-peerId works without it */
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
      const authResponse = CBOR_ENC.encode({
        type: "signaling_auth_response",
        pubkey: myPubkey,
        signature: sig,
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
        directoryNodeId = nodeId;
        deps.logger.info("directory.auth.challenge.verified", { directoryNodeId });
      }

      // ── Step 7: announce our peer info so the directory can broker sessions ──
      const peerInfo = CBOR_ENC.encode({
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

      const stream = wrapSignalingStream(sigStream, iter, node, deps.logger);
      return {
        stream,
        directoryNodeId,
        manifestVersion: deps.getManifestVersion?.() ?? 0,
      };
    } catch (err: unknown) {
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
): SignalingStream {
  let closed = false;
  return {
    async send(frame: unknown): Promise<void> {
      const encoded = CBOR_ENC.encode(frame) as Uint8Array;
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
          logger.warn("directory.signaling.stream.ended", {});
        } catch (err: unknown) {
          logger.warn("directory.signaling.reader.error", { error: errMsg(err) });
        }
      })();
    },
    close(): void {
      if (closed) return;
      closed = true;
      try {
        sigStream.abort(new Error("signaling_closed"));
      } catch {
        /* already closed */
      }
      void safeStop(node);
    },
  };
}
