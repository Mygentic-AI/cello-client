/**
 * NetworkDirectoryNode — DirectoryNodeStub backed by a real libp2p connection.
 *
 * Implements the DirectoryNodeStub interface by dialing the directory node's
 * /cello/frost/1.0.0 endpoint. Used in live e2e mode instead of InProcessDirectoryNodeStub.
 *
 * Wire protocol (one stream per operation, CBOR + it-length-prefixed):
 *   frost_bootstrap:      push share material to directory (called from bootstrapKeyShares)
 *   frost_commit_request: ask directory to generate a nonce commitment
 *   frost_sign_request:   ask directory to compute a partial signature
 */

import { createHash } from "node:crypto";
import { decode as cborDecode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";
import { ed25519_FROST, FrostThresholdSigner } from "@cello-protocol/crypto";
import {
  bootstrapKeyShares,
  storeDkgResult,
  getClientFrostIdentifier,
  getClientRefreshRoster,
  generateClientRefreshContribution,
  applyRefreshToLocalShare,
} from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "./types.js";
import type {
  DirectoryNodeStub,
  StubCommitment,
  StubSignParams,
  BootstrapResult,
} from "@cello-protocol/crypto/frost/types.js";

const NOOP_LOGGER: Logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
};
import type {
  DkgRound1Broadcast,
  DkgRound2Share,
  FrostDkgRound1Response,
  FrostDkgRound2Response,
  FrostDkgRound3Response,
  FrostRefreshContribution,
  FrostRefreshRound1Response,
  FrostRefreshRound2Response,
} from "@cello-protocol/protocol-types";

const FROST_PROTOCOL_ID = "/cello/frost/1.0.0";

// Prove K_local possession on every /cello/frost/1.0.0 commit/sign request. The directory
// verifies an Ed25519 signature, made with K_local priv, over SHA-256(FROST_AUTH_DOMAIN ||
// agentPubkeyBytes || utf8(epochId) || tail): tail = utf8("commit") for a commit, the framedMsg for a
// sign (binding the auth to the exact message signed). Without this the signing stream is a blind oracle
// (see the directory's verifyFrostAuth). The signer is the agent's own K_local, threaded via
// setBootstrapContext by every ceremony path (session/seal, DKG, refresh).
export type FrostAuthSigner = (hash: Uint8Array) => Promise<Uint8Array>;
const FROST_AUTH_DOMAIN = "CELLO-FROST-AUTH-v1";
// Domain separation (must match the directory's verifyFrostAuth): 0x00 = commit; 0x01 || framedMsg = sign.
const FROST_AUTH_COMMIT_TAIL = new Uint8Array([0x00]);
const FROST_AUTH_SIGN_PREFIX = 0x01;

// ─── NetworkDirectoryNode ─────────────────────────────────────────────────────

export class NetworkDirectoryNode implements DirectoryNodeStub {
  readonly id: string;

  readonly #node: CelloNode;
  readonly #directoryPeerId: string;
  readonly #directoryMultiaddrs: string[];
  readonly #logger: Logger;

  // Set during bootstrapKeyShares — used to identify which agent's share to retrieve
  #agentPubkeyHex: string | null = null;
  #epochId: string | null = null;
  // Signs the K_local auth on commit/sign requests (set via setBootstrapContext).
  #signAuth: FrostAuthSigner | null = null;

  // Stored during receiveShare — used by tests to get the FrostPublic for signRound calls
  #lastPub: Parameters<DirectoryNodeStub["receiveShare"]>[1] | null = null;

  constructor(opts: {
    id: string;
    node: CelloNode;
    directoryPeerId: string;
    directoryMultiaddrs: string[];
    logger?: Logger;
  }) {
    this.id = opts.id;
    this.#node = opts.node;
    this.#directoryPeerId = opts.directoryPeerId;
    this.#directoryMultiaddrs = opts.directoryMultiaddrs;
    this.#logger = opts.logger ?? NOOP_LOGGER;
  }

  isReachable(): boolean {
    // For the network path, optimistically return true at pre-ceremony check time.
    // Actual reachability is discovered during generateCommitment/signRound.
    return true;
  }

  /** Return the FrostPublic from the last receiveShare call. Used by tests to construct signRound params. */
  getLastPub(): Parameters<DirectoryNodeStub["receiveShare"]>[1] | null {
    return this.#lastPub;
  }

  async receiveShare(...[secret, pub]: Parameters<DirectoryNodeStub["receiveShare"]>): Promise<void> {
    this.#lastPub = pub;
    if (!this.#agentPubkeyHex || !this.#epochId) {
      throw new Error("NetworkDirectoryNode: setBootstrapContext must be called before receiveShare");
    }

    // Serialize FrostSecret: { identifier, signingShare }
    const secretSerialized = {
      identifier: (secret as unknown as { identifier: string }).identifier,
      signingShare: (secret as unknown as { signingShare: Uint8Array }).signingShare,
    };

    // Serialize FrostPublic: { signers, commitments[], verifyingShares{} }
    const pubSerialized = {
      signers: (pub as unknown as { signers: { min: number; max: number } }).signers,
      commitments: (pub as unknown as { commitments: Uint8Array[] }).commitments,
      verifyingShares: (pub as unknown as { verifyingShares: Record<string, Uint8Array> }).verifyingShares,
    };

    const frame = encodeCbor({
      type: "frost_bootstrap",
      agentPubkey: this.#agentPubkeyHex,
      epochId: this.#epochId,
      secret: secretSerialized.signingShare,
      identifier: secretSerialized.identifier,
      commitments: pubSerialized.commitments,
      verifyingShares: pubSerialized.verifyingShares,
      signers: pubSerialized.signers,
    });

    const stream = await this.#openStream();
    try {
      stream.send(lp.encode.single(frame));
      // Read the response before closing — directory sends frost_bootstrap_ok
      for await (const chunk of lp.decode(stream)) {
        const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
        const resp = cborDecode(bytes) as { type: string };
        if (resp.type !== "frost_bootstrap_ok") {
          throw new Error(`NetworkDirectoryNode: unexpected bootstrap response: ${resp.type}`);
        }
        break;
      }
    } finally {
      stream.close().catch(() => {});
    }
  }

  async generateCommitment(): Promise<StubCommitment> {
    this.#logger.debug("frost.directory.commitment.start", { agent: this.#agentPubkeyHex?.slice(0, 16), epochId: this.#epochId, directoryPeerId: this.#directoryPeerId?.slice(0, 16) });
    if (!this.#agentPubkeyHex || !this.#epochId) {
      this.#logger.debug("frost.directory.commitment.abort", { reason: "missing_context", hasAgent: !!this.#agentPubkeyHex, hasEpochId: !!this.#epochId });
      throw new Error("NetworkDirectoryNode: setBootstrapContext must be called before generateCommitment");
    }

    const frame = encodeCbor({
      type: "frost_commit_request",
      agentPubkey: this.#agentPubkeyHex,
      epochId: this.#epochId,
      peerIdString: this.#node.getPeerId(),
      authSig: await this.#buildAuthSig(FROST_AUTH_COMMIT_TAIL), // SEC-2
    });

    this.#logger.debug("frost.directory.stream.opening", { directoryPeerId: this.#directoryPeerId?.slice(0, 16), multiaddr: this.#directoryMultiaddrs[0] });
    const stream = await this.#openStream();
    this.#logger.debug("frost.directory.stream.opened", {});
    try {
      stream.send(lp.encode.single(frame));
      await stream.close();

      for await (const chunk of lp.decode(stream)) {
        const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
        const resp = cborDecode(bytes) as {
          type: string;
          ok: boolean;
          reason?: string;
          nodeId?: string;
          nonceCommitment?: StubCommitment["nonceCommitment"];
        };

        this.#logger.debug("frost.directory.commitment.response", { ok: resp.ok, reason: resp.reason, nodeId: resp.nodeId?.slice(0, 16) });
        if (!resp.ok) {
          throw new Error(`NetworkDirectoryNode: commit request failed: ${resp.reason}`);
        }

        return {
          nodeId: resp.nodeId!,
          nonceCommitment: resp.nonceCommitment!,
          nonces: null as unknown as StubCommitment["nonces"],
        };
      }
    } finally {
      stream.close().catch(() => {});
    }

    throw new Error("NetworkDirectoryNode: no response to frost_commit_request");
  }

  async signRound(params: StubSignParams): Promise<Uint8Array | null> {
    this.#logger.debug("frost.directory.sign.start", { agent: this.#agentPubkeyHex?.slice(0, 16), epochId: this.#epochId, ceremonyId: params.ceremonyId?.slice(0, 16) });
    if (!this.#agentPubkeyHex || !this.#epochId) {
      this.#logger.debug("frost.directory.sign.abort", { reason: "missing_context" });
      throw new Error("NetworkDirectoryNode: setBootstrapContext must be called before signRound");
    }

    const frame = encodeCbor({
      type: "frost_sign_request",
      agentPubkey: this.#agentPubkeyHex,
      epochId: this.#epochId,
      framedMsg: params.msg,
      commitmentList: params.commitmentList,
      ceremonyId: params.ceremonyId,
      peerIdString: params.ceremonyId,
      // Bound to THIS framedMsg, with the 0x01 sign-frame domain-separation prefix.
      authSig: await this.#buildAuthSig(Buffer.concat([Buffer.from([FROST_AUTH_SIGN_PREFIX]), Buffer.from(params.msg)])),
    });

    this.#logger.debug("frost.directory.sign.stream.opening", {});
    const stream = await this.#openStream();
    this.#logger.debug("frost.directory.sign.stream.opened", {});
    try {
      stream.send(lp.encode.single(frame));
      await stream.close();

      for await (const chunk of lp.decode(stream)) {
        const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
        const resp = cborDecode(bytes) as {
          type: string;
          ok: boolean;
          reason?: string;
          partialSignature?: Uint8Array;
        };

        this.#logger.debug("frost.directory.sign.response", { ok: resp.ok, reason: resp.reason, sigLength: resp.partialSignature ? (resp.partialSignature as Uint8Array).length : null });
        if (!resp.ok) {
          return null;
        }

        const sig = resp.partialSignature;
        if (!sig) return null;
        return sig instanceof Uint8Array ? sig : new Uint8Array(sig as unknown as ArrayBuffer);
      }
    } finally {
      stream.close().catch(() => {});
    }

    return null;
  }

  // Called by the network-aware bootstrapKeyShares before distributing shares. `signAuth` is the
  // agent's K_local signer, used to authenticate every subsequent commit/sign request; EVERY ceremony
  // path (session/seal, DKG, refresh) must pass it or the enforcing directory refuses the request.
  setBootstrapContext(agentPubkeyHex: string, epochId: string, signAuth?: FrostAuthSigner): void {
    this.#agentPubkeyHex = agentPubkeyHex;
    this.#epochId = epochId;
    if (signAuth) this.#signAuth = signAuth;
  }

  // Hash bound by the directory's verifyFrostAuth. tail = utf8("commit") | framedMsg.
  #frostAuthHash(tail: Uint8Array): Uint8Array {
    return new Uint8Array(
      createHash("sha256")
        .update(Buffer.concat([
          Buffer.from(FROST_AUTH_DOMAIN, "utf8"),
          Buffer.from(this.#agentPubkeyHex!, "hex"),
          Buffer.from(this.#epochId!, "utf8"),
          Buffer.from(tail),
        ]))
        .digest(),
    );
  }

  // The K_local auth signature to attach, or undefined if no signer was threaded — which the enforcing
  // directory then refuses with AUTH_REQUIRED, surfacing an un-threaded path loudly, not silently.
  async #buildAuthSig(tail: Uint8Array): Promise<Uint8Array | undefined> {
    if (!this.#signAuth) {
      this.#logger.warn("frost.directory.auth.no_signer", { agent: this.#agentPubkeyHex?.slice(0, 16), epochId: this.#epochId });
      return undefined;
    }
    return this.#signAuth(this.#frostAuthHash(tail));
  }

  /** Open a /cello/frost/1.0.0 stream to this directory node. Used by DKG coordinator. */
  async openStream(): Promise<import("@libp2p/interface").Stream> {
    return this.#openStream();
  }

  async #openStream(): Promise<import("@libp2p/interface").Stream> {
    this.#logger.debug("frost.directory.stream.open.attempt", { peerId: this.#directoryPeerId?.slice(0, 16), multiaddr: this.#directoryMultiaddrs[0] });
    try {
      const s = await this.#node.newStream(this.#directoryPeerId, FROST_PROTOCOL_ID);
      this.#logger.debug("frost.directory.stream.open.ok", {});
      return s;
    } catch (err1: unknown) {
      const msg1 = err1 instanceof Error ? err1.message : String(err1);
      this.#logger.debug("frost.directory.stream.open.retry", { error: msg1 });
      try {
        await this.#node.dial(this.#directoryMultiaddrs[0]!);
        this.#logger.debug("frost.directory.stream.dial.ok", {});
        const s = await this.#node.newStream(this.#directoryPeerId, FROST_PROTOCOL_ID);
        this.#logger.debug("frost.directory.stream.open.ok", {});
        return s;
      } catch (err2: unknown) {
        const msg2 = err2 instanceof Error ? err2.message : String(err2);
        this.#logger.debug("frost.directory.stream.open.failed", { error: msg2 });
        throw err2;
      }
    }
  }
}

// ─── DKG round methods on NetworkDirectoryNode ───────────────────────────────

// These methods are used by runNetworkDkg to execute the 3 DKG rounds
// over /cello/frost/1.0.0 streams. They are internal to the DKG coordinator flow.

/**
 * Run DKG round 1 with this directory node.
 * Opens a new stream, sends frost_dkg_round1_request, returns the broadcast.
 */
async function dkgRound1WithNode(
  node: NetworkDirectoryNode,
  agentPubkeyHex: string,
  epochId: string,
  signers: { min: number; max: number },
  preAuthToken?: string,
): Promise<DkgRound1Broadcast> {
  const frame = encodeCbor({
    type: "frost_dkg_round1_request",
    agentPubkey: agentPubkeyHex,
    epochId,
    signers,
    // Include preAuthToken when present.
    ...(preAuthToken !== undefined ? { preAuthToken } : {}),
  });
  const stream = await node.openStream();
  try {
    stream.send(lp.encode.single(frame));
    for await (const chunk of lp.decode(stream)) {
      const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
      const parsed = parseDkgRound1Response(bytes);
      if (parsed.kind === "invalid") throw new Error("dkgRound1: invalid response");
      if (parsed.kind === "preauth_error") throw new Error(`dkgRound1 rejected: ${parsed.reason}`);
      const resp = parsed.response;
      if (!resp.ok) throw new Error(`dkgRound1 failed: ${resp.reason}`);
      return resp.broadcast;
    }
  } finally {
    stream.close().catch(() => {});
  }
  throw new Error("dkgRound1: no response received");
}

/**
 * Run DKG round 2 with this directory node.
 * Opens a new stream, sends frost_dkg_round2_request, returns sharesForOthers.
 */
async function dkgRound2WithNode(
  node: NetworkDirectoryNode,
  agentPubkeyHex: string,
  epochId: string,
  othersRound1: DkgRound1Broadcast[],
): Promise<DkgRound2Share[]> {
  const frame = encodeCbor({
    type: "frost_dkg_round2_request",
    agentPubkey: agentPubkeyHex,
    epochId,
    othersRound1: othersRound1.map((b) => ({
      identifier: b.identifier,
      commitment: b.commitment,
      proofOfKnowledge: b.proofOfKnowledge,
    })),
  });
  const stream = await node.openStream();
  try {
    stream.send(lp.encode.single(frame));
    for await (const chunk of lp.decode(stream)) {
      const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
      const resp = parseDkgRound2Response(bytes);
      if (!resp) throw new Error("dkgRound2: invalid response");
      if (!resp.ok) throw new Error(`dkgRound2 failed: ${resp.reason}`);
      return resp.sharesForOthers;
    }
  } finally {
    stream.close().catch(() => {});
  }
  throw new Error("dkgRound2: no response received");
}

/**
 * Run DKG round 3 with this directory node.
 * Opens a new stream, sends frost_dkg_round3_request, returns shareCommitment.
 */
async function dkgRound3WithNode(
  node: NetworkDirectoryNode,
  agentPubkeyHex: string,
  epochId: string,
  sharesForMe: DkgRound2Share[],
  allRound1: DkgRound1Broadcast[],
): Promise<Uint8Array> {
  const frame = encodeCbor({
    type: "frost_dkg_round3_request",
    agentPubkey: agentPubkeyHex,
    epochId,
    sharesForMe: sharesForMe.map((s) => ({
      identifier: s.signerIdentifier,
      targetIdentifier: s.targetIdentifier,
      signingShare: s.signingShare,
    })),
    allOthersRound1: allRound1.map((b) => ({
      identifier: b.identifier,
      commitment: b.commitment,
      proofOfKnowledge: b.proofOfKnowledge,
    })),
  });
  const stream = await node.openStream();
  try {
    stream.send(lp.encode.single(frame));
    for await (const chunk of lp.decode(stream)) {
      const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
      const resp = parseDkgRound3Response(bytes);
      if (!resp) throw new Error("dkgRound3: invalid response");
      if (!resp.ok) throw new Error(`dkgRound3 failed: ${resp.reason}`);
      return resp.shareCommitment;
    }
  } finally {
    stream.close().catch(() => {});
  }
  throw new Error("dkgRound3: no response received");
}

// ─── DKG response parsers (client-side decoders) ──────────────────────────────

/** Structured result for parseDkgRound1Response — distinguishes normal responses from preauth rejections */
type DkgRound1ParseResult =
  | { kind: "response"; response: FrostDkgRound1Response }
  | { kind: "preauth_error"; reason: string }
  | { kind: "invalid" };

function parseDkgRound1Response(bytes: Uint8Array): DkgRound1ParseResult {
  let obj: unknown;
  try { obj = cborDecode(bytes); } catch { return { kind: "invalid" }; }
  if (typeof obj !== "object" || obj === null) return { kind: "invalid" };
  const o = obj as Record<string, unknown>;

  // preauth_error frames from the directory MUST be surfaced, never dropped as "invalid" — a silently
  // discarded rejection reads to the caller as a malformed frame instead of a refused authorization.
  if (o["type"] === "preauth_error") {
    const reason = typeof o["reason"] === "string" ? o["reason"] : "PRE_AUTH_TOKEN_MISSING";
    return { kind: "preauth_error", reason };
  }

  if (o["type"] !== "frost_dkg_round1_response") return { kind: "invalid" };
  if (o["ok"] === true) {
    const raw = o["broadcast"];
    if (typeof raw !== "object" || raw === null) return { kind: "invalid" };
    const b = raw as Record<string, unknown>;
    const identifier = typeof b["identifier"] === "string" ? b["identifier"] : null;
    const proofOfKnowledge = toU8(b["proofOfKnowledge"]);
    const commitment = parseU8Array(b["commitment"]);
    if (!identifier || !proofOfKnowledge || !commitment) return { kind: "invalid" };
    return { kind: "response", response: { type: "frost_dkg_round1_response", ok: true, broadcast: { identifier, commitment, proofOfKnowledge } } };
  }
  const reason = o["reason"];
  if (reason !== "already_in_progress" && reason !== "internal_error") return { kind: "invalid" };
  return { kind: "response", response: { type: "frost_dkg_round1_response", ok: false, reason } };
}

function parseDkgRound2Response(bytes: Uint8Array): FrostDkgRound2Response | null {
  let obj: unknown;
  try { obj = cborDecode(bytes); } catch { return null; }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "frost_dkg_round2_response") return null;
  if (o["ok"] === true) {
    const rawShares = o["sharesForOthers"];
    if (!Array.isArray(rawShares)) return null;
    const sharesForOthers: DkgRound2Share[] = [];
    for (const item of rawShares) {
      if (typeof item !== "object" || item === null) return null;
      const s = item as Record<string, unknown>;
      // Accept both "signerIdentifier" (protocol-types canonical) and "identifier" (new wire)
      const signerIdentifier =
        typeof s["signerIdentifier"] === "string" ? s["signerIdentifier"] :
        typeof s["identifier"] === "string" ? s["identifier"] : null;
      const targetIdentifier = typeof s["targetIdentifier"] === "string" ? s["targetIdentifier"] : null;
      const signingShare = toU8(s["signingShare"]);
      if (!signerIdentifier || !targetIdentifier || !signingShare) return null;
      sharesForOthers.push({ signerIdentifier, targetIdentifier, signingShare });
    }
    return { type: "frost_dkg_round2_response", ok: true, sharesForOthers };
  }
  const reason = o["reason"];
  if (reason !== "round1_not_complete" && reason !== "verification_failed" && reason !== "internal_error") return null;
  return { type: "frost_dkg_round2_response", ok: false, reason };
}

function parseDkgRound3Response(bytes: Uint8Array): FrostDkgRound3Response | null {
  let obj: unknown;
  try { obj = cborDecode(bytes); } catch { return null; }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "frost_dkg_round3_response") return null;
  if (o["ok"] === true) {
    const sc = o["shareCommitment"];
    // shareCommitment comes as raw bytes (CBOR-encoded Uint8Array)
    const shareCommitment = typeof sc === "string"
      ? new Uint8Array(Buffer.from(sc, "hex"))
      : sc instanceof Uint8Array ? sc
      : Buffer.isBuffer(sc) ? new Uint8Array(sc as Buffer)
      : null;
    if (!shareCommitment || shareCommitment.length !== 32) return null;
    return { type: "frost_dkg_round3_response", ok: true, shareCommitment };
  }
  const reason = o["reason"];
  if (reason !== "round2_not_complete" && reason !== "share_verification_failed" && reason !== "internal_error") return null;
  return { type: "frost_dkg_round3_response", ok: false, reason };
}

function toU8(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

function parseU8Array(v: unknown): Uint8Array[] | null {
  if (!Array.isArray(v)) return null;
  const result: Uint8Array[] = [];
  for (const item of v) {
    const b = toU8(item);
    if (!b) return null;
    result.push(b);
  }
  return result;
}

// ─── bootstrapNetworkKeyShares ────────────────────────────────────────────────

/**
 * Network-aware FROST bootstrap for live e2e mode.
 *
 * Runs trustedDealer locally, then pushes each directory node's share over the
 * /cello/frost/1.0.0 network protocol. Returns a FrostThresholdSigner configured
 * to use NetworkDirectoryNodes, plus the primaryPubkey.
 *
 * TEST-ONLY: this uses the trustedDealer shortcut, so it is guarded by NODE_ENV=test. The production
 * path is runNetworkDkg.
 */
export async function bootstrapNetworkKeyShares(
  agentPubkey: Uint8Array,
  opts: {
    threshold: number;
    participants: number;
    directoryNodes: NetworkDirectoryNode[];
  },
): Promise<{ signer: FrostThresholdSigner; primaryPubkey: Uint8Array }> {
  // bootstrapKeyShares uses trustedDealer — a test-harness shortcut, not a real DKG. This function
  // inherits that constraint, so it must never run outside tests.
  if (process.env.NODE_ENV !== "test") {
    throw new Error("bootstrapNetworkKeyShares uses trustedDealer which is test-only. Real DKG (M3) required in production.");
  }
  const agentPubkeyHex = Buffer.from(agentPubkey).toString("hex");
  const epochId = `${agentPubkeyHex}:epoch:1`;

  // Set context on all nodes so receiveShare knows which agent/epoch to use
  for (const node of opts.directoryNodes) {
    node.setBootstrapContext(agentPubkeyHex, epochId);
  }

  // bootstrapKeyShares runs trustedDealer and calls node.receiveShare() on each node.
  // For NetworkDirectoryNode, receiveShare() sends the share over the network.
  const result: BootstrapResult = await bootstrapKeyShares(agentPubkey, {
    threshold: opts.threshold,
    participants: opts.participants,
    directoryNodeStubs: opts.directoryNodes,
  });

  const signer = new FrostThresholdSigner(
    {
      threshold: opts.threshold,
      participants: opts.participants,
      directoryNodeStubs: opts.directoryNodes,
    },
    agentPubkey,
  );

  return { signer, primaryPubkey: result.primaryPubkey };
}

// ─── runNetworkDkg ─────────────────────────────────────────────────────────────

/**
 * Run a real 3-round FROST DKG ceremony with directory nodes over /cello/frost/1.0.0.
 *
 * Production path for key establishment. The client acts as DKG coordinator:
 *   Round 1: All nodes generate their secret polynomials. Client does the same.
 *   Round 2: Client collects all round1 broadcasts and distributes them to all nodes.
 *            All nodes compute shares for every other participant.
 *   Round 3: Client routes round2 shares to recipients and all nodes finalize.
 *            All nodes return shareCommitment = group public key.
 *
 * Validates that all nodes derive the same primary_pubkey before returning.
 *
 * After a successful DKG:
 *   - Each directory node has its FrostSecret stored (via dkgRound3)
 *   - The client's local share is stored via storeDkgResult
 *   - Returns a FrostThresholdSigner for future signing ceremonies
 *
 * Crypto reference: RFC 9591 (FROST DKG)
 *
 * @param agentPubkey - client's Ed25519 K_local public key (32 bytes)
 * @param opts.threshold - minimum signers required (t in t-of-n)
 * @param opts.directoryNodes - the n directory nodes (each will hold a share)
 */
export async function runNetworkDkg(
  agentPubkey: Uint8Array,
  opts: {
    threshold: number;
    participants: number;
    directoryNodes: NetworkDirectoryNode[];
    /** Pre-authorization token to present in the Round 1 frame. */
    preAuthToken?: string;
    /** K_local signer for the DKG-time commit/sign requests' auth. */
    signAuth?: FrostAuthSigner;
  },
): Promise<{
  signer: FrostThresholdSigner;
  primaryPubkey: Uint8Array;
  /** Serializable FROST share data for DB persistence. NEVER log signingShare. */
  signingShare: Uint8Array;
  identifier: string;
  commitments: Uint8Array[];
  verifyingShares: Record<string, Uint8Array>;
  threshold: number;
  participants: number;
}> {
  const agentPubkeyHex = Buffer.from(agentPubkey).toString("hex");
  // Client identifier: same derivation as used in bootstrapKeyShares for consistency
  const clientIdStr = `client:${agentPubkeyHex}`;
  const clientIdentifier = ed25519_FROST.Identifier.derive(clientIdStr);
  const epochId = `${agentPubkeyHex}:epoch:1`;

  // Total participants = directory nodes + 1 (client)
  // threshold is the signing threshold (t-of-n where n = directoryNodes.length + 1)
  const signers = { min: opts.threshold, max: opts.participants + 1 };

  // ─── Round 1 ────────────────────────────────────────────────────────────────
  // Client runs DKG.round1 locally; all directory nodes run round1 via streams.
  // RFC 9591 §5.1

  const clientR1 = ed25519_FROST.DKG.round1(clientIdentifier, signers);
  const clientRound1Broadcast: DkgRound1Broadcast = {
    identifier: clientR1.public.identifier,
    commitment: clientR1.public.commitment.map((c: Uint8Array) => new Uint8Array(c)),
    proofOfKnowledge: new Uint8Array(clientR1.public.proofOfKnowledge),
  };

  // Directory nodes run round1 in parallel
  const nodeRound1Broadcasts = await Promise.all(
    opts.directoryNodes.map((node) =>
      dkgRound1WithNode(node, agentPubkeyHex, epochId, signers, opts.preAuthToken)
    )
  );

  // allRound1 = client + all directory node broadcasts
  const allRound1: DkgRound1Broadcast[] = [clientRound1Broadcast, ...nodeRound1Broadcasts];

  // DOD-INV-NODEID, enforced where it is actually decidable. Every check upstream compares MANIFEST
  // nodeId strings, but a node's FROST identifier is derived from its OWN deployed NODE_ID
  // (directory-side `frost-handler.ts`). So two entries with DISTINCT nodeIds, deployed on boxes that
  // share one NODE_ID, collide here and pass every string check in the consortium.
  //
  // These are the identifiers actually in play, so this is the first point where the collapse is
  // visible. `DKG.round2` below does reject it — @noble/curves throws `Duplicate id=…` — but as an
  // exception from inside a crypto library, which then had to survive every catch between here and
  // the operator. Refusing here names the cause while the node list is still in hand.
  const seenIdentifiers = new Map<string, number>();
  for (let i = 0; i < allRound1.length; i++) {
    const prev = seenIdentifiers.get(allRound1[i]!.identifier);
    if (prev !== undefined) {
      // Index 0 is the client; 1..n are opts.directoryNodes[0..n-1].
      const who = (idx: number) => (idx === 0 ? "the client" : `directory node ${opts.directoryNodes[idx - 1]?.id ?? idx}`);
      throw new Error(
        `DKG round 1 produced a DUPLICATE FROST identifier: ${who(prev)} and ${who(i)} both derived ` +
          `${allRound1[i]!.identifier.slice(0, 24)}… — two participants sharing one identifier are one ` +
          `participant, so the quorum is smaller than it looks. Most likely two directory nodes are ` +
          `deployed with the same NODE_ID.`,
      );
    }
    seenIdentifiers.set(allRound1[i]!.identifier, i);
  }

  // ─── Round 2 ────────────────────────────────────────────────────────────────
  // Client runs DKG.round2 locally (receives others' round1 → generates shares for others).
  // All directory nodes run round2 in parallel.
  // RFC 9591 §5.2

  // For the client, othersRound1 = all directory nodes' broadcasts
  const clientOthersRound1 = nodeRound1Broadcasts.map((b) => ({
    identifier: b.identifier,
    commitment: b.commitment.map((c) => new Uint8Array(c)),
    proofOfKnowledge: new Uint8Array(b.proofOfKnowledge),
  }));
  const clientR2 = ed25519_FROST.DKG.round2(clientR1.secret, clientOthersRound1);

  // For each directory node, othersRound1 = all other participants EXCEPT that node itself
  const nodeRound2Results = await Promise.all(
    opts.directoryNodes.map((node, i) => {
      // Each node receives round1 from everyone EXCEPT itself
      const othersForNode = allRound1.filter((_, j) =>
        j !== i + 1  // i+1 because index 0 is the client
      );
      return dkgRound2WithNode(node, agentPubkeyHex, epochId, othersForNode);
    })
  );

  // ─── Route round2 shares ─────────────────────────────────────────────────────
  // Collect all shares (client-generated + node-generated), route to recipients.
  // Each participant needs shares from all OTHER participants.
  // sharesForClient: shares where targetIdentifier === clientIdentifier
  // sharesForNode[i]: shares where targetIdentifier === nodeRound1Broadcasts[i].identifier

  // Build a map: targetIdentifier → accumulated DkgRound2Share[]
  const sharesForAll = new Map<string, DkgRound2Share[]>();

  // Add client's shares (for each directory node)
  const clientSharesRecord = clientR2 as Record<string, { identifier: string; signingShare: Uint8Array }>;
  for (const [targetId, share] of Object.entries(clientSharesRecord)) {
    const shares = sharesForAll.get(targetId) ?? [];
    shares.push({
      signerIdentifier: clientIdentifier,
      targetIdentifier: targetId,
      signingShare: new Uint8Array(share.signingShare),
    });
    sharesForAll.set(targetId, shares);
  }

  // Add directory node shares (for client and other directory nodes)
  for (const nodeShares of nodeRound2Results) {
    for (const share of nodeShares) {
      const shares = sharesForAll.get(share.targetIdentifier) ?? [];
      shares.push(share);
      sharesForAll.set(share.targetIdentifier, shares);
    }
  }

  // ─── Round 3 ────────────────────────────────────────────────────────────────
  // Client runs DKG.round3 locally.
  // All directory nodes run round3 in parallel.
  // RFC 9591 §5.3

  // Client's round3: receives shares addressed to clientIdentifier
  const clientSharesForMe = (sharesForAll.get(clientIdentifier) ?? []).map((s) => ({
    identifier: s.signerIdentifier,  // SENDER's identifier (for round3 matching)
    signingShare: new Uint8Array(s.signingShare),
  }));
  const clientKey = ed25519_FROST.DKG.round3(clientR1.secret, clientOthersRound1, clientSharesForMe);

  // Directory nodes' round3: parallel
  const nodeCommitments = await Promise.all(
    opts.directoryNodes.map((node, i) => {
      const nodeId = nodeRound1Broadcasts[i]!.identifier;
      const nodeSharesForMe = sharesForAll.get(nodeId) ?? [];
      const allOthersForNode = allRound1.filter((_, j) => j !== i + 1);
      return dkgRound3WithNode(node, agentPubkeyHex, epochId, nodeSharesForMe, allOthersForNode);
    })
  );

  // ─── Verify all nodes agree on primary_pubkey ─────────────────────────────
  const primaryPubkey = new Uint8Array(clientKey.public.commitments[0]);
  const primaryPubkeyHex = Buffer.from(primaryPubkey).toString("hex");

  for (const nodeCommitment of nodeCommitments) {
    const nodeHex = Buffer.from(nodeCommitment).toString("hex");
    if (nodeHex !== primaryPubkeyHex) {
      // Clean up client secret to avoid leaking state
      try { ed25519_FROST.DKG.clean(clientR1.secret); } catch { /* ignore */ }
      throw new Error(
        `DKG failed: node commitment ${nodeHex.slice(0, 16)}… does not match client primary_pubkey ${primaryPubkeyHex.slice(0, 16)}…`
      );
    }
  }

  // ─── Store client's local DKG share ──────────────────────────────────────
  // storeDkgResult is the production key storage path (no NODE_ENV guard).
  storeDkgResult(agentPubkeyHex, clientKey.secret, clientKey.public);

  // Clean up DKG secret now that it's been safely stored
  try { ed25519_FROST.DKG.clean(clientR1.secret); } catch { /* ignore */ }

  // Set signing context on each directory node so generateCommitment/signRound can
  // identify which agent's share to use in future FROST signing ceremonies. The K_local signer MUST be
  // threaded here so the DKG-time and later signing requests carry a valid auth.
  for (const node of opts.directoryNodes) {
    node.setBootstrapContext(agentPubkeyHex, epochId, opts.signAuth);
  }

  // ─── Build FrostThresholdSigner ───────────────────────────────────────────
  const signer = new FrostThresholdSigner(
    {
      threshold: opts.threshold,
      participants: opts.participants,
      directoryNodeStubs: opts.directoryNodes,
    },
    agentPubkey,
  );

  // Extract serializable FROST share data for DB persistence. NEVER log signingShare.
  const serializedSecret = clientKey.secret as unknown as { identifier: string; signingShare: Uint8Array };
  const serializedPub = clientKey.public as unknown as {
    commitments: Uint8Array[];
    verifyingShares: Record<string, Uint8Array>;
  };

  return {
    signer,
    primaryPubkey,
    signingShare: new Uint8Array(serializedSecret.signingShare),
    identifier: serializedSecret.identifier,
    commitments: serializedPub.commitments.map((c) => new Uint8Array(c)),
    verifyingShares: Object.fromEntries(
      Object.entries(serializedPub.verifyingShares).map(([k, v]) => [k, new Uint8Array(v)])
    ),
    threshold: opts.threshold,
    participants: opts.participants,
  };
}

// ─── Proactive share resharing (PSS) orchestration ─────────
// A client-coordinated 2-round refresh that rotates every shareholder's share to a new epoch while keeping
// the group public key unchanged (frost-resharing.ts). The client is the UNIFORM RELAY: it collects one
// contribution per node (round 1) and distributes the agreed set — narrowed to each node's own sub-share
// (round 2) — so a directory cannot equivocate and a node never sees another party's sub-shares.

async function refreshRound1WithNode(
  node: NetworkDirectoryNode,
  agentPubkeyHex: string,
  fromEpochId: string,
  toEpochId: string,
  signers: { min: number; max: number },
  participantIds: string[],
): Promise<FrostRefreshContribution> {
  const frame = encodeCbor({
    type: "frost_refresh_round1_request",
    agentPubkey: agentPubkeyHex,
    fromEpochId,
    toEpochId,
    signers,
    participantIds,
  });
  const stream = await node.openStream();
  try {
    stream.send(lp.encode.single(frame));
    for await (const chunk of lp.decode(stream)) {
      const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
      const resp = cborDecode(bytes) as FrostRefreshRound1Response;
      if (resp.type !== "frost_refresh_round1_response") throw new Error("refreshRound1: invalid response");
      if (!resp.ok) throw new Error(`refreshRound1 failed: ${resp.reason}`);
      return resp.contribution;
    }
  } finally {
    stream.close().catch(() => {});
  }
  throw new Error("refreshRound1: no response received");
}

async function refreshRound2WithNode(
  node: NetworkDirectoryNode,
  agentPubkeyHex: string,
  fromEpochId: string,
  toEpochId: string,
  signers: { min: number; max: number },
  participantIds: string[],
  contributions: FrostRefreshContribution[],
): Promise<Uint8Array> {
  const frame = encodeCbor({
    type: "frost_refresh_round2_request",
    agentPubkey: agentPubkeyHex,
    fromEpochId,
    toEpochId,
    signers,
    participantIds,
    contributions,
  });
  const stream = await node.openStream();
  try {
    stream.send(lp.encode.single(frame));
    for await (const chunk of lp.decode(stream)) {
      const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
      const resp = cborDecode(bytes) as FrostRefreshRound2Response;
      if (resp.type !== "frost_refresh_round2_response") throw new Error("refreshRound2: invalid response");
      if (!resp.ok) throw new Error(`refreshRound2 failed: ${resp.reason}`);
      return new Uint8Array(resp.shareCommitment);
    }
  } finally {
    stream.close().catch(() => {});
  }
  throw new Error("refreshRound2: no response received");
}

/**
 * Run a proactive share refresh across the consortium. Rotates the client's + every directory node's share
 * from epoch `fromEpochN` to `fromEpochN + 1`, leaving the group public key byte-identical. Verifies every
 * party reports the same (unchanged) group key before returning the client's serializable new-epoch share.
 */
export async function runNetworkRefresh(
  agentPubkey: Uint8Array,
  opts: {
    threshold: number;
    participants: number;
    directoryNodes: NetworkDirectoryNode[];
    fromEpochN: number;
    /** K_local signer for any commit/sign auth during the refresh. */
    signAuth?: FrostAuthSigner;
  },
): Promise<{
  toEpochN: number;
  primaryPubkey: Uint8Array;
  signingShare: Uint8Array;
  identifier: string;
  commitments: Uint8Array[];
  verifyingShares: Record<string, Uint8Array>;
}> {
  const agentPubkeyHex = Buffer.from(agentPubkey).toString("hex");
  const fromEpochId = `${agentPubkeyHex}:epoch:${opts.fromEpochN}`;
  const toEpochN = opts.fromEpochN + 1;
  const toEpochId = `${agentPubkeyHex}:epoch:${toEpochN}`;
  const signers = { min: opts.threshold, max: opts.participants + 1 };
  const participantIds = getClientRefreshRoster(agentPubkeyHex);

  // ─── Round 1: collect one contribution per participant ───
  const nodeContributions = await Promise.all(
    opts.directoryNodes.map((node) =>
      refreshRound1WithNode(node, agentPubkeyHex, fromEpochId, toEpochId, signers, participantIds),
    ),
  );
  const clientContribution = generateClientRefreshContribution(agentPubkeyHex, signers, participantIds);
  const allContributions: FrostRefreshContribution[] = [clientContribution, ...nodeContributions];

  // ─── Round 2: each node applies; narrow each contribution's subShares to that node's own entry ───
  const clientId = getClientFrostIdentifier(agentPubkeyHex);
  const narrowFor = (recipientId: string): FrostRefreshContribution[] =>
    allContributions.map((c) => ({
      fromId: c.fromId,
      commitment: c.commitment,
      subShares: { [recipientId]: c.subShares[recipientId] },
    }));

  const nodeCommitments = await Promise.all(
    opts.directoryNodes.map((node, idx) =>
      refreshRound2WithNode(
        node, agentPubkeyHex, fromEpochId, toEpochId, signers, participantIds,
        narrowFor(nodeContributions[idx].fromId),
      ),
    ),
  );

  // Client applies its own refresh (rotates _localShares in-package).
  const clientResult = applyRefreshToLocalShare(agentPubkeyHex, narrowFor(clientId), signers, participantIds);

  // ─── Verify all parties agree on the (unchanged) group key ───
  const primaryPubkeyHex = Buffer.from(clientResult.primaryPubkey).toString("hex");
  for (const nc of nodeCommitments) {
    if (Buffer.from(nc).toString("hex") !== primaryPubkeyHex) {
      throw new Error("Refresh failed: a directory node's post-refresh group key does not match the client's");
    }
  }

  // Advance every node's signing context to the new epoch.
  for (const node of opts.directoryNodes) {
    node.setBootstrapContext(agentPubkeyHex, toEpochId, opts.signAuth); // SEC-2
  }

  return {
    toEpochN,
    primaryPubkey: clientResult.primaryPubkey,
    signingShare: clientResult.signingShare,
    identifier: clientResult.identifier,
    commitments: clientResult.commitments,
    verifyingShares: clientResult.verifyingShares,
  };
}
