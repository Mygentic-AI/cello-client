/**
 * M16 043-POSTERS Part C — publishing on a channel this daemon does NOT hold the key to.
 *
 * The admin lends an agent the right to post with a signed, expiring PASS. The agent signs its post
 * with its own key (`signPosterPost`), carries the pass, and numbers the post in its own LANE of the
 * log (`<channelHex>/<posterHex>`), so it never collides with the admin or another poster.
 *
 * Same order of operations as the admin's publisher, for the same reasons: screen → take the lane's
 * next number → encrypt (binding that number) → sign → APPEND TO THE LOG → deposit on every relay.
 *
 * ⚠️ **EVERY GAP REFUSES, NOTHING DEGRADES.**
 *   - no pass, or an expired one            → `no_posting_pass` (never "post without one")
 *   - non-public, no group key held         → `channel_group_key_unavailable` (NEVER plaintext)
 *   - no subscription row                   → `channel_unknown` (no relays to send to)
 *
 * A poster deposit carries NO fetch key — the poster cannot sign one, and the relay refuses one on a
 * poster deposit. The clock-skew re-sign the admin's publisher does is not repeated here: a refused
 * post stays in the lane's log and `resendMissing` carries it.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import { encryptBody } from "@cello-protocol/crypto";
import {
  decodeRelayPostReceipt, encodeBroadcastArtifact, signPosterPost, verifyRelayPostReceipt,
  type BroadcastArtifact,
} from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";
import type { ChannelLogStore } from "./channel-log-store.js";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import type { ChannelPosterPassStore } from "./channel-poster-pass-store.js";
import type { DepositOutcome, RelayDepositSeam, ScreenVerdict } from "./channel-publisher.js";
import { DEFAULT_RESEND_PACE_MS } from "./channel-publisher.js";
import { extractErrorMessage } from "./error-message.js";

export type PosterPublishRefusal =
  | "blocked_by_screen" | "channel_unknown" | "key_unavailable" | "no_relay_accepted" | "post_invalid"
  | "no_posting_pass" | "channel_group_key_unavailable"
  // 044-POSTERBELL Part E2: the relays refused because the admin removed this poster (or the pass
  // lapsed). The relay's own reason, surfaced so the poster is told rather than sent to resend.
  | "pass_revoked" | "posting_closed" | "pass_expired";

/** The relay refusals that mean "you can no longer post here", not "try again". */
const REMOVED_POSTER_REASONS = new Set<string>(["pass_revoked", "posting_closed", "pass_expired"]);

export type PosterPublishResult =
  | { ok: true; seq: number; deposited: DepositOutcome[]; poster_receipt_cbor?: Uint8Array }
  | { ok: false; reason: PosterPublishRefusal; detail?: string; seq?: number; deposited?: DepositOutcome[] };

export interface ChannelPosterPublisherOptions {
  logger: Logger;
  log: ChannelLogStore;
  passes: ChannelPosterPassStore;
  subscriptions: ChannelSubscriptionStore;
  deposit: RelayDepositSeam;
  resolveAgentId: (agentName: string) => string;
  getAgentKey: (agentName: string) => KeyProvider | null;
  screenOutbound: (bytes: Uint8Array, ctx: { agentName: string; correlationId?: string }) => Promise<ScreenVerdict>;
  resendPaceMs?: number;
  now?: () => number;
}

const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");

export class ChannelPosterPublisher {
  readonly #o: ChannelPosterPublisherOptions;
  readonly #now: () => number;

  constructor(opts: ChannelPosterPublisherOptions) {
    this.#o = opts;
    this.#now = opts.now ?? (() => Date.now());
  }

  /** The relays a poster deposits to: the channel's, from this agent's subscription row. */
  relaysFor(agentName: string, channelHex: string): string[] {
    return this.#o.subscriptions.get(this.#o.resolveAgentId(agentName), channelHex)?.relays ?? [];
  }

  async publish(agentName: string, channelHex: string, title: string, body: string, correlationId?: string): Promise<PosterPublishResult> {
    const { logger, log } = this.#o;
    const cid = correlationId !== undefined ? { correlationId } : {};
    const agentId = this.#o.resolveAgentId(agentName);
    const sub = this.#o.subscriptions.get(agentId, channelHex);
    if (!sub || sub.status !== "active") {
      return { ok: false, reason: "channel_unknown", detail: "this agent is not an active member of that channel" };
    }
    const pass = this.#o.passes.get(agentId, channelHex);
    const now = this.#now();
    if (!pass || now > pass.expires_at) {
      logger.info("channel.publish.refused", { ...cid, channel_pubkey: channelHex, reason: "no_posting_pass" });
      return {
        ok: false, reason: "no_posting_pass",
        detail: pass ? "this agent's posting pass has expired; the admin renews it while online" : "the admin has not given this agent a posting pass",
      };
    }
    const agentKey = this.#o.getAgentKey(agentName);
    if (!agentKey) return { ok: false, reason: "key_unavailable", detail: "the agent key is not loaded" };
    // The newest generation this member holds. Checked BEFORE the lane number is taken, so a refusal
    // leaves no gap in the lane.
    const gk = sub.access === "public" ? null : (this.#o.subscriptions.keysFor(agentId, channelHex)[0] ?? null);
    if (sub.access !== "public" && gk === null) {
      logger.warn("channel.publish.refused", { ...cid, channel_pubkey: channelHex, reason: "channel_group_key_unavailable" });
      return { ok: false, reason: "channel_group_key_unavailable", detail: "this member holds no group key for the channel" };
    }

    const verdict = await this.#o.screenOutbound(new TextEncoder().encode(`${title}\n${body}`), { agentName, ...cid });
    if (verdict.disposition !== "allow") {
      logger.info("channel.publish.refused", {
        ...cid, channel_pubkey: channelHex, disposition: verdict.disposition, reason: verdict.reason ?? "blocked",
      });
      return { ok: false, reason: "blocked_by_screen", detail: verdict.reason ?? verdict.disposition };
    }

    const lane = `${channelHex}/${hexOf(await agentKey.getPublicKey())}`;
    log.ensureChannel(lane);
    const { seq } = log.nextPosition(lane);
    const channelPubkey = new Uint8Array(Buffer.from(channelHex, "hex"));
    const plaintext = new TextEncoder().encode(body);
    const wire = gk === null ? plaintext : encryptBody(gk, channelPubkey, seq, plaintext);
    let post: BroadcastArtifact;
    try {
      post = await signPosterPost(agentKey, {
        channel_pubkey: channelPubkey, seq, published_at: now, title, body: wire, supersedes: null,
      }, pass.pass_cbor);
    } catch (err: unknown) {
      return { ok: false, reason: "post_invalid", detail: extractErrorMessage(err) };
    }
    // THE LOG, BEFORE THE NETWORK — the same rule as the admin's publisher.
    log.append(lane, post, correlationId);

    const deposited = await Promise.all(sub.relays.map((relay) => this.#depositOnce(relay, post, lane, correlationId)));
    const ok = deposited.filter((d) => d.ok);
    logger.info("channel.post.published", {
      ...cid, channel_pubkey: channelHex, lane, seq,
      relays_ok: ok.map((d) => d.relay), relays_failed: deposited.filter((d) => !d.ok).map((d) => d.relay),
    });
    if (ok.length === 0) {
      // 044-POSTERBELL Part E2: if every relay refused because we were removed as a poster (or the
      // pass lapsed), the post will never land — drop the whole lane so `resend` never offers it,
      // and surface the relay's real reason so the operator is told, not sent to resend.
      const removed = deposited.map((d) => d.reason).find((r): r is string => r !== undefined && REMOVED_POSTER_REASONS.has(r));
      if (removed) {
        log.pruneThrough(lane, seq);
        logger.info("channel.publish.refused", { ...cid, channel_pubkey: channelHex, reason: removed, lane, seq });
        return { ok: false, reason: removed as PosterPublishRefusal, seq, deposited };
      }
      return { ok: false, reason: "no_relay_accepted", seq, deposited };
    }
    // 044-POSTERBELL: hand up one verified relay receipt so the caller can ring the members. A post
    // that was taken but whose every receipt was unverifiable rings nobody — there is no proof to
    // give the directory — and that is correct, not a failure of the publish.
    const withReceipt = ok.find((d) => d.receipt_cbor !== undefined)?.receipt_cbor;
    return { ok: true, seq, deposited, ...(withReceipt ? { poster_receipt_cbor: withReceipt } : {}) };
  }

  /** Re-deposit this agent's lane on one relay. Refuses when no unexpired pass is held — the relay would. */
  async resendMissing(
    agentName: string, channelHex: string, relay: string, correlationId?: string,
  ): Promise<{ deposited: number; refused?: "no_posting_pass" | "key_unavailable"; poster_receipt_cbor?: Uint8Array }> {
    const agentId = this.#o.resolveAgentId(agentName);
    const pass = this.#o.passes.get(agentId, channelHex);
    if (!pass || this.#now() > pass.expires_at) {
      this.#o.logger.warn("channel.resend.refused", { channel_pubkey: channelHex, reason: "no_posting_pass" });
      return { deposited: 0, refused: "no_posting_pass" };
    }
    const agentKey = this.#o.getAgentKey(agentName);
    if (!agentKey) return { deposited: 0, refused: "key_unavailable" };
    const lane = `${channelHex}/${hexOf(await agentKey.getPublicKey())}`;
    const { log } = this.#o;
    log.ensureChannel(lane);
    const head = log.head(lane);
    if (head.first_seq === null || head.last_seq === null) return { deposited: 0 };

    // Everything logged, oldest first: `channel_head` has no lane, and a relay answers a post it
    // already holds with its original receipt, so a repeat costs a round trip and changes nothing.
    let deposited = 0;
    let receipt: Uint8Array | undefined;
    const pace = this.#o.resendPaceMs ?? DEFAULT_RESEND_PACE_MS;
    for (const post of log.readRange(lane, head.first_seq, head.last_seq)) {
      const outcome = await this.#depositOnce(relay, post, lane, correlationId);
      if (outcome.ok) deposited += 1;
      // 044-POSTERBELL: keep one verified receipt so the resend can ring the members too.
      if (outcome.receipt_cbor && !receipt) receipt = outcome.receipt_cbor;
      if (pace > 0) await new Promise((r) => setTimeout(r, pace));
    }
    return { deposited, ...(receipt ? { poster_receipt_cbor: receipt } : {}) };
  }

  async #depositOnce(relay: string, post: BroadcastArtifact, lane: string, correlationId?: string): Promise<DepositOutcome> {
    const cid = correlationId !== undefined ? { correlationId } : {};
    let answer: Awaited<ReturnType<RelayDepositSeam>>;
    try {
      answer = await this.#o.deposit(relay, { post_cbor: encodeBroadcastArtifact(post) });
    } catch (err: unknown) {
      this.#o.logger.warn("channel.post.deposit_failed", { ...cid, lane, seq: post.seq, relay, reason: extractErrorMessage(err) });
      return { relay, ok: false, reason: extractErrorMessage(err) };
    }
    if (!answer.ok) {
      this.#o.logger.warn("channel.post.deposit_failed", { ...cid, lane, seq: post.seq, relay, reason: answer.reason });
      return { relay, ok: false, reason: answer.reason };
    }
    const decoded = decodeRelayPostReceipt(answer.receipt_cbor);
    if (!decoded.ok || !verifyRelayPostReceipt(decoded.receipt, post)) {
      this.#o.logger.warn("channel.post.deposit_failed", { ...cid, lane, seq: post.seq, relay, reason: "receipt_invalid" });
      return { relay, ok: true, receipt_unfiled: "receipt_invalid" };
    }
    // 044-POSTERBELL: keep the verified receipt bytes so the ring can prove this post to the directory.
    const receipt_cbor = new Uint8Array(answer.receipt_cbor);
    try {
      this.#o.log.recordReceipt(lane, decoded.receipt, correlationId);
      return { relay, ok: true, receipt_cbor };
    } catch (err: unknown) {
      this.#o.logger.warn("channel.post.receipt_unfiled", { ...cid, lane, seq: post.seq, relay, reason: extractErrorMessage(err) });
      return { relay, ok: true, receipt_unfiled: extractErrorMessage(err), receipt_cbor };
    }
  }
}
