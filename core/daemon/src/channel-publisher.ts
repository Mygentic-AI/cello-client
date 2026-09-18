/**
 * ChannelPublisher — M16 018-PUBCOLLECT, the publishing half.
 *
 * A channel publishes through **two relays of its own choosing**, so one being down does not stop
 * delivery. Nothing coordinates them: each holds its own queue, and the subscriber takes the union.
 *
 * ─── The order of operations, and why it is not negotiable ───────────────────────────────────
 *
 *   1. screen the title and body           — refuse, never warn-and-send
 *   2. encrypt the body (unless public)
 *   3. take the next number, sign with BOTH keys
 *   4. APPEND TO THE LOG
 *   5. deposit on both relays, store each receipt
 *
 * ⚠️ **STEP 4 IS BEFORE STEP 5, AND THAT IS THE WHOLE DESIGN.** A post that reached a relay but not
 * the log is invisible to its own publisher: it cannot be resent to a relay that lost it, cannot be
 * pruned, and cannot be proved. The log is the durable copy; the network is the optimistic part.
 * `resendMissing` exists precisely because the log outlives any relay's memory.
 *
 * ⚠️ **ONE RELAY FAILING IS NOT A FAILED PUBLISH.** Treating it as one would make a two-relay design
 * strictly less available than a single-relay design, which inverts the reason for having two.
 * Both failing gives `no_relay_accepted` — and the post STAYS in the log, because the next attempt
 * has to send the same signed bytes rather than a new post at a new number.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  decodeRelayPostReceipt,
  encodeBroadcastArtifact,
  encodeChannelInfo,
  signBroadcastArtifact,
  signChannelInfo,
  verifyRelayPostReceipt,
  buildChannelPruneTbs,
  type BroadcastArtifact,
  type ChannelAccess,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "./channel-log-store.js";

/** How the publisher reaches a relay. The transport is the caller's; this owns the decisions. */
export type RelayDepositSeam = (
  relay: string,
  req: { post_cbor: Uint8Array },
) => Promise<
  | { ok: true; receipt_cbor: Uint8Array }
  | { ok: false; reason: string; skew_ms?: number }
>;

/** Deposit the channel's info record. Separate from a post: it carries no sequence and no receipt. */
export type RelayInfoDepositSeam = (
  relay: string,
  req: { info_cbor: Uint8Array },
) => Promise<{ ok: true } | { ok: false; reason: string }>;

/** Ask a relay to drop everything through a post number, oldest end only. */
export type RelayPruneSeam = (
  relay: string,
  req: { channelHex: string; throughSeq: number; timeMs: number; signature: Uint8Array },
) => Promise<{ ok: true; dropped?: number } | { ok: false; reason: string }>;

export type ScreenVerdict = { disposition: "allow" | "block" | "warn" | "redact"; reason?: string };

/**
 * Gap between deposits during a refill, so a long backlog stays under the relay's per-publisher
 * rate limit. Only `resendMissing` paces — an ordinary publish is two deposits and pacing it would
 * add latency to every post to protect against a burst that cannot happen.
 */
export const DEFAULT_RESEND_PACE_MS = 50;

export interface ChannelPublisherOptions {
  db: DaemonDatabase;
  logger: Logger;
  log: ChannelLogStore;
  deposit: RelayDepositSeam;
  depositInfo: RelayInfoDepositSeam;
  /**
   * Optional ONLY so a caller that cannot prune says so: an absent seam reports each relay as
   * `relay_prune_unavailable`, never as a successful prune.
   */
  prune?: RelayPruneSeam;
  /**
   * Where a relay's queue begins and ends. Optional: without it `resendMissing` re-sends everything
   * logged, which is correct but chattier. See the note at its use for why a RECEIPT is not the
   * right question to ask.
   */
  relayHead?: (relay: string, channelHex: string) => Promise<{ first_held_seq: number | null; last_seq: number | null }>;
  screenOutbound: (bytes: Uint8Array, ctx: { agentName: string; correlationId?: string }) => Promise<ScreenVerdict>;
  getChannelKey: (channelHex: string) => KeyProvider | null;
  getAgentKey: (agentName: string) => KeyProvider | null;
  /** 019 owns the group key; the publisher must not be able to tell what this does. */
  encryptBody: (plaintext: Uint8Array, channelHex: string) => Promise<Uint8Array>;
  /** Overridable so a test can refill without waiting; production takes the default. */
  resendPaceMs?: number;
  channelInfo: (channelHex: string) => {
    access: ChannelAccess; relays: string[]; guidance: string; retention_seconds: number;
  } | null;
  now?: () => number;
}

export type PublishRefusal =
  | "blocked_by_screen" | "channel_unknown" | "key_unavailable" | "no_relay_accepted" | "post_invalid";

export interface DepositOutcome {
  relay: string;
  /** Did this relay TAKE the post. Nothing else belongs in this flag — see `receipt_unfiled`. */
  ok: boolean;
  reason?: string;
  /** What the relay said our clock is off by, carried so the correction can use the largest. */
  skew_ms?: number;
  /**
   * The relay took the post and its receipt could not be filed (unverifiable, or naming bytes this
   * log does not hold). SEPARATE FROM `ok` on purpose: folding it in reported a post that is safely
   * on two relays as `no_relay_accepted`, and sent the operator to resend something already there.
   */
  receipt_unfiled?: string;
}

export type PublishResult =
  | { ok: true; seq: number; deposited: DepositOutcome[] }
  | { ok: false; reason: PublishRefusal; detail?: string; seq?: number; deposited?: DepositOutcome[] };

export class ChannelPublisher {
  readonly #opts: ChannelPublisherOptions;
  readonly #now: () => number;

  constructor(opts: ChannelPublisherOptions) {
    this.#opts = opts;
    this.#now = opts.now ?? (() => Date.now());
  }

  async publish(agentName: string, channelHex: string, title: string, body: string, correlationId?: string): Promise<PublishResult> {
    const { logger, log } = this.#opts;
    const info = this.#opts.channelInfo(channelHex);
    if (!info) return { ok: false, reason: "channel_unknown", detail: "no channel info for that pubkey" };

    const channelKey = this.#opts.getChannelKey(channelHex);
    const agentKey = this.#opts.getAgentKey(agentName);
    if (!channelKey || !agentKey) {
      return { ok: false, reason: "key_unavailable", detail: "the channel key or the agent key is not loaded" };
    }

    // 1. Screen BEFORE anything is signed or stored. The subscriber's inbound screen is the
    //    enforcement; this is the early check that spares an honest publisher the friction of
    //    publishing something every reader will refuse.
    const verdict = await this.#opts.screenOutbound(
      new TextEncoder().encode(`${title}\n${body}`),
      { agentName, ...(correlationId !== undefined ? { correlationId } : {}) },
    );
    if (verdict.disposition !== "allow") {
      logger.info("channel.publish.refused", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, disposition: verdict.disposition, reason: verdict.reason ?? "blocked",
      });
      return { ok: false, reason: "blocked_by_screen", detail: verdict.reason ?? verdict.disposition };
    }

    // 2. A public channel is readable by anyone, so encrypting it would be theatre — and would lock
    //    out the subscribers it exists for, who hold no key.
    const plaintext = new TextEncoder().encode(body);
    const wire = info.access === "public" ? plaintext : await this.#opts.encryptBody(plaintext, channelHex);

    // 3. Position and signatures.
    log.ensureChannel(channelHex);
    const { seq } = log.nextPosition(channelHex);
    let post: BroadcastArtifact;
    try {
      post = await signBroadcastArtifact(channelKey, agentKey, {
        seq, published_at: this.#now(), title, body: wire, supersedes: null, ext: null,
      });
    } catch (err: unknown) {
      return { ok: false, reason: "post_invalid", detail: extract(err) };
    }

    // 4. THE LOG, BEFORE THE NETWORK.
    log.append(channelHex, post, correlationId);

    // 5. Both relays, in parallel — a deposit is independent of the other, and making the second
    //    wait on the first would double the latency of the ordinary case for no gain.
    let deposited = await Promise.all(info.relays.map((relay) => this.#depositOnce(relay, post, channelHex, correlationId)));
    let ok = deposited.filter((d) => d.ok);

    /**
     * ⚠️ **THE CLOCK-SKEW CORRECTION IS ONE POST FOR ALL RELAYS, AND ONLY WHILE NONE HAS TAKEN IT.**
     *
     * `published_at` is inside both signatures, so a corrected post is different BYTES at the same
     * number. Correcting per relay would let relay A hold one body at seq N and relay B another —
     * and a subscriber taking the union of the two sees exactly what a fork looks like, produced by
     * an honest publisher with a wrong clock. So the correction happens here, once, and only when
     * NO relay accepted the original: a relay that already answered holds a receipt bound to those
     * bytes by hash, and re-signing under it would strand the proof.
     */
    if (ok.length === 0 && deposited.some((d) => d.reason === "clock_skew")) {
      const corrected = await this.#resignForSkew(agentName, channelHex, post, deposited, correlationId);
      if (corrected) {
        post = corrected;
        deposited = await Promise.all(info.relays.map((relay) => this.#depositOnce(relay, post, channelHex, correlationId)));
        ok = deposited.filter((d) => d.ok);
      }
    }

    logger.info("channel.post.published", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex,
      seq,
      relays_ok: ok.map((d) => d.relay),
      relays_failed: deposited.filter((d) => !d.ok).map((d) => d.relay),
    });

    if (ok.length === 0) {
      // The post STAYS in the log. A retry must send these bytes, not a new post at a new number:
      // the number and the time are inside both signatures.
      return { ok: false, reason: "no_relay_accepted", seq, deposited };
    }
    return { ok: true, seq, deposited };
  }

  /**
   * One deposit on one relay. No retry lives here — see the skew note in `publish`, which is where
   * a correction has to happen if it is to produce the same bytes for every relay.
   *
   * A relay that TOOK the post is `ok: true` even when its receipt could not be filed. The two facts
   * are reported separately because folding them together turned a post that is safely on two relays
   * into `no_relay_accepted`, and sent the operator to resend something already there.
   */
  async #depositOnce(relay: string, post: BroadcastArtifact, channelHex: string, correlationId?: string): Promise<DepositOutcome> {
    const { logger } = this.#opts;
    let answer: Awaited<ReturnType<RelayDepositSeam>>;
    try {
      answer = await this.#opts.deposit(relay, { post_cbor: encodeBroadcastArtifact(post) });
    } catch (err: unknown) {
      logger.warn("channel.post.deposit_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, relay, reason: extract(err),
      });
      return { relay, ok: false, reason: extract(err) };
    }

    if (answer.ok) {
      const filed = this.#storeReceipt(channelHex, post, answer.receipt_cbor, relay, correlationId);
      return filed.ok ? { relay, ok: true } : { relay, ok: true, receipt_unfiled: filed.reason };
    }

    logger.warn("channel.post.deposit_failed", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, seq: post.seq, relay, reason: answer.reason,
    });
    return {
      relay, ok: false, reason: answer.reason,
      ...(answer.skew_ms !== undefined ? { skew_ms: answer.skew_ms } : {}),
    };
  }

  /**
   * Re-sign a post ONCE at a clock the relays will accept, and put the corrected bytes in the log.
   *
   * The correction is the LARGEST skew any relay reported: a post the fastest relay will take is one
   * the others will too, and correcting to the smallest would leave the strictest relay refusing
   * again with no retry left.
   *
   * Returns `null` when the correction cannot be made — the keys are gone, or the log refuses to
   * replace bytes it has already receipted. `null` leaves the ORIGINAL post standing, which is the
   * safe direction: the post is in the log at its number and `resendMissing` can carry it later.
   */
  async #resignForSkew(
    agentName: string, channelHex: string, post: BroadcastArtifact,
    deposited: DepositOutcome[], correlationId?: string,
  ): Promise<BroadcastArtifact | null> {
    const { logger } = this.#opts;
    const channelKey = this.#opts.getChannelKey(channelHex);
    // BY NAME, from the caller. This read the empty string once, which is no agent, so the lookup
    // was always null and the correction never ran in production — the test harness ignored the
    // argument, so nothing said so.
    const agentKey = this.#opts.getAgentKey(agentName);
    if (!channelKey || !agentKey) {
      logger.warn("channel.post.resign_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, reason: "key_unavailable",
      });
      return null;
    }

    const skews = deposited.map((d) => d.skew_ms ?? 0);
    const corrected = this.#now() - Math.max(...skews);
    let resigned: BroadcastArtifact;
    try {
      resigned = await signBroadcastArtifact(channelKey, agentKey, {
        seq: post.seq, published_at: corrected, title: post.title,
        body: post.body, supersedes: post.supersedes, ext: null,
      });
      this.#opts.log.replaceUnreceipted(channelHex, resigned, correlationId);
    } catch (err: unknown) {
      logger.warn("channel.post.resign_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, reason: extract(err),
      });
      return null;
    }
    return resigned;
  }

  /** Verify a receipt against the post it names before storing it; an unverified one is worthless. */
  #storeReceipt(channelHex: string, post: BroadcastArtifact, receiptCbor: Uint8Array, relay: string, correlationId?: string): { ok: true } | { ok: false; reason: string } {
    const decoded = decodeRelayPostReceipt(receiptCbor);
    if (!decoded.ok || !verifyRelayPostReceipt(decoded.receipt, post)) {
      this.#opts.logger.warn("channel.post.deposit_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, relay, reason: "receipt_invalid",
      });
      return { ok: false, reason: "receipt_invalid" };
    }
    try {
      this.#opts.log.recordReceipt(channelHex, decoded.receipt, correlationId);
      // Learn which key answers at this address, so `resendMissing` can tell the two relays apart.
      this.#relayKeys.set(relay, Buffer.from(decoded.receipt.relay_pubkey).toString("hex"));
      return { ok: true };
    } catch (err: unknown) {
      // A receipt naming bytes this log does not hold. The relay DID take the post — the caller
      // reports that separately, because calling the deposit failed would send the operator to
      // resend a post the relay already has.
      this.#opts.logger.warn("channel.post.receipt_unfiled", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, relay, reason: extract(err),
      });
      return { ok: false, reason: extract(err) };
    }
  }

  /**
   * Re-deposit everything a relay has not receipted, oldest first.
   *
   * This is what refills a relay that lost content and what fills a newly added one — the same path,
   * which is why it is exercised by ordinary operation rather than only by a crash.
   */
  async resendMissing(agentName: string, channelHex: string, relay: string, correlationId?: string): Promise<{ deposited: number }> {
    const { log, logger } = this.#opts;
    const head = log.head(channelHex);
    if (head.first_seq === null || head.last_seq === null) return { deposited: 0 };

    /**
     * ⚠️ WHAT THE RELAY HOLDS NOW, NOT WHAT IT ONCE RECEIPTED — and this is a deviation from the
     * order, raised there.
     *
     * The order says to deposit "every logged post that relay has not receipted". But a receipt
     * proves the relay TOOK the post once, not that it still has it — and the case the same sentence
     * names, "refills a relay that lost content", is precisely a relay whose receipts are all in the
     * log and whose queue is empty. Skipping on receipts refills nothing, which the enforcer caught:
     * a restarted relay got 3 posts back out of 6.
     *
     * So the relay is asked where its queue begins and ends, and anything outside that is sent. When
     * it cannot be asked, every logged post is sent — a repeat is a no-op the relay answers with the
     * receipt it already signed, so the cost of over-sending is bandwidth and the cost of
     * under-sending is a relay permanently missing posts.
     */
    let holds: { first: number; last: number } | null = null;
    if (this.#opts.relayHead) {
      try {
        const reported = await this.#opts.relayHead(relay, channelHex);
        if (reported.first_held_seq !== null && reported.last_seq !== null) {
          holds = { first: reported.first_held_seq, last: reported.last_seq };
        }
      } catch (err: unknown) {
        logger.warn("channel.resend.head_unavailable", {
          channel_pubkey: channelHex, relay, reason: extract(err),
          impact: "every logged post is re-sent; a repeat is a no-op at the relay",
        });
      }
    }

    let deposited = 0;
    // Oldest first: a relay's queue only accepts the next number, so any other order stalls at the
    // first gap and refills nothing after it.
    for (const post of log.readRange(channelHex, head.first_seq, head.last_seq)) {
      if (holds !== null && post.seq >= holds.first && post.seq <= holds.last) continue;
      // PACED. A refill of a long backbone is the one path that deposits hundreds of posts in a
      // row, and the relay rate-limits per publisher — so an unpaced refill trips the limiter part
      // way through and the rest of the backlog is refused, which looks exactly like a relay that
      // will not take the channel's posts at all.
      if (deposited > 0) await this.#pause(this.#opts.resendPaceMs ?? DEFAULT_RESEND_PACE_MS);
      const outcome = await this.#depositOnce(relay, post, channelHex, correlationId);
      if (outcome.ok) deposited += 1;
    }
    logger.info("channel.resend.completed", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, relay, deposited,
    });
    return { deposited };
  }

  /**
   * Prune the log, then tell both relays to drop the same range.
   *
   * ⚠️ **EACH RELAY'S OUTCOME IS THE ONE IT GAVE.** This used to report `ok: true` for every relay
   * without contacting any of them, so an operator pruning 500 posts was shown two successful
   * relays while both still held and served every post. A relay that is down is `ok: false` with its
   * reason, and its copy survives until its own retention sweeps it — which is what retention is for.
   */
  async pruneChannel(agentName: string, channelHex: string, throughSeq: number, correlationId?: string): Promise<{
    pruned: number; relays: Array<{ relay: string; ok: boolean; reason?: string }>;
  }> {
    const { logger } = this.#opts;
    const { pruned } = this.#opts.log.pruneThrough(channelHex, throughSeq);
    const info = this.#opts.channelInfo(channelHex);
    const relays = info?.relays ?? [];

    /**
     * ⚠️ THE PRUNE IS SIGNED BY THE CHANNEL KEY, and it has to be: the frame is not a post, so
     * nothing else proves the caller owns the channel. An unsigned prune would let anyone who knows
     * a channel's public key delete its backbone from both relays.
     */
    const channelKey = this.#opts.getChannelKey(channelHex);
    const timeMs = this.#now();
    const signature = channelKey
      ? await channelKey.sign(buildChannelPruneTbs(Buffer.from(channelHex, "hex"), throughSeq, timeMs))
      : null;

    const outcomes = await Promise.all(relays.map(async (relay) => {
      if (!this.#opts.prune || signature === null) {
        // No seam wired, or no key to sign with, is not a successful prune. Say which it was.
        return { relay, ok: false, reason: signature === null ? "key_unavailable" : "relay_prune_unavailable" };
      }
      try {
        const answer = await this.#opts.prune(relay, { channelHex, throughSeq, timeMs, signature });
        if (!answer.ok) {
          logger.warn("channel.prune.relay_refused", {
            ...(correlationId !== undefined ? { correlationId } : {}),
            channel_pubkey: channelHex, relay, through_seq: throughSeq, reason: answer.reason,
          });
          return { relay, ok: false, reason: answer.reason };
        }
        return { relay, ok: true };
      } catch (err: unknown) {
        logger.warn("channel.prune.relay_unreachable", {
          ...(correlationId !== undefined ? { correlationId } : {}),
          channel_pubkey: channelHex, relay, through_seq: throughSeq, reason: extract(err),
        });
        return { relay, ok: false, reason: extract(err) };
      }
    }));

    logger.info("channel.log.pruned", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, through_seq: throughSeq, pruned,
      relays_pruned: outcomes.filter((o) => o.ok).map((o) => o.relay),
      relays_still_holding: outcomes.filter((o) => !o.ok).map((o) => o.relay),
    });
    return { pruned, relays: outcomes };
  }

  /**
   * Sign and deposit the channel's info record. Only the CHANNEL key signs it.
   *
   * ⚠️ **THE DEPOSIT IS THE POINT, NOT THE SIGNATURE.** The record is the only way a subscriber
   * learns a channel's relays, access and admin key. This used to sign it, log
   * `channel.info.published` and return the bytes to the caller without contacting a relay — so an
   * operator was told their channel was published while no one could find it. The event now names
   * only the relays that actually took it.
   */
  async publishInfo(agentName: string, channelHex: string, correlationId?: string): Promise<
    | { ok: true; info_cbor: Uint8Array; relays: Array<{ relay: string; ok: boolean; reason?: string }> }
    | { ok: false; reason: PublishRefusal; detail?: string }
  > {
    const { logger } = this.#opts;
    const info = this.#opts.channelInfo(channelHex);
    const channelKey = this.#opts.getChannelKey(channelHex);
    const agentKey = this.#opts.getAgentKey(agentName);
    if (!info) return { ok: false, reason: "channel_unknown" };
    if (!channelKey || !agentKey) return { ok: false, reason: "key_unavailable" };

    const record = await signChannelInfo(channelKey, {
      access: info.access,
      admin_pubkey: await agentKey.getPublicKey(),
      relays: info.relays,
      guidance: info.guidance,
      retention_seconds: info.retention_seconds,
      updated_at: this.#now(),
      ext: null,
    });
    const info_cbor = encodeChannelInfo(record);

    const outcomes = await Promise.all(info.relays.map(async (relay) => {
      try {
        const answer = await this.#opts.depositInfo(relay, { info_cbor });
        if (!answer.ok) return { relay, ok: false, reason: answer.reason };
        return { relay, ok: true };
      } catch (err: unknown) {
        return { relay, ok: false, reason: extract(err) };
      }
    }));

    const took = outcomes.filter((o) => o.ok);
    if (took.length === 0) {
      logger.warn("channel.info.deposit_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex,
        reasons: outcomes.map((o) => o.reason ?? "unknown"),
      });
      return { ok: false, reason: "no_relay_accepted", detail: outcomes.map((o) => `${o.relay}: ${o.reason ?? "unknown"}`).join("; ") };
    }
    logger.info("channel.info.published", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, access: info.access,
      relays_ok: took.map((o) => o.relay),
      relays_failed: outcomes.filter((o) => !o.ok).map((o) => o.relay),
    });
    return { ok: true, info_cbor, relays: outcomes };
  }

  /**
   * Has this RELAY receipted this post?
   *
   * ⚠️ A receipt names the relay's KEY; a relay list names ADDRESSES. Nothing in the stored receipt
   * says which address it came from, so the two are joined by what this process has observed: every
   * accepted deposit teaches it that address → key. Until that is learned, a post is treated as NOT
   * delivered there — the conservative direction, because a redundant re-deposit is a no-op the
   * relay answers with the receipt it already signed, while wrongly skipping one leaves a relay
   * permanently missing a post.
   *
   * The mapping is in memory and does not survive a restart; the RECEIPTS do, and the first
   * successful deposit after a restart relearns the key. 019, which records the relay set properly,
   * is where this stops being inferred.
   */
  /**
   * address → relay pubkey, learned from the receipts this process has accepted.
   *
   * Kept because it is what lets an operator surface say WHICH relay signed a post's receipt; the
   * resend no longer consults it, for the reason recorded there — a receipt says a relay took a
   * post once, not that it still holds it.
   */
  readonly #relayKeys = new Map<string, string>();

  /** The relays this channel publishes to, so a caller can refill all of them without naming one. */
  relaysFor(channelHex: string): string[] {
    return this.#opts.channelInfo(channelHex)?.relays ?? [];
  }

  /** The pacing gap between refill deposits. Its own method so a test can drive it to zero. */
  #pause(ms: number): Promise<void> {
    if (ms <= 0) return Promise.resolve();
    return new Promise((resolve) => { setTimeout(resolve, ms); });
  }

  /** The relay key observed at an address, or null if this process has not seen one answer yet. */
  relayKeyAt(relay: string): string | null {
    return this.#relayKeys.get(relay) ?? null;
  }
}

function extract(err: unknown): string {
  if (err instanceof Error) return err.message;
  const m = (err as { message?: unknown } | null)?.message;
  return typeof m === "string" ? m : JSON.stringify(err);
}
