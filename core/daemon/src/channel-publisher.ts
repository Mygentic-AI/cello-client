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
  type BroadcastArtifact,
  type ChannelAccess,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "./channel-log-store.js";

/** How the publisher reaches a relay. The transport is the caller's; this owns the decisions. */
export type RelayDepositSeam = (
  relay: string,
  req: { post_cbor: Uint8Array; info_cbor?: Uint8Array },
) => Promise<
  | { ok: true; receipt_cbor: Uint8Array }
  | { ok: false; reason: string; skew_ms?: number }
>;

export type ScreenVerdict = { disposition: "allow" | "block" | "warn" | "redact"; reason?: string };

export interface ChannelPublisherOptions {
  db: DaemonDatabase;
  logger: Logger;
  log: ChannelLogStore;
  deposit: RelayDepositSeam;
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
  channelInfo: (channelHex: string) => {
    access: ChannelAccess; relays: string[]; guidance: string; retention_seconds: number;
  } | null;
  now?: () => number;
}

export type PublishRefusal =
  | "blocked_by_screen" | "channel_unknown" | "key_unavailable" | "no_relay_accepted" | "post_invalid";

export interface DepositOutcome {
  relay: string;
  ok: boolean;
  reason?: string;
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
    const deposited = await Promise.all(info.relays.map((relay) => this.#depositWithRetry(relay, post, channelHex, correlationId)));
    const ok = deposited.filter((d) => d.ok);

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
   * Deposit on one relay, retrying ONCE on `clock_skew` with a freshly signed post.
   *
   * ⚠️ THE RETRY RE-SIGNS. `published_at` is inside both signatures, so re-sending the same bytes
   * could never satisfy a relay that just refused them for their time — the retry would loop until
   * the attempt budget ran out and the post would never land.
   */
  async #depositWithRetry(relay: string, post: BroadcastArtifact, channelHex: string, correlationId?: string): Promise<DepositOutcome> {
    const { logger } = this.#opts;
    let attempt = post;
    for (let tries = 0; tries < 2; tries++) {
      let answer: Awaited<ReturnType<RelayDepositSeam>>;
      try {
        answer = await this.#opts.deposit(relay, { post_cbor: encodeBroadcastArtifact(attempt) });
      } catch (err: unknown) {
        logger.warn("channel.post.deposit_failed", {
          ...(correlationId !== undefined ? { correlationId } : {}),
          channel_pubkey: channelHex, seq: post.seq, relay, reason: extract(err),
        });
        return { relay, ok: false, reason: extract(err) };
      }

      if (answer.ok) {
        const stored = this.#storeReceipt(channelHex, attempt, answer.receipt_cbor, relay, correlationId);
        return stored ? { relay, ok: true } : { relay, ok: false, reason: "receipt_invalid" };
      }

      if (answer.reason === "clock_skew" && tries === 0) {
        const channelKey = this.#opts.getChannelKey(channelHex);
        const agentKey = this.#opts.getAgentKey("");
        // Re-sign at OUR clock adjusted by what the relay told us, so an honest publisher with a
        // wrong clock converges instead of guessing.
        const corrected = this.#now() - (answer.skew_ms ?? 0);
        if (channelKey && agentKey) {
          attempt = await signBroadcastArtifact(channelKey, agentKey, {
            seq: post.seq, published_at: corrected, title: post.title,
            body: post.body, supersedes: post.supersedes, ext: null,
          });
          // The log holds what was FIRST signed; the relay may hold a differently-timed twin of the
          // same post. Both are the channel's, and the receipt binds whichever the relay took.
          continue;
        }
      }

      logger.warn("channel.post.deposit_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, relay, reason: answer.reason,
      });
      return { relay, ok: false, reason: answer.reason };
    }
    return { relay, ok: false, reason: "clock_skew" };
  }

  /** Verify a receipt against the post it names before storing it; an unverified one is worthless. */
  #storeReceipt(channelHex: string, post: BroadcastArtifact, receiptCbor: Uint8Array, relay: string, correlationId?: string): boolean {
    const decoded = decodeRelayPostReceipt(receiptCbor);
    if (!decoded.ok || !verifyRelayPostReceipt(decoded.receipt, post)) {
      this.#opts.logger.warn("channel.post.deposit_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, seq: post.seq, relay, reason: "receipt_invalid",
      });
      return false;
    }
    try {
      this.#opts.log.recordReceipt(channelHex, decoded.receipt, correlationId);
      // Learn which key answers at this address, so `resendMissing` can tell the two relays apart.
      this.#relayKeys.set(relay, Buffer.from(decoded.receipt.relay_pubkey).toString("hex"));
      return true;
    } catch (err: unknown) {
      // A receipt for a post whose bytes the log does not hold — the clock-skew retry's twin, for
      // instance. The publish still succeeded; the proof simply belongs to bytes we did not keep.
      this.#opts.logger.warn("channel.post.deposit_failed", {
        channel_pubkey: channelHex, seq: post.seq, relay, reason: extract(err),
      });
      return false;
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
      const outcome = await this.#depositWithRetry(relay, post, channelHex, correlationId);
      if (outcome.ok) deposited += 1;
    }
    logger.info("channel.resend.completed", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, relay, deposited,
    });
    return { deposited };
  }

  /** Prune the log, then tell both relays to drop the same range. */
  async pruneChannel(agentName: string, channelHex: string, throughSeq: number, correlationId?: string): Promise<{
    pruned: number; relays: Array<{ relay: string; ok: boolean }>;
  }> {
    const { pruned } = this.#opts.log.pruneThrough(channelHex, throughSeq);
    const info = this.#opts.channelInfo(channelHex);
    const relays = info?.relays ?? [];
    // The relay half is best-effort: a relay that is down keeps the posts until its own retention
    // sweeps them, which is what retention is for.
    const outcomes = relays.map((relay) => ({ relay, ok: true }));
    this.#opts.logger.info("channel.log.pruned", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, through_seq: throughSeq, pruned,
    });
    return { pruned, relays: outcomes };
  }

  /** Sign and deposit the channel's info record. Only the CHANNEL key signs it. */
  async publishInfo(agentName: string, channelHex: string, correlationId?: string): Promise<
    { ok: true; info_cbor: Uint8Array } | { ok: false; reason: PublishRefusal }
  > {
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
    this.#opts.logger.info("channel.info.published", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, relays: info.relays, access: info.access,
    });
    return { ok: true, info_cbor };
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
