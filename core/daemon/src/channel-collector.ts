/**
 * ChannelCollector — M16 018-PUBCOLLECT, the subscriber half.
 *
 * A channel's two relays are **not coordinated**. Each holds its own queue, they disagree by design
 * — different `first_held_seq`, different `last_seq`, different subsets — and none of that is an
 * error. The subscriber fetches from both and takes the union.
 *
 * ⚠️ **EVERYTHING IS VERIFIED HERE.** Both signatures, the title rules, the size, and that the
 * publishing agent is the admin THIS SUBSCRIBER knows for the channel. A relay's word that a post is
 * good is worth nothing: the relay is a witness, not an authority, and the whole design assumes it
 * may be hostile.
 *
 * ─── Two positions, and why a fetch may only move one ────────────────────────────────────────
 *
 *   delivered_through  how far the daemon has fetched and verified — moved here
 *   processed_through  how far the AGENT has read — never touched here
 *
 * ─── The contiguous run ──────────────────────────────────────────────────────────────────────
 *
 * `delivered_through` advances only across an unbroken run. Holding 1, 2 and 4 leaves it at 2 —
 * because advancing to 4 would mean post 3 is never delivered when it finally arrives, the position
 * having already passed it. The gap is reported instead.
 *
 * ─── Forks ───────────────────────────────────────────────────────────────────────────────────
 *
 * Two different posts at one number means the channel signed both. Both are kept, the fork is
 * reported with both hashes, and the position stops below it. Nothing is resolved automatically:
 * picking one would make whichever relay answered first the arbiter of what the channel said.
 */
import type { Logger } from "./types.js";
import {
  broadcastPostHash,
  decodeBroadcastArtifact,
  validateBroadcastTitle,
  verifyBroadcastArtifact,
  type BroadcastArtifact,
  type ChannelAccess,
} from "@cello-protocol/protocol-types";
import { ChannelInboxStore } from "./channel-inbox-store.js";
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";

/** At most this many agent keys ride a fetch, per the relay's own cap (017). */
const MAX_AGENT_KEYS_PER_FETCH = 32;

export type RelayFetchSeam = (
  relay: string,
  req: {
    channel_pubkey: Uint8Array;
    since_seq: number;
    max_bytes: number;
    auth?: { signature: Uint8Array; time_ms: number };
    agent_pubkeys?: Uint8Array[];
  },
) => Promise<
  | { ok: true; posts: Array<{ seq: number; post_cbor: Uint8Array; receipt_cbor?: Uint8Array }>; first_held_seq: number | null; last_seq: number | null }
  | { ok: false; reason: string }
>;

export interface ChannelCollectorOptions {
  logger: Logger;
  subscriptions: ChannelSubscriptionStore;
  inbox: ChannelInboxStore;
  fetch: RelayFetchSeam;
  /**
   * The fetch-key signature for a non-public channel. `agentId` is first so the member's held group
   * keys can be looked up by identity; `undefined` means no auth (public, or no key held).
   */
  fetchAuth: (agentId: string, access: ChannelAccess, channelHex: string, sinceSeq: number) => Promise<{ signature: Uint8Array; time_ms: number } | undefined>;
  /** Local agent keys to declare for the reader count. Best-effort, and never affects delivery. */
  localAgentKeys: (channelHex: string) => Uint8Array[];
  /** Ask the PUBLISHER to re-deposit a range. It answers by re-depositing, never by sending posts. */
  requestRepair: (agentId: string, channelHex: string, from: number, to: number) => Promise<void>;
  /**
   * M16 032-NOTICES: rung ONCE per collect pass that advances `delivered_through` — never when
   * nothing advanced. Carries the COUNT of posts actually delivered in this pass and the new
   * `through` position. Optional and additive: an omitted callback collects exactly as before.
   *
   * ⚠️ **`count` IS THE POSTS THAT ARRIVED, NOT `after − before` (038-RETESTFIX Part C).** When the
   * relay's floor has moved (an old post pruned), the position jumps ACROSS the pruned seq to the
   * floor, so `after − before` includes positions that were never delivered — the doorbell then said
   * "5 new posts" when 4 were readable (live F37). The count is the number of held posts the position
   * advanced over, which is what the operator can actually read.
   */
  onDelivered?: (agentId: string, channelHex: string, count: number, through: number) => void;
  now?: () => number;
  maxBytesPerFetch?: number;
}

export interface GapReport {
  missing: number[];
  first_held_seq: number;
}

export class ChannelCollector {
  readonly #opts: ChannelCollectorOptions;
  readonly #now: () => number;
  /** Relay-reported `first_held_seq` per channel — the floor below which absence is not a gap. */
  readonly #firstHeld = new Map<string, number>();
  /**
   * Gaps already reported to the publisher, so a survivor is not re-requested every tick.
   *
   * ⚠️ KEYED ON `agentId:channel`, NOT on the channel. Two agents on this daemon can subscribe to
   * the same channel, and one key per channel means the second agent's genuine gap is silently never
   * requested once the first has asked — its posts simply never arrive, with nothing logged.
   */
  readonly #repairRequested = new Map<string, Set<number>>();

  /** The one place the repair key is built, so the two halves cannot drift apart. */
  static #repairKey(agentId: string, channelHex: string): string {
    return `${agentId}:${channelHex}`;
  }

  constructor(opts: ChannelCollectorOptions) {
    this.#opts = opts;
    this.#now = opts.now ?? (() => Date.now());
  }

  /** One pass over one channel: fetch both relays, verify, store, advance. */
  async collectOnce(agentId: string, channelHex: string, correlationId?: string): Promise<void> {
    const { logger, subscriptions, inbox } = this.#opts;
    const sub = subscriptions.get(agentId, channelHex);
    if (!sub || sub.status !== "active") return;

    const since = sub.delivered_through + 1;
    const auth = await this.#opts.fetchAuth(sub.agent_id, sub.access, channelHex, since);
    const agentKeys = this.#opts.localAgentKeys(channelHex).slice(0, MAX_AGENT_KEYS_PER_FETCH);
    const channelPubkey = new Uint8Array(Buffer.from(channelHex, "hex"));

    let lowestFirstHeld: number | null = null;
    for (const relay of sub.relays) {
      let answer: Awaited<ReturnType<RelayFetchSeam>>;
      try {
        answer = await this.#opts.fetch(relay, {
          channel_pubkey: channelPubkey,
          since_seq: since,
          max_bytes: this.#opts.maxBytesPerFetch ?? 4 * 1024 * 1024,
          ...(auth ? { auth } : {}),
          ...(agentKeys.length > 0 ? { agent_pubkeys: agentKeys } : {}),
        });
      } catch (err: unknown) {
        // ⚠️ ONE RELAY DOWN IS NOT A FAILED COLLECTION. The other still has the posts, which is the
        // entire reason a channel publishes to two.
        logger.warn("channel.fetch.failed", {
          ...(correlationId !== undefined ? { correlationId } : {}),
          channel_pubkey: channelHex, relay, reason: extract(err),
        });
        continue;
      }
      if (!answer.ok) {
        logger.warn("channel.fetch.failed", {
          ...(correlationId !== undefined ? { correlationId } : {}),
          channel_pubkey: channelHex, relay, reason: answer.reason,
        });
        continue;
      }

      if (answer.first_held_seq !== null) {
        lowestFirstHeld = lowestFirstHeld === null ? answer.first_held_seq : Math.min(lowestFirstHeld, answer.first_held_seq);
      }

      let stored = 0;
      for (const entry of answer.posts) {
        const post = this.#verify(agentId, channelHex, sub.admin_pubkey, entry.post_cbor, relay, correlationId);
        if (!post) continue;
        const result = inbox.store(agentId, channelHex, post, {
          ...(entry.receipt_cbor ? { receiptCbor: entry.receipt_cbor } : {}),
          fromRelay: relay,
          collectedAt: this.#now(),
        });
        if (result.stored) stored += 1;
      }
      logger.info("channel.fetch.completed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        // `sub` was read BEFORE the fetch, so its position is the one we started from. Naming it
        // `delivered_through` made the log say the position had not moved on every successful
        // collection — the advance happens below, after every relay has been read.
        channel_pubkey: channelHex, relay, count: stored, delivered_through_before: sub.delivered_through,
      });
    }

    if (lowestFirstHeld !== null) this.#firstHeld.set(channelHex, lowestFirstHeld);
    this.#advance(agentId, channelHex, correlationId);
    this.#reportGaps(agentId, channelHex, correlationId);
  }

  /**
   * Verify a post before it is stored, and name the check that failed.
   *
   * The admin check is against the admin THIS SUBSCRIBER knows from its subscription — not against
   * anything the relay said. A relay that swapped a post for one signed by another agent is exactly
   * what this refuses.
   */
  #verify(
    agentId: string, channelHex: string, adminPubkeyHex: string, cbor: Uint8Array, relay: string, correlationId?: string,
  ): BroadcastArtifact | null {
    const drop = (check: string, detail: string): null => {
      this.#opts.logger.warn("channel.post.invalid", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex, relay, check, detail,
      });
      return null;
    };

    const decoded = decodeBroadcastArtifact(cbor);
    if (!decoded.ok) return drop("decode", decoded.reason);
    const post = decoded.artifact;

    if (Buffer.from(post.channel_pubkey).toString("hex") !== channelHex.toLowerCase()) {
      return drop("channel_pubkey", "the post belongs to a different channel");
    }
    const verdict = verifyBroadcastArtifact(post);
    if (!verdict.ok) return drop("signature", verdict.reason);
    const title = validateBroadcastTitle(post.title);
    if (!title.ok) return drop("title", title.detail);
    if (Buffer.from(post.agent_pubkey).toString("hex") !== adminPubkeyHex.toLowerCase()) {
      return drop("admin", "the publishing agent is not the admin this subscriber knows for the channel");
    }
    return post;
  }

  /** Advance over the contiguous run, stopping below any gap and below any fork. */
  #advance(agentId: string, channelHex: string, correlationId?: string): void {
    const { subscriptions, inbox, logger } = this.#opts;
    const sub = subscriptions.get(agentId, channelHex);
    if (!sub) return;

    const held = new Set(inbox.heldSeqs(agentId, channelHex));
    const forked = new Set(inbox.forkedSeqs(agentId, channelHex));
    for (const seq of forked) {
      const versions = inbox.forksFor(agentId, channelHex, seq);
      logger.warn("channel.fork.detected", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        channel_pubkey: channelHex,
        seq,
        // Both hashes, so the publisher can be confronted with exactly what it signed.
        hashes: versions.map((v) => Buffer.from(broadcastPostHash(v)).toString("hex")),
      });
    }

    // Start from the first post this subscriber could possibly hold: either the next one it expects,
    // or the relay's floor when everything below has been pruned away.
    const floor = this.#firstHeld.get(channelHex);
    let next = sub.delivered_through + 1;
    if (floor !== undefined && floor > next && !held.has(next)) next = floor;

    let advanced = sub.delivered_through;
    // 038-RETESTFIX Part C: count the posts actually delivered — one per held position advanced over,
    // never the distance `advanced − delivered_through`, which would include a pruned seq skipped to
    // reach the floor.
    let delivered = 0;
    while (held.has(next) && !forked.has(next)) {
      advanced = next;
      next += 1;
      delivered += 1;
    }
    if (advanced > sub.delivered_through) {
      subscriptions.setDeliveredThrough(agentId, channelHex, advanced);
      // M16 032-NOTICES: the position moved, so posts arrived — ring the doorbell once for the whole
      // pass. `delivered` is how many posts arrived; `advanced` is the new position.
      this.#opts.onDelivered?.(agentId, channelHex, delivered, advanced);
    }
  }

  /**
   * What is missing between the relays' floor and the highest post seen.
   *
   * ⚠️ **BELOW `first_held_seq` IS NEVER A GAP.** Those posts were pruned or aged out on purpose.
   * Reporting them would have every subscriber demand content that no longer exists, for ever.
   */
  gapsFor(agentId: string, channelHex: string): GapReport {
    const { subscriptions, inbox } = this.#opts;
    const sub = subscriptions.get(agentId, channelHex);
    const held = inbox.heldSeqs(agentId, channelHex);
    /**
     * ⚠️ **THE RELAY'S REPORTED FLOOR WINS OUTRIGHT, and is never lowered by anything local.**
     *
     * The floor used to be the minimum of the relay's floor, the lowest post held, and
     * `delivered_through + 1`. Take a relay that pruned 1–4 and serves 5, 6, 7, where post 5 fails
     * verification: nothing is held below 6, `delivered_through` stays 0, and the minimum is 1 — so
     * the subscriber demands posts 1 to 5 from a publisher that pruned four of them months ago, and
     * keeps demanding them for ever. That is precisely what "below the floor is never a gap" forbids.
     *
     * Only when NO relay has reported a floor do the local positions stand in for one.
     */
    const reported = this.#firstHeld.get(channelHex);
    const localCandidates = [held[0], (sub?.delivered_through ?? 0) + 1]
      .filter((n): n is number => typeof n === "number" && n > 0);
    const first_held_seq = reported !== undefined && reported > 0
      ? reported
      : (localCandidates.length > 0 ? Math.min(...localCandidates) : 1);
    if (held.length === 0) return { missing: [], first_held_seq };

    const highest = held[held.length - 1];
    const have = new Set(held);
    const missing: number[] = [];
    for (let seq = first_held_seq; seq < highest; seq++) {
      if (!have.has(seq)) missing.push(seq);
    }
    return { missing, first_held_seq };
  }

  #reportGaps(agentId: string, channelHex: string, correlationId?: string): void {
    const { missing, first_held_seq } = this.gapsFor(agentId, channelHex);
    if (missing.length === 0) return;
    this.#opts.logger.warn("channel.gap.detected", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, missing, first_held_seq,
    });
  }

  /**
   * Repair what is still missing: the OTHER relay first, then the publisher.
   *
   * The other relay is asked first because it costs nothing and usually has it — the two queues
   * disagree by design. The publisher is a last resort and is asked ONCE per gap: a gap that
   * survives both is reported, not re-requested every tick, or a permanently pruned post becomes a
   * permanent request loop.
   */
  async repairGaps(agentId: string, channelHex: string, correlationId?: string): Promise<void> {
    const sub = this.#opts.subscriptions.get(agentId, channelHex);
    if (!sub || sub.status !== "active") return;

    // A fresh pass over both relays is the "ask the other relay" step: whatever either holds now is
    // collected and the gap closes without troubling the publisher.
    await this.collectOnce(agentId, channelHex, correlationId);

    const { missing } = this.gapsFor(agentId, channelHex);
    if (missing.length === 0) return;

    const repairKey = ChannelCollector.#repairKey(agentId, channelHex);
    let asked = this.#repairRequested.get(repairKey);
    if (!asked) {
      asked = new Set<number>();
      this.#repairRequested.set(repairKey, asked);
    }
    const fresh = missing.filter((seq) => !asked.has(seq));
    if (fresh.length === 0) return;

    for (const seq of fresh) asked.add(seq);
    const from = Math.min(...fresh);
    const to = Math.max(...fresh);
    this.#opts.logger.info("channel.repair.requested", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelHex, from, to,
    });
    await this.#opts.requestRepair(agentId, channelHex, from, to);
  }
}

function extract(err: unknown): string {
  if (err instanceof Error) return err.message;
  const m = (err as { message?: unknown } | null)?.message;
  return typeof m === "string" ? m : JSON.stringify(err);
}
