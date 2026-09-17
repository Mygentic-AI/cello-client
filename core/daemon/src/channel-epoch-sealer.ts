/**
 * ChannelEpochSealer — M16 008-EPOCH.
 *
 * Until an epoch is sealed and notarized, a channel could hand two subscribers two different
 * message #47s, both validly signed. **The unsealed window IS the window in which a channel can lie**,
 * so how long an epoch may stay open is a security parameter:
 *
 *   - force-sealed 24 hours after its first leaf, or at 1,000 leaves, whichever comes first;
 *   - the publisher may seal earlier at will;
 *   - an epoch with zero leaves never seals;
 *   - a channel may declare a SHORTER cap, never a longer one — a longer one is an error it sees,
 *     not a silent clamp.
 *
 * A seal signs the open epoch's root (003) and is recorded, and the epoch is closed in the log (007),
 * in ONE transaction. The log's close is a compare-and-set, so a publish that lands while the seal is
 * being signed makes the close refuse and the record roll back: no seal ever covers a root the epoch
 * has already moved past. The notarization slot stays null here; order 009 fills it.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeChannelEpochSeal, signChannelEpochSeal } from "@cello-protocol/protocol-types";
import { ChannelLogError, EPOCH_MAX_LEAVES, type ChannelLogStore } from "./channel-log-store.js";
import type { ChannelEpochSealStore } from "./channel-epoch-seal-store.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

export const EPOCH_MAX_AGE_MS = 24 * 60 * 60 * 1000; // protocol maximum
export { EPOCH_MAX_LEAVES }; // protocol maximum; defined beside the append that enforces it

export interface ChannelEpochPolicy { maxAgeMs: number; maxLeaves: number }

export interface SealOutcome {
  sealed: true; epoch_index: number; epoch_root: Uint8Array; leaf_count: number; seal_cbor: Uint8Array;
}
export type SealRefusal = { sealed: false; reason: "epoch_empty" | "channel_unknown" | "key_unavailable" };

type Trigger = "explicit" | "cap_age" | "cap_leaves";

/** Errors the sealer has already logged before rethrowing, so a caller does not log them twice. */
const LOGGED = new WeakSet<object>();
export function sealerAlreadyLogged(err: unknown): boolean {
  return typeof err === "object" && err !== null && LOGGED.has(err);
}

export interface ChannelEpochSealerDeps {
  log: ChannelLogStore;
  sealStore: ChannelEpochSealStore;
  getKeyProvider: (channelPubkeyHex: string) => KeyProvider | null;
  logger: Logger;
  /** Injectable clock. `sealed_at` and the age cap both read it — never Date.now() inline. */
  now: () => number;
}

export class ChannelEpochSealer {
  readonly #deps: ChannelEpochSealerDeps;

  constructor(deps: ChannelEpochSealerDeps) {
    this.#deps = deps;
  }

  /** Fill a declared policy from the protocol maxima; anything larger is an error, not a clamp. */
  static validatePolicy(p: Partial<ChannelEpochPolicy>): ChannelEpochPolicy {
    const maxAgeMs = p.maxAgeMs ?? EPOCH_MAX_AGE_MS;
    const maxLeaves = p.maxLeaves ?? EPOCH_MAX_LEAVES;
    if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1 || maxAgeMs > EPOCH_MAX_AGE_MS) {
      throw new RangeError(`maxAgeMs must be an integer from 1 to ${EPOCH_MAX_AGE_MS} (24 hours); a longer epoch is a longer window in which a channel can equivocate`);
    }
    if (!Number.isSafeInteger(maxLeaves) || maxLeaves < 1 || maxLeaves > EPOCH_MAX_LEAVES) {
      throw new RangeError(`maxLeaves must be an integer from 1 to ${EPOCH_MAX_LEAVES}`);
    }
    return { maxAgeMs, maxLeaves };
  }

  /** Seal now if the open epoch has at least one leaf. */
  sealNow(channelPubkeyHex: string, correlationId: string): Promise<SealOutcome | SealRefusal> {
    return this.#seal(channelPubkeyHex, correlationId, "explicit");
  }

  /** Seals iff leaves >= maxLeaves OR (leaves >= 1 AND now - opened_at >= maxAgeMs). */
  async sealIfDue(
    channelPubkeyHex: string,
    policy: ChannelEpochPolicy,
    correlationId: string,
  ): Promise<SealOutcome | SealRefusal | { sealed: false; reason: "not_due" }> {
    let open: ReturnType<ChannelLogStore["openEpochRoot"]>;
    try {
      open = this.#deps.log.openEpochRoot(channelPubkeyHex);
    } catch (err) {
      if (err instanceof ChannelLogError && err.code === "channel_unknown") return { sealed: false, reason: "channel_unknown" };
      throw err;
    }
    if (open.leaf_count === 0) return { sealed: false, reason: "not_due" };
    if (open.leaf_count >= policy.maxLeaves) return this.#seal(channelPubkeyHex, correlationId, "cap_leaves");
    if (this.#deps.now() - open.opened_at >= policy.maxAgeMs) return this.#seal(channelPubkeyHex, correlationId, "cap_age");
    return { sealed: false, reason: "not_due" };
  }

  async #seal(channelPubkeyHex: string, correlationId: string, trigger: Trigger): Promise<SealOutcome | SealRefusal> {
    const { log, sealStore, getKeyProvider, logger, now } = this.#deps;

    let open: ReturnType<ChannelLogStore["openEpochRoot"]>;
    let position: ReturnType<ChannelLogStore["nextPosition"]>;
    try {
      open = log.openEpochRoot(channelPubkeyHex);
      position = log.nextPosition(channelPubkeyHex);
    } catch (err) {
      if (err instanceof ChannelLogError && err.code === "channel_unknown") return { sealed: false, reason: "channel_unknown" };
      throw err;
    }
    if (open.leaf_count === 0) {
      logger.info("channel.epoch.seal_skipped_empty", { correlationId, channel_pubkey: channelPubkeyHex, epoch_index: position.epoch_index });
      return { sealed: false, reason: "epoch_empty" };
    }

    const kp = getKeyProvider(channelPubkeyHex);
    if (!kp) {
      logger.error("channel.epoch.seal_failed", {
        correlationId, channel_pubkey: channelPubkeyHex, epoch_index: position.epoch_index, reason: "key_unavailable",
        impact: "the open epoch stays open, so its window for equivocation keeps growing until this channel's key is loaded",
      });
      return { sealed: false, reason: "key_unavailable" };
    }

    const seal = await signChannelEpochSeal(kp, {
      epoch_index: position.epoch_index,
      epoch_root: open.root,
      first_seq: open.first_seq,
      leaf_count: open.leaf_count,
      prev_epoch_root: position.prev_epoch_root,
      sealed_at: now(),
    });

    try {
      sealStore.transaction(() => {
        sealStore.record(channelPubkeyHex, seal);
        log.closeEpoch(channelPubkeyHex, seal.epoch_root);
      });
    } catch (err) {
      if (err instanceof ChannelLogError && err.code === "epoch_changed") {
        // The designed compare-and-set refusal on a busy channel, not a fault.
        logger.info("channel.epoch.seal_retry", {
          correlationId, channel_pubkey: channelPubkeyHex, epoch_index: seal.epoch_index, reason: err.code,
          impact: "a publish landed while the seal was being signed; nothing was recorded and the next attempt seals the larger epoch",
        });
      } else {
        const reason = err instanceof ChannelLogError ? err.code : extractErrorMessage(err);
        logger.error("channel.epoch.seal_failed", {
          correlationId, channel_pubkey: channelPubkeyHex, epoch_index: seal.epoch_index, reason,
          impact: "nothing was recorded and the epoch stays open; the next seal attempt covers whatever it holds then",
        });
      }
      if (typeof err === "object" && err !== null) LOGGED.add(err);
      throw err;
    }

    logger.info("channel.epoch.sealed", {
      correlationId,
      channel_pubkey: channelPubkeyHex,
      epoch_index: seal.epoch_index,
      leaf_count: seal.leaf_count,
      first_seq: seal.first_seq,
      trigger,
    });
    return {
      sealed: true,
      epoch_index: seal.epoch_index,
      epoch_root: seal.epoch_root,
      leaf_count: seal.leaf_count,
      seal_cbor: encodeChannelEpochSeal(seal),
    };
  }
}
