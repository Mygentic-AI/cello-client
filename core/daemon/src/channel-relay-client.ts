/**
 * M16 018-PUBCOLLECT — the daemon's client for the relay's channel protocol.
 *
 * Speaks `/cello/channel/1.0.0` (defined by order 017) over length-prefixed CBOR: one logical
 * request per stream, dial-then-`newStream`, exactly as `content-park-client.ts` does for the park
 * protocol. It owns the transport and nothing else — every decision about what to publish, what to
 * believe and what to store belongs to the publisher and the collector.
 *
 * ⚠️ **A DIAL FAILURE AND A REFUSAL ARE DIFFERENT ANSWERS, and the caller branches on both.** A
 * relay that cannot be reached is not a relay that said no: the first is survivable by the other
 * relay and retried later, the second is a verdict about the post. Collapsing them would make an
 * unreachable relay look like a rejection of the content.
 *
 * ⚠️ The transport rejects with PLAIN OBJECT LITERALS carrying `reason`, not Errors — `String(err)`
 * on one prints "[object Object]". Its own reason is preserved rather than overwritten with a
 * generic one; `content-park-client.ts` records what discarding it cost.
 */
import * as lp from "it-length-prefixed";
import type { Stream } from "@libp2p/interface";
import type { CelloNode } from "@cello-protocol/transport";
import { encodeCbor, decodeCbor } from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";

export const CHANNEL_PROTOCOL_ID = "/cello/channel/1.0.0";

/**
 * ⚠️ THE SHARED ENCODER, NOT A LOCAL ONE. `no-multiple-cbor-encoders.test.ts` exists because a
 * locally-constructed cbor-x encoder was copy-pasted into fourteen files and two of them used
 * cbor-x's bare `encode` instead — writing tag-64 typed arrays into the same columns the others
 * wrote as raw bytes. cbor-x reads both, so the corruption was invisible until a non-cbor-x reader
 * touched it. This file built its own anyway; the guard caught it.
 *
 * (The guard is a text scan, so it fires on a comment that spells the forbidden call out too. That
 * is the right trade — a scanner that skipped comments would miss a commented-out one.)
 */

function toU8(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  const c = chunk as { subarray?: () => Uint8Array };
  return typeof c?.subarray === "function" ? c.subarray() : new Uint8Array(chunk as ArrayBufferLike);
}

function reasonOf(err: unknown): string {
  if (err !== null && typeof err === "object" && typeof (err as { reason?: unknown }).reason === "string") {
    return (err as { reason: string }).reason;
  }
  if (err instanceof Error) return err.message;
  const m = (err as { message?: unknown } | null)?.message;
  return typeof m === "string" ? m : "relay_unreachable";
}

export interface ChannelRelayClientOptions {
  getNode: () => CelloNode | null;
  logger: Logger;
}

export class ChannelRelayClient {
  readonly #opts: ChannelRelayClientOptions;

  constructor(opts: ChannelRelayClientOptions) {
    this.#opts = opts;
  }

  /**
   * One request, one stream. THROWS when the relay could not be reached at all, and RESOLVES with
   * whatever the relay said otherwise — including a refusal, which is an answer.
   */
  async request(relayAddr: string, frame: Record<string, unknown>): Promise<Record<string, unknown>> {
    const node = this.#opts.getNode();
    if (node === null) throw new Error("node_stopped");

    let peerId: string;
    try {
      ({ peerId } = await node.dial(relayAddr));
    } catch (err: unknown) {
      throw new Error(reasonOf(err));
    }

    let stream: Stream;
    try {
      stream = await node.newStream(peerId, CHANNEL_PROTOCOL_ID);
    } catch (err: unknown) {
      // `protocol_not_supported` here means the relay is not carrying channels — a real and
      // distinguishable condition, not a refusal of this post.
      throw new Error(reasonOf(err));
    }

    try {
      stream.send(lp.encode.single(encodeCbor(frame)));
      const iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]();
      const res = await iter.next();
      if (res.done || res.value === undefined) throw new Error("relay_closed_without_answering");
      const answer = decodeCbor(toU8(res.value)) as unknown;
      if (typeof answer !== "object" || answer === null || Array.isArray(answer)) {
        throw new Error("relay_answer_malformed");
      }
      return answer as Record<string, unknown>;
    } finally {
      await stream.close().catch(() => { /* the stream is going away; the answer is already read */ });
    }
  }

  /** Deposit one post. A refusal comes back as `{ ok: false, reason }`, never as a throw. */
  async deposit(relayAddr: string, req: { post_cbor: Uint8Array; fetch_key?: { pubkey: Uint8Array; time_ms: number; signature: Uint8Array } }): Promise<
    { ok: true; receipt_cbor: Uint8Array } | { ok: false; reason: string; skew_ms?: number }
  > {
    const answer = await this.request(relayAddr, {
      type: "channel_deposit",
      post_cbor: req.post_cbor,
      ...(req.fetch_key ? { fetch_key: req.fetch_key } : {}),
    });
    if (answer["type"] === "channel_deposit_ok" && answer["receipt_cbor"] instanceof Uint8Array) {
      return { ok: true, receipt_cbor: answer["receipt_cbor"] };
    }
    return {
      ok: false,
      reason: typeof answer["reason"] === "string" ? answer["reason"] : "unexpected_answer",
      ...(typeof answer["skew_ms"] === "number" ? { skew_ms: answer["skew_ms"] } : {}),
    };
  }

  /** Fetch from a post number. The caller verifies everything that comes back. */
  async fetch(relayAddr: string, req: {
    channel_pubkey: Uint8Array; since_seq: number; max_bytes: number;
    auth?: { signature: Uint8Array; time_ms: number }; agent_pubkeys?: Uint8Array[];
    /** 043-POSTERS: a poster's lane; absent = the admin lane. */
    lane_poster?: Uint8Array;
  }): Promise<
    | { ok: true; posts: Array<{ seq: number; post_cbor: Uint8Array; receipt_cbor?: Uint8Array }>; first_held_seq: number | null; last_seq: number | null }
    | { ok: false; reason: string }
  > {
    const answer = await this.request(relayAddr, {
      type: "channel_fetch",
      channel_pubkey: req.channel_pubkey,
      since_seq: req.since_seq,
      max_bytes: req.max_bytes,
      ...(req.auth ? { auth: req.auth } : {}),
      ...(req.agent_pubkeys ? { agent_pubkeys: req.agent_pubkeys } : {}),
      ...(req.lane_poster ? { lane_poster: req.lane_poster } : {}),
    });
    if (answer["type"] !== "channel_posts" || !Array.isArray(answer["posts"])) {
      return { ok: false, reason: typeof answer["reason"] === "string" ? answer["reason"] : "unexpected_answer" };
    }
    const posts: Array<{ seq: number; post_cbor: Uint8Array; receipt_cbor?: Uint8Array }> = [];
    for (const raw of answer["posts"] as Array<Record<string, unknown>>) {
      const seq = raw["seq"];
      const postCbor = raw["post_cbor"];
      // A malformed entry is skipped rather than failing the whole fetch: the other posts in the
      // batch are still good, and the collector verifies each one anyway.
      if (typeof seq !== "number" || !(postCbor instanceof Uint8Array)) continue;
      posts.push({
        seq,
        post_cbor: postCbor,
        ...(raw["receipt_cbor"] instanceof Uint8Array ? { receipt_cbor: raw["receipt_cbor"] } : {}),
      });
    }
    return {
      ok: true,
      posts,
      first_held_seq: typeof answer["first_held_seq"] === "number" ? answer["first_held_seq"] : null,
      last_seq: typeof answer["last_seq"] === "number" ? answer["last_seq"] : null,
    };
  }

  /** 043-POSTERS: the poster lanes a relay holds for a channel, each with its newest seq. */
  async lanes(relayAddr: string, req: {
    channel_pubkey: Uint8Array; auth?: { signature: Uint8Array; time_ms: number };
  }): Promise<{ ok: true; lanes: Array<{ poster_pubkey: Uint8Array; last_seq: number }> } | { ok: false; reason: string }> {
    const answer = await this.request(relayAddr, {
      type: "channel_lanes", channel_pubkey: req.channel_pubkey, ...(req.auth ? { auth: req.auth } : {}),
    });
    if (answer["type"] !== "channel_lanes_result" || !Array.isArray(answer["lanes"])) {
      return { ok: false, reason: typeof answer["reason"] === "string" ? answer["reason"] : "unexpected_answer" };
    }
    const lanes: Array<{ poster_pubkey: Uint8Array; last_seq: number }> = [];
    for (const raw of answer["lanes"] as Array<Record<string, unknown>>) {
      const pk = raw["poster_pubkey"];
      const last = raw["last_seq"];
      // A malformed entry names no lane we could fetch; the others are still good.
      if (!(pk instanceof Uint8Array) || pk.length !== 32 || typeof last !== "number") continue;
      lanes.push({ poster_pubkey: pk, last_seq: last });
    }
    return { ok: true, lanes };
  }

  /** Where a relay's queue begins and ends, without pulling any posts. */
  async head(relayAddr: string, channelPubkey: Uint8Array): Promise<{ first_held_seq: number | null; last_seq: number | null }> {
    const answer = await this.request(relayAddr, { type: "channel_head", channel_pubkey: channelPubkey });
    return {
      first_held_seq: typeof answer["first_held_seq"] === "number" ? answer["first_held_seq"] : null,
      last_seq: typeof answer["last_seq"] === "number" ? answer["last_seq"] : null,
    };
  }

  /**
   * Deposit the channel's info record. No receipt: the record carries no post number, so there is
   * nothing for a relay to order or countersign — it either holds the latest one or it does not.
   */
  async depositInfo(relayAddr: string, req: { info_cbor: Uint8Array }): Promise<{ ok: true } | { ok: false; reason: string }> {
    const answer = await this.request(relayAddr, { type: "channel_info_set", info_record: req.info_cbor });
    if (answer["type"] === "channel_info_set_ok") return { ok: true };
    return { ok: false, reason: typeof answer["reason"] === "string" ? answer["reason"] : "unexpected_answer" };
  }

  /** Ask a relay to drop everything through a post number. Oldest end only — the relay enforces that. */
  async prune(relayAddr: string, req: { channel_pubkey: Uint8Array; through_seq: number; time_ms: number; signature: Uint8Array }): Promise<
    { ok: true; dropped?: number } | { ok: false; reason: string }
  > {
    const answer = await this.request(relayAddr, {
      type: "channel_prune",
      channel_pubkey: req.channel_pubkey,
      through_seq: req.through_seq,
      time_ms: req.time_ms,
      signature: req.signature,
    });
    // `pruned` is the relay's own field name for how many it dropped — read it as sent.
    if (answer["type"] === "channel_prune_ok") {
      return { ok: true, ...(typeof answer["pruned"] === "number" ? { dropped: answer["pruned"] } : {}) };
    }
    return { ok: false, reason: typeof answer["reason"] === "string" ? answer["reason"] : "unexpected_answer" };
  }

  /** 045-NOTICEBELL: deposit one sealed channel notice. A refusal is `{ ok: false, reason }`. */
  async depositNotice(relayAddr: string, record: Uint8Array): Promise<{ ok: true } | { ok: false; reason: string }> {
    const answer = await this.request(relayAddr, { type: "channel_notice_set", record });
    if (answer["type"] === "channel_notice_set_ok") return { ok: true };
    return { ok: false, reason: typeof answer["reason"] === "string" ? answer["reason"] : "unexpected_answer" };
  }

  /** 045-NOTICEBELL: the sealed notice this relay holds at a slot, or null. */
  async getNotice(relayAddr: string, slot: Uint8Array): Promise<Uint8Array | null> {
    const answer = await this.request(relayAddr, { type: "channel_notice_get", slot });
    return answer["record"] instanceof Uint8Array ? answer["record"] : null;
  }

  /** The channel's info record as this relay holds it, or null. */
  async info(relayAddr: string, channelPubkey: Uint8Array): Promise<Uint8Array | null> {
    const answer = await this.request(relayAddr, { type: "channel_info", channel_pubkey: channelPubkey });
    return answer["info_record"] instanceof Uint8Array ? answer["info_record"] : null;
  }
}
