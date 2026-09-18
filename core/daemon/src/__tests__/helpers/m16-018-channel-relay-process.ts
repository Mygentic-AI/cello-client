/**
 * M16 018-PUBCOLLECT enforcer — a channel relay in its own OS process.
 *
 * ⚠️ **THIS IS A FIXTURE, NOT THE RELAY, AND THE DIFFERENCE IS RECORDED RATHER THAN GLOSSED.** The
 * real relay is `packages/relay` in trustless-cello, a different repository that this one does not
 * depend on. What this process proves is that the DAEMON's publisher and collector work over real
 * libp2p, from separate processes, against something that speaks 017's wire contract — the two
 * relays disagreeing, one dying mid-run, a refill afterwards. What it cannot prove is the relay's
 * own behaviour, which is 017's enforcer's job and was proven there against the real binary.
 *
 * The wire contract mirrored here (authoritative: `packages/relay/src/channel-protocol.ts`):
 *   channel_deposit → channel_deposit_ok { receipt_cbor } | channel_deposit_rejected { reason }
 *   channel_fetch   → channel_posts { posts[], first_held_seq, last_seq }
 *   channel_head    → channel_head_result
 *
 * Deliberately NOT mirrored: the identity lookup, the limiters, the reader counts. A fixture that
 * reimplemented those would be a second relay whose agreement with the first nobody checks.
 *
 * Usage: node --import tsx m16-018-channel-relay-process.ts <relaySeedHex> [holdOnlySeqsCsv]
 * Prints one JSON line: { multiaddr, peerId, relayPubkey }. Runs until SIGTERM.
 * `holdOnlySeqsCsv` makes this relay REFUSE the listed post numbers, so a test can withhold a post
 * from one relay and watch the subscriber get it from the other.
 */
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import {
  decodeBroadcastArtifact,
  encodeRelayPostReceipt,
  signRelayPostReceipt,
  verifyBroadcastArtifact,
} from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";

const CHANNEL_PROTOCOL_ID = "/cello/channel/1.0.0";
const CBOR_ENC = new Encoder({ tagUint8Array: false, useRecords: false });

function toU8(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  const c = chunk as { subarray?: () => Uint8Array };
  return typeof c?.subarray === "function" ? c.subarray() : new Uint8Array(chunk as ArrayBufferLike);
}

async function main(): Promise<void> {
  const [relaySeedHex, withheldCsv] = process.argv.slice(2);
  if (!relaySeedHex) throw new Error("usage: m16-018-channel-relay-process.ts <relaySeedHex> [withheldSeqsCsv]");

  const relayKey = new InMemoryKeyProvider(new Uint8Array(Buffer.from(relaySeedHex, "hex")));
  const withheld = new Set((withheldCsv ?? "").split(",").filter((s) => s.length > 0).map(Number));

  /** channelHex → seq → { post, receipt } */
  const queues = new Map<string, Map<number, { post: Uint8Array; receipt: Uint8Array }>>();

  const node = await createNode({ listenAddresses: ["/ip4/127.0.0.1/tcp/0"], keyProvider: relayKey });
  await node.start();

  await node.handle(CHANNEL_PROTOCOL_ID, (stream: Stream) => {
    void (async () => {
      try {
        const iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]();
        const res = await iter.next();
        if (res.done || res.value === undefined) return;
        const frame = decode(toU8(res.value)) as Record<string, unknown>;
        const answer = await handle(frame);
        stream.send(lp.encode.single(CBOR_ENC.encode(answer)));
      } catch (err: unknown) {
        process.stderr.write(`${err instanceof Error ? err.message : JSON.stringify(err)}\n`);
      } finally {
        await stream.close().catch(() => { /* going away */ });
      }
    })();
  }, { maxInboundStreams: 256 });

  async function handle(frame: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (frame["type"] === "channel_deposit") {
      const postCbor = frame["post_cbor"];
      if (!(postCbor instanceof Uint8Array)) return { type: "channel_deposit_rejected", reason: "bad_post" };
      const decoded = decodeBroadcastArtifact(postCbor);
      if (!decoded.ok) return { type: "channel_deposit_rejected", reason: "bad_post" };
      const post = decoded.artifact;
      // Both signatures, as the real relay does — the one check a fixture must not skip, because the
      // publisher's whole claim is that what it sends verifies.
      if (!verifyBroadcastArtifact(post).ok) return { type: "channel_deposit_rejected", reason: "signature_invalid" };
      if (withheld.has(post.seq)) return { type: "channel_deposit_rejected", reason: "queue_full" };

      const channelHex = Buffer.from(post.channel_pubkey).toString("hex");
      let queue = queues.get(channelHex);
      if (!queue) {
        queue = new Map();
        queues.set(channelHex, queue);
      }
      const held = queue.get(post.seq);
      if (held) {
        // A re-deposit is a no-op answered with the receipt already signed — what a refill runs on.
        return { type: "channel_deposit_ok", receipt_cbor: held.receipt, seq: post.seq };
      }
      const receipt = encodeRelayPostReceipt(await signRelayPostReceipt(relayKey, post, Date.now()));
      queue.set(post.seq, { post: postCbor, receipt });
      return { type: "channel_deposit_ok", receipt_cbor: receipt, seq: post.seq };
    }

    if (frame["type"] === "channel_fetch") {
      const channelPubkey = frame["channel_pubkey"];
      const sinceSeq = frame["since_seq"];
      if (!(channelPubkey instanceof Uint8Array) || typeof sinceSeq !== "number") {
        return { type: "channel_fetch_rejected", reason: "bad_frame" };
      }
      const queue = queues.get(Buffer.from(channelPubkey).toString("hex")) ?? new Map();
      const seqs = [...queue.keys()].sort((a, b) => a - b);
      const posts = seqs.filter((s) => s >= sinceSeq).map((s) => ({
        seq: s, post_cbor: queue.get(s)!.post, receipt_cbor: queue.get(s)!.receipt,
      }));
      return {
        type: "channel_posts",
        posts,
        first_held_seq: seqs.length > 0 ? seqs[0] : null,
        last_seq: seqs.length > 0 ? seqs[seqs.length - 1] : null,
      };
    }

    if (frame["type"] === "channel_head") {
      const channelPubkey = frame["channel_pubkey"];
      const queue = channelPubkey instanceof Uint8Array
        ? queues.get(Buffer.from(channelPubkey).toString("hex")) ?? new Map()
        : new Map();
      const seqs = [...queue.keys()].sort((a, b) => a - b);
      return {
        type: "channel_head_result",
        first_held_seq: seqs.length > 0 ? seqs[0] : null,
        last_seq: seqs.length > 0 ? seqs[seqs.length - 1] : null,
      };
    }

    return { type: "channel_frame_rejected", reason: "unknown_frame_type" };
  }

  process.stdout.write(
    JSON.stringify({
      multiaddr: node.listenAddresses()[0],
      peerId: node.getPeerId(),
      relayPubkey: Buffer.from(await relayKey.getPublicKey()).toString("hex"),
    }) + "\n",
  );

  const stop = (): void => { void node.stop().then(() => process.exit(0), () => process.exit(1)); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : JSON.stringify(err)}\n`);
  process.exit(1);
});
