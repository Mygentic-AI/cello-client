/**
 * M16 016-CLIENTREWORK enforcer, PROCESS A: sign three posts, append them with a relay receipt
 * each, and exit.
 *
 * Runs as its own OS process so the DB is written by one process and read by another — the only
 * shape that proves the log is durable rather than an artifact of one open handle and one cache.
 *
 * Usage: node --import tsx m16-016-publish-process.ts <dbPath>
 * Prints one JSON line to stdout: { channel, agent, relay, seqs }.
 */
import { generateKeypair } from "@cello-protocol/crypto";
import { signBroadcastArtifact, signRelayPostReceipt } from "@cello-protocol/protocol-types";
import { openTestDb } from "./encrypted-db.js";
import { ChannelLogStore } from "../../channel-log-store.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

async function main(): Promise<void> {
  const dbPath = process.argv[2];
  if (!dbPath) throw new Error("usage: m16-016-publish-process.ts <dbPath>");

  const db = openTestDb(dbPath);
  try {
    const channel = generateKeypair();
    const agent = generateKeypair();
    const relay = generateKeypair();
    const channelHex = Buffer.from(await channel.getPublicKey()).toString("hex");

    const store = new ChannelLogStore(db, silent);
    store.ensureChannel(channelHex);

    const seqs: number[] = [];
    for (let i = 0; i < 3; i++) {
      const { seq } = store.nextPosition(channelHex);
      const post = await signBroadcastArtifact(channel, agent, {
        seq,
        published_at: Date.now(),
        title: `enforcer post ${seq}`,
        body: new Uint8Array([seq, 0xaa, 0xbb]),
        supersedes: null,
        ext: null,
      });
      store.append(channelHex, post);
      store.recordReceipt(channelHex, await signRelayPostReceipt(relay, post, Date.now()));
      seqs.push(seq);
    }

    process.stdout.write(
      JSON.stringify({
        channel: channelHex,
        agent: Buffer.from(await agent.getPublicKey()).toString("hex"),
        relay: Buffer.from(await relay.getPublicKey()).toString("hex"),
        seqs,
      }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
