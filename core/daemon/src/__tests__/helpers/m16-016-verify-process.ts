/**
 * M16 016-CLIENTREWORK enforcer, PROCESS B: open the same encrypted DB a separate process wrote,
 * verify every post and every receipt, and print the head.
 *
 * It is handed the channel's pubkey and nothing else: every key it verifies against comes out of
 * the stored bytes, so a log that stored something other than what was signed fails here.
 *
 * Usage: node --import tsx m16-016-verify-process.ts <dbPath> <channelPubkeyHex>
 * Prints one JSON line to stdout: { posts, receipts, head, all_verified }.
 */
import { verifyBroadcastArtifact, verifyRelayPostReceipt } from "@cello-protocol/protocol-types";
import { openTestDb } from "./encrypted-db.js";
import { extractErrorMessage } from "../../error-message.js";
import { ChannelLogStore } from "../../channel-log-store.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

function main(): void {
  const [dbPath, channelHex] = process.argv.slice(2);
  if (!dbPath || !channelHex) throw new Error("usage: m16-016-verify-process.ts <dbPath> <channelPubkeyHex>");

  const db = openTestDb(dbPath);
  try {
    const store = new ChannelLogStore(db, silent);
    const head = store.head(channelHex);
    const posts = store.readRange(channelHex, 1, Number.MAX_SAFE_INTEGER);

    const failures: string[] = [];
    let receipts = 0;
    for (const post of posts) {
      const verdict = verifyBroadcastArtifact(post);
      if (!verdict.ok) failures.push(`post ${post.seq}: ${verdict.reason}`);
      const stored = store.receiptsFor(channelHex, post.seq);
      if (stored.length === 0) failures.push(`post ${post.seq}: no receipt`);
      for (const receipt of stored) {
        receipts += 1;
        if (!verifyRelayPostReceipt(receipt, post)) failures.push(`receipt for post ${post.seq} does not verify`);
      }
    }

    process.stdout.write(
      JSON.stringify({
        posts: posts.map((p) => ({ seq: p.seq, title: p.title })),
        receipts,
        head,
        failures,
        all_verified: failures.length === 0,
      }) + "\n",
    );
  } finally {
    db.close();
  }
}

try {
  main();
} catch (err: unknown) {
  process.stderr.write(`${extractErrorMessage(err)}\n`);
  process.exit(1);
}
