/**
 * M16 019-MEMBERSHIP enforcer — ONE MEMBER, in its own OS process.
 *
 * Reads a channel from two relays over real libp2p, using only what it was given at join time: the
 * group keys it holds and the fetch key derived from them. Separate processes are the point — the
 * ejected member must be a different process holding a different database, so "it cannot read" is
 * not an artifact of one heap knowing too much.
 *
 * Usage:
 *   node --import tsx m16-019-member-process.ts <dbPath> <agentId> <channelHex> <adminHex>
 *                                               <memberSeedHex> <relayA> <relayB> <keysJson>
 *
 * `keysJson` is `[{ generation, keyHex }]` — the generations this member holds. An ejected member
 * is simply run with the OLD list, which is exactly its real position.
 *
 * Prints one JSON line: { fetched, decrypted, refusals } where
 *   fetched    post numbers the relays were willing to hand over
 *   decrypted  post numbers this member could actually read
 *   refusals   the reason each relay gave, when it gave one
 */
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { decodeBroadcastArtifact, buildChannelFetchAuthTbs } from "@cello-protocol/protocol-types";
import { decryptBody, deriveFetchKey, type GroupKey } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { ChannelRelayClient } from "../../channel-relay-client.js";
import { extractErrorMessage } from "../../error-message.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

async function main(): Promise<void> {
  const [, agentId, channelHex, , memberSeedHex, relayA, relayB, keysJson] = process.argv.slice(2);
  if (!agentId || !channelHex || !memberSeedHex || !relayA || !relayB || !keysJson) {
    throw new Error("usage: m16-019-member-process.ts <dbPath> <agentId> <channelHex> <adminHex> <memberSeedHex> <relayA> <relayB> <keysJson>");
  }

  const keys: GroupKey[] = (JSON.parse(keysJson) as Array<{ generation: number; keyHex: string }>)
    .map((k) => ({ generation: k.generation, key: new Uint8Array(Buffer.from(k.keyHex, "hex")) }));

  const member = new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberSeedHex, "hex")));
  const node = await createNode({
    listenAddresses: [], keyProvider: member,
    relayServer: { enabled: false }, autonatResponder: { enabled: false },
  });
  await node.start();

  const client = new ChannelRelayClient({ getNode: () => node, logger: silent });
  const channelPubkey = new Uint8Array(Buffer.from(channelHex, "hex"));

  /**
   * ⚠️ SIGNED WITH THE NEWEST KEY THIS MEMBER HOLDS. An ejected member's newest is the generation
   * before the re-key, so this signature no longer matches what the relays were told to require —
   * which is the whole mechanism, and it fails at the RELAY, before any ciphertext moves.
   */
  const newest = [...keys].sort((a, b) => b.generation - a.generation)[0];
  const fetchKey = newest ? await deriveFetchKey(newest, channelPubkey) : null;

  const fetched = new Set<number>();
  const decrypted = new Set<number>();
  const refusals: string[] = [];

  for (const relay of [relayA, relayB]) {
    const timeMs = Date.now();
    const auth = fetchKey
      ? { signature: await fetchKey.sign(buildChannelFetchAuthTbs(channelPubkey, 1, timeMs)), time_ms: timeMs }
      : undefined;
    let answer;
    try {
      answer = await client.fetch(relay, {
        channel_pubkey: channelPubkey, since_seq: 1, max_bytes: 1024 * 1024,
        ...(auth ? { auth } : {}),
      });
    } catch (err: unknown) {
      refusals.push(extractErrorMessage(err));
      continue;
    }
    if (!answer.ok) {
      refusals.push(answer.reason);
      continue;
    }
    for (const entry of answer.posts) {
      fetched.add(entry.seq);
      const post = decodeBroadcastArtifact(entry.post_cbor);
      if (!post.ok) continue;
      // The bodies are encrypted under a generation this member may or may not hold. `unknown_generation`
      // is the answer for a member who missed a re-key, and it is NOT an error.
      const opened = decryptBody(keys, channelPubkey, entry.seq, post.artifact.body);
      if (opened.ok) decrypted.add(entry.seq);
    }
  }

  process.stdout.write(`${JSON.stringify({
    fetched: [...fetched].sort((a, b) => a - b),
    decrypted: [...decrypted].sort((a, b) => a - b),
    refusals,
  })}\n`);
  await node.stop();
}

main().catch((err: unknown) => {
  process.stderr.write(`${extractErrorMessage(err)}\n`);
  process.exit(1);
});
