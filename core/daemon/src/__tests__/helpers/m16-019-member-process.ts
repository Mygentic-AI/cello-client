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
 * `keysJson` is `[bundleHex]` — the WRAPPED key bundles this member was actually sent by the admin,
 * unwrapped here with its own identity key. Handing over raw keys instead would have skipped the
 * wrapping the join exists to perform. An ejected member is simply run with the bundles it received
 * BEFORE the ejection, which is exactly its real position.
 *
 * Prints one JSON line: { fetched, decrypted, refusals } where
 *   fetched    post numbers the relays were willing to hand over
 *   decrypted  post numbers this member could actually read
 *   refusals   the reason each relay gave, when it gave one
 */
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { decodeBroadcastArtifact, buildChannelFetchAuthTbs } from "@cello-protocol/protocol-types";
import { decryptBody, deriveFetchKey, unwrapGroupKey, type GroupKey } from "@cello-protocol/crypto";
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

  const member = new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberSeedHex, "hex")));
  const channelPubkeyForUnwrap = new Uint8Array(Buffer.from(channelHex, "hex"));

  /**
   * ⚠️ UNWRAPPED HERE, with this member's OWN key. The bundles came from the admin's real join
   * path; handing this process raw group keys would have skipped the wrapping entirely, which is
   * most of what a join does.
   */
  const keys: GroupKey[] = [];
  for (const bundleHex of JSON.parse(keysJson) as string[]) {
    const opened = await unwrapGroupKey(new Uint8Array(Buffer.from(bundleHex, "hex")), channelPubkeyForUnwrap, member);
    if (!opened.ok) throw new Error(`could not unwrap a bundle addressed to this member: ${opened.reason}`);
    keys.push(opened.gk);
  }
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
