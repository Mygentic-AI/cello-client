/**
 * M16 019-MEMBERSHIP / 037-TESTTRUTH enforcer — ONE MEMBER, in its own OS process.
 *
 * Reads a channel from two relays over real libp2p, using only what it was given at join time: the
 * group keys it holds and the fetch key derived from them. Separate processes are the point — the
 * ejected member must be a different process holding a different database, so "it cannot read" is
 * not an artifact of one heap knowing too much.
 *
 * TWO MODES:
 *
 *   fetch   <dbPath> <agentId> <channelHex> <adminHex> <memberSeedHex> <relayA> <relayB> <keysJson>
 *     The 019 ejection path: fetch each relay directly with a hand-derived fetch signature, and
 *     report which posts each relay was willing to hand over. Its point is the RELAY's refusal of an
 *     ejected member, so it deliberately signs its own auth rather than routing through production.
 *
 *   collect <dbPath> <agentId> <agentName> <channelHex> <adminHex> <memberSeedHex> <access>
 *           <relayA> <relayB> <keysJson>
 *     037-TESTTRUTH end-to-end: read through the PRODUCTION stack — `ChannelCollector` with
 *     `createChannelFetchAuth` (030), driven by `createChannelCollectTicker` whose online check is
 *     `createIsAgentOnlineById` (029). `agentId` and `agentName` are DIFFERENT on purpose: the tick
 *     asks by id, and only the id→name mapping keeps this agent from reading as offline — which is
 *     exactly the bug 029 fixed and which no multi-process test exercised before. Prints the exact
 *     plaintext (title + body) of every post read.
 *
 * `keysJson` is `[bundleHex]` — the WRAPPED key bundles this member was actually sent by the admin,
 * unwrapped here with its own identity key (empty for a public channel, which carries no key).
 */
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { decodeBroadcastArtifact, buildChannelFetchAuthTbs, type ChannelAccess } from "@cello-protocol/protocol-types";
import { decryptBody, deriveFetchKey, unwrapGroupKey, type GroupKey } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { ChannelRelayClient } from "../../channel-relay-client.js";
import { ChannelCollector } from "../../channel-collector.js";
import { ChannelInboxStore } from "../../channel-inbox-store.js";
import { ChannelSubscriptionStore } from "../../channel-subscription-store.js";
import { createChannelFetchAuth } from "../../channel-fetch-auth.js";
import { createChannelCollectTicker } from "../../channel-collect-tick.js";
import { createIsAgentOnlineById } from "../../agent-online.js";
import { openTestDb } from "./encrypted-db.js";
import { extractErrorMessage } from "../../error-message.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** Unwrap each wrapped bundle addressed to this member into a held group key. */
async function unwrapAll(bundles: string[], channelPubkey: Uint8Array, member: InMemoryKeyProvider): Promise<GroupKey[]> {
  const keys: GroupKey[] = [];
  for (const bundleHex of bundles) {
    const opened = await unwrapGroupKey(new Uint8Array(Buffer.from(bundleHex, "hex")), channelPubkey, member);
    if (!opened.ok) throw new Error(`could not unwrap a bundle addressed to this member: ${opened.reason}`);
    keys.push(opened.gk);
  }
  return keys;
}

/**
 * The 019 ejection path: fetch directly, signing with the NEWEST key held. An ejected member's
 * newest is the generation before the re-key, so its signature no longer matches what the relays
 * were told to require — the refusal happens at the RELAY, before any ciphertext moves.
 */
async function fetchMode(rest: string[]): Promise<void> {
  const [, agentId, channelHex, , memberSeedHex, relayA, relayB, keysJson] = rest;
  if (!agentId || !channelHex || !memberSeedHex || !relayA || !relayB || !keysJson) {
    throw new Error("usage: m16-019-member-process.ts fetch <dbPath> <agentId> <channelHex> <adminHex> <memberSeedHex> <relayA> <relayB> <keysJson>");
  }

  const member = new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberSeedHex, "hex")));
  const channelPubkey = new Uint8Array(Buffer.from(channelHex, "hex"));
  const keys = await unwrapAll(JSON.parse(keysJson) as string[], channelPubkey, member);

  const node = await createNode({
    listenAddresses: [], keyProvider: member,
    relayServer: { enabled: false }, autonatResponder: { enabled: false },
  });
  await node.start();
  const client = new ChannelRelayClient({ getNode: () => node, logger: silent });

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

/**
 * 037-TESTTRUTH end-to-end: collect through the production stack, then read the exact plaintext.
 */
async function collectMode(rest: string[]): Promise<void> {
  const [dbPath, agentId, agentName, channelHex, adminHex, memberSeedHex, access, relayA, relayB, keysJson] = rest;
  if (!dbPath || !agentId || !agentName || !channelHex || !adminHex || !memberSeedHex || !access || !relayA || !relayB || !keysJson) {
    throw new Error("usage: m16-019-member-process.ts collect <dbPath> <agentId> <agentName> <channelHex> <adminHex> <memberSeedHex> <access> <relayA> <relayB> <keysJson>");
  }
  if (agentId === agentName) throw new Error("collect mode needs agentId != agentName to exercise createIsAgentOnlineById");

  const member = new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberSeedHex, "hex")));
  const channelPubkey = new Uint8Array(Buffer.from(channelHex, "hex"));
  const keys = await unwrapAll(JSON.parse(keysJson) as string[], channelPubkey, member);

  const db = openTestDb(dbPath);
  const subs = new ChannelSubscriptionStore(db, silent);
  const inbox = new ChannelInboxStore(db, silent);
  // The subscription a real join would have written — keyed on the STABLE agent_id.
  subs.upsert({
    agent_id: agentId, channel_pubkey: channelHex, admin_pubkey: adminHex,
    access: access as ChannelAccess, relays: [relayA, relayB],
  });
  // Held where a real subscriber keeps its keys, so the production fetch auth derives the fetch key
  // the relays were told to require. Public carries no key, so there is nothing to store.
  for (const gk of keys) subs.addKey(agentId, channelHex, gk, Date.now());

  const node = await createNode({
    listenAddresses: [], keyProvider: member,
    relayServer: { enabled: false }, autonatResponder: { enabled: false },
  });
  await node.start();
  const relayClient = new ChannelRelayClient({ getNode: () => node, logger: silent });

  const collector = new ChannelCollector({
    db, logger: silent, subscriptions: subs, inbox,
    fetch: (relay, req) => relayClient.fetch(relay, req),
    fetchAuth: createChannelFetchAuth({ keysFor: (a, c) => subs.keysFor(a, c), logger: silent }),
    localAgentKeys: () => [],
    requestRepair: () => Promise.resolve(),
  });

  // 029-COLLECTID: the tick asks isAgentOnline BY ID. This agent is online only under its NAME, so
  // the id→name mapping in createIsAgentOnlineById is the only thing that lets it collect. Revert
  // that mapping and this agent reads as offline and fetches nothing.
  const onlineAgents = new Set<string>([agentName]);
  const isAgentOnline = createIsAgentOnlineById({
    onlineAgents,
    explicitlyOfflineAgents: new Set<string>(),
    agentNameForId: (id) => (id === agentId ? agentName : null),
  });
  const ticker = createChannelCollectTicker({
    logger: silent, collector, subscriptions: subs, isAgentOnline, retrySpreadMs: 0,
  });
  await ticker.collectNow(agentId);

  const isPublic = access === "public";
  const collected = inbox.heldSeqs(agentId, channelHex);
  const posts: Array<{ seq: number; title: string; body: string }> = [];
  const dec = new TextDecoder();
  for (const seq of collected) {
    for (const art of inbox.range(agentId, channelHex, seq, seq)) {
      let body: string;
      if (isPublic) {
        body = dec.decode(art.body);
      } else {
        const opened = decryptBody(keys, channelPubkey, seq, art.body);
        if (!opened.ok) continue;
        body = dec.decode(opened.plaintext);
      }
      posts.push({ seq, title: art.title, body });
    }
  }

  // Decision 3: name the position advanced and the key generations held — the outcome, not "no throw".
  const deliveredThrough = subs.get(agentId, channelHex)?.delivered_through ?? 0;
  const generations = subs.keysFor(agentId, channelHex).map((k) => k.generation);
  process.stdout.write(`${JSON.stringify({ agentId, agentName, collected, posts, deliveredThrough, generations })}\n`);
  await node.stop();
  db.close();
}

async function main(): Promise<void> {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "collect") { await collectMode(rest); return; }
  if (mode === "fetch") { await fetchMode(rest); return; }
  throw new Error(`unknown mode ${String(mode)} (expected fetch|collect)`);
}

main().catch((err: unknown) => {
  process.stderr.write(`${extractErrorMessage(err)}\n`);
  process.exit(1);
});
