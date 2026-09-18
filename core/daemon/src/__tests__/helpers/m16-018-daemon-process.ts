/**
 * M16 018-PUBCOLLECT enforcer — a publishing or collecting daemon, in its own OS process.
 *
 * Uses the REAL `ChannelPublisher`, `ChannelCollector` and `ChannelRelayClient` against relays
 * reached over real libp2p, with its own SQLCipher database. Nothing is shared with the test
 * process but the relay addresses.
 *
 * Usage:
 *   m16-018-daemon-process.ts publish <dbPath> <channelSeed> <adminSeed> <relayA> <relayB> <count>
 *   m16-018-daemon-process.ts resend  <dbPath> <channelSeed> <adminSeed> <relayA> <relayB> <relayToRefill>
 *   m16-018-daemon-process.ts collect <dbPath> <channelHex> <adminHex> <relayA> <relayB>
 *
 * Prints one JSON line describing the outcome.
 */
import { InMemoryKeyProvider, deriveFetchKey, type GroupKey } from "@cello-protocol/crypto";
import { buildChannelFetchKeyTbs, buildChannelFetchAuthTbs } from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import { ChannelLogStore } from "../../channel-log-store.js";
import { ChannelPublisher } from "../../channel-publisher.js";
import { ChannelCollector } from "../../channel-collector.js";
import { ChannelInboxStore } from "../../channel-inbox-store.js";
import { ChannelSubscriptionStore } from "../../channel-subscription-store.js";
import { ChannelRelayClient } from "../../channel-relay-client.js";
import { openTestDb } from "./encrypted-db.js";
import type { Logger } from "../../types.js";

const AGENT = "enforcer-agent";

/**
 * A FIXED group key, shared by the publisher and subscriber halves of this fixture so both derive
 * the same fetch key. 018 is not about membership — 019's enforcer covers that — but an `open`
 * channel is still gated at the relay, so this fixture has to hold a key to exercise the path at all.
 */
const ENFORCER_GROUP_KEY: GroupKey = { generation: 1, key: new Uint8Array(Buffer.alloc(32, 0x4b)) };

/** Structured to stderr, so stdout carries exactly one JSON line for the test to parse. */
const logger: Logger = {
  debug: (n, c) => process.stderr.write(`${JSON.stringify({ level: "debug", event: n, ...c })}\n`),
  info: (n, c) => process.stderr.write(`${JSON.stringify({ level: "info", event: n, ...c })}\n`),
  warn: (n, c) => process.stderr.write(`${JSON.stringify({ level: "warn", event: n, ...c })}\n`),
  error: (n, c) => process.stderr.write(`${JSON.stringify({ level: "error", event: n, ...c })}\n`),
};

const seeded = (hex: string): InMemoryKeyProvider => new InMemoryKeyProvider(new Uint8Array(Buffer.from(hex, "hex")));

async function main(): Promise<void> {
  const [mode, dbPath, ...rest] = process.argv.slice(2);
  const node = await createNode({ listenAddresses: [], keyProvider: seeded(Buffer.alloc(32, 0xc7).toString("hex")) });
  await node.start();
  const relayClient = new ChannelRelayClient({ getNode: () => node, logger });
  const db = openTestDb(dbPath);

  try {
    if (mode === "publish" || mode === "resend") {
      const [channelSeed, adminSeed, relayA, relayB, last] = rest;
      const channelKp = seeded(channelSeed);
      const adminKp = seeded(adminSeed);
      const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
      const log = new ChannelLogStore(db, logger);

      const publisher = new ChannelPublisher({
        db, logger, log,
        deposit: (relay, req) => relayClient.deposit(relay, req),
        // Asking what the relay HOLDS is what makes a refill work: a restarted relay has all its
        // receipts in the publisher's log and nothing in its queue.
        relayHead: (relay, channelHex) =>
          relayClient.head(relay, new Uint8Array(Buffer.from(channelHex, "hex"))),
        // The enforcer is about the relay path, so the screen allows — the refusal case is a unit
        // test, where it can be asserted precisely.
        screenOutbound: () => Promise.resolve({ disposition: "allow" as const }),
        getChannelKey: () => channelKp,
        getAgentKey: () => adminKp,
        encryptBody: (plaintext) => Promise.resolve(new Uint8Array(plaintext.map((b) => b ^ 0x5a))),
        channelInfo: () => ({
          access: "open" as const, relays: [relayA, relayB],
          guidance: "enforcer channel", retention_seconds: 7 * 24 * 3600,
        }),
        /**
         * M16 019: an `open` channel is not public, so the publisher refuses to deposit without a
         * fetch key — a deposit with none leaves the relay serving the queue to anyone. Derived from
         * a FIXED group key so the subscriber half below derives the identical one and can sign its
         * fetches, which is what the relay now checks.
         */
        currentFetchKey: async () => {
          const fetchKey = await deriveFetchKey(ENFORCER_GROUP_KEY, await channelKp.getPublicKey());
          const timeMs = Date.now();
          return {
            pubkey: fetchKey.publicKey,
            time_ms: timeMs,
            signature: await channelKp.sign(
              buildChannelFetchKeyTbs(await channelKp.getPublicKey(), fetchKey.publicKey, timeMs),
            ),
          };
        },
      });

      if (mode === "resend") {
        const result = await publisher.resendMissing(AGENT, channelHex, last);
        process.stdout.write(JSON.stringify({ mode, deposited: result.deposited, channel: channelHex }) + "\n");
        return;
      }

      const published: Array<{ seq: number; relays_ok: string[]; relays_failed: string[] }> = [];
      for (let i = 1; i <= Number(last); i++) {
        const result = await publisher.publish(AGENT, channelHex, `enforcer post ${String(i)}`, `body ${String(i)}`);
        published.push(
          result.ok
            ? {
                seq: result.seq,
                relays_ok: result.deposited.filter((d) => d.ok).map((d) => d.relay),
                relays_failed: result.deposited.filter((d) => !d.ok).map((d) => d.relay),
              }
            : { seq: result.seq ?? -1, relays_ok: [], relays_failed: (result.deposited ?? []).map((d) => d.relay) },
        );
      }
      process.stdout.write(JSON.stringify({ mode, channel: channelHex, published }) + "\n");
      return;
    }

    if (mode === "collect") {
      const [channelHex, adminHex, relayA, relayB] = rest;
      const subs = new ChannelSubscriptionStore(db, logger);
      const inbox = new ChannelInboxStore(db, logger);
      subs.upsert({
        agent_id: AGENT, channel_pubkey: channelHex, admin_pubkey: adminHex,
        access: "public", relays: [relayA, relayB],
      });

      const collector = new ChannelCollector({
        db, logger, subscriptions: subs, inbox,
        fetch: (relay, req) => relayClient.fetch(relay, req),
        // The same fixed group key the publisher used, so the derived fetch key matches what the
        // relays were told to require. A subscriber that could not sign would be turned away.
        fetchAuth: async (_access, chHex, sinceSeq) => {
          const channelPubkey = new Uint8Array(Buffer.from(chHex, "hex"));
          const fetchKey = await deriveFetchKey(ENFORCER_GROUP_KEY, channelPubkey);
          const timeMs = Date.now();
          return {
            signature: await fetchKey.sign(buildChannelFetchAuthTbs(channelPubkey, sinceSeq, timeMs)),
            time_ms: timeMs,
          };
        },
        localAgentKeys: () => [],
        requestRepair: () => Promise.resolve(),
      });

      await collector.collectOnce(AGENT, channelHex);
      const sub = subs.get(AGENT, channelHex);
      const gaps = collector.gapsFor(AGENT, channelHex);
      process.stdout.write(JSON.stringify({
        mode,
        delivered_through: sub?.delivered_through ?? 0,
        processed_through: sub?.processed_through ?? 0,
        held: inbox.heldSeqs(AGENT, channelHex),
        missing: gaps.missing,
      }) + "\n");
      return;
    }

    throw new Error(`unknown mode ${String(mode)}`);
  } finally {
    db.close();
    await node.stop().catch(() => { /* shutting down */ });
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : JSON.stringify(err)}\n`);
  process.exit(1);
});
