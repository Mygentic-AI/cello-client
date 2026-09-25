/**
 * M16 019-MEMBERSHIP enforcer — the ADMIN/PUBLISHER, in its own OS process.
 *
 * ⚠️ **THIS RUNS THE REAL CODE, and the first version of this enforcer did not.** That one built
 * group keys by hand and called `client.deposit` directly, so reverting the entire eject
 * transaction, the whole wiring file and `currentFetchKey` left it green — it proved the relay
 * fixture honoured a signature scheme, and nothing about this unit. Here the join goes through
 * `ChannelJoinExchange.onAdminFrame`, the ejection through `ChannelMembershipStore.eject`, the
 * re-key through the same derivation the daemon wires, and every post through `ChannelPublisher`.
 *
 * Usage: node --import tsx m16-019-admin-process.ts <dbPath> <channelSeed> <adminSeed>
 *                                                   <memberAHex> <memberBHex> <relayA> <relayB>
 *
 * Prints one JSON line:
 *   { channelHex, adminHex, gen1BundleA, gen1BundleB, gen2BundleA, ejectGeneration }
 * The bundles are what each member's daemon would have received; the test hands them to the member
 * processes, which unwrap them with their own keys.
 */
import { InMemoryKeyProvider, deriveFetchKey, generateGroupKey, wrapGroupKeyFor, encryptBody } from "@cello-protocol/crypto";
import {
  encodeChannelJoinRequest, decodeChannelJoinAccepted, buildChannelFetchKeyTbs,
} from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import { openTestDb } from "./encrypted-db.js";
import { ChannelMembershipStore } from "../../channel-membership-store.js";
import { ChannelSubscriptionStore } from "../../channel-subscription-store.js";
import { ChannelLogStore } from "../../channel-log-store.js";
import { ChannelRelayClient } from "../../channel-relay-client.js";
import { ChannelPublisher } from "../../channel-publisher.js";
import { createChannelJoinExchange, ensureCurrentGroupKey } from "../../channel-join-exchange.js";
import { extractErrorMessage } from "../../error-message.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

async function main(): Promise<void> {
  const [dbPath, channelSeed, adminSeed, memberAHex, memberBHex, relayA, relayB, phase] = process.argv.slice(2);
  if (!dbPath || !channelSeed || !adminSeed || !memberAHex || !memberBHex || !relayA || !relayB || !phase) {
    throw new Error("usage: m16-019-admin-process.ts <dbPath> <channelSeed> <adminSeed> <memberAHex> <memberBHex> <relayA> <relayB> <setup|eject>");
  }

  const db = openTestDb(dbPath);
  const channelKp = new InMemoryKeyProvider(new Uint8Array(Buffer.from(channelSeed, "hex")));
  const adminKp = new InMemoryKeyProvider(new Uint8Array(Buffer.from(adminSeed, "hex")));
  const channelPubkey = await channelKp.getPublicKey();
  const channelHex = hex(channelPubkey);
  const adminHex = hex(await adminKp.getPublicKey());

  const members = new ChannelMembershipStore(db, silent);
  const subscriptions = new ChannelSubscriptionStore(db, silent);
  const log = new ChannelLogStore(db, silent);

  // The channel's own settings — the row whose absence made every join refuse.
  members.putSettings(channelHex, {
    access: "invite_only", members_visible: false, guidance: "enforcer channel",
    retention_seconds: 7 * 24 * 3600, relays: [relayA, relayB], admin_pubkey: adminHex,
  });

  const sent: Uint8Array[] = [];
  const exchange = createChannelJoinExchange({
    logger: silent, members, subscriptions,
    sendInSession: (_sessionId, content) => { sent.push(content); return Promise.resolve(); },
    localChannelAdmin: () => ({
      agentId: "admin-agent", adminPubkeyHex: adminHex,
      channelKeyProvider: channelKp, adminKeyProvider: adminKp,
    }),
    profileAdminPubkey: () => Promise.resolve(adminHex),
    keyProviderFor: () => adminKp,
    raiseNotice: () => { /* the admin's inbox is not what this proves */ },
  });

  /** A member asks to join, and the ADMIN's real code decides. Invite-only → pending → approve. */
  async function join(memberHex: string): Promise<Uint8Array> {
    const before = sent.length;
    await exchange.onAdminFrame("s1", memberHex, encodeChannelJoinRequest({
      channel_pubkey: channelPubkey,
      subscriber_pubkey: new Uint8Array(Buffer.from(memberHex, "hex")),
      note: "enforcer",
    }));
    // Invite-only answers `pending_approval`; the admin's explicit approval is what sends the key.
    const approved = await exchange.approve(channelHex, memberHex, "s1");
    if (!approved.ok) throw new Error(`approve failed: ${approved.reason}`);
    const accepted = decodeChannelJoinAccepted(sent[sent.length - 1]);
    if (!accepted.ok) throw new Error(`no acceptance for ${memberHex.slice(0, 8)}: ${accepted.reason}`);
    if (sent.length <= before) throw new Error("nothing was sent");
    return accepted.frame.key_bundle;
  }

  /**
   * ⚠️ TWO PHASES, TWO PROCESSES, ONE DATABASE. The members have to read BEFORE the ejection and
   * again after, and the relay's gate moves with the re-key — so the admin cannot do both in one
   * run. Splitting it also proves the admin's own state survives a restart, which is the property
   * that broke when its group key lived only in memory.
   */
  const setup = phase === "setup";
  const gen1BundleA = setup ? await join(memberAHex) : new Uint8Array(0);
  const gen1BundleB = setup ? await join(memberBHex) : new Uint8Array(0);

  // ─── The publisher, with the fetch key derived exactly as the daemon's wiring derives it ──────
  const node = await createNode({
    listenAddresses: [], keyProvider: adminKp,
    relayServer: { enabled: false }, autonatResponder: { enabled: false },
  });
  await node.start();
  const relayClient = new ChannelRelayClient({ getNode: () => node, logger: silent });

  const currentFetchKey = async (): Promise<{ pubkey: Uint8Array; time_ms: number; signature: Uint8Array } | undefined> => {
    const newest = subscriptions.keysFor("admin-agent", channelHex)[0];
    if (!newest) return undefined;
    const fetchKey = await deriveFetchKey(newest, channelPubkey);
    const timeMs = Date.now();
    return {
      pubkey: fetchKey.publicKey, time_ms: timeMs,
      signature: await channelKp.sign(buildChannelFetchKeyTbs(channelPubkey, fetchKey.publicKey, timeMs)),
    };
  };

  const publisher = new ChannelPublisher({
    logger: silent, log,
    deposit: (relay, req) => relayClient.deposit(relay, req),
    depositInfo: (relay, req) => relayClient.depositInfo(relay, req),
    relayHead: (relay, chHex) => relayClient.head(relay, new Uint8Array(Buffer.from(chHex, "hex"))),
    screenOutbound: () => Promise.resolve({ disposition: "allow" as const }),
    getChannelKey: () => channelKp,
    getAgentKey: () => adminKp,
    // 037-TESTTRUTH (028): the PRODUCTION mint-or-reuse the daemon's `encryptBodyFor` runs, not a
    // hand-rolled "newest key held" lookup — so a private publish here fails exactly when production
    // would. The generation comes from settings (the eject bumps it), and `encryptBody` binds it.
    encryptBody: (plaintext, chHex, seq) => {
      const gk = ensureCurrentGroupKey({ members, subscriptions, now: Date.now }, "admin-agent", chHex);
      if (!gk) throw new Error("channel_group_key_unavailable");
      return Promise.resolve(encryptBody(gk, channelPubkey, seq, plaintext));
    },
    currentFetchKey,
    channelInfo: () => {
      const s = members.settings(channelHex);
      return s ? { access: s.access, relays: s.relays, guidance: s.guidance, retention_seconds: s.retention_seconds } : null;
    },
  });

  let gen2BundleA = new Uint8Array(0);
  let ejectGeneration = 0;
  let remaining: string[] = [];

  if (setup) {
    const first = await publisher.publish("admin-agent", channelHex, "before the ejection", "body one");
    if (!first.ok) throw new Error(`first publish failed: ${first.reason}`);
  } else {
    // ─── The ejection: the REAL store transaction, then a re-key wrapped per remaining member ───
    const outcome = members.eject(channelHex, memberBHex);
    ejectGeneration = outcome.generation;
    remaining = outcome.remaining;
    const gk2 = generateGroupKey(outcome.generation);
    // Stored BEFORE it is wrapped for anyone — dying in between would leave the settings naming a
    // generation whose key existed nowhere, and the channel silent for everyone.
    subscriptions.addKey("admin-agent", channelHex, gk2, Date.now());
    gen2BundleA = await wrapGroupKeyFor(gk2, channelPubkey, new Uint8Array(Buffer.from(memberAHex, "hex")), adminKp);

    const second = await publisher.publish("admin-agent", channelHex, "after the ejection", "body two");
    if (!second.ok) throw new Error(`second publish failed: ${second.reason}`);
  }

  process.stdout.write(`${JSON.stringify({
    channelHex, adminHex,
    gen1BundleA: hex(gen1BundleA), gen1BundleB: hex(gen1BundleB), gen2BundleA: hex(gen2BundleA),
    ejectGeneration, remaining,
  })}\n`);
  await node.stop();
  db.close();
}

main().catch((err: unknown) => {
  process.stderr.write(`${extractErrorMessage(err)}\n`);
  process.exit(1);
});
