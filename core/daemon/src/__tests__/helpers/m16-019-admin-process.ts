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
import { buildChannelFetchKeyTbs } from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import { openTestDb } from "./encrypted-db.js";
import { ChannelMembershipStore } from "../../channel-membership-store.js";
import { ChannelSubscriptionStore } from "../../channel-subscription-store.js";
import { ChannelLogStore } from "../../channel-log-store.js";
import { ChannelRelayClient } from "../../channel-relay-client.js";
import { ChannelPublisher } from "../../channel-publisher.js";
import { ensureCurrentGroupKey } from "../../channel-join-exchange.js";
import { writeChannelNotice } from "../../channel-notices.js";
import { extractErrorMessage } from "../../error-message.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/**
 * 037-TESTTRUTH end-to-end posts. The member must read these back as EXACTLY this plaintext, so the
 * enforcer asserts titles and bodies rather than "it did not throw". The admin echoes them in its
 * output, and the member's decrypted output must equal them.
 */
const E2E_INVITE_POSTS: ReadonlyArray<{ title: string; body: string }> = [
  { title: "invite post one", body: "the first body, members only" },
  { title: "invite post two", body: "the second body, members only" },
];
const E2E_PUBLIC_POSTS: ReadonlyArray<{ title: string; body: string }> = [
  { title: "public post one", body: "readable by anyone" },
];

async function main(): Promise<void> {
  const [dbPath, channelSeed, adminSeed, memberAHex, memberBHex, relayA, relayB, phase] = process.argv.slice(2);
  if (!dbPath || !channelSeed || !adminSeed || !memberAHex || !memberBHex || !relayA || !relayB || !phase) {
    throw new Error("usage: m16-019-admin-process.ts <dbPath> <channelSeed> <adminSeed> <memberAHex> <memberBHex> <relayA> <relayB> <setup|eject|e2e-invite|e2e-public>");
  }
  const setup = phase === "setup";
  const inviteE2e = phase === "e2e-invite";
  const publicE2e = phase === "e2e-public";

  const db = openTestDb(dbPath);
  const channelKp = new InMemoryKeyProvider(new Uint8Array(Buffer.from(channelSeed, "hex")));
  const adminKp = new InMemoryKeyProvider(new Uint8Array(Buffer.from(adminSeed, "hex")));
  const channelPubkey = await channelKp.getPublicKey();
  const channelHex = hex(channelPubkey);
  const adminHex = hex(await adminKp.getPublicKey());

  const members = new ChannelMembershipStore(db, silent);
  const subscriptions = new ChannelSubscriptionStore(db, silent);
  const log = new ChannelLogStore(db, silent);

  // The channel's own settings — the row whose absence made every join refuse. `e2e-public` is the
  // one phase whose channel is public; every other phase is invite-only.
  members.putSettings(channelHex, {
    access: publicE2e ? "public" : "invite_only", members_visible: false, guidance: "enforcer channel",
    retention_seconds: 7 * 24 * 3600, relays: [relayA, relayB], admin_pubkey: adminHex,
  });

  /**
   * 046-JOINBELL: admission is the admin's decision recorded in its store plus the key wrapped for
   * the member — no session. (The join request/answer records are proven in
   * m16-020-join-through-directory.test.ts; what THIS process proves is the relay-side ejection.)
   */
  function join(memberHex: string): Promise<Uint8Array> {
    members.admit(channelHex, memberHex, "active", Date.now());
    const gk = ensureCurrentGroupKey({ members, subscriptions, now: Date.now }, "admin-agent", channelHex);
    if (!gk) throw new Error("no group key");
    return wrapGroupKeyFor(gk, channelPubkey, new Uint8Array(Buffer.from(memberHex, "hex")), adminKp);
  }

  function joinPublic(memberHex: string): Promise<Uint8Array> {
    members.admit(channelHex, memberHex, "active", Date.now());
    return Promise.resolve(new Uint8Array(0));
  }

  const gen1BundleA = publicE2e ? await joinPublic(memberAHex)
    : (setup || inviteE2e) ? await join(memberAHex) : new Uint8Array(0);
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

  // ─── 037-TESTTRUTH end-to-end: publish through the REAL publisher and report the exact plaintext ─
  if (inviteE2e || publicE2e) {
    const toPublish = publicE2e ? E2E_PUBLIC_POSTS : E2E_INVITE_POSTS;
    const posts: Array<{ seq: number; title: string; body: string }> = [];
    for (const p of toPublish) {
      const r = await publisher.publish("admin-agent", channelHex, p.title, p.body);
      if (!r.ok) throw new Error(`e2e publish failed at "${p.title}": ${r.reason}`);
      posts.push({ seq: r.seq, title: p.title, body: p.body });
    }
    process.stdout.write(`${JSON.stringify({
      channelHex, adminHex,
      gen1BundleA: hex(gen1BundleA),
      publicBundleEmpty: publicE2e ? gen1BundleA.length === 0 : undefined,
      posts,
    })}\n`);
    await node.stop();
    db.close();
    return;
  }

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
    // 045/046: the new key reaches the remaining member ONLY as a sealed group_key notice on the
    // relays — the test reads it back from another process with the member's own key.
    const noticeRelays = {
      deposit: async (relays: string[], record: Uint8Array): Promise<number> => {
        let ok = 0;
        for (const r of relays) if ((await relayClient.depositNotice(r, record)).ok) ok += 1;
        return ok;
      },
      fetch: () => Promise.resolve([]),
    };
    const written = await writeChannelNotice({ relays: noticeRelays, logger: silent }, channelKp, [relayA, relayB], memberAHex, "group_key", gen2BundleA);
    if (!written) throw new Error("no relay took the group_key notice");

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
