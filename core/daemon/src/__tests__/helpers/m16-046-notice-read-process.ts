/**
 * M16 046-JOINBELL enforcer helper — a MEMBER'S process reads its own sealed `group_key` notice from
 * a relay, verifies the channel key signed it, opens it with its own key, and prints the bundle.
 *
 * Usage: node --import tsx m16-046-notice-read-process.ts <memberSeedHex> <channelHex> <relayAddr>
 * Prints one JSON line: {"bundle": "<hex>" | null, "reason"?: string}
 */
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { channelNoticeSlot, decodeChannelNotice, verifyChannelNotice } from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import { ChannelRelayClient } from "../../channel-relay-client.js";
import { extractErrorMessage } from "../../error-message.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

async function main(): Promise<void> {
  const [memberSeed, channelHex, relayAddr] = process.argv.slice(2);
  if (!memberSeed || !channelHex || !relayAddr) throw new Error("usage: <memberSeedHex> <channelHex> <relayAddr>");
  const me = new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberSeed, "hex")));
  const shared = await me.staticSharedSecret(new Uint8Array(Buffer.from(channelHex, "hex")));
  if (!shared) throw new Error("no shared secret");
  const node = await createNode({ listenAddresses: [], keyProvider: me, relayServer: { enabled: false }, autonatResponder: { enabled: false } });
  await node.start();
  const record = await new ChannelRelayClient({ getNode: () => node, logger: silent }).getNotice(relayAddr, channelNoticeSlot(shared, "group_key"));
  await node.stop();
  const out = (bundle: Uint8Array | null, reason?: string): void => {
    process.stdout.write(`${JSON.stringify({ bundle: bundle ? Buffer.from(bundle).toString("hex") : null, ...(reason ? { reason } : {}) })}\n`);
  };
  if (!record) { out(null, "no_notice"); return; }
  const d = decodeChannelNotice(record);
  if (!d.ok || Buffer.from(d.notice.channel_pubkey).toString("hex") !== channelHex || !verifyChannelNotice(d.notice)) { out(null, "rejected"); return; }
  out(await me.openContentSeal(d.notice.sealed));
}

main().catch((err: unknown) => { process.stderr.write(`${extractErrorMessage(err)}\n`); process.exit(1); });
