/**
 * M16 030-FETCHAUTH — the production fetch auth a member signs when it fetches a non-public channel.
 *
 * Before this order the production collector sent no fetch auth (the pre-019 placeholder
 * `() => Promise.resolve(undefined)`), so both relays refused every member fetch of an open or
 * invite-only channel with `not_a_member`. The relay is right to refuse: it serves a non-public
 * channel only when `auth.signature` verifies under the fetch pubkey the ADMIN deposited, over
 * `buildChannelFetchAuthTbs(channel_pubkey, since_seq, time_ms)`, with `time_ms` inside its skew
 * window. A member derives the same fetch key deterministically from the group key it holds, so the
 * relay checks the member's signature against the admin's deposited key without either side sharing
 * a secret.
 *
 * Sign with the fetch key of the member's NEWEST held generation (`keysFor` returns newest first). A
 * member who missed a re-key then holds only an old generation and is refused `not_a_member` — that
 * is the ejection property working, not a bug to route around, so this never tries an older key.
 */
import { Buffer } from "node:buffer";
import type { ChannelAccess } from "@cello-protocol/protocol-types";
import { buildChannelFetchAuthTbs } from "@cello-protocol/protocol-types";
import { deriveFetchKey, type GroupKey } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";

export function createChannelFetchAuth(deps: {
  keysFor: (agentId: string, channelHex: string) => readonly GroupKey[]; // newest first
  logger: Logger;
  now?: () => number;
}): (agentId: string, access: ChannelAccess, channelHex: string, sinceSeq: number)
     => Promise<{ signature: Uint8Array; time_ms: number } | undefined> {
  const now = deps.now ?? ((): number => Date.now());
  return async (agentId, access, channelHex, sinceSeq) => {
    // A public channel is served to anyone, so no credential is minted — sending one would be a
    // credential where none is required.
    if (access === "public") return undefined;

    const newest = deps.keysFor(agentId, channelHex)[0];
    if (!newest) {
      // No group key held for this channel: never invent one. The relay's `not_a_member` refusal is
      // then the visible outcome, and this log says why no auth was sent.
      deps.logger.warn("channel.fetch.auth.no_key", { channel_pubkey: channelHex, agent_id: agentId });
      return undefined;
    }

    const channelPubkey = new Uint8Array(Buffer.from(channelHex, "hex"));
    const fetchKey = await deriveFetchKey(newest, channelPubkey);
    const timeMs = now();
    return {
      signature: await fetchKey.sign(buildChannelFetchAuthTbs(channelPubkey, sinceSeq, timeMs)),
      time_ms: timeMs,
    };
  };
}
