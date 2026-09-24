/**
 * M16 030-FETCHAUTH — the production fetch auth a member signs when it fetches a non-public channel.
 *
 * The relay serves a non-public channel only if `auth.signature` verifies under the admin's deposited
 * fetch pubkey, over `buildChannelFetchAuthTbs(channel_pubkey, since_seq, time_ms)`. These tests use
 * the REAL group-key crypto — `generateGroupKey`, `deriveFetchKey`, `buildChannelFetchAuthTbs`, and
 * the same Ed25519 `verify` the relay imports — so a green test proves the relay would accept it. No
 * crypto stubs.
 */
import { describe, it, expect } from "vitest";
import { generateGroupKey, deriveFetchKey, verify, type GroupKey } from "@cello-protocol/crypto";
import { buildChannelFetchAuthTbs } from "@cello-protocol/protocol-types";
import { createChannelFetchAuth } from "../channel-fetch-auth.js";
import type { Logger } from "../types.js";

const CHANNEL_HEX = "aa".repeat(32);
const CHANNEL_PUBKEY = new Uint8Array(Buffer.from(CHANNEL_HEX, "hex"));

function recorder(): { logger: Logger; events: Array<{ name: string; ctx?: unknown }> } {
  const events: Array<{ name: string; ctx?: unknown }> = [];
  const logger: Logger = {
    debug: (n, c) => events.push({ name: n, ctx: c }),
    info: (n, c) => events.push({ name: n, ctx: c }),
    warn: (n, c) => events.push({ name: n, ctx: c }),
    error: (n, c) => events.push({ name: n, ctx: c }),
  };
  return { logger, events };
}

describe("M16 030-FETCHAUTH: a member proves membership when it fetches", () => {
  it("1. a member's fetch auth verifies exactly as the relay checks it", async () => {
    const gk = generateGroupKey(1);
    const { logger } = recorder();
    const fetchAuth = createChannelFetchAuth({
      keysFor: () => [gk],
      logger,
      now: () => 1_700_000_000_000,
    });

    const out = await fetchAuth("agent-1", "invite_only", CHANNEL_HEX, 5);
    expect(out).toBeDefined();
    expect(out!.time_ms).toBe(1_700_000_000_000);

    const fetchKey = await deriveFetchKey(gk, CHANNEL_PUBKEY);
    const tbs = buildChannelFetchAuthTbs(CHANNEL_PUBKEY, 5, out!.time_ms);
    expect(verify(fetchKey.publicKey, tbs, out!.signature)).toBe(true);
  });

  it("2. a public channel gets NO auth", async () => {
    const gk = generateGroupKey(1);
    const { logger } = recorder();
    const fetchAuth = createChannelFetchAuth({ keysFor: () => [gk], logger });

    const out = await fetchAuth("agent-1", "public", CHANNEL_HEX, 5);
    expect(out).toBeUndefined();
  });

  it("3. the NEWEST held generation signs, not an older one", async () => {
    const gk1 = generateGroupKey(1);
    const gk2 = generateGroupKey(2);
    const { logger } = recorder();
    // keysFor returns newest first, exactly as the subscription store does.
    const fetchAuth = createChannelFetchAuth({
      keysFor: (): readonly GroupKey[] => [gk2, gk1],
      logger,
      now: () => 1_700_000_000_000,
    });

    const out = await fetchAuth("agent-1", "open", CHANNEL_HEX, 9);
    expect(out).toBeDefined();

    const tbs = buildChannelFetchAuthTbs(CHANNEL_PUBKEY, 9, out!.time_ms);
    const newest = await deriveFetchKey(gk2, CHANNEL_PUBKEY);
    const older = await deriveFetchKey(gk1, CHANNEL_PUBKEY);
    expect(verify(newest.publicKey, tbs, out!.signature)).toBe(true);
    expect(verify(older.publicKey, tbs, out!.signature)).toBe(false);
  });

  it("4. no key held → undefined and a channel.fetch.auth.no_key warn", async () => {
    const { logger, events } = recorder();
    const fetchAuth = createChannelFetchAuth({ keysFor: () => [], logger });

    const out = await fetchAuth("agent-X", "invite_only", CHANNEL_HEX, 1);
    expect(out).toBeUndefined();

    const warn = events.find((e) => e.name === "channel.fetch.auth.no_key");
    expect(warn, "the relay's refusal must be the visible outcome, so log why no auth was sent").toBeDefined();
    expect(warn!.ctx).toMatchObject({ channel_pubkey: CHANNEL_HEX, agent_id: "agent-X" });
  });
});
