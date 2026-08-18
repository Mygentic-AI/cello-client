/**
 * DOD-M12B-SESSION-SEED-1 — the mechanism the whole line rests on, proven against a real node.
 *
 * A session node that is torn down (laptop close, relay reconnect) must come back at the SAME peer
 * id, or the counterparty can never dial us again: the id they were handed at establishment would
 * be dead, and libp2p connections are bidirectional only if BOTH ids still resolve.
 *
 * `createNode` already accepts `transportPrivateKey` and feeds it to `generateKeyPairFromSeed`, so
 * nothing here is new behaviour — what is new is that `SessionNodeManager` will now depend on this
 * being deterministic, and a dependency nobody asserts is a dependency that can be silently broken
 * by a transport refactor.
 *
 * Revert test (RUN): change `createNode` to ignore `transportPrivateKey` and the first case fails.
 */
import { describe, it, expect } from "vitest";
import { createNode } from "../node.js";

const LISTEN = ["/ip4/127.0.0.1/tcp/0"];

async function peerIdFor(seed: Uint8Array | undefined): Promise<string> {
  const node = await createNode({
    listenAddresses: LISTEN,
    nodeType: "session",
    ...(seed ? { transportPrivateKey: seed } : {}),
  });
  try {
    return node.getPeerId();
  } finally {
    await node.stop();
  }
}

describe("DOD-M12B-SESSION-SEED-1: a seed is a stable transport identity", () => {
  it("the same seed yields the same peer id — this is what lets a rebuilt session node be dialable", async () => {
    const seed = new Uint8Array(32).fill(7);
    expect(await peerIdFor(seed)).toBe(await peerIdFor(seed));
  }, 30_000);

  it("a different seed yields a different peer id — sessions stay unlinkable to a passive observer", async () => {
    // The recorded reason for ephemeral ids (2026-04-11) is PRIVACY: an observer must not be able to
    // correlate one agent's Monday session with its Tuesday session. Per-session seeds keep that.
    expect(await peerIdFor(new Uint8Array(32).fill(7))).not.toBe(await peerIdFor(new Uint8Array(32).fill(8)));
  }, 30_000);

  it("no seed yields a random id — the pre-existing behaviour for anything not session-scoped", async () => {
    expect(await peerIdFor(undefined)).not.toBe(await peerIdFor(undefined));
  }, 30_000);
});
