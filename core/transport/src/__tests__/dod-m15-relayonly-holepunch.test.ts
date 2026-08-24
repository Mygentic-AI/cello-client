/**
 * DOD-M15-RELAYONLY-1 — the hole-punch must be switchable off, or relay-only is defeated at runtime.
 *
 * ─── Why this exists, and it is a defect the rest of the unit could not see ─────────────────────
 *
 * Relay-only stops publishing this agent's direct address and stops dialling the counterparty's, so
 * neither side can reach the other directly. **And then dcutr undoes it.**
 *
 * `node.ts` registered `dcutr()` on EVERY node, and the note beside it states the mechanism exactly:
 * *"the standing receiver is the inbound side of a relayed connection, **and the inbound side starts
 * the upgrade**."* dcutr's entire job is to UPGRADE a relayed connection into a direct one. So a
 * relay-only agent would route its session over the relay precisely as asked, and then hole-punch
 * its way to a direct connection anyway — **disclosing the address the setting exists to hide.**
 *
 * **The address a peer cannot be TOLD, a hole-punch still REVEALS.** Suppressing the published
 * address is therefore necessary and not sufficient, and that is why this half is not optional.
 *
 * ─── Why it needed its own test rather than a line in the relay-only file ──────────────────────
 *
 * Nothing in the daemon-side unit can observe this. Every one of those tests passes with dcutr fully
 * enabled, because none of them watches a live connection being upgraded — the leak happens in
 * libp2p, after the assertion. **A capability that is registered is a capability that will be used**,
 * so the honest place to assert it is at registration: the service is absent, or it is not.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { generateKeyPair } from "@libp2p/crypto/keys";
import { createNode } from "../node.js";
import type { KeyProvider } from "../types.js";

/** The protocol dcutr registers. Absent from `getProtocols()` iff the service was never added. */
const DCUTR_PROTOCOL_ID = "/libp2p/dcutr";

function keyProvider(): KeyProvider {
  return { getPrivateKey: async () => generateKeyPair("Ed25519") } as unknown as KeyProvider;
}

describe("DOD-M15-RELAYONLY-1 — hole-punching is off when the operator asked not to be reachable", () => {
  const cleanups: Array<() => Promise<void>> = [];
  beforeEach(() => { cleanups.length = 0; });
  afterEach(async () => { for (const c of cleanups) { try { await c(); } catch { /* teardown */ } } });

  async function nodeWith(holePunch?: { enabled: boolean }): Promise<string[]> {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      ...(holePunch ? { holePunch } : {}),
    });
    await node.start();
    cleanups.push(async () => { await node.stop(); });
    return node.getProtocols();
  }

  it("★★★ holePunch disabled → dcutr is NOT REGISTERED, so nothing can start an upgrade", async () => {
    /**
     * The assertion the whole second half of this control rests on. Asserted at REGISTRATION rather
     * than by observing a connection: a service that is present will be used, and a test that tried
     * to watch the upgrade not happening would pass for the wrong reason on any slow machine.
     *
     * **Revert test, RUN:** restore the unconditional `dcutr: dcutr()` in `node.ts` and this goes red
     * while every daemon-side relay-only test stays green — which is exactly the blind spot that made
     * this defect invisible.
     */
    expect(
      await nodeWith({ enabled: false }),
      "dcutr must be absent. If it is registered, a relay-only agent hole-punches to a DIRECT " +
        "connection and discloses the address the setting exists to hide — and no daemon-side test " +
        "can see it, because the leak happens inside libp2p after every assertion has passed.",
    ).not.toContain(DCUTR_PROTOCOL_ID);
  }, 30_000);

  it("★★ the DEFAULT is unchanged — every other node still hole-punches", async () => {
    /**
     * The regression half, and it matters as much: a direct connection is faster and cheaper than a
     * relayed one, and `DOD-NAT-REACHABILITY-1` depends on the upgrade happening. A privacy setting
     * that quietly degraded every ordinary agent's connectivity would be its own defect.
     */
    expect(await nodeWith(), "omitted = enabled, exactly as before this unit").toContain(DCUTR_PROTOCOL_ID);
  }, 30_000);

  it("★ explicitly enabled behaves as the default — the flag has no third meaning", async () => {
    expect(await nodeWith({ enabled: true })).toContain(DCUTR_PROTOCOL_ID);
  }, 30_000);
});
