/**
 * M16 031-KEYSASKEYS (daemon side) — the daemon fills `ScreenContext.knownPublicKeys` with ONLY the
 * public keys it actually knows that appear in the message, and NEVER any private key material.
 *
 * Test 6 pins the extractor (`createKnownPublicKeysIn`) against stubbed sources — a private seed in
 * hex is 64 hex characters too, and it must never leak into the known set. Test 7 proves the wired
 * `cello_send` path passes the list to the gateway, using a recording gateway client.
 */
import { describe, it, expect } from "vitest";
import { createKnownPublicKeysIn } from "../known-public-keys.js";
import { startTwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { SecurityGatewayClient, ScreenContext, ScreenVerdict } from "@cello-protocol/gateway";

const OWN = "aa".repeat(32); // this daemon's own agent pubkey (64-hex)
const CONTACT = "bb".repeat(32); // one contact's pubkey
const UNKNOWN = "cc".repeat(32); // a 64-hex value the daemon does not know
const PRIVATE_SEED = "dd".repeat(32); // 64-hex, but private key material — must never be returned

describe("M16 031 — the daemon returns only known public keys in the message", () => {
  it("test 6: only known public keys are returned (private seed and unknown token excluded), lowercased", () => {
    const fn = createKnownPublicKeysIn({
      loadedAgentPubkeys: () => [OWN],
      contactPubkeys: () => [CONTACT],
      followedChannelPubkeys: () => [],
      counterpartyPubkey: () => undefined,
    });
    // The own key appears UPPERCASE in the message — the result must be lowercased.
    const content = new TextEncoder().encode(
      `own ${OWN.toUpperCase()} contact ${CONTACT} unknown ${UNKNOWN} seed ${PRIVATE_SEED}`,
    );
    const out = fn("alice", "sess", content);
    expect(new Set(out)).toEqual(new Set([OWN, CONTACT]));
    expect(out).not.toContain(UNKNOWN);
    expect(out).not.toContain(PRIVATE_SEED);
  });
});

/** A gateway client that RECORDS the knownPublicKeys the daemon passed, then allows. Starts undefined. */
class RecordingGateway implements SecurityGatewayClient {
  readonly mode = "enforcing" as const;
  lastKnownKeys: string[] | undefined;
  async screenOutbound(content: Uint8Array, ctx: ScreenContext): Promise<ScreenVerdict> {
    this.lastKnownKeys = ctx.knownPublicKeys;
    return { disposition: "allow", content };
  }
  async screenInbound(): Promise<ScreenVerdict> {
    return { disposition: "allow" };
  }
}

describe("M16 031 — cello_send passes knownPublicKeys to the gateway", () => {
  it("test 7: sending the counterparty's own pubkey records knownPublicKeys containing it", async () => {
    const gw = new RecordingGateway();
    const fx = await startTwoConnectionFixture({ agents: ["alice"], securityGateway: gw });
    try {
      const CP = "ce0fa3d0642cc07e0dd614ae919e3d8b1864bbaae4bdf4494dc9430f72501cfc";
      const SID = "9a".repeat(32);
      await fx.createSession(SID, "alice", CP, "bob-peer");
      const client = await fx.connectAs("alice");
      const res = (await client.send("cello_send", { session_id: SID, content: `my pubkey is ${CP}` })) as {
        ok?: boolean;
      };
      expect(res.ok).toBe(true);
      expect(gw.lastKnownKeys).toContain(CP);
    } finally {
      await fx.cleanup();
    }
  });
});
