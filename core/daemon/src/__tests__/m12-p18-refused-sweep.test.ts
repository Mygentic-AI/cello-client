/**
 * M12-P18 — content parked for a session WE REFUSED is swept, not re-pulled forever.
 *
 * The counterparty_unknown loop: the abuse cap refuses a session, so no session row is ever created;
 * content the sender already parked for it then fails authentication (no counterparty to bind to) on
 * every drain and is never confirm-deleted. Measured 78× on one box for a single session.
 *
 * The fix acts on OUR OWN refusal, never on the content — which is what keeps it inside the SEC-1
 * rule that a forgery must not be able to evict itself. Content for a session we did NOT refuse is
 * still left alone.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import { sealParkEnvelope } from "../park-envelope.js";
import { createContentPark } from "../content-park.js";

const SID = "b4".repeat(16);

describe("M12-P18: durable refused-session record", () => {
  it("records a refusal durably and reads it back; unknown sessions read false", async () => {
    const { startTwoConnectionFixture } = await import("./helpers/two-connection-fixture.js");
    const fx = await startTwoConnectionFixture({ dirPrefix: "cello-p18-" });
    try {
      expect(fx.snm.wasSessionRefused("alice", SID)).toBe(false);
      fx.snm.recordRefusedSession("alice", SID, "abuse_bound_sessions_per_sender");
      expect(fx.snm.wasSessionRefused("alice", SID)).toBe(true);
      // A different session this agent never refused stays false.
      expect(fx.snm.wasSessionRefused("alice", "ff".repeat(16))).toBe(false);
    } finally {
      await fx.cleanup();
    }
  });
});

describe("M12-P18: the drain sweeps refused-session content, and only that", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-p18-sweep-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  async function harness(wasRefused: boolean) {
    const confirm = vi.fn(async () => ({ ok: true }));
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const content = new TextEncoder().encode("parked for a session that will never exist");
    const contentHash = new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
    const ciphertext = await sealParkEnvelope({
      signer: sender, sessionIdHex: SID, recipientPubkey: await recipient.getPublicKey(), contentHash,
    });

    const sessionNodeManager = {
      getStandingReceiverNode: () => ({}),
      standingReceiverAbsenceReason: () => "none",
      // No session row → the auth gate returns counterparty_unknown, exactly like production.
      recoverParkedEntry: async () => ({ ok: false as const, reason: "counterparty_unknown" }),
      wasSessionRefused: () => wasRefused,
      recordSealedAnnex: () => true,
    };
    const park = createContentPark({
      logger: { debug() {}, info() {}, warn() {}, error() {} } as never,
      sessionNodeManager: sessionNodeManager as never,
      agents: [{ name: "alice", state: "online", pubkey: "aa".repeat(32) }] as never,
      getKeyProvider: () => recipient as never,
      securityGateway: { screenInbound: async () => ({ disposition: "allow" }), screenOutbound: async () => ({ disposition: "allow" }) } as never,
      makeContentParkClient: () => ({
        pull: async () => [{ sessionIdHex: SID, contentHashHex: Buffer.from(contentHash).toString("hex"), ciphertext }],
        confirm,
      }) as never,
    });
    const res = await park.recoverParkedFromRelay(
      { name: "alice", state: "online", pubkey: Buffer.from(await recipient.getPublicKey()).toString("hex") } as never,
      "12D3KooWFake", ["/ip4/127.0.0.1/tcp/1"],
    );
    return { confirm, res };
  }

  it("REFUSED session → the parked content is confirm-deleted (loop stops)", async () => {
    const h = await harness(true);
    expect(h.confirm, "content for a session we refused must be swept").toHaveBeenCalledTimes(1);
    expect((h.res as { refused: number }).refused, "and not carried as an unresolved refusal").toBe(0);
  });

  it("NOT-refused session → content is LEFT ALONE (SEC-1: no self-eviction, genuine content survives)", async () => {
    const h = await harness(false);
    expect(h.confirm, "content we did not refuse must not be deleted").not.toHaveBeenCalled();
    expect((h.res as { refused: number }).refused).toBe(1);
  });
});
