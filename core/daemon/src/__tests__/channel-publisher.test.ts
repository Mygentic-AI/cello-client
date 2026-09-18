/**
 * M16 018-PUBCOLLECT — the publisher half.
 *
 * A channel publishes through TWO relays of its own choosing, so one being down does not stop
 * delivery. Nothing coordinates them: each holds its own queue and the subscriber takes the union.
 * The publisher's log is the durable copy behind both, and each relay's signed receipt is the proof
 * of what was sent and when that relay took it.
 *
 * Real DB, real keys, fake relay seam. Tests are written RED-first.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  decodeBroadcastArtifact,
  decodeChannelInfo,
  signRelayPostReceipt,
  verifyChannelInfo,
  verifyRelayPostReceipt,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelPublisher, type RelayDepositSeam } from "../channel-publisher.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";

let dir: string;
let db: DaemonDatabase;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-018-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

interface Seen {
  relay: string;
  postCbor: Uint8Array;
}

interface Harness {
  publisher: ChannelPublisher;
  log: ChannelLogStore;
  channelKp: InMemoryKeyProvider;
  adminKp: InMemoryKeyProvider;
  channelHex: string;
  relayKeys: Map<string, InMemoryKeyProvider>;
  deposits: Seen[];
  /** Relays that refuse, and with what. */
  refuse: Map<string, { reason: string; skew_ms?: number }>;
  /** Relays that throw outright — a relay that is simply down. */
  down: Set<string>;
  screen: { block: boolean };
  clock: { now: number };
}

async function harness(opts: { access?: "public" | "open" } = {}): Promise<Harness> {
  const channelKp = generateKeypair();
  const adminKp = generateKeypair();
  const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
  const relayKeys = new Map<string, InMemoryKeyProvider>([
    [RELAY_A, generateKeypair()],
    [RELAY_B, generateKeypair()],
  ]);
  const deposits: Seen[] = [];
  const refuse = new Map<string, { reason: string; skew_ms?: number }>();
  const down = new Set<string>();
  const screen = { block: false };
  const clock = { now: 1_800_000_000_000 };

  const deposit: RelayDepositSeam = async (relay, req) => {
    if (down.has(relay)) throw new Error(`relay ${relay} is unreachable`);
    deposits.push({ relay, postCbor: req.post_cbor });
    const refusal = refuse.get(relay);
    if (refusal) {
      refuse.delete(relay); // refuse once, so a retry can be observed succeeding
      return { ok: false, reason: refusal.reason, ...(refusal.skew_ms !== undefined ? { skew_ms: refusal.skew_ms } : {}) };
    }
    const decoded = decodeBroadcastArtifact(req.post_cbor);
    if (!decoded.ok) return { ok: false, reason: "bad_post" };
    const receipt = await signRelayPostReceipt(relayKeys.get(relay)!, decoded.artifact, clock.now);
    const { encodeRelayPostReceipt } = await import("@cello-protocol/protocol-types");
    return { ok: true, receipt_cbor: encodeRelayPostReceipt(receipt) };
  };

  const log = new ChannelLogStore(db, silent);
  const publisher = new ChannelPublisher({
    db,
    logger: silent,
    log,
    now: () => clock.now,
    deposit,
    // The seam `cello_send` uses. The subscriber's inbound screen is the enforcement; this is the
    // early check that spares an honest publisher the friction.
    screenOutbound: () => Promise.resolve(screen.block ? { disposition: "block", reason: "injection" } : { disposition: "allow" }),
    getChannelKey: () => channelKp,
    getAgentKey: () => adminKp,
    /**
     * 019 owns the group key; this stands in for it. It XORs rather than merely prefixing, because a
     * prefix leaves the plaintext readable — and test 7, which asserts the body is not readable,
     * would then pass against a publisher that never encrypted anything at all.
     */
    encryptBody: (plaintext) => Promise.resolve(new Uint8Array([0xe1, ...plaintext.map((b) => b ^ 0x5a)])),
    channelInfo: () => ({
      access: opts.access ?? "open",
      relays: [RELAY_A, RELAY_B],
      guidance: "what this channel is for",
      retention_seconds: 7 * 24 * 3600,
    }),
  });

  return { publisher, log, channelKp, adminKp, channelHex, relayKeys, deposits, refuse, down, screen, clock };
}

describe("M16 018-PUBCOLLECT: publishing", () => {
  it("1. a publish signs, logs and deposits to BOTH relays, storing both receipts", async () => {
    const h = await harness();
    const result = await h.publisher.publish("agent-1", h.channelHex, "Deploy finished", "the body");
    expect(result.ok, result.ok ? "" : `refused: ${result.reason}`).toBe(true);
    if (!result.ok) return;

    expect(result.seq).toBe(1);
    expect(result.deposited.map((d) => d.relay).sort()).toEqual([RELAY_A, RELAY_B].sort());
    expect(result.deposited.every((d) => d.ok)).toBe(true);

    // Both receipts are stored against the post, and both verify.
    const post = h.log.readRange(h.channelHex, 1, 1)[0];
    const receipts = h.log.receiptsFor(h.channelHex, 1);
    expect(receipts).toHaveLength(2);
    for (const r of receipts) expect(verifyRelayPostReceipt(r, post)).toBe(true);
  });

  it("2. the LOG is written before any deposit — a throwing seam still leaves the post logged", async () => {
    /**
     * ⚠️ THE ORDERING THE WHOLE DESIGN RESTS ON. A post that reached a relay but not the log is
     * invisible to its own publisher: it cannot be resent, cannot be pruned, and cannot be proved.
     * The log is the durable copy; the network is the optimistic part.
     */
    const h = await harness();
    h.down.add(RELAY_A);
    h.down.add(RELAY_B);

    const result = await h.publisher.publish("agent-1", h.channelHex, "nobody took it", "body");
    expect(result.ok ? "accepted" : result.reason).toBe("no_relay_accepted");

    // Logged anyway, with both relays reported failed.
    expect(h.log.head(h.channelHex)).toEqual({ first_seq: 1, last_seq: 1, pruned_through: 0 });
    expect(h.log.receiptsFor(h.channelHex, 1)).toEqual([]);
  });

  it("3. one relay down is still a SUCCESSFUL publish, with one receipt", async () => {
    const h = await harness();
    h.down.add(RELAY_B);

    const result = await h.publisher.publish("agent-1", h.channelHex, "half delivered", "body");
    expect(result.ok, result.ok ? "" : `refused: ${result.reason}`).toBe(true);
    if (!result.ok) return;
    expect(result.deposited.filter((d) => d.ok).map((d) => d.relay)).toEqual([RELAY_A]);
    expect(result.deposited.filter((d) => !d.ok).map((d) => d.relay)).toEqual([RELAY_B]);
    expect(h.log.receiptsFor(h.channelHex, 1)).toHaveLength(1);
  });

  it("4. BOTH down gives no_relay_accepted and the post stays for a retry", async () => {
    const h = await harness();
    h.down.add(RELAY_A);
    h.down.add(RELAY_B);
    const first = await h.publisher.publish("agent-1", h.channelHex, "kept", "body");
    expect(first.ok ? "accepted" : first.reason).toBe("no_relay_accepted");

    // The post is in the log, so a later resend can deliver exactly what was signed.
    h.down.clear();
    const resent = await h.publisher.resendMissing("agent-1", h.channelHex, RELAY_A);
    expect(resent.deposited).toBe(1);
    expect(h.log.receiptsFor(h.channelHex, 1)).toHaveLength(1);
  });

  it("5. clock_skew is retried ONCE with a fresh published_at, and the two attempts differ", async () => {
    const h = await harness();
    h.refuse.set(RELAY_A, { reason: "clock_skew", skew_ms: 90_000 });

    const result = await h.publisher.publish("agent-1", h.channelHex, "re-signed", "body");
    expect(result.ok).toBe(true);

    const toA = h.deposits.filter((d) => d.relay === RELAY_A);
    expect(toA, "the refused attempt and the retry").toHaveLength(2);
    // ⚠️ A NEW SIGNATURE OVER A NEW TIME. The time is inside the signature, so re-sending the same
    // bytes could never satisfy the relay — retrying without re-signing would loop forever.
    expect(Buffer.from(toA[0].postCbor).equals(Buffer.from(toA[1].postCbor))).toBe(false);

    const first = decodeBroadcastArtifact(toA[0].postCbor);
    const second = decodeBroadcastArtifact(toA[1].postCbor);
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    // The retry APPLIES the relay's number rather than guessing: the relay said this publisher was
    // 90s ahead, so the re-signed time is 90s earlier. Re-signing at the same clock would be refused
    // identically, for ever.
    expect(second.artifact.published_at).toBe(first.artifact.published_at - 90_000);
    expect(second.artifact.seq, "a retry is the SAME post, not the next one").toBe(first.artifact.seq);
  });

  it("6. a blocked outbound screen refuses: nothing signed, logged or sent", async () => {
    const h = await harness();
    h.screen.block = true;

    const result = await h.publisher.publish("agent-1", h.channelHex, "dangerous", "body");
    expect(result.ok ? "accepted" : result.reason).toBe("blocked_by_screen");
    // ⚠️ REFUSES, never warns-and-publishes. The screen is the publisher's own early check, and a
    // check that proceeds anyway is decoration.
    expect(h.deposits, "nothing reached a relay").toEqual([]);
    // Nothing reached the log either — and the channel was never even opened in it, so `head`
    // refuses rather than reporting an empty channel that a refused publish had created.
    let thrown: unknown;
    try { h.log.head(h.channelHex); } catch (err) { thrown = err; }
    expect((thrown as { code?: string } | undefined)?.code, "nothing reached the log").toBe("channel_unknown");
  });

  it("7. a PUBLIC channel's body is plaintext; an open channel's is ciphertext", async () => {
    const open = await harness({ access: "open" });
    await open.publisher.publish("agent-1", open.channelHex, "sealed", "secret words");
    const openPost = open.log.readRange(open.channelHex, 1, 1)[0];
    expect(openPost.body[0], "the encrypt seam's marker byte").toBe(0xe1);
    expect(Buffer.from(openPost.body).toString("utf-8")).not.toContain("secret words");

    const pub = await harness({ access: "public" });
    await pub.publisher.publish("agent-1", pub.channelHex, "open to all", "public words");
    const pubPost = pub.log.readRange(pub.channelHex, 1, 1)[0];
    // A public channel is readable by anyone, so encrypting it would be theatre — and would stop a
    // subscriber who has no key from reading what the channel exists to publish.
    expect(Buffer.from(pubPost.body).toString("utf-8")).toBe("public words");
  });

  it("8. resendMissing deposits only what a relay has NOT receipted, oldest first", async () => {
    const h = await harness();
    h.down.add(RELAY_B);
    for (const title of ["one", "two", "three"]) {
      await h.publisher.publish("agent-1", h.channelHex, title, "body");
    }
    expect(h.log.receiptsFor(h.channelHex, 2)).toHaveLength(1); // relay A only

    h.down.clear();
    h.deposits.length = 0;
    const result = await h.publisher.resendMissing("agent-1", h.channelHex, RELAY_B);
    expect(result.deposited).toBe(3);
    // Oldest first: a relay refills in order, because its queue only accepts the next number.
    const seqs = h.deposits.map((d) => {
      const decoded = decodeBroadcastArtifact(d.postCbor);
      return decoded.ok ? decoded.artifact.seq : -1;
    });
    expect(seqs).toEqual([1, 2, 3]);
    expect(h.deposits.every((d) => d.relay === RELAY_B)).toBe(true);

    // Nothing is re-sent to a relay that already receipted it.
    h.deposits.length = 0;
    expect((await h.publisher.resendMissing("agent-1", h.channelHex, RELAY_B)).deposited).toBe(0);
  });

  it("9. pruneChannel prunes locally and tells both relays", async () => {
    const h = await harness();
    for (const t of ["a", "b", "c"]) await h.publisher.publish("agent-1", h.channelHex, t, "body");

    const pruned = await h.publisher.pruneChannel("agent-1", h.channelHex, 2);
    expect(pruned.pruned).toBe(2);
    expect(h.log.head(h.channelHex)).toEqual({ first_seq: 3, last_seq: 3, pruned_through: 2 });
    expect(pruned.relays.map((r) => r.relay).sort()).toEqual([RELAY_A, RELAY_B].sort());
  });

  it("10. the info record round-trips and verifies; an ADMIN-key signature is refused", async () => {
    const h = await harness();
    const published = await h.publisher.publishInfo("agent-1", h.channelHex);
    expect(published.ok, published.ok ? "" : published.reason).toBe(true);
    if (!published.ok) return;

    const decoded = decodeChannelInfo(published.info_cbor);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(verifyChannelInfo(decoded.info)).toBe(true);
    expect(decoded.info.relays).toEqual([RELAY_A, RELAY_B]);
    expect(decoded.info.access).toBe("open");

    // ⚠️ Only the CHANNEL key may say where a channel's subscribers should look. A record signed by
    // the admin agent would let a replaced admin redirect an entire audience.
    const { signChannelInfo } = await import("@cello-protocol/protocol-types");
    const byAdmin = await signChannelInfo(h.adminKp, {
      access: "open", admin_pubkey: await h.adminKp.getPublicKey(), relays: [RELAY_A],
      guidance: "", retention_seconds: 3600, updated_at: h.clock.now, ext: null,
    });
    // It verifies against the ADMIN key it names, and that is exactly the problem: a subscriber
    // checks against the CHANNEL key, and against that it is not a record at all.
    expect(verifyChannelInfo({ ...byAdmin, channel_pubkey: await h.channelKp.getPublicKey() })).toBe(false);
  });
});
