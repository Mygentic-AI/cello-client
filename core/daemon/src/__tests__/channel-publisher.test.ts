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
import {
  ChannelPublisher,
  type RelayDepositSeam, type RelayInfoDepositSeam, type RelayPruneSeam,
  type ChannelPublisherOptions,
} from "../channel-publisher.js";
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
  /** The seams this publisher was built from, so a test can swap exactly one. */
  options: ChannelPublisherOptions;
  log: ChannelLogStore;
  channelKp: InMemoryKeyProvider;
  adminKp: InMemoryKeyProvider;
  channelHex: string;
  relayKeys: Map<string, InMemoryKeyProvider>;
  deposits: Seen[];
  logStateAtDeposit: boolean[];
  held: Map<string, Set<number>>;
  /** Relays that refuse, and with what. */
  refuse: Map<string, { reason: string; skew_ms?: number }>;
  /** Relays that throw outright — a relay that is simply down. */
  down: Set<string>;
  screen: { block: boolean };
  clock: { now: number };
  /** The info record each relay currently holds — empty means no relay was ever told. */
  infoHeld: Map<string, Uint8Array>;
  /** Every prune request a relay received. An empty list means no relay was asked. */
  pruneCalls: Array<{ relay: string; throughSeq: number; signature: Uint8Array }>;
}

async function harness(opts: { access?: "public" | "open" } = {}): Promise<Harness> {
  const log = new ChannelLogStore(db, silent);
  const channelKp = generateKeypair();
  const adminKp = generateKeypair();
  const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
  const relayKeys = new Map<string, InMemoryKeyProvider>([
    [RELAY_A, generateKeypair()],
    [RELAY_B, generateKeypair()],
  ]);
  const deposits: Seen[] = [];
  /** For each deposit, whether the log already held the post when the relay was called. */
  const logStateAtDeposit: boolean[] = [];
  /** What each relay actually holds, so `relayHead` can answer truthfully. */
  const held = new Map<string, Set<number>>([[RELAY_A, new Set()], [RELAY_B, new Set()]]);
  const refuse = new Map<string, { reason: string; skew_ms?: number }>();
  const down = new Set<string>();
  const screen = { block: false };
  const clock = { now: 1_800_000_000_000 };

  const deposit: RelayDepositSeam = async (relay, req) => {
    // ⚠️ WHAT THE LOG HELD AT THE MOMENT THIS WAS CALLED. Asserting only that the post is logged
    // AFTERWARDS proves nothing about order — it is logged either way. The first version of test 2
    // did exactly that and passed against a publisher that deposited first.
    const decodedNow = decodeBroadcastArtifact(req.post_cbor);
    if (decodedNow.ok) {
      let loggedAtDepositTime = false;
      try {
        loggedAtDepositTime = log.readRange(channelHex, decodedNow.artifact.seq, decodedNow.artifact.seq).length > 0;
      } catch {
        loggedAtDepositTime = false; // the channel is not even open in the log yet
      }
      logStateAtDeposit.push(loggedAtDepositTime);
    }
    if (down.has(relay)) throw new Error(`relay ${relay} is unreachable`);
    deposits.push({ relay, postCbor: req.post_cbor });
    const refusal = refuse.get(relay);
    if (refusal) {
      refuse.delete(relay); // refuse once, so a retry can be observed succeeding
      return { ok: false, reason: refusal.reason, ...(refusal.skew_ms !== undefined ? { skew_ms: refusal.skew_ms } : {}) };
    }
    const decoded = decodeBroadcastArtifact(req.post_cbor);
    if (!decoded.ok) return { ok: false, reason: "bad_post" };
    held.get(relay)!.add(decoded.artifact.seq);
    const receipt = await signRelayPostReceipt(relayKeys.get(relay)!, decoded.artifact, clock.now);
    const { encodeRelayPostReceipt } = await import("@cello-protocol/protocol-types");
    return { ok: true, receipt_cbor: encodeRelayPostReceipt(receipt) };
  };

  /** Info records each relay holds, so a test can ask whether a deposit actually reached one. */
  const infoHeld = new Map<string, Uint8Array>();
  const depositInfo: RelayInfoDepositSeam = (relay, req) => {
    if (down.has(relay)) throw new Error(`relay ${relay} is unreachable`);
    const refusal = refuse.get(relay);
    if (refusal) {
      refuse.delete(relay);
      return Promise.resolve({ ok: false, reason: refusal.reason });
    }
    infoHeld.set(relay, req.info_cbor);
    return Promise.resolve({ ok: true });
  };

  /** Prune requests each relay received, so a test can tell "asked and dropped" from "never asked". */
  const pruneCalls: Array<{ relay: string; throughSeq: number; signature: Uint8Array }> = [];
  const prune: RelayPruneSeam = (relay, req) => {
    if (down.has(relay)) throw new Error(`relay ${relay} is unreachable`);
    pruneCalls.push({ relay, throughSeq: req.throughSeq, signature: req.signature });
    const holding = held.get(relay)!;
    let dropped = 0;
    for (const seq of [...holding]) {
      if (seq <= req.throughSeq) { holding.delete(seq); dropped += 1; }
    }
    return Promise.resolve({ ok: true, dropped });
  };

  // Captured so a test can rebuild the publisher with ONE seam swapped for the production one.
  const options: ChannelPublisherOptions = {
    depositInfo,
    prune,
    // No waiting in tests. Production paces refills under the relay's rate limit.
    resendPaceMs: 0,
    logger: silent,
    log,
    now: () => clock.now,
    deposit,
    // What the relay HOLDS, which is the question a refill has to ask — a receipt says it took the
    // post once, not that it still has it.
    relayHead: (relay) => {
      const seqs = [...held.get(relay)!].sort((a, b) => a - b);
      return Promise.resolve({
        first_held_seq: seqs.length > 0 ? seqs[0] : null,
        last_seq: seqs.length > 0 ? seqs[seqs.length - 1] : null,
      });
    },
    // The seam `cello_send` uses. The subscriber's inbound screen is the enforcement; this is the
    // early check that spares an honest publisher the friction.
    screenOutbound: () => Promise.resolve(screen.block ? { disposition: "block", reason: "injection" } : { disposition: "allow" }),
    /**
     * ⚠️ BOTH LOOKUPS ARE NAME-SENSITIVE, and that is not fussiness. They ignored their argument,
     * so the publisher's skew retry — which asked for the agent key under the EMPTY STRING — passed
     * every test while being `null` in production, where the real lookup is a map read. A harness
     * that answers any question with the right key cannot see a caller asking the wrong one.
     */
    getChannelKey: (hex) => (hex.toLowerCase() === channelHex.toLowerCase() ? channelKp : null),
    getAgentKey: (name) => (name === "agent-1" ? adminKp : null),
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
  };
  const publisher = new ChannelPublisher(options);

  return {
    publisher, options, log, channelKp, adminKp, channelHex, relayKeys, deposits, logStateAtDeposit,
    held, refuse, down, screen, clock, infoHeld, pruneCalls,
  };
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

    // ⚠️ AND THE ORDER ITSELF, which "it is logged afterwards" does not prove — it is logged either
    // way. Every relay call saw the post ALREADY in the log.
    expect(h.logStateAtDeposit.length, "both relays were attempted").toBe(2);
    expect(
      h.logStateAtDeposit.every((seen) => seen),
      "a relay was called before the post was durable — reverse the order and this is what catches it",
    ).toBe(true);
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

  it("5. clock_skew re-signs ONCE, at the LARGEST reported skew, and sends the SAME bytes to both relays", async () => {
    const h = await harness();
    // Both relays refuse, by different amounts. Correcting to the smaller one would leave the
    // stricter relay refusing again with no retry left.
    h.refuse.set(RELAY_A, { reason: "clock_skew", skew_ms: 60_000 });
    h.refuse.set(RELAY_B, { reason: "clock_skew", skew_ms: 90_000 });
    // The harness refuses once per relay, so the corrected attempt is the one they accept.

    const result = await h.publisher.publish("agent-1", h.channelHex, "re-signed", "body");
    expect(result.ok).toBe(true);

    const toA = h.deposits.filter((d) => d.relay === RELAY_A);
    const toB = h.deposits.filter((d) => d.relay === RELAY_B);
    expect(toA, "the refused attempt and the corrected one").toHaveLength(2);
    expect(toB).toHaveLength(2);

    // ⚠️ A NEW SIGNATURE OVER A NEW TIME. The time is inside the signature, so re-sending the same
    // bytes could never satisfy the relay — retrying without re-signing would loop forever.
    expect(Buffer.from(toA[0].postCbor).equals(Buffer.from(toA[1].postCbor))).toBe(false);

    /**
     * ⚠️ **THE HEART OF THIS TEST: BOTH RELAYS GET IDENTICAL BYTES.** Correcting per relay gives
     * relay A one body at post 1 and relay B another — and a subscriber taking the union of the two
     * sees precisely what a fork looks like, manufactured by an honest publisher with a bad clock.
     */
    expect(Buffer.from(toA[1].postCbor).equals(Buffer.from(toB[1].postCbor))).toBe(true);

    const first = decodeBroadcastArtifact(toA[0].postCbor);
    const second = decodeBroadcastArtifact(toA[1].postCbor);
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    // The LARGEST skew, not the first one heard: 90s, the amount the stricter relay reported.
    expect(second.artifact.published_at).toBe(first.artifact.published_at - 90_000);
    expect(second.artifact.seq, "a correction is the SAME post, not the next one").toBe(first.artifact.seq);

    // And the LOG holds the corrected bytes — the ones the relays took and receipted. Leaving the
    // original there would mean every receipt named bytes the publisher could not produce again.
    const stored = h.log.readRange(h.channelHex, 1, 1)[0];
    expect(stored.published_at).toBe(second.artifact.published_at);
    expect(h.log.receiptsFor(h.channelHex, 1), "both relays' receipts filed").toHaveLength(2);
  });

  it("5b. a relay that ALREADY took the post is never re-signed under: the receipt stays valid", async () => {
    const h = await harness();
    // A takes it; B refuses for skew. There is now a receipt bound to those bytes by hash.
    h.refuse.set(RELAY_B, { reason: "clock_skew", skew_ms: 90_000 });

    const result = await h.publisher.publish("agent-1", h.channelHex, "one took it", "body");
    expect(result.ok).toBe(true);

    // ⚠️ NO CORRECTION HAPPENED. One relay accepting means those bytes ARE the post; re-signing
    // under A's receipt would strand it, and put two bodies at post 1 across the two relays.
    expect(h.deposits.filter((d) => d.relay === RELAY_A), "A was asked once").toHaveLength(1);
    expect(h.deposits.filter((d) => d.relay === RELAY_B), "B was asked once").toHaveLength(1);

    const receipts = h.log.receiptsFor(h.channelHex, 1);
    expect(receipts, "A's receipt, and it still binds the stored bytes").toHaveLength(1);
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

  it("7b. with NO group key — production today — a non-public channel FAILS CLOSED", async () => {
    /**
     * ⚠️ **THE SEAM THE DAEMON ACTUALLY WIRES, not the test's stand-in.** 019 owns the group key, so
     * the real `encryptBody` rejects. Test 7 proves the publisher encrypts when it CAN; this proves
     * what happens when it cannot, which is the case in production right now.
     *
     * The failure direction is the whole point: a publisher that fell back to plaintext would put
     * the operator's content on two public relays under an `access` promising members-only. Nothing
     * is signed, numbered, logged or deposited.
     */
    const h = await harness({ access: "open" });
    const failClosed = new ChannelPublisher({
      ...h.options,
      encryptBody: () => Promise.reject(new Error("channel_group_key_unavailable")),
    });

    await expect(failClosed.publish("agent-1", h.channelHex, "members only", "secret words")).rejects.toThrow(
      "channel_group_key_unavailable",
    );
    expect(h.deposits, "nothing reached a relay").toEqual([]);
    // The channel was never even opened in the log: the refusal happens before a number is taken.
    let thrown: unknown;
    try { h.log.head(h.channelHex); } catch (err) { thrown = err; }
    expect(thrown, "no position was burned on a post that was never made").toBeDefined();
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

    /**
     * ⚠️ **THE RELAYS WERE ASKED, AND THEY DROPPED.** The earlier version of this test asserted
     * `pruned.relays.map(r => r.relay)` — which is the channel's CONFIGURED relay list, true of code
     * that contacts nobody. It passed against exactly that: a `relays.map(r => ({relay: r, ok: true}))`
     * that told the operator both relays had dropped 500 posts while both still served every one.
     */
    expect(h.pruneCalls.map((c) => c.relay).sort()).toEqual([RELAY_A, RELAY_B].sort());
    for (const call of h.pruneCalls) {
      expect(call.throughSeq).toBe(2);
      // Signed by the CHANNEL key: without a signature anyone knowing the public key could delete
      // the channel's backbone from both relays.
      expect(call.signature.length).toBe(64);
    }
    // What the relays actually still hold — the assertion the operator's belief rests on.
    expect([...h.held.get(RELAY_A)!].sort()).toEqual([3]);
    expect([...h.held.get(RELAY_B)!].sort()).toEqual([3]);
    expect(pruned.relays.every((r) => r.ok)).toBe(true);
  });

  it("9b. a relay that is DOWN is reported as still holding the posts, never as pruned", async () => {
    const h = await harness();
    for (const t of ["a", "b", "c"]) await h.publisher.publish("agent-1", h.channelHex, t, "body");
    h.down.add(RELAY_B);

    const pruned = await h.publisher.pruneChannel("agent-1", h.channelHex, 2);
    // The local log is pruned either way: that half cannot fail partway.
    expect(pruned.pruned).toBe(2);
    expect(pruned.relays.find((r) => r.relay === RELAY_A)?.ok).toBe(true);
    // ⚠️ AND B IS NOT `ok`. It never heard the request and is still serving posts 1 and 2. Reporting
    // it as pruned is the difference between an operator who knows their content is still out there
    // and one who believes it is gone.
    expect(pruned.relays.find((r) => r.relay === RELAY_B)?.ok).toBe(false);
    expect([...h.held.get(RELAY_B)!].sort()).toEqual([1, 2, 3]);
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

    /**
     * ⚠️ **BOTH RELAYS ACTUALLY RECEIVED IT.** Signing the record is not publishing it: this record
     * is the ONLY way a subscriber learns a channel's relays, access and admin key, so a version
     * that signed it, logged `channel.info.published` and returned the bytes to the caller left the
     * operator certain their channel was live while nobody could find it. That version passed this
     * test, because the test stopped at the signature.
     */
    expect([...h.infoHeld.keys()].sort()).toEqual([RELAY_A, RELAY_B].sort());
    expect(Buffer.from(h.infoHeld.get(RELAY_A)!).equals(Buffer.from(published.info_cbor))).toBe(true);
    expect(published.relays.every((r) => r.ok)).toBe(true);

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

  it("10b. no relay takes the info record → the operator is told the channel is undiscoverable", async () => {
    const h = await harness();
    h.down.add(RELAY_A);
    h.down.add(RELAY_B);

    const published = await h.publisher.publishInfo("agent-1", h.channelHex);
    // ⚠️ NOT `ok`. A signed record nobody holds is a channel no subscriber can find, and reporting
    // success here is the failure mode this test exists for.
    expect(published.ok).toBe(false);
    if (published.ok) return;
    expect(published.reason).toBe("no_relay_accepted");
    expect(h.infoHeld.size).toBe(0);
  });
});
