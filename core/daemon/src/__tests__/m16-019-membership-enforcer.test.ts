/**
 * M16 019-MEMBERSHIP — enforcer: an ejection proven across SEPARATE OS PROCESSES.
 *
 * The unit tests prove each decision against a seam. This proves the sequence an operator lives
 * through, with the relays and both members out of process and reached over real libp2p:
 *
 *   1. two members join an invite-only channel and both read a post;
 *   2. one is ejected, which rotates the group key and therefore the fetch key;
 *   3. a further post is published, carrying the new fetch key to both relays;
 *   4. the remaining member reads it — and the ejected one is REFUSED AT THE RELAY, before any
 *      ciphertext moves, rather than merely being unable to decrypt.
 *
 * ⚠️ Step 4 is the whole order. "Cannot read" is the weaker property: an ejected member who can
 * still fetch learns the channel's size, cadence and timing, and a test that only checked
 * decryption would pass against a build that leaked all three.
 *
 * ⚠️ THE RELAYS ARE FIXTURES, not `packages/relay` — that binary lives in the other repository, and
 * 017's enforcer proved it there. What is real here is every line of the member's path and the
 * process and network boundaries between them. Recorded rather than left to be assumed.
 */
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InMemoryKeyProvider, generateGroupKey, encryptBody, deriveFetchKey } from "@cello-protocol/crypto";
import {
  signBroadcastArtifact, encodeBroadcastArtifact, buildChannelFetchKeyTbs,
} from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import { ChannelRelayClient } from "../channel-relay-client.js";
import type { Logger } from "../types.js";

const PKG_ROOT = join(import.meta.dirname, "..", "..");
const HELPERS = join(PKG_ROOT, "src/__tests__/helpers");
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const seedHex = (byte: number): string => Buffer.alloc(32, byte).toString("hex");
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

function startRelay(seed: string): Promise<{ child: ChildProcess; multiaddr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(HELPERS, "m16-018-channel-relay-process.ts"), seed], {
      cwd: PKG_ROOT, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.on("data", (c: Buffer) => {
      out += c.toString("utf-8");
      const line = out.split("\n").find((l) => l.trim().startsWith("{"));
      if (line) {
        const parsed = JSON.parse(line) as { multiaddr: string };
        resolve({ child, multiaddr: parsed.multiaddr });
      }
    });
    child.stderr.on("data", (c: Buffer) => { process.stderr.write(`[relay] ${c.toString("utf-8")}`); });
    child.on("error", reject);
    setTimeout(() => { reject(new Error("relay did not announce in time")); }, 30_000);
  });
}

function runMember(args: string[]): Promise<{ fetched: number[]; decrypted: number[]; refusals: string[] }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(HELPERS, "m16-019-member-process.ts"), ...args], {
      cwd: PKG_ROOT, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (c: Buffer) => { out += c.toString("utf-8"); });
    child.stderr.on("data", (c: Buffer) => { err += c.toString("utf-8"); });
    child.on("error", reject);
    child.on("exit", (code) => {
      const line = out.split("\n").find((l) => l.trim().startsWith("{"));
      if (!line) { reject(new Error(`member exited ${String(code)} with no result: ${err}`)); return; }
      resolve(JSON.parse(line) as { fetched: number[]; decrypted: number[]; refusals: string[] });
    });
  });
}

let dir: string;
const children: ChildProcess[] = [];

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "cello-m16-019e-")); });
afterEach(() => {
  for (const c of children) { try { c.kill("SIGTERM"); } catch { /* already gone */ } }
  children.length = 0;
  rmSync(dir, { recursive: true, force: true });
});

describe("M16 019-MEMBERSHIP enforcer", () => {
  it("an ejected member is refused AT THE RELAY, while the remaining one reads on", async () => {
    const relayA = await startRelay(seedHex(0x51));
    const relayB = await startRelay(seedHex(0x52));
    children.push(relayA.child, relayB.child);

    const channelKp = new InMemoryKeyProvider(new Uint8Array(Buffer.from(seedHex(0x61), "hex")));
    const adminKp = new InMemoryKeyProvider(new Uint8Array(Buffer.from(seedHex(0x62), "hex")));
    const channelPubkey = await channelKp.getPublicKey();
    const channelHex = hex(channelPubkey);
    const adminHex = hex(await adminKp.getPublicKey());

    const memberASeed = seedHex(0x71);
    const memberBSeed = seedHex(0x72);

    // The publisher's own transport, in this process — it is the one role the enforcer drives
    // directly, because what is being proven is what the MEMBERS can and cannot do.
    const node = await createNode({
      listenAddresses: [], keyProvider: adminKp,
      relayServer: { enabled: false }, autonatResponder: { enabled: false },
    });
    await node.start();
    const client = new ChannelRelayClient({ getNode: () => node, logger: silent });

    /** Publish one post under a generation, carrying that generation's fetch key to both relays. */
    async function publish(seq: number, gk: { generation: number; key: Uint8Array }, title: string): Promise<void> {
      const body = encryptBody(gk, channelPubkey, seq, new TextEncoder().encode(`${title} body`));
      const post = await signBroadcastArtifact(channelKp, adminKp, {
        seq, published_at: Date.now(), title, body, supersedes: null, ext: null,
      });
      const fetchKey = await deriveFetchKey(gk, channelPubkey);
      const timeMs = Date.now();
      const signature = await channelKp.sign(buildChannelFetchKeyTbs(channelPubkey, fetchKey.publicKey, timeMs));
      for (const relay of [relayA.multiaddr, relayB.multiaddr]) {
        const answer = await client.deposit(relay, {
          post_cbor: encodeBroadcastArtifact(post),
          fetch_key: { pubkey: fetchKey.publicKey, time_ms: timeMs, signature },
        });
        expect(answer.ok, answer.ok ? "" : answer.reason).toBe(true);
      }
    }

    // ── 1. Generation 1: both members hold it, and both read post 1 ────────────────────────────
    const gen1 = generateGroupKey(1);
    await publish(1, gen1, "before the ejection");

    const gen1Json = JSON.stringify([{ generation: 1, keyHex: hex(gen1.key) }]);
    const argsFor = (seed: string, id: string, keysJson: string): string[] =>
      [join(dir, `${id}.db`), id, channelHex, adminHex, seed, relayA.multiaddr, relayB.multiaddr, keysJson];

    const aBefore = await runMember(argsFor(memberASeed, "member-a", gen1Json));
    const bBefore = await runMember(argsFor(memberBSeed, "member-b", gen1Json));
    expect(aBefore.decrypted, "A reads post 1").toEqual([1]);
    expect(bBefore.decrypted, "B reads post 1 — both are members at this point").toEqual([1]);

    // ── 2 & 3. B is ejected: a NEW generation, and the next post carries its fetch key ─────────
    const gen2 = generateGroupKey(2);
    await publish(2, gen2, "after the ejection");

    // ── 4. A holds the new key. B holds only the old one. ──────────────────────────────────────
    const bothGens = JSON.stringify([
      { generation: 1, keyHex: hex(gen1.key) },
      { generation: 2, keyHex: hex(gen2.key) },
    ]);
    const aAfter = await runMember(argsFor(memberASeed, "member-a2", bothGens));
    expect(aAfter.decrypted, "A reads both posts").toEqual([1, 2]);

    const bAfter = await runMember(argsFor(memberBSeed, "member-b2", gen1Json));
    /**
     * ⚠️ **NOTHING FETCHED AT ALL — not "fetched but unreadable".** B's newest key is generation 1,
     * so the fetch signature it can produce no longer matches what the relays were told to require.
     * Both relays turn it away before any ciphertext moves. A build that had rotated the group key
     * without sending the fetch key would pass a decryption-only check and fail this one, while
     * leaking the channel's size, cadence and timing to somebody who had been removed from it.
     */
    expect(bAfter.fetched, "B gets nothing from either relay").toEqual([]);
    expect(bAfter.decrypted).toEqual([]);
    expect(bAfter.refusals, "and both relays said why").toEqual(["not_a_member", "not_a_member"]);

    await node.stop();
  }, 180_000);
});
