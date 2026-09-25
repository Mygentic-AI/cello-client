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
import { InMemoryKeyProvider } from "@cello-protocol/crypto";

const PKG_ROOT = join(import.meta.dirname, "..", "..");
const HELPERS = join(PKG_ROOT, "src/__tests__/helpers");

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

interface AdminResult {
  channelHex: string; adminHex: string;
  gen1BundleA: string; gen1BundleB: string; gen2BundleA: string;
  ejectGeneration: number; remaining: string[];
}

interface E2EPost { seq: number; title: string; body: string }
interface E2EAdminResult {
  channelHex: string; adminHex: string; gen1BundleA: string;
  publicBundleEmpty?: boolean; posts: E2EPost[];
}
interface CollectResult {
  agentId: string; agentName: string; collected: number[]; posts: E2EPost[];
  deliveredThrough: number; generations: number[];
}

function runHelper<T>(script: string, args: string[]): Promise<T> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(HELPERS, script), ...args], {
      cwd: PKG_ROOT, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (c: Buffer) => { out += c.toString("utf-8"); });
    child.stderr.on("data", (c: Buffer) => { err += c.toString("utf-8"); });
    child.on("error", reject);
    child.on("exit", (code) => {
      const line = out.split("\n").find((l) => l.trim().startsWith("{"));
      if (!line) { reject(new Error(`${script} exited ${String(code)} with no result: ${err}`)); return; }
      resolve(JSON.parse(line) as T);
    });
  });
}

const runAdmin = (args: string[]): Promise<AdminResult> =>
  runHelper<AdminResult>("m16-019-admin-process.ts", args);

function runMember(args: string[]): Promise<{ fetched: number[]; decrypted: number[]; refusals: string[] }> {
  return new Promise((resolve, reject) => {
    // The ejection path is the member helper's `fetch` mode; `collect` is the 037 end-to-end path.
    const child = spawn(process.execPath, ["--import", "tsx", join(HELPERS, "m16-019-member-process.ts"), "fetch", ...args], {
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

    const memberASeed = seedHex(0x71);
    const memberBSeed = seedHex(0x72);
    const memberAHex = hex(await new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberASeed, "hex"))).getPublicKey());
    const memberBHex = hex(await new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberBSeed, "hex"))).getPublicKey());

    /**
     * ⚠️ **THE ADMIN RUNS THE REAL CODE, IN ITS OWN PROCESS.** Both members join through
     * `ChannelJoinExchange.onAdminFrame` and the admin's explicit approval; the ejection is
     * `ChannelMembershipStore.eject`; both posts go through `ChannelPublisher` with the fetch key
     * derived from the group key the join stored. The first version of this test built keys by hand
     * and deposited directly, so reverting this entire unit left it green.
     */
    const adminArgs = (ph: string): string[] => [
      join(dir, "admin.db"), seedHex(0x61), seedHex(0x62),
      memberAHex, memberBHex, relayA.multiaddr, relayB.multiaddr, ph,
    ];
    const setup = await runAdmin(adminArgs("setup"));
    const channelHex = setup.channelHex;

    const argsFor = (seed: string, id: string, bundles: string[]): string[] =>
      [join(dir, `${id}.db`), id, channelHex, setup.adminHex, seed, relayA.multiaddr, relayB.multiaddr,
        JSON.stringify(bundles)];

    // ── 1. Both members joined and both read the first post ───────────────────────────────────
    const aBefore = await runMember(argsFor(memberASeed, "member-a", [setup.gen1BundleA]));
    const bBefore = await runMember(argsFor(memberBSeed, "member-b", [setup.gen1BundleB]));
    expect(aBefore.decrypted, "A reads post 1").toEqual([1]);
    expect(bBefore.decrypted, "B reads post 1 — both are members at this point").toEqual([1]);

    // ── 2 & 3. A SECOND admin process ejects B and publishes again ─────────────────────────────
    // A fresh process on the same database: the admin's group key and settings have to survive a
    // restart, which is the property that broke when the key lived only in memory.
    const ejected = await runAdmin(adminArgs("eject"));
    expect(ejected.ejectGeneration, "the store advanced the generation").toBe(2);
    expect(ejected.remaining, "only A remains a member").toEqual([memberAHex]);

    // ── 4. A holds the re-key bundle; B was never sent one ────────────────────────────────────
    const aAfter = await runMember(argsFor(memberASeed, "member-a2", [setup.gen1BundleA, ejected.gen2BundleA]));
    expect(aAfter.decrypted, "A reads both posts").toEqual([1, 2]);

    const bAfter = await runMember(argsFor(memberBSeed, "member-b2", [setup.gen1BundleB]));
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

  }, 180_000);

  /**
   * 037-TESTTRUTH end-to-end (decision 2): the whole channel flow through the PRODUCTION wiring,
   * across separate OS processes. The admin publishes through the real `ChannelPublisher` (encrypting
   * via the production group-key path, 028); the member reads through the real `ChannelCollector`
   * with `createChannelFetchAuth` (030), driven by `createChannelCollectTicker` whose online check is
   * `createIsAgentOnlineById` (029) — and the member's id ≠ its name, so the id→name mapping is
   * load-bearing. Assertions name the exact plaintext, never "it did not throw".
   */
  it("end-to-end: invite-only join→approve→publish 2→collect→read both as exact plaintext, then a public read", async () => {
    const relayA = await startRelay(seedHex(0x53));
    const relayB = await startRelay(seedHex(0x54));
    children.push(relayA.child, relayB.child);

    const memberSeed = seedHex(0x73);
    const memberHex = hex(await new InMemoryKeyProvider(new Uint8Array(Buffer.from(memberSeed, "hex"))).getPublicKey());

    // ── invite-only: admin registers the channel, member joins, admin approves, admin publishes 2 ──
    const inviteAdmin = await runHelper<E2EAdminResult>("m16-019-admin-process.ts", [
      join(dir, "e2e-invite-admin.db"), seedHex(0x63), seedHex(0x64),
      memberHex, memberHex, relayA.multiaddr, relayB.multiaddr, "e2e-invite",
    ]);
    expect(inviteAdmin.posts.map((p) => p.seq), "the admin published two posts").toEqual([1, 2]);
    expect(inviteAdmin.gen1BundleA.length, "the member was sent a wrapped key bundle").toBeGreaterThan(0);

    // The member collects through the production collector + fetch auth, its online check keyed on an
    // id that differs from its name — and reads BOTH posts as the exact titles and bodies the admin
    // published.
    const inviteRead = await runHelper<CollectResult>("m16-019-member-process.ts", [
      "collect", join(dir, "e2e-invite-member.db"), "member-stable-id", "member-display-name",
      inviteAdmin.channelHex, inviteAdmin.adminHex, memberSeed, "invite_only",
      relayA.multiaddr, relayB.multiaddr, JSON.stringify([inviteAdmin.gen1BundleA]),
    ]);
    expect(inviteRead.collected, "the member collected both posts").toEqual([1, 2]);
    expect(inviteRead.posts, "and read them as the exact plaintext the admin published").toEqual(inviteAdmin.posts);
    // Decision 3: delivered_through advanced across the contiguous run, and the member holds the
    // generation-1 group key the join delivered (that key is what let it decrypt).
    expect(inviteRead.deliveredThrough, "delivered_through advanced to the second post").toBe(2);
    expect(inviteRead.generations, "the member holds the generation-1 group key from the join").toEqual([1]);

    // ── public: member joins a public channel → admitted with an empty bundle → reads a post ────────
    const publicAdmin = await runHelper<E2EAdminResult>("m16-019-admin-process.ts", [
      join(dir, "e2e-public-admin.db"), seedHex(0x65), seedHex(0x66),
      memberHex, memberHex, relayA.multiaddr, relayB.multiaddr, "e2e-public",
    ]);
    expect(publicAdmin.publicBundleEmpty, "a public join is admitted with an empty key bundle").toBe(true);
    expect(publicAdmin.posts.map((p) => p.seq)).toEqual([1]);

    const publicRead = await runHelper<CollectResult>("m16-019-member-process.ts", [
      "collect", join(dir, "e2e-public-member.db"), "public-stable-id", "public-display-name",
      publicAdmin.channelHex, publicAdmin.adminHex, memberSeed, "public",
      relayA.multiaddr, relayB.multiaddr, JSON.stringify([]),
    ]);
    expect(publicRead.collected, "the public reader collected the post").toEqual([1]);
    expect(publicRead.posts, "and read it as the exact plaintext").toEqual(publicAdmin.posts);
    expect(publicRead.deliveredThrough, "delivered_through advanced to the public post").toBe(1);
    expect(publicRead.generations, "a public channel carries no group key").toEqual([]);
  }, 180_000);
});
