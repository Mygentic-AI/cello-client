/**
 * M16 018-PUBCOLLECT — enforcer: publish and collect across SEPARATE OS PROCESSES over real libp2p.
 *
 * The unit tests prove the decisions in one heap, against a fake seam. This proves the sequence the
 * order actually describes, with the relays out of process and reached over the wire:
 *
 *   1. five posts published to two relays, with post 3 WITHHELD from one of them;
 *   2. a subscriber ending with all five at `delivered_through` 5 — the union working;
 *   3. a relay killed, a sixth post published anyway with one receipt — one relay down is not a
 *      failed publish;
 *   4. the relay restarted and refilled by `resendMissing`, catching up.
 *
 * ⚠️ THE RELAYS ARE FIXTURES, NOT `packages/relay`. That binary lives in trustless-cello, which this
 * repo does not depend on; 017's own enforcer proved it against the real thing. What is real here is
 * every line of the DAEMON's path — publisher, collector, relay client, stores — and the process
 * and network boundaries between them. Recorded on the order rather than left to be assumed.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";

const PKG_ROOT = join(import.meta.dirname, "../..");
const HELPERS = join(PKG_ROOT, "src/__tests__/helpers");

const seedHex = (byte: number): string => Buffer.alloc(32, byte).toString("hex");
const CHANNEL_SEED = seedHex(0x31);
const ADMIN_SEED = seedHex(0x32);

function pubkeyOf(seed: string): Promise<Uint8Array> {
  return new InMemoryKeyProvider(new Uint8Array(Buffer.from(seed, "hex"))).getPublicKey();
}

function run(script: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(HELPERS, script), ...args], {
      cwd: PKG_ROOT, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => { stdout += c.toString("utf-8"); });
    child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf-8"); });
    child.on("error", reject);
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

interface RunningRelay { child: ChildProcess; multiaddr: string }

async function startRelay(seed: string, withheldSeqs: number[] = []): Promise<RunningRelay> {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", join(HELPERS, "m16-018-channel-relay-process.ts"), seed, withheldSeqs.join(",")],
    { cwd: PKG_ROOT, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"] },
  );
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (c: Buffer) => { stdout += c.toString("utf-8"); });
  child.stderr?.on("data", (c: Buffer) => { stderr += c.toString("utf-8"); });

  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const line = stdout.split("\n").find((l) => l.trim().startsWith("{"));
    if (line) return { child, multiaddr: (JSON.parse(line) as { multiaddr: string }).multiaddr };
    if (child.exitCode !== null) throw new Error(`relay exited (${String(child.exitCode)}):\n${stderr}`);
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`relay did not report an address:\n${stderr}`);
}

const running: ChildProcess[] = [];
let dir: string | undefined;

afterEach(() => {
  for (const child of running.splice(0)) child.kill("SIGKILL");
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

describe("M16 018-PUBCOLLECT enforcer — two relays, two daemons, separate processes", () => {
  it("withheld post, union, a relay death mid-run, and a refill that catches up", async () => {
    dir = mkdtempSync(join(tmpdir(), "cello-m16-018-enf-"));
    const channelHex = Buffer.from(await pubkeyOf(CHANNEL_SEED)).toString("hex");
    const adminHex = Buffer.from(await pubkeyOf(ADMIN_SEED)).toString("hex");

    // Relay B refuses post 3, so the two queues genuinely differ — which is the design, not a fault.
    const relayA = await startRelay(seedHex(0x41));
    const relayB = await startRelay(seedHex(0x42), [3]);
    running.push(relayA.child, relayB.child);

    // ── 1. publish five, one withheld from B ────────────────────────────────────────────────
    const pubDb = join(dir, "publisher.db");
    const published = await run("m16-018-daemon-process.ts", [
      "publish", pubDb, CHANNEL_SEED, ADMIN_SEED, relayA.multiaddr, relayB.multiaddr, "5",
    ]);
    expect(published.code, published.stderr.slice(-800)).toBe(0);
    const pubResult = JSON.parse(published.stdout.trim()) as {
      published: Array<{ seq: number; relays_ok: string[]; relays_failed: string[] }>;
    };
    console.info(`[m16-018 enforcer] published: ${JSON.stringify(pubResult.published)}`);
    expect(pubResult.published.map((p) => p.seq)).toEqual([1, 2, 3, 4, 5]);
    // Post 3 reached only one relay, and that is still a successful publish.
    const third = pubResult.published.find((p) => p.seq === 3)!;
    expect(third.relays_ok).toHaveLength(1);
    expect(third.relays_failed).toHaveLength(1);

    // ── 2. a subscriber ends with all five, from the union ──────────────────────────────────
    const subDb = join(dir, "subscriber.db");
    const collected = await run("m16-018-daemon-process.ts", [
      "collect", subDb, channelHex, adminHex, relayA.multiaddr, relayB.multiaddr,
    ]);
    expect(collected.code, collected.stderr.slice(-800)).toBe(0);
    const collectResult = JSON.parse(collected.stdout.trim()) as {
      delivered_through: number; processed_through: number; held: number[]; missing: number[];
    };
    console.info(`[m16-018 enforcer] collected: ${JSON.stringify(collectResult)}`);
    expect(collectResult.held).toEqual([1, 2, 3, 4, 5]);
    expect(collectResult.delivered_through, "the union closes the gap one relay had").toBe(5);
    expect(collectResult.missing).toEqual([]);
    // ⚠️ A fetch never marks anything as read.
    expect(collectResult.processed_through).toBe(0);

    // ── 3. kill a relay, publish a sixth: one receipt, still a success ───────────────────────
    relayB.child.kill("SIGKILL");
    await new Promise((r) => setTimeout(r, 500));
    // ⚠️ THE SAME publisher database, so the post takes the NEXT number. A fresh database would
    // restart at 1, and a relay that already holds 1 refuses it `position_taken` — which would look
    // like "the surviving relay rejected the post" when the real cause is a publisher that forgot
    // what it had already sent.
    const sixth = await run("m16-018-daemon-process.ts", [
      "publish", pubDb, CHANNEL_SEED, ADMIN_SEED, relayA.multiaddr, relayB.multiaddr, "1",
    ]);
    expect(sixth.code, sixth.stderr.slice(-800)).toBe(0);
    const sixthResult = JSON.parse(sixth.stdout.trim()) as {
      published: Array<{ seq: number; relays_ok: string[]; relays_failed: string[] }>;
    };
    console.info(`[m16-018 enforcer] with one relay dead: ${JSON.stringify(sixthResult.published)}`);
    expect(sixthResult.published[0].relays_ok, "the surviving relay took it").toHaveLength(1);
    expect(sixthResult.published[0].relays_failed, "the dead one is reported, not hidden").toHaveLength(1);

    // ── 4. restart the relay and refill it ───────────────────────────────────────────────────
    const relayBAgain = await startRelay(seedHex(0x42));
    running.push(relayBAgain.child);
    const refilled = await run("m16-018-daemon-process.ts", [
      "resend", pubDb, CHANNEL_SEED, ADMIN_SEED, relayA.multiaddr, relayBAgain.multiaddr, relayBAgain.multiaddr,
    ]);
    expect(refilled.code, refilled.stderr.slice(-800)).toBe(0);
    const refillResult = JSON.parse(refilled.stdout.trim()) as { deposited: number };
    console.info(`[m16-018 enforcer] refilled: ${JSON.stringify(refillResult)}`);
    // A restarted relay holds nothing, so every logged post goes back — which is exactly what makes
    // the publisher's log the durable copy behind both relays. Six now: the five from before plus
    // the one published while this relay was dead.
    expect(refillResult.deposited).toBe(6);

    // And the subscriber can now get everything from the refilled relay alone.
    const fromRefilled = await run("m16-018-daemon-process.ts", [
      "collect", join(dir, "subscriber2.db"), channelHex, adminHex, relayBAgain.multiaddr, relayBAgain.multiaddr,
    ]);
    expect(fromRefilled.code, fromRefilled.stderr.slice(-800)).toBe(0);
    const refilledCollect = JSON.parse(fromRefilled.stdout.trim()) as { delivered_through: number; held: number[] };
    console.info(`[m16-018 enforcer] from the refilled relay alone: ${JSON.stringify(refilledCollect)}`);
    expect(refilledCollect.held).toEqual([1, 2, 3, 4, 5, 6]);
    expect(refilledCollect.delivered_through).toBe(6);
  }, 300_000);
});
