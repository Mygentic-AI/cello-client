/**
 * M16 016-CLIENTREWORK — enforcer: the post log survives the process that wrote it, and the epoch
 * verb is gone from a real daemon.
 *
 * Two separate OS processes: A signs three posts, appends them with a relay receipt each, and
 * exits; B opens the same encrypted database, verifies every post and receipt against the keys
 * inside the stored bytes, and prints the head. Then a REAL daemon binary boots and is asked for
 * `cello_channel_seal`, which must now be an unknown verb, with no channel-epoch event in its log.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connectToDaemon } from "../ipc-client.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";

const PKG_ROOT = join(import.meta.dirname, "../..");

function runNode(script: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(PKG_ROOT, "src/__tests__/helpers", script), ...args], {
      cwd: PKG_ROOT,
      env: { ...process.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => { stdout += c.toString("utf-8"); });
    child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf-8"); });
    child.on("error", reject);
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("M16 016-CLIENTREWORK enforcer", () => {
  let dir: string | undefined;
  let celloDir: string | undefined;
  let daemon: SpawnedDaemon | undefined;

  afterEach(async () => {
    if (daemon) {
      await daemon.stopGracefully().catch(() => daemon?.kill("SIGKILL"));
      daemon = undefined;
    }
    await cleanupCelloDir(celloDir);
    celloDir = undefined;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  it("one process publishes three posts with receipts; a SECOND process verifies them all", async () => {
    dir = mkdtempSync(join(tmpdir(), "cello-m16-016-"));
    const dbPath = join(dir, "sessions.db");

    const publish = await runNode("m16-016-publish-process.ts", [dbPath]);
    expect(publish.stderr, publish.stderr).toBe("");
    expect(publish.code).toBe(0);
    const published = JSON.parse(publish.stdout.trim()) as { channel: string; seqs: number[] };
    console.info(`[m16-016 enforcer] process A: ${publish.stdout.trim()}`);
    expect(published.seqs).toEqual([1, 2, 3]);

    const verify = await runNode("m16-016-verify-process.ts", [dbPath, published.channel]);
    expect(verify.stderr, verify.stderr).toBe("");
    expect(verify.code).toBe(0);
    console.info(`[m16-016 enforcer] process B: ${verify.stdout.trim()}`);
    const verified = JSON.parse(verify.stdout.trim()) as {
      posts: Array<{ seq: number }>; receipts: number; head: unknown; failures: string[]; all_verified: boolean;
    };
    expect(verified.failures).toEqual([]);
    expect(verified.all_verified).toBe(true);
    expect(verified.posts.map((p) => p.seq)).toEqual([1, 2, 3]);
    expect(verified.receipts).toBe(3);
    expect(verified.head).toEqual({ first_seq: 1, last_seq: 3, pruned_through: 0 });
  }, 120_000);

  it("3. a real daemon refuses cello_channel_seal as an unknown verb, and logs no epoch event", async () => {
    celloDir = await makeCelloDir("cello-m16-016-");
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");

    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    let refusal: string;
    try {
      await client.send("cello_channel_seal", { agent: "singleton-test-agent" });
      refusal = "the verb was answered";
    } catch (err) {
      refusal = err instanceof Error ? err.message : String(err);
    } finally {
      client.close();
    }
    console.info(`[m16-016 enforcer] cello_channel_seal → ${refusal}`);
    expect(refusal).not.toBe("the verb was answered");
    expect(refusal.toLowerCase()).toContain("unknown");

    const output = daemon.output();
    expect(output).toContain("daemon.started");
    expect(output).not.toContain("channel.epoch");
    expect(output).not.toContain("channel.seal_request");
  }, 120_000);
});
