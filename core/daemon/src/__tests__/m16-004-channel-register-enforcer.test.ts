/**
 * M16 004-IDENTITY-WIRE — enforcer: the channel-registration refusal holds across a real process
 * boundary.
 *
 * The unit tests call the handler in the test's own process. This spawns the REAL `cello-daemon`
 * binary as a separate OS process and calls `cello_register` over its IPC socket, so what is proven
 * is what a CLI or MCP client would actually receive: a channel registration missing its admin
 * pubkey comes back as `invalid_channel_registration`, not as some later failure.
 *
 * A full live channel registration against a real directory is order 005's enforcer; a directory
 * cannot echo the channel flag until 005 ships.
 */

import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { connectToDaemon } from "../ipc-client.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";

describe("M16 004-IDENTITY-WIRE enforcer: cello_register over a real daemon's socket", () => {
  let celloDir: string | undefined;
  let daemon: SpawnedDaemon | undefined;

  afterEach(async () => {
    if (daemon) {
      await daemon.stopGracefully().catch(() => daemon?.kill("SIGKILL"));
      daemon = undefined;
    }
    await cleanupCelloDir(celloDir);
    celloDir = undefined;
  });

  it("a channel registration without adminPubkeyHex is refused with invalid_channel_registration", async () => {
    celloDir = await makeCelloDir("cello-m16-004-");
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");

    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    try {
      const result = (await client.send("cello_register", {
        agent: "singleton-test-agent",
        preAuthToken: "enforcer-token",
        channel: true,
      })) as { ok: boolean; reason?: string };
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("invalid_channel_registration");
    } finally {
      client.close();
    }
  });
});
