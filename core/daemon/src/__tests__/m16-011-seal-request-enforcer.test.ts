/**
 * M16 011-SEALREQ — enforcer: the requested-seal limiter holds in a real daemon, over its real socket.
 *
 * Boots the REAL cello-daemon binary as a separate OS process, records its agent as a channel with
 * two published leaves in that daemon's own encrypted database, restarts it, and calls
 * `cello_channel_seal` twice back-to-back over the IPC socket. The first must seal; the second must
 * be rate-limited with time left on the window, reporting the seal the first one made.
 */
import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { generateKeypair, InMemoryKeyProvider } from "@cello-protocol/crypto";
import { signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { connectToDaemon } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { DbIdentityStore, DbRegistrationPersistence } from "../db-identity-store.js";
import { ChannelLogStore } from "../channel-log-store.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import type { Logger } from "../types.js";

const AGENT = "singleton-test-agent";
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("M16 011-SEALREQ enforcer: cello_channel_seal twice over a real daemon's socket", () => {
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

  it("the first request is honored and the second is rate-limited with the first seal's root", async () => {
    celloDir = await makeCelloDir("cello-m16-011-");
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    await daemon.stopGracefully();
    daemon = undefined;

    const db = openEncryptedDatabaseAtPath(join(celloDir, "sessions.db"));
    try {
      const row = new DbIdentityStore(db, silent).listAgents().find((a) => a.agentName === AGENT);
      expect(row, "the daemon should have loaded its agent into the identity store").toBeDefined();
      const kp = new InMemoryKeyProvider(row!.kLocalSeed);
      const channelHex = Buffer.from(await kp.getPublicKey()).toString("hex");
      await new DbRegistrationPersistence({ db, agentName: AGENT, logger: silent }).persistRegistrationState({
        agentId: "enforcer-channel", primaryPubkey: "5b".repeat(32), mlDsaPubkey: "6c".repeat(32),
        registeredAt: Date.now(), keyBinding: "7d".repeat(64), channel: true,
        adminPubkey: generateKeypair().toJSON()["publicKey"]!,
      });
      const log = new ChannelLogStore(db, silent);
      log.ensureChannel(channelHex);
      for (let i = 0; i < 2; i++) {
        const pos = log.nextPosition(channelHex);
        const artifact = await signBroadcastArtifact(kp, {
          seq: pos.seq, epoch_index: pos.epoch_index, title: `post ${pos.seq}`, body_ciphertext: new Uint8Array([pos.seq]),
          supersedes: null, prev_epoch_root: null, ext: null,
        });
        log.append(channelHex, artifact, Date.now());
      }
    } finally {
      db.close();
    }

    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    let first: Record<string, unknown>;
    let second: Record<string, unknown>;
    try {
      first = (await client.send("cello_channel_seal", { agent: AGENT })) as Record<string, unknown>;
      second = (await client.send("cello_channel_seal", { agent: AGENT })) as Record<string, unknown>;
    } finally {
      client.close();
    }
    console.info(`[m16-011 enforcer] first:  ${JSON.stringify(first)}`);
    console.info(`[m16-011 enforcer] second: ${JSON.stringify(second)}`);

    expect(first).toMatchObject({ honored: true, epoch_index: 0, leaf_count: 2 });
    expect(second).toMatchObject({ honored: false, reason: "rate_limited", latest_epoch_index: 0, latest_epoch_root: first["epoch_root"] });
    expect(second["retry_after_ms"] as number).toBeGreaterThan(0);
    expect(daemon.output()).toContain("channel.seal_request.honored");
    expect(daemon.output()).toContain("channel.seal_request.rate_limited");
  }, 90_000);
});
