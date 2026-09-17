/**
 * M16 008-EPOCH — enforcer: the epoch cap is enforced by the running daemon, not only by a unit call.
 *
 * Boots the REAL cello-daemon binary as a separate OS process, records its agent as a channel and
 * gives it a channel log whose open epoch's first leaf is 25 hours old, restarts it with a short
 * scheduler tick, and waits for the daemon to seal that epoch on its own with trigger "cap_age".
 */
import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { generateKeypair, InMemoryKeyProvider } from "@cello-protocol/crypto";
import { signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { DbIdentityStore, DbRegistrationPersistence } from "../db-identity-store.js";
import { ChannelLogStore } from "../channel-log-store.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import type { Logger } from "../types.js";

const AGENT = "singleton-test-agent";
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("M16 008-EPOCH enforcer: a real daemon seals an over-age epoch on its own", () => {
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

  it("channel.epoch.sealed with trigger cap_age appears for an epoch opened 25 hours ago", async () => {
    celloDir = await makeCelloDir("cello-m16-008-");
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    await daemon.stopGracefully();
    daemon = undefined;

    const db = openEncryptedDatabaseAtPath(join(celloDir, "sessions.db"));
    let channelHex = "";
    try {
      const row = new DbIdentityStore(db, silent).listAgents().find((a) => a.agentName === AGENT);
      expect(row, "the daemon should have loaded its agent into the identity store").toBeDefined();
      const kp = new InMemoryKeyProvider(row!.kLocalSeed);
      channelHex = Buffer.from(await kp.getPublicKey()).toString("hex");
      await new DbRegistrationPersistence({ db, agentName: AGENT, logger: silent }).persistRegistrationState({
        agentId: "enforcer-channel", primaryPubkey: "5b".repeat(32), mlDsaPubkey: "6c".repeat(32),
        registeredAt: Date.now(), keyBinding: "7d".repeat(64), channel: true,
        adminPubkey: generateKeypair().toJSON()["publicKey"]!,
      });
      const log = new ChannelLogStore(db, silent);
      log.ensureChannel(channelHex);
      const pos = log.nextPosition(channelHex);
      const artifact = await signBroadcastArtifact(kp, {
        seq: pos.seq, epoch_index: pos.epoch_index, title: "a day-old post", body_ciphertext: new Uint8Array([1]),
        supersedes: null, prev_epoch_root: null, ext: null,
      });
      log.append(channelHex, artifact, Date.now() - 25 * 60 * 60 * 1000);
    } finally {
      db.close();
    }

    daemon = spawnRealDaemon(celloDir, { CELLO_CHANNEL_EPOCH_TICK_MS: "500" });
    await daemon.waitForEvent("daemon.started");
    const sealed = await daemon.waitForEvent("channel.epoch.sealed", 20_000);
    console.info(`[m16-008 enforcer] ${JSON.stringify(sealed)}`);
    expect(sealed["trigger"]).toBe("cap_age");
    expect(sealed["channel_pubkey"]).toBe(channelHex);
    expect(sealed["leaf_count"]).toBe(1);
  }, 90_000);
});
