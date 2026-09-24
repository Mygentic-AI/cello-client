/**
 * M16 006-NOCONVERSE — enforcer: a channel's refusal to initiate holds across a real process boundary.
 *
 * The unit tests run the daemon inside the test's own process. This spawns the REAL `cello-daemon`
 * binary as a separate OS process, records the agent as a registered channel in that daemon's own
 * encrypted database (through the production registration writer), restarts it, and calls
 * `cello_initiate_session` over its IPC socket. What crosses the socket is what a CLI or MCP client
 * would actually receive.
 */

import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import { connectToDaemon } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { DbRegistrationPersistence } from "../db-identity-store.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import type { Logger } from "../types.js";
import { fixturePqIdentityRecord, registeredPqFields } from "./helpers/pq-identity.js";

const AGENT = "singleton-test-agent";
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("M16 006-NOCONVERSE enforcer: cello_initiate_session as a channel over a real daemon's socket", () => {
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

  it("a channel agent is refused with channel_cannot_initiate", async () => {
    celloDir = await makeCelloDir("cello-m16-006-");

    // First boot creates the encrypted DB and moves the agent's identity into it.
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    await daemon.stopGracefully();
    daemon = undefined;

    // Record the agent as a registered channel, exactly as a channel registration leaves the row.
    const db = openEncryptedDatabaseAtPath(join(celloDir, "sessions.db"));
    try {
      const enforcerPersistence = new DbRegistrationPersistence({ db, agentName: AGENT, logger: silent });
      const enforcerPq = await fixturePqIdentityRecord("enforcer-channel");
      await enforcerPersistence.persistPqIdentity(enforcerPq);
      await enforcerPersistence.persistRegistrationState({
        agentId: "enforcer-channel",
        primaryPubkey: "5b".repeat(32),
        ...registeredPqFields(enforcerPq),
        registeredAt: Date.now(),
        keyBinding: "7d".repeat(64),
        channel: true,
        adminPubkey: generateKeypair().toJSON()["publicKey"]!,
      });
    } finally {
      db.close();
    }

    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    try {
      const result = (await client.send("cello_initiate_session", {
        agent: AGENT,
        target_pubkey: "ab".repeat(32),
      })) as { ok: boolean; reason?: string };
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("channel_cannot_initiate");
    } finally {
      client.close();
    }
    expect(daemon.output()).toContain("session.initiate.refused_channel");
  });
});
