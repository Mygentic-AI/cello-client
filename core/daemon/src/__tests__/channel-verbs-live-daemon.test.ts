/**
 * M16 018-PUBCOLLECT — the four channel verbs against a REAL daemon, over a REAL socket.
 *
 * ⚠️ **THIS IS THE LAYER EVERY EXPENSIVE DEFECT IN THIS UNIT LIVED IN.** The unit tests build a
 * publisher from seams and prove its decisions; the enforcer runs publisher and collector across OS
 * processes. Both bypass the handlers, the wiring and the CLI — so all of these shipped green:
 *
 *   - the verbs were registered into a map nothing wired, reachable from no surface at all;
 *   - nothing could write a channel's relay list, so every verb answered `channel_unknown` for
 *     every channel, for ever;
 *   - `resend` demanded a relay multiaddr the CLI never sent, so it could not succeed;
 *   - the clock-skew retry looked its key up under the empty string and was always `null`.
 *
 * Each one is invisible from either side alone and obvious the moment a daemon is asked to do the
 * thing an operator would ask it to do. That is what this file does and all it does — it asserts
 * the verbs are REACHABLE and answer coherently, not that a relay took anything, because there is
 * no relay here. Delivery is the enforcer's job.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";

const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";

describe("M16 018-PUBCOLLECT: the channel verbs on a live daemon", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let client: IpcClient | null;
  /** alice's public key: she is the agent AND, for this test, the channel. */
  let alicePubkeyHex: string;

  const silent: Logger = {
    debug: () => undefined, info: () => undefined, warn: () => undefined, error: () => undefined,
  } as unknown as Logger;

  async function config(): Promise<DaemonConfig> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    const kp = await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    alicePubkeyHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: silent,
    };
  }

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-m16-verbs-"));
    handle = null;
    client = null;
    handle = await startDaemon(await config());
    client = await connectToDaemon(join(tempDir, "daemon.sock"));
    await client.send("ipc.connect", { clientType: "cli" });
  });

  afterEach(async () => {
    if (client) { try { client.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  const call = (verb: string, params: Record<string, unknown>): Promise<Record<string, unknown>> =>
    client!.send(verb, params) as Promise<Record<string, unknown>>;

  it("27. all five verbs are REACHABLE on the operator's socket", () => {
    const verbs = [...handle!.getHandlers().keys()];
    /**
     * ⚠️ The check that would have caught 017's hole and this unit's first cut. A handler module
     * that is written, compiled and tested but never registered is a feature that does not exist,
     * and nothing else in this file can run if this fails.
     */
    for (const verb of [
      "cello_channel_config", "cello_channel_publish",
      "cello_channel_info_set", "cello_channel_prune", "cello_channel_resend",
    ]) {
      expect(verbs, `${verb} is not registered — the module is wired to nothing`).toContain(verb);
    }
  });

  it("28. a channel must be SET UP before it can publish, and the refusal says so", async () => {
    const answer = await call("cello_channel_publish", {
      agent: "alice", channel: alicePubkeyHex, title: "before setup", body: "body",
    });
    // Not a crash and not a silent success: the channel genuinely is unknown to this daemon.
    expect(answer["ok"]).toBe(false);
    expect(answer["reason"]).toBe("channel_unknown");
  });

  it("29. setup records the relays, and refuses a channel whose key this daemon does not hold", async () => {
    const good = await call("cello_channel_config", {
      agent: "alice", channel: alicePubkeyHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    expect(good["ok"], JSON.stringify(good)).toBe(true);
    expect(good["relays"]).toEqual([RELAY_A, RELAY_B]);

    // ⚠️ A channel is an agent whose key this daemon holds. Recording relays for somebody else's
    // channel would leave every later verb failing on a key lookup, which describes neither the
    // mistake nor how to fix it.
    const foreign = await call("cello_channel_config", {
      agent: "alice", channel: "de".repeat(32), access: "public", relays: [RELAY_A, RELAY_B],
    });
    expect(foreign["ok"]).toBe(false);
    expect(foreign["reason"]).toBe("channel_key_not_held");
    expect(String(foreign["guidance"])).toContain("does not hold");
  });

  it("30. after setup, publish REACHES the relays and reports each one's real outcome", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: alicePubkeyHex, access: "public", relays: [RELAY_A, RELAY_B],
    });

    const answer = await call("cello_channel_publish", {
      agent: "alice", channel: alicePubkeyHex, title: "the first post", body: "hello",
    });

    /**
     * ⚠️ **`no_relay_accepted` IS THE PASS HERE**, and the distinction is the whole value of this
     * test. Those two multiaddrs point at nothing, so a publisher that got as far as trying to
     * reach them is a publisher that screened, signed, logged and dialled. The failures this file
     * exists for produce `channel_unknown` (no config), `key_unavailable` (the empty-string
     * lookup), or no handler at all — never a relay that was contacted and did not answer.
     */
    expect(answer["ok"]).toBe(false);
    expect(answer["reason"]).toBe("no_relay_accepted");
    // And the post SURVIVES, so the guidance must not tell the operator to publish it again.
    expect(String(answer["guidance"])).toContain("resend");
  });

  it("31. resend runs with NO relay named — it refills every relay the channel publishes to", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: alicePubkeyHex, access: "public", relays: [RELAY_A, RELAY_B],
    });

    const answer = await call("cello_channel_resend", { agent: "alice", channel: alicePubkeyHex });
    /**
     * ⚠️ Requiring a multiaddr here made the ONLY repair command an operator has impossible to run
     * from the terminal: the CLI sent no relay and the daemon answered `bad_relay`, always. It now
     * defaults to every configured relay.
     */
    expect(answer["ok"], JSON.stringify(answer)).toBe(true);
    expect(answer["relays"]).toEqual([
      { relay: RELAY_A, deposited: 0 },
      { relay: RELAY_B, deposited: 0 },
    ]);
  });

  it("32. prune tells the operator its relays are STILL HOLDING the posts when it could not reach them", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: alicePubkeyHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    // Publish one so the log has something to prune. It reaches no relay, which is fine.
    await call("cello_channel_publish", {
      agent: "alice", channel: alicePubkeyHex, title: "to be pruned", body: "body",
    });

    const answer = await call("cello_channel_prune", {
      agent: "alice", channel: alicePubkeyHex, through_seq: 1,
    });
    expect(answer["ok"]).toBe(true);
    expect(answer["pruned"]).toBe(1);
    /**
     * ⚠️ **NEITHER RELAY IS `ok`, AND THE OPERATOR IS TOLD.** The first version reported every relay
     * as successfully pruned without contacting any of them, so an operator deleting 500 posts was
     * shown two green relays while both kept serving every one.
     */
    const relays = answer["relays"] as Array<{ relay: string; ok: boolean }>;
    expect(relays.every((r) => !r.ok)).toBe(true);
    expect(String(answer["guidance"])).toContain("did not drop");
  });

  it("33. a PRIVATE channel refuses to publish rather than depositing readable plaintext", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: alicePubkeyHex, access: "invite_only", relays: [RELAY_A, RELAY_B],
    });

    /**
     * ⚠️ **FAIL CLOSED.** There is no group key until 019. A publisher that fell back to plaintext
     * would put the operator's content on two relays under an `access` that promises members-only —
     * the one outcome the encrypt step exists to prevent. The daemon refuses, and the CLI prints
     * what it said rather than blaming the socket.
     */
    let refusal: unknown;
    try {
      await call("cello_channel_publish", {
        agent: "alice", channel: alicePubkeyHex, title: "members only", body: "secret",
      });
    } catch (err: unknown) {
      refusal = err;
    }
    expect(refusal, "a private publish must not succeed").toBeDefined();
    expect(String((refusal as Error).message)).toContain("channel_group_key_unavailable");
  });
});
