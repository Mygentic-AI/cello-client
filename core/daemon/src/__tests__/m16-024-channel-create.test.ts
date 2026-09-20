/**
 * M16 024-CREATE — `cello_channel_create` composes register → config → info-set in the daemon.
 *
 * Sixteen orders built everything a channel does and none built the step that brings one into
 * existence. This unit proves the single composing handler: it mints the channel identity when
 * needed, registers it, records its relays/access and deposits its info record — reporting WHICH
 * step failed and how to finish by hand, and never leaving a registered channel the daemon does not
 * know is a channel.
 *
 * ─── What is proven where, and why ────────────────────────────────────────────────────────────
 *
 * cello-client has NO directory harness — every daemon test that calls `cello_register` asserts a
 * REFUSAL, because a real registration runs a DKG against the GCP consortium. So:
 *
 *  • Composition and refusal ORDERING (Section A) use injected step stubs — the handler's control
 *    flow, not its persistence.
 *  • The register-FAILURE path and the mint ROLLBACK (Section B) run against the REAL daemon over a
 *    real socket, with the REAL `cello_register` (which fails with no directory). This is the
 *    real-persistence proof: an implementation that minted and did not roll back would leave an
 *    active agent row, and this test would catch it.
 *  • The happy composition (Section C) writes to a REAL `ChannelConfigStore` through the REAL
 *    wiring and publisher, with a SEPARATE admin identity. Only the registration step is stubbed —
 *    the one step that needs a directory this repo does not have — and that is stated at the test.
 *    It asserts the persisted config row, not a spy, and that publish works with nothing in between.
 *
 * The identity-table channel FLAG is set only by a directory-echoed registration (004's own note:
 * "a directory cannot echo the channel flag until 005 ships"), so it is proven by 005's enforcer and
 * the live smoke in trustless-cello, not here.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { generateKeypair, type InMemoryKeyProvider, type KeyProvider } from "@cello-protocol/crypto";
import { registerChannelCreateHandler, type ChannelCreateDeps } from "../channel-create-handler.js";
import { wireChannelPublishing } from "../channel-publish-wiring.js";
import { ChannelConfigStore } from "../channel-config-store.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import { connectToDaemon } from "../ipc-client.js";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import { DEFAULT_RETENTION_SECONDS } from "../channel-config-store.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const ADMIN_HEX = "aa".repeat(32);
const CHANNEL_HEX = "cc".repeat(32);
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

interface Spies {
  register: Array<{ name: string; preAuthToken: string; adminPubkeyHex: string; access: string }>;
  config: Array<{ agentName: string; channelHex: string; relays: string[]; access: string; guidance: string; retention_seconds: number }>;
  info: Array<{ agentName: string; channelHex: string }>;
}

/** Build the create handler with the three steps as spies, each overridable per test. */
function makeHandler(overrides: Partial<ChannelCreateDeps> = {}): { fn: Handler; spies: Spies } {
  const spies: Spies = { register: [], config: [], info: [] };
  const handlers = new Map<string, Handler>();
  const deps: ChannelCreateDeps = {
    handlers,
    logger: silent,
    resolveCurrentAgent: () => "admin",
    agentPubkey: (name) => (name === "admin" ? ADMIN_HEX : null),
    registerChannel: async (opts) => {
      spies.register.push({ name: opts.name, preAuthToken: opts.preAuthToken, adminPubkeyHex: opts.adminPubkeyHex, access: opts.access });
      return { ok: true, channelPubkeyHex: CHANNEL_HEX };
    },
    applyChannelConfig: (agentName, channelHex, cfg) => {
      spies.config.push({ agentName, channelHex, relays: cfg.relays, access: cfg.access, guidance: cfg.guidance, retention_seconds: cfg.retention_seconds });
      return { ok: true };
    },
    depositChannelInfo: async (agentName, channelHex) => {
      spies.info.push({ agentName, channelHex });
      return { ok: true };
    },
    ...overrides,
  };
  registerChannelCreateHandler(deps);
  const fn = handlers.get("cello_channel_create");
  if (!fn) throw new Error("cello_channel_create was not registered");
  return { fn, spies };
}

describe("M16 024-CREATE Section A: the composing handler's control flow", () => {
  it("1. happy composition — returns ok and runs register → config → info-set, in order, with the given values", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-tok", guidance: "The morning bulletin" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(true);
    expect(result.channel_pubkey).toBe(CHANNEL_HEX);
    expect(result.name).toBe("newschan");
    expect(result.access).toBe("public");
    expect(result.relays).toEqual([RELAY_A, RELAY_B]);
    expect(result.admin_pubkey).toBe(ADMIN_HEX);

    expect(spies.register).toEqual([{ name: "newschan", preAuthToken: "CELLO-tok", adminPubkeyHex: ADMIN_HEX, access: "public" }]);
    // Both relays, the access, AND the description all reach the config step.
    expect(spies.config).toEqual([{ agentName: "admin", channelHex: CHANNEL_HEX, relays: [RELAY_A, RELAY_B], access: "public", guidance: "The morning bulletin", retention_seconds: DEFAULT_RETENTION_SECONDS }]);
    expect(spies.info).toEqual([{ agentName: "admin", channelHex: CHANNEL_HEX }]);
  });

  it("2. register refused — step 'register', and config/info-set never run", async () => {
    const { fn, spies } = makeHandler({
      registerChannel: async () => ({ ok: false, reason: "directory_unreachable" }),
    });
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(false);
    expect(result.step).toBe("register");
    expect(result.reason).toBe("directory_unreachable");
    // The step guidance names `cello channel create`, never `register-agent`.
    expect(String(result.guidance)).toContain("cello channel create");
    expect(String(result.guidance)).not.toContain("register-agent");
    expect(spies.config).toEqual([]);
    expect(spies.info).toEqual([]);
  });

  it("3. a relays list of length one is refused BEFORE step 1 runs", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("bad_relays");
    expect(spies.register).toEqual([]);
  });

  it("4. a relay that is not a multiaddr (a token mis-parsed as a relay) is refused BEFORE step 1", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, "CELLO-a-token-not-a-relay"], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("bad_relays");
    expect(String(result.guidance)).toContain("multiaddr");
    expect(spies.register).toEqual([]);
  });

  it("a missing pre-auth token is refused with missing_preauth_token, before step 1", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B] },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_preauth_token");
    expect(spies.register).toEqual([]);
  });

  it("info-set fails — step 'info_set', guidance names the info-set command, and config DID run", async () => {
    const { fn, spies } = makeHandler({
      depositChannelInfo: async () => ({ ok: false, reason: "no_relay_accepted" }),
    });
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.step).toBe("info_set");
    expect(String(result.guidance)).toContain(`cello channel info-set ${CHANNEL_HEX}`);
    expect(spies.config).toHaveLength(1);
  });
});

describe("M16 024-CREATE Section B: register failure leaves NO active identity (real daemon)", () => {
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

  it("create mints the identity, the real registration fails with no directory, and the mint is rolled back", async () => {
    celloDir = await makeCelloDir("cello-m16-024-");
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");

    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "cli" });
      const result = (await client.send("cello_channel_create", {
        // singleton-test-agent is the pre-created agent this fixture boots with — the admin.
        agent: "singleton-test-agent",
        name: "brand-new-channel",
        access: "public",
        relays: [RELAY_A, RELAY_B],
        preAuthToken: "DEV-enforcer-token",
      })) as { ok: boolean; step?: string };

      // No directory here, so the real cello_register cannot complete.
      expect(result.ok).toBe(false);
      expect(result.step).toBe("register");

      // THE REAL-PERSISTENCE ASSERTION: the identity create minted was rolled back, so it is not an
      // active agent. An implementation that minted and did not roll back would list it here.
      // `cello_list_agents` is the WIRE method behind the `cello_agents` tool.
      const agents = (await client.send("cello_list_agents", {})) as { agents?: Array<{ name: string }> };
      const names = (agents.agents ?? []).map((a) => a.name);
      expect(names, "the rolled-back channel identity must not remain an active agent").not.toContain("brand-new-channel");
      // The admin the fixture booted with is untouched.
      expect(names).toContain("singleton-test-agent");
    } finally {
      client.close();
    }
  }, 40_000);
});

describe("M16 024-CREATE Section C: the config create records is real, and publish needs no command between", () => {
  let dir: string;
  let db: DaemonDatabase;
  let adminKp: InMemoryKeyProvider;
  let channelKp: InMemoryKeyProvider;
  let adminPubkeyHex: string;
  let channelPubkeyHex: string;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    dir = mkdtempSync(join(tmpdir(), "cello-m16-024c-"));
    db = openTestDb(join(dir, "sessions.db"));
    adminKp = generateKeypair();
    channelKp = generateKeypair();
    adminPubkeyHex = Buffer.from(await adminKp.getPublicKey()).toString("hex");
    channelPubkeyHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  it("create (separate admin) writes the real channel_config row; publish is not channel_unknown afterwards", async () => {
    const handlers = new Map<string, Handler>();
    // The registration step needs a directory this repo has no harness for, so it is the ONE step
    // stubbed here (Section B exercises the real, failing registration). The channel identity's key
    // is pre-loaded, so registerChannel resolves its pubkey without minting.
    handlers.set("cello_register", async () => ({ ok: true, agent_id: "a1", primary_pubkey: channelPubkeyHex }));

    // Two DISTINCT identities: `admin` administers, `channel` is the channel. Admin is NOT the channel.
    const loadedAgents = [
      { name: "admin", pubkey: adminPubkeyHex, keyProvider: adminKp as KeyProvider },
      { name: "channel", pubkey: channelPubkeyHex, keyProvider: channelKp as KeyProvider },
    ];
    const keyProviders = new Map<string, KeyProvider>([["admin", adminKp], ["channel", channelKp]]);

    wireChannelPublishing({
      handlers,
      logger: silent,
      getDb: () => db,
      getNode: () => null,
      screenOutbound: (content, ctx) => new PassthroughGatewayClient().screenOutbound(content, ctx),
      loadedAgents,
      keyProviders,
      resolveCurrentAgent: (_connectionId, explicitAgent) => explicitAgent ?? "admin",
      isAgentOnline: () => true,
      activeMembers: () => [],
      signalingFor: () => null,
    });

    const create = handlers.get("cello_channel_create");
    expect(create, "wireChannelPublishing must register cello_channel_create").toBeDefined();

    const created = (await create!(
      { agent: "admin", name: "channel", access: "public", relays: [RELAY_A, RELAY_B], guidance: "Release notes", preAuthToken: "DEV-tok" },
      "conn1",
    )) as Record<string, unknown>;

    // The config was recorded (create reached step 2). No relay exists in this harness, so the info
    // deposit cannot land — that is the enforcer's job — so create reports step 'info_set'.
    expect(created.ok).toBe(false);
    expect(created.step).toBe("info_set");

    // REAL PERSISTENCE: the channel_config row holds both relays, the access, the description, and
    // the SEPARATE admin's pubkey (proving admin != channel, and that the admin identity was recorded).
    const row = new ChannelConfigStore(db, silent).get(channelPubkeyHex);
    expect(row, "create must have written the channel_config row").not.toBeNull();
    expect(row!.relays).toEqual([RELAY_A, RELAY_B]);
    expect(row!.access).toBe("public");
    expect(row!.guidance).toBe("Release notes");
    expect(row!.admin_pubkey).toBe(adminPubkeyHex);

    // Publish works with NO `setup` command between: before a config row exists publish answers
    // channel_unknown; after create records it, publish reaches the relays (which point nowhere here,
    // hence no_relay_accepted — a contacted relay, not an unknown channel).
    const publish = handlers.get("cello_channel_publish");
    const pub = (await publish!(
      { agent: "admin", channel: channelPubkeyHex, title: "v1", body: "first release" },
      "conn1",
    )) as Record<string, unknown>;
    expect(pub.reason).not.toBe("channel_unknown");
    expect(pub.reason).toBe("no_relay_accepted");
  });
});
