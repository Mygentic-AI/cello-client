/**
 * M16 024-CREATE — `cello_channel_create` composes register → config → info-set in the daemon.
 *
 * Sixteen orders built everything a channel does and none built the step that brings one into
 * existence. This unit proves the single composing handler: it mints the channel identity when
 * needed, registers it WITH NO TOKEN (the admin's signature over the channel's pubkey is the basis
 * of the right), records the two relays the DIRECTORY picked, and deposits its info record —
 * reporting WHICH step failed and how to finish by hand, never leaving a registered channel the
 * daemon does not know is a channel.
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
 *    wiring and publisher, with a SEPARATE admin identity that actually signs. Only the registration
 *    step is stubbed — the one step that needs a directory this repo does not have — and that is
 *    stated at the test. It asserts the persisted config row (the directory's relays), not a spy,
 *    and that publish works with nothing in between. It also proves that a directory echoing fewer
 *    than two distinct relays is treated as a failed registration with nothing persisted.
 *
 * The identity-table channel FLAG is set only by a directory-echoed registration (004's own note:
 * "a directory cannot echo the channel flag until 005 ships"), and the directory's admin-signature
 * gate + relay pick are proven by the directory's own tests and the live smoke in trustless-cello.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { generateKeypair, verify, type InMemoryKeyProvider, type KeyProvider } from "@cello-protocol/crypto";
import { registerChannelCreateHandler, type ChannelCreateDeps } from "../channel-create-handler.js";
import { wireChannelPublishing } from "../channel-publish-wiring.js";
import { registerChannelPublishHandlers } from "../channel-publish-handlers.js";
import type { ChannelPublisher } from "../channel-publisher.js";
import type { ChannelConfig } from "../channel-config-store.js";
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
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

interface Spies {
  register: Array<{ name: string; adminName: string; adminPubkeyHex: string; access: string }>;
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
      spies.register.push({ name: opts.name, adminName: opts.adminName, adminPubkeyHex: opts.adminPubkeyHex, access: opts.access });
      // The directory picks the two relays — the handler records exactly what comes back.
      return { ok: true, channelPubkeyHex: CHANNEL_HEX, relays: [RELAY_A, RELAY_B] };
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
  it("1. happy composition — returns ok, records the DIRECTORY's relays, and runs register → config → info-set in order", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", guidance: "The morning bulletin" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(true);
    expect(result.channel_pubkey).toBe(CHANNEL_HEX);
    expect(result.name).toBe("newschan");
    expect(result.access).toBe("public");
    // The relays are the directory's, echoed back to the operator — not anything they typed.
    expect(result.relays).toEqual([RELAY_A, RELAY_B]);
    expect(result.admin_pubkey).toBe(ADMIN_HEX);

    // No token, no relays travel to the register step — just name/admin/access.
    expect(spies.register).toEqual([{ name: "newschan", adminName: "admin", adminPubkeyHex: ADMIN_HEX, access: "public" }]);
    // The directory's relays, the access, AND the description all reach the config step.
    expect(spies.config).toEqual([{ agentName: "admin", channelHex: CHANNEL_HEX, relays: [RELAY_A, RELAY_B], access: "public", guidance: "The morning bulletin", retention_seconds: DEFAULT_RETENTION_SECONDS }]);
    expect(spies.info).toEqual([{ agentName: "admin", channelHex: CHANNEL_HEX }]);
  });

  it("2. register refused (bad admin signature) — step 'register', and config/info-set never run", async () => {
    const { fn, spies } = makeHandler({
      registerChannel: async () => ({ ok: false, reason: "invalid_channel_registration" }),
    });
    const result = (await fn(
      { name: "newschan", access: "public" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(false);
    expect(result.step).toBe("register");
    expect(result.reason).toBe("invalid_channel_registration");
    // The step guidance names `cello channel create`, never `register-agent`.
    expect(String(result.guidance)).toContain("cello channel create");
    expect(String(result.guidance)).not.toContain("register-agent");
    expect(spies.config).toEqual([]);
    expect(spies.info).toEqual([]);
  });

  it("3. the directory returned fewer than two relays — step 'register', reason directory_returned_no_relays, nothing else runs", async () => {
    const { fn, spies } = makeHandler({
      registerChannel: async () => ({ ok: false, reason: "directory_returned_no_relays" }),
    });
    const result = (await fn(
      { name: "newschan", access: "public" },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.step).toBe("register");
    expect(result.reason).toBe("directory_returned_no_relays");
    expect(spies.config).toEqual([]);
    expect(spies.info).toEqual([]);
  });

  it("4. a pre-auth token is refused with channel_needs_no_token, BEFORE the register step runs", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", preAuthToken: "CELLO-a-token" },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("channel_needs_no_token");
    expect(spies.register).toEqual([]);
  });

  it("4b. a relay argument (the old habit) is refused with channel_needs_no_token, BEFORE the register step runs", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B] },
      "conn1",
    )) as Record<string, unknown>;
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("channel_needs_no_token");
    expect(spies.register).toEqual([]);
  });

  it("info-set fails — step 'info_set', guidance names the info-set command, and config DID run", async () => {
    const { fn, spies } = makeHandler({
      depositChannelInfo: async () => ({ ok: false, reason: "no_relay_accepted" }),
    });
    const result = (await fn(
      { name: "newschan", access: "public" },
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

  it("create mints the identity, signs with the admin key, the real registration fails with no directory, and the mint is rolled back", async () => {
    celloDir = await makeCelloDir("cello-m16-024-");
    // A closed local port, so the real `cello_register` genuinely has NO directory — never the live
    // consortium the bundled manifest would pick.
    daemon = spawnRealDaemon(celloDir, { CELLO_DIRECTORY_URL: "http://127.0.0.1:9" });
    await daemon.waitForEvent("daemon.started");

    const client = await connectToDaemon(join(celloDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "cli" });
      const result = (await client.send("cello_channel_create", {
        // singleton-test-agent is the pre-created agent this fixture boots with — the admin. It signs
        // the new channel's pubkey; no token is presented.
        agent: "singleton-test-agent",
        name: "brand-new-channel",
        access: "public",
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

      // "Fails with no directory" must be TRUE, not just the comment's claim. Without a directory
      // override this daemon bootstrapped against the LIVE consortium, and every full-suite run
      // registered a throwaway channel there; the live directory then crashed replying to the
      // vanished test daemon (2026-09-25). The daemon's own log must never name a live node.
      expect(daemon.output(), "the test daemon reached a live CELLO directory").not.toMatch(/mygentic\.ai/);
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

  /** Wire the real publishing stack with a `cello_register` stub that echoes the given relays. */
  function wire(registerRelays: string[]): Map<string, Handler> {
    const handlers = new Map<string, Handler>();
    // The registration step needs a directory this repo has no harness for, so it is the ONE step
    // stubbed here (Section B exercises the real, failing registration). The channel identity's key
    // is pre-loaded, so registerChannel resolves its pubkey without minting. The stub echoes the
    // relays the directory would have picked.
    handlers.set("cello_register", async () => ({ ok: true, agent_id: "a1", primary_pubkey: channelPubkeyHex, relays: registerRelays }));

    // Two DISTINCT identities: `admin` administers and SIGNS, `channel` is the channel. Admin != channel.
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
      notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    });
    return handlers;
  }

  it("create (separate admin) writes the real channel_config row with the directory's relays; publish is not channel_unknown afterwards", async () => {
    const handlers = wire([RELAY_A, RELAY_B]);
    const create = handlers.get("cello_channel_create");
    expect(create, "wireChannelPublishing must register cello_channel_create").toBeDefined();

    const created = (await create!(
      { agent: "admin", name: "channel", access: "public", guidance: "Release notes" },
      "conn1",
    )) as Record<string, unknown>;

    // The config was recorded (create reached step 2). No relay exists in this harness, so the info
    // deposit cannot land — that is the enforcer's job — so create reports step 'info_set'.
    expect(created.ok).toBe(false);
    expect(created.step).toBe("info_set");

    // REAL PERSISTENCE: the channel_config row holds the DIRECTORY's two relays, the access, the
    // description, and the SEPARATE admin's pubkey (proving admin != channel, and the admin was recorded).
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

  it("a directory echo of fewer than two distinct relays is a failed registration — step 'register', directory_returned_no_relays, and nothing is persisted", async () => {
    const handlers = wire([RELAY_A]); // one relay: not enough
    const create = handlers.get("cello_channel_create")!;
    const created = (await create(
      { agent: "admin", name: "channel", access: "public" },
      "conn1",
    )) as Record<string, unknown>;

    expect(created.ok).toBe(false);
    expect(created.step).toBe("register");
    expect(created.reason).toBe("directory_returned_no_relays");

    // NOTHING PERSISTED: no channel_config row was written, so a channel with one relay never exists.
    const row = new ChannelConfigStore(db, silent).get(channelPubkeyHex);
    expect(row, "a one-relay echo must not write a channel_config row").toBeNull();
  });

  it("item 3: the admin signs the DOMAIN-SEPARATED message, not the bare channel pubkey", async () => {
    // Capture what the register step is handed, so we can check the exact bytes the admin signed.
    const captured: { adminSignature?: string; adminPubkeyHex?: string } = {};
    const handlers = new Map<string, Handler>();
    handlers.set("cello_register", async (params) => {
      captured.adminSignature = params?.["adminSignature"] as string;
      captured.adminPubkeyHex = params?.["adminPubkeyHex"] as string;
      return { ok: true, agent_id: "a1", primary_pubkey: channelPubkeyHex, relays: [RELAY_A, RELAY_B] };
    });
    wireChannelPublishing({
      handlers, logger: silent, getDb: () => db, getNode: () => null,
      screenOutbound: (content, ctx) => new PassthroughGatewayClient().screenOutbound(content, ctx),
      loadedAgents: [
        { name: "admin", pubkey: adminPubkeyHex, keyProvider: adminKp as KeyProvider },
        { name: "channel", pubkey: channelPubkeyHex, keyProvider: channelKp as KeyProvider },
      ],
      keyProviders: new Map<string, KeyProvider>([["admin", adminKp], ["channel", channelKp]]),
      resolveCurrentAgent: (_c, explicit) => explicit ?? "admin",
      isAgentOnline: () => true, activeMembers: () => [], signalingFor: () => null,
      notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    });

    await handlers.get("cello_channel_create")!({ agent: "admin", name: "channel", access: "public" }, "conn1");

    expect(captured.adminSignature, "register must receive an admin signature").toBeDefined();
    expect(captured.adminPubkeyHex).toBe(adminPubkeyHex);
    const sig = new Uint8Array(Buffer.from(captured.adminSignature!, "hex"));
    const adminPubkey = new Uint8Array(Buffer.from(adminPubkeyHex, "hex"));
    const channelPubkeyBytes = new Uint8Array(Buffer.from(channelPubkeyHex, "hex"));
    const taggedMsg = new Uint8Array(Buffer.concat([Buffer.from("cello.channel.admin.v1", "utf8"), channelPubkeyBytes]));

    // The signature verifies over the TAGGED message the directory checks, and NOT over the bare
    // pubkey — a K_local signature made for another purpose cannot be replayed as this authorization.
    expect(verify(adminPubkey, taggedMsg, sig)).toBe(true);
    expect(verify(adminPubkey, channelPubkeyBytes, sig)).toBe(false);
  });
});

describe("M16 024-CREATE item 6: a failed rollback is logged, not swallowed", () => {
  let dir: string;
  let db: DaemonDatabase;

  beforeEach(() => {
    process.env["CELLO_ENV"] = "test";
    dir = mkdtempSync(join(tmpdir(), "cello-m16-024-rb-"));
    db = openTestDb(join(dir, "sessions.db"));
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  it("when the mint rollback's removeAgent throws, channel.create.rollback_failed is logged with the name and error", async () => {
    const logs: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const capturing: Logger = {
      debug() {}, info() {},
      warn(event: string, ctx?: Record<string, unknown>) { logs.push({ event, ctx: ctx ?? {} }); },
      error() {},
    };

    const adminKp = generateKeypair();
    const channelKp = generateKeypair();
    const adminPubkeyHex = Buffer.from(await adminKp.getPublicKey()).toString("hex");
    const channelPubkeyHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");

    const handlers = new Map<string, Handler>();
    // The channel name is NOT pre-loaded, so create mints it (mintedHere = true). The mint stub adds
    // the key so the pubkey resolves; registration then FAILS, triggering the rollback.
    const loadedAgents = [{ name: "admin", pubkey: adminPubkeyHex, keyProvider: adminKp as KeyProvider }];
    const keyProviders = new Map<string, KeyProvider>([["admin", adminKp]]);
    handlers.set("cello_create_agent", async () => {
      keyProviders.set("channel", channelKp);
      loadedAgents.push({ name: "channel", pubkey: channelPubkeyHex, keyProvider: channelKp as KeyProvider });
      return { ok: true };
    });
    handlers.set("cello_register", async () => ({ ok: false, reason: "register_failed" }));
    // The rollback's removeAgent throws — before item 6 this was swallowed by .catch(() => undefined).
    handlers.set("cello_remove_agent", async () => { throw new Error("db locked"); });

    wireChannelPublishing({
      handlers, logger: capturing, getDb: () => db, getNode: () => null,
      screenOutbound: (content, ctx) => new PassthroughGatewayClient().screenOutbound(content, ctx),
      loadedAgents, keyProviders,
      resolveCurrentAgent: (_c, explicit) => explicit ?? "admin",
      isAgentOnline: () => true, activeMembers: () => [], signalingFor: () => null,
      notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    });

    const created = (await handlers.get("cello_channel_create")!(
      { agent: "admin", name: "channel", access: "public" }, "conn1",
    )) as Record<string, unknown>;
    // The create still fails at the register step (the rollback is best-effort cleanup).
    expect(created.step).toBe("register");

    const rb = logs.find((l) => l.event === "channel.create.rollback_failed");
    expect(rb, "a failed rollback must be logged, not swallowed").toBeDefined();
    expect(rb!.ctx["name"]).toBe("channel");
    expect(String(rb!.ctx["error"])).toContain("db locked");
  });
});

describe("M16 024-CREATE item 4: the directory's refusal detail reaches the operator", () => {
  let dir: string;
  let db: DaemonDatabase;

  beforeEach(() => {
    process.env["CELLO_ENV"] = "test";
    dir = mkdtempSync(join(tmpdir(), "cello-m16-024-d-"));
    db = openTestDb(join(dir, "sessions.db"));
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  it("a register refusal carrying the directory detail surfaces in channel.create.failed AND the returned guidance, not a generic register failure", async () => {
    const logs: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const capturing: Logger = {
      debug() {}, info() {},
      warn(event: string, ctx?: Record<string, unknown>) { logs.push({ event, ctx: ctx ?? {} }); },
      error() {},
    };

    const adminKp = generateKeypair();
    const channelKp = generateKeypair();
    const adminPubkeyHex = Buffer.from(await adminKp.getPublicKey()).toString("hex");
    const channelPubkeyHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");

    // The register step returns exactly what the real chain produces for a channel refused at the
    // directory's admin-signature gate: registrationGuidance("dkg_failed", <detail carrying "admin
    // signature does not verify">). Item 4 proves the create surfaces this, not a generic fallback.
    const directoryGuidance =
      "The FROST DKG ceremony with the directory failed: dkgRound1 rejected: CHANNEL_REGISTRATION_INVALID: admin signature does not verify";
    const handlers = new Map<string, Handler>();
    handlers.set("cello_register", async () => ({ ok: false, reason: "dkg_failed", guidance: directoryGuidance }));

    wireChannelPublishing({
      handlers, logger: capturing, getDb: () => db, getNode: () => null,
      screenOutbound: (content, ctx) => new PassthroughGatewayClient().screenOutbound(content, ctx),
      loadedAgents: [
        { name: "admin", pubkey: adminPubkeyHex, keyProvider: adminKp as KeyProvider },
        { name: "channel", pubkey: channelPubkeyHex, keyProvider: channelKp as KeyProvider },
      ],
      keyProviders: new Map<string, KeyProvider>([["admin", adminKp], ["channel", channelKp]]),
      resolveCurrentAgent: (_c, explicit) => explicit ?? "admin",
      isAgentOnline: () => true, activeMembers: () => [], signalingFor: () => null,
      notify: { channelPosts() {}, channelJoinAnswer() {}, channelJoinRequest() {} },
    });

    const created = (await handlers.get("cello_channel_create")!(
      { agent: "admin", name: "channel", access: "public" }, "conn1",
    )) as Record<string, unknown>;

    expect(created.step).toBe("register");
    // The returned guidance is the directory's, not the generic "nothing was created" fallback.
    expect(String(created.guidance)).toContain("admin signature does not verify");

    const failed = logs.find((l) => l.event === "channel.create.failed");
    expect(failed, "channel.create.failed must be logged").toBeDefined();
    expect(String(failed!.ctx["guidance"])).toContain("admin signature does not verify");
  });
});

// ─── M16 040-CLEANUP Parts C & E — refusal guidance on the publisher's verbs ────────────────────
//
// Both parts live in registerChannelPublishHandlers, which builds the operator-facing guidance from
// what the publisher returned. A fake publisher lets a test force the exact refusal shape each part
// is about — an info deposit no relay took (Part C), and a post every relay refused `not_a_channel`
// (Part E) — without a directory or a real relay.
describe("M16 040-CLEANUP: publish/info-set refusal guidance", () => {
  type H = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

  function wireHandlers(publisherFake: Partial<ChannelPublisher>, cfg: ChannelConfig | null) {
    const handlers = new Map<string, H>();
    const setCalls: Array<{ channelHex: string; guidance: string }> = [];
    registerChannelPublishHandlers({
      handlers,
      logger: silent,
      getPublisher: () => publisherFake as unknown as ChannelPublisher,
      setChannelConfig: (_agentName, channelHex, config) => { setCalls.push({ channelHex, guidance: config.guidance }); return { ok: true }; },
      getChannelConfig: () => cfg,
      resolveCurrentAgent: (_connectionId, explicit) => explicit ?? "admin",
    });
    return { handlers, setCalls };
  }

  const CFG: ChannelConfig = {
    access: "invite_only", relays: [RELAY_A, RELAY_B], guidance: "old description",
    retention_seconds: 3600, admin_pubkey: ADMIN_HEX,
  };

  it("Part C: info-set --guidance with every deposit refused says subscribers still see the old text, and still saves locally", async () => {
    const { handlers, setCalls } = wireHandlers(
      { publishInfo: () => Promise.resolve({ ok: false, reason: "no_relay_accepted" }) },
      CFG,
    );
    const res = (await handlers.get("cello_channel_info_set")!(
      { channel: CHANNEL_HEX, guidance: "new description", agent: "admin" }, "conn1",
    )) as { ok: boolean; reason: string; guidance: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("no_relay_accepted");
    expect(res.guidance).toContain("Saved here, but no relay took it");
    expect(res.guidance).toContain("subscribers still see the old description");
    // MUST NOT CHANGE #2: the new description was stored locally BEFORE the deposit was attempted.
    expect(setCalls).toEqual([{ channelHex: CHANNEL_HEX, guidance: "new description" }]);
  });

  it("Part E: a post EVERY relay refused not_a_channel says the channel is too new and to resend", async () => {
    // Right after create, a relay's short negative cache can refuse `not_a_channel` for up to 30s.
    const { handlers } = wireHandlers(
      { publish: () => Promise.resolve({ ok: false, reason: "no_relay_accepted", seq: 1, deposited: [
        { relay: RELAY_A, ok: false, reason: "not_a_channel" },
        { relay: RELAY_B, ok: false, reason: "not_a_channel" },
      ] }) },
      CFG,
    );
    const res = (await handlers.get("cello_channel_publish")!(
      { channel: CHANNEL_HEX, title: "v1", body: "hi", agent: "admin" }, "conn1",
    )) as { ok: boolean; reason: string; guidance: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("no_relay_accepted");
    expect(res.guidance).toContain("do not know this channel yet");
    expect(res.guidance).toContain("30 seconds");
    expect(res.guidance).toContain("cello channel resend");
    // Not the ordinary "retry now" text — this is the too-new case.
    expect(res.guidance).not.toContain("retry with");
  });

  it("Part E: any OTHER refusal keeps today's post-in-the-log text", async () => {
    // One relay refused not_a_channel, the other for a different reason → NOT the all-new case.
    const { handlers } = wireHandlers(
      { publish: () => Promise.resolve({ ok: false, reason: "no_relay_accepted", seq: 1, deposited: [
        { relay: RELAY_A, ok: false, reason: "not_a_channel" },
        { relay: RELAY_B, ok: false, reason: "clock_skew" },
      ] }) },
      CFG,
    );
    const res = (await handlers.get("cello_channel_publish")!(
      { channel: CHANNEL_HEX, title: "v1", body: "hi", agent: "admin" }, "conn1",
    )) as { ok: boolean; guidance: string };

    expect(res.guidance).toContain("It is in your log");
    expect(res.guidance).not.toContain("do not know this channel yet");
  });
});
