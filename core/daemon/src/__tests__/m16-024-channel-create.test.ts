/**
 * M16 024-CREATE — `cello_channel_create` composes register → config → info-set in the daemon.
 *
 * Sixteen orders built everything a channel does and none built the step that brings one into
 * existence. This unit proves the single composing handler: it runs the three existing steps in
 * order, reports WHICH step failed and how to finish by hand, and never leaves a registered channel
 * the daemon does not know is a channel.
 *
 * Tests 1–4 drive the handler with the three steps INJECTED as spies, so the composition and its
 * failure-step semantics are checkable without a live directory (a real registration needs a DKG
 * against the consortium, which is the enforcer's job, not a unit's). The last test wires the REAL
 * config store and REAL publisher through `wireChannelPublishing` and proves the DoD's create→publish
 * clause: after create, publish needs NO `setup` command in between.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { generateKeypair, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import { registerChannelCreateHandler, type ChannelCreateDeps } from "../channel-create-handler.js";
import { wireChannelPublishing } from "../channel-publish-wiring.js";
import { openTestDb } from "./helpers/encrypted-db.js";
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
  config: Array<{ agentName: string; channelHex: string; relays: string[]; access: string; retention_seconds: number }>;
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
      spies.config.push({ agentName, channelHex, relays: cfg.relays, access: cfg.access, retention_seconds: cfg.retention_seconds });
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

describe("M16 024-CREATE: cello_channel_create composes the three steps", () => {
  it("1. happy path — returns ok with the channel pubkey, and runs register → config → info-set in order", async () => {
    const { fn, spies } = makeHandler();
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(true);
    expect(result.channel_pubkey).toBe(CHANNEL_HEX);
    expect(result.name).toBe("newschan");
    expect(result.access).toBe("public");
    expect(result.relays).toEqual([RELAY_A, RELAY_B]);
    expect(result.admin_pubkey).toBe(ADMIN_HEX);

    // Step 1 registered the NEW identity as a channel administered by the current agent.
    expect(spies.register).toEqual([{ name: "newschan", preAuthToken: "CELLO-tok", adminPubkeyHex: ADMIN_HEX, access: "public" }]);
    // Step 2 recorded BOTH relays and the access against the channel's own pubkey, as the admin.
    expect(spies.config).toEqual([{ agentName: "admin", channelHex: CHANNEL_HEX, relays: [RELAY_A, RELAY_B], access: "public", retention_seconds: DEFAULT_RETENTION_SECONDS }]);
    // Step 3 deposited the info record for that channel.
    expect(spies.info).toEqual([{ agentName: "admin", channelHex: CHANNEL_HEX }]);
  });

  it("2. the directory refuses the token — step 'register', and NOTHING is persisted locally", async () => {
    const { fn, spies } = makeHandler({
      registerChannel: async () => ({ ok: false, reason: "invalid_preauth_token", guidance: "The directory rejected the token." }),
    });
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-bad" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(false);
    expect(result.step).toBe("register");
    expect(result.reason).toBe("invalid_preauth_token");
    // The whole point: a register failure leaves no channel behind — config and info never ran.
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
    // Validated up front — the registration was never attempted.
    expect(spies.register).toEqual([]);
    expect(spies.config).toEqual([]);
  });

  it("4. info-set fails — step 'info_set', guidance names the info-set command, and the channel IS set up", async () => {
    const { fn, spies } = makeHandler({
      depositChannelInfo: async () => ({ ok: false, reason: "no_relay_accepted" }),
    });
    const result = (await fn(
      { name: "newschan", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;

    expect(result.ok).toBe(false);
    expect(result.step).toBe("info_set");
    expect(result.reason).toBe("no_relay_accepted");
    // The command that finishes the job by hand — the info-set the description deposit needs.
    expect(String(result.guidance)).toContain(`cello channel info-set ${CHANNEL_HEX}`);
    // Steps 1–2 persisted: the channel is registered and its relays/access are recorded.
    expect(spies.register).toHaveLength(1);
    expect(spies.config).toHaveLength(1);
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
});

describe("M16 024-CREATE: after create, publish works with no command in between", () => {
  let dir: string;
  let db: DaemonDatabase;
  let alicePubkeyHex: string;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    dir = mkdtempSync(join(tmpdir(), "cello-m16-024-"));
    db = openTestDb(join(dir, "sessions.db"));
    const aliceKp = generateKeypair();
    alicePubkeyHex = Buffer.from(await aliceKp.getPublicKey()).toString("hex");
    // alice is the agent AND, for this harness, the channel whose key the daemon holds.
    loadedAgents = [{ name: "alice", pubkey: alicePubkeyHex, keyProvider: aliceKp }];
    keyProviders = new Map([["alice", aliceKp]]);
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  let loadedAgents: Array<{ name: string; pubkey: string; keyProvider: InMemoryKeyProvider }>;
  let keyProviders: Map<string, InMemoryKeyProvider>;

  it("records the config that publish needs — publish is NOT channel_unknown afterwards", async () => {
    const handlers = new Map<string, Handler>();
    // The registration step needs a directory a unit test does not have — stub it so it succeeds and
    // resolves alice as the channel. Everything else in the sequence is the REAL wiring.
    handlers.set("cello_register", async () => ({ ok: true, agent_id: "a1", primary_pubkey: alicePubkeyHex }));

    wireChannelPublishing({
      handlers,
      logger: silent,
      getDb: () => db,
      getNode: () => null,
      screenOutbound: (content, ctx) => new PassthroughGatewayClient().screenOutbound(content, ctx),
      loadedAgents,
      keyProviders: keyProviders as unknown as Map<string, import("@cello-protocol/crypto").KeyProvider>,
      resolveCurrentAgent: (_connectionId, explicitAgent) => explicitAgent ?? "alice",
      isAgentOnline: () => true,
      activeMembers: () => [],
      signalingFor: () => null,
    });

    const create = handlers.get("cello_channel_create");
    expect(create, "wireChannelPublishing must register cello_channel_create").toBeDefined();

    const created = (await create!(
      { name: "alice", access: "public", relays: [RELAY_A, RELAY_B], preAuthToken: "CELLO-tok" },
      "conn1",
    )) as Record<string, unknown>;

    // The config was recorded (create got PAST step 2). There is no relay in this harness, so the
    // info deposit cannot land — that is the enforcer's job, not a unit's — so create reports
    // step 'info_set', which is exactly "the channel IS set up but the description did not deposit".
    expect(created.ok).toBe(false);
    expect(created.step).toBe("info_set");

    // The property the DoD asks for: publish works with NO `setup` command between. Before a config
    // row exists, publish answers `channel_unknown`; after create records it, publish reaches the
    // relays instead (they point nowhere here, hence no_relay_accepted — a contacted relay, not an
    // unknown channel).
    const publish = handlers.get("cello_channel_publish");
    const pub = (await publish!(
      { agent: "alice", channel: alicePubkeyHex, title: "the first post", body: "hello" },
      "conn1",
    )) as Record<string, unknown>;
    expect(pub.reason).not.toBe("channel_unknown");
    expect(pub.reason).toBe("no_relay_accepted");
  });
});
