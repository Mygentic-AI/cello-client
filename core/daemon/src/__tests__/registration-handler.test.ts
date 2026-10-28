/**
 * CELLO-M7-REGISTRATION — cello_register handler single-flight guard (review M1)
 *
 * The directory's registration reply frames carry no agent identifier, so two
 * concurrent registrations over the one shared directory signaling stream would
 * cross-wire. The handler serializes registration daemon-wide. This test drives
 * the real CLI→IPC→handler path and proves the second concurrent call is rejected
 * with registration_already_in_progress, deterministically (no timing race on the
 * assertion) by blocking the directory endpoint resolver.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { RegistrationManager } from "../registration-manager.js";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { registerRegisterHandler } from "../register-handler.js";
import { connectToDaemon } from "../ipc-client.js";
import {
  FileKeyProvider, generateKeypair, signDaemonCredential, decodeRegistrationGrant, verifyDaemonSignature, registrationProofBytes,
} from "@cello-protocol/crypto";
import type { DaemonCredential } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";
import { openEncryptedDatabase, resolveDbKey, dbKeyPathFor, type DaemonDatabase } from "../sqlcipher-db.js";
import { DbPairingStore } from "../pairing-store.js";
import { registrationGuidance } from "../operator-guidance.js";

describe("cello_register single-flight guard", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-reg-handler-"));
    handle = null;
    logger = { debug() {}, info() {}, warn() {}, error() {} };
  });

  afterEach(async () => {
    if (handle) {
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("rejects a concurrent registration with registration_already_in_progress", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "alice"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "alice", "key"));

    // Block directory endpoint resolution so the first registration claims the
    // single-flight slot and parks there while the second call arrives.
    let releaseResolver!: () => void;
    const resolverGate = new Promise<void>((r) => { releaseResolver = r; });
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      directoryEndpointResolver: async () => {
        await resolverGate;
        return null; // after release, resolution "fails" → first call ends in directory_unreachable
      },
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);

    // First registration: passes validation, claims the slot, parks in the resolver.
    const first = client.send("cello_register", { agent: "alice", channel: true, adminPubkeyHex: "ab".repeat(32), adminSignature: "cd".repeat(64) }) as Promise<{ ok: boolean; reason?: string }>;
    // Let the daemon process the first request and reach the resolver await.
    await new Promise((r) => setTimeout(r, 80));

    // Second registration while the first holds the slot → rejected.
    const second = (await client.send("cello_register", { agent: "alice", channel: true, adminPubkeyHex: "ab".repeat(32), adminSignature: "cd".repeat(64) })) as { ok: boolean; reason?: string };
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("registration_already_in_progress");

    // Release the first; it ends in directory_unreachable (resolver returned null),
    // and crucially the slot is freed (finally), so a later registration could proceed.
    releaseResolver();
    const firstResult = await first;
    expect(firstResult.ok).toBe(false);
    expect(firstResult.reason).toBe("directory_unreachable");

    client.close();
  });

  it("7. an unpaired daemon with no token answers not_paired, naming the command that pairs", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "alice"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "alice", "key"));
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);
    const result = (await client.send("cello_register", { agent: "alice" })) as { ok: boolean; reason?: string; guidance?: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("not_paired");
    expect(result.guidance).toContain("cello register-agent");
    client.close();
  });
});

/**
 * DOD-M15-EXPIRY-CONSUMER-POLICY-1 — registration PROCEEDS on a manifest outside its window, and
 * says so.
 *
 * ⚠️ THIS REPLACES TWO SOURCE-TEXT ASSERTIONS THAT WERE HOLLOW, and the bypass is worth recording
 * because it is subtle: they read the handler's own source and asserted a `logger.warn` appeared
 * between two markers and no `return { ok: false` did. **Change one argument — pass `null` instead
 * of the manifest to `classifyManifestValidity` — and the event never fires in production while
 * both tests still pass**, because the text between the markers is byte-identical. They survived
 * deletion and not neutering, which is the failure mode that actually ships.
 *
 * I wrote them because I could not reach the branch at IPC altitude: a daemon will not START on an
 * expired manifest, and the check sits after a 10 s signaling wait. Both true — and both irrelevant,
 * because `registerRegisterHandler` injects EVERY dependency on that path. The seam was one level
 * down from where I was testing.
 */
describe("DOD-M15-EXPIRY-CONSUMER-POLICY-1: a lapsed manifest is reported, and does NOT block", () => {
  it("★ emits registration.manifest.lapsed AND still proceeds past it", async () => {
    const warns: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const handlers = new Map<string, (p: Record<string, unknown> | undefined, c: string) => Promise<unknown>>();
    const logger: Logger = {
      debug() {}, info() {}, error() {},
      warn(event, ctx) { warns.push({ event, ctx: (ctx ?? {}) as Record<string, unknown> }); },
    };

    const expired = {
      version: 3,
      not_before: "2020-01-01T00:00:00Z",
      expires: "2020-06-01T00:00:00Z",
      nodes: [{ nodeId: "n1", pubkey: "aa".repeat(32), region: "local", provider: "gcp", endpoint: "http://127.0.0.1:1", role: "validator" }],
    };

    let reachedRoster = false;
    registerRegisterHandler({
      handlers: handlers as never,
      logger,
      keyProviders: new Map([["alice", { getPublicKey: async () => new Uint8Array(32).fill(1) } as never]]),
      getPersistence: () => ({}) as never,
      getAgentSignaling: () => ({ signaling: {} as never, getNode: () => null }),
      // TRUE: the 10 s wait is the thing that stopped an IPC-level test reaching the branch.
      waitForSignalingConnected: async () => true,
      dropAgentSignaling: async () => {},
      startAgentInternal: () => ({ ok: true }),
      directoryEndpointResolver: async () => ({ peerId: "12D3KooWX", multiaddr: "/ip4/127.0.0.1/tcp/1" }) as never,
      loadedAgents: [{ name: "alice", pubkey: "11".repeat(32), keyProvider: {} as never }],
      registrationGuidance: () => "guidance",
      pairingStore: { credential: () => ({ nonce: "00" }), daemonKey: () => { throw new Error("stub: no daemon key") } } as never,
      manifestProvider: {
        loadAndVerify: async () => expired as never,
        getCurrentManifest: () => { reachedRoster = true; return expired as never; },
        updateManifest: () => {},
      } as never,
    });

    const handler = handlers.get("cello_register")!;
    expect(handler, "the handler must be registered").toBeDefined();
    await handler({ agent: "alice", channel: true, adminPubkeyHex: "ab".repeat(32), adminSignature: "cd".repeat(64) }, "conn-1").catch(() => undefined);

    const lapsed = warns.find((w) => w.event === "registration.manifest.lapsed");
    expect(
      lapsed,
      "the operator must be told the roster came from a manifest outside its window — a later " +
        "dkg_below_threshold names an exit point with no cause anywhere",
    ).toBeDefined();
    expect(lapsed!.ctx["state"]).toBe("expired");

    expect(
      reachedRoster,
      "and it must have gone ON to resolve the roster — the PERMIT half. Refusing here would strand " +
        "a running daemon, since a restart without a replacement manifest never comes back",
    ).toBe(true);
  });
});

/**
 * M16 004-IDENTITY-WIRE — the IPC surface for registering a broadcast channel. The two params travel
 * together or not at all; the handler refuses an inconsistent pair before any directory work.
 */
describe("M16 004-IDENTITY-WIRE: cello_register channel params", () => {
  const ADMIN = "ab".repeat(32);
  const ADMIN_SIG = "cd".repeat(64);

  function makeHandler() {
    const handlers = new Map<string, (p: Record<string, unknown> | undefined, c: string) => Promise<unknown>>();
    registerRegisterHandler({
      handlers: handlers as never,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      keyProviders: new Map([["alice", { getPublicKey: async () => new Uint8Array(32).fill(1) } as never]]),
      getPersistence: () => ({}) as never,
      getAgentSignaling: () => ({
        signaling: { registerInboundHandler: () => () => {} } as never,
        getNode: () => null,
      }),
      waitForSignalingConnected: async () => true,
      dropAgentSignaling: async () => {},
      startAgentInternal: () => ({ ok: true }),
      directoryEndpointResolver: async () => ({ peerId: "12D3KooWX", multiaddr: "/ip4/127.0.0.1/tcp/1" }) as never,
      loadedAgents: [{ name: "alice", pubkey: "11".repeat(32), keyProvider: {} as never }],
      registrationGuidance: () => "guidance",
      pairingStore: { credential: () => ({ nonce: "00" }), daemonKey: () => { throw new Error("stub: no daemon key") } } as never,
    });
    return handlers.get("cello_register")!;
  }

  afterEach(() => { vi.restoreAllMocks(); });

  it("channel without adminPubkeyHex is refused", async () => {
    const spy = vi.spyOn(RegistrationManager.prototype, "register");
    const result = (await makeHandler()({ agent: "alice", channel: true }, "c")) as {
      ok: boolean; reason?: string;
    };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("invalid_channel_registration");
    expect(spy).not.toHaveBeenCalled();
  });

  it("adminPubkeyHex without channel is refused", async () => {
    const spy = vi.spyOn(RegistrationManager.prototype, "register");
    const result = (await makeHandler()({ agent: "alice", adminPubkeyHex: ADMIN }, "c")) as {
      ok: boolean; reason?: string;
    };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("invalid_channel_registration");
    expect(spy).not.toHaveBeenCalled();
  });

  it("a channel is refused without adminSignature", async () => {
    // M16 024-CREATE: a channel presents no token, but it MUST present the admin's signature — the
    // basis of its right. Missing it is refused before the manager is touched.
    const spy = vi.spyOn(RegistrationManager.prototype, "register");
    const result = (await makeHandler()({ agent: "alice", channel: true, adminPubkeyHex: ADMIN }, "c")) as {
      ok: boolean; reason?: string;
    };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("invalid_channel_registration");
    expect(spy).not.toHaveBeenCalled();
  });

  it("well-formed channel params reach the manager WITH the admin signature and NO token", async () => {
    let received: unknown[] | undefined;
    vi.spyOn(RegistrationManager.prototype, "register").mockImplementation(async (...args: unknown[]) => {
      received = args;
      return { error: "stopped_here_by_test" };
    });
    // A channel presents no preAuthToken — its admin signature is the authorization.
    await makeHandler()({ agent: "alice", channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG }, "c");
    expect(received, "the manager must have been invoked").toBeDefined();
    // The token argument is undefined for a channel; the channel opts carry the signature.
    expect(received![1]).toBeUndefined();
    expect(received![2]).toEqual({ channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
  });
});

/**
 * Registration with this device's credential: the grant presented in round 1, and what the
 * directory's refusals become at the IPC surface.
 */
describe("cello_register with the device credential", () => {
  const ACCOUNT = "3f0c8a2e-1b7d-4e5f-9a6b-2c4d6e8f0a1b";
  let dir: string;
  let db: DaemonDatabase;
  let store: DbPairingStore;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-reg-cred-"));
    const dbPath = join(dir, "cello.db");
    db = openEncryptedDatabase(dbPath, resolveDbKey(dbPath, dbKeyPathFor(dbPath)));
    store = new DbPairingStore(db, { debug() {}, info() {}, warn() {}, error() {} });
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    db.close();
    await rm(dir, { recursive: true, force: true });
  });

  async function pair(): Promise<DaemonCredential> {
    const cred = await signDaemonCredential(
      { v: 1, daemon_pubkey: store.daemonKey().pubkeyHex, account_id: ACCOUNT, nonce: "cd".repeat(16), issued_at: "2026-10-28T00:00:00Z" },
      generateKeypair(),
    );
    store.saveCredential(cred);
    return cred;
  }

  function makeHandler(agents: Array<{ name: string; pubkey: string }>) {
    const handlers = new Map<string, (p: Record<string, unknown> | undefined, c: string) => Promise<unknown>>();
    registerRegisterHandler({
      handlers: handlers as never,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      keyProviders: new Map(agents.map((a) => [a.name, {} as never])),
      getPersistence: () => ({ persistAgentUserLink: async () => {} }) as never,
      getAgentSignaling: () => ({ signaling: { registerInboundHandler: () => () => {} } as never, getNode: () => null }),
      waitForSignalingConnected: async () => true,
      dropAgentSignaling: async () => {},
      startAgentInternal: () => ({ ok: true }),
      directoryEndpointResolver: async () => ({ peerId: "12D3KooWX", multiaddr: "/ip4/127.0.0.1/tcp/1" }) as never,
      loadedAgents: agents.map((a) => ({ ...a, keyProvider: {} as never })),
      registrationGuidance,
      pairingStore: store,
    });
    return handlers.get("cello_register")!;
  }

  const ALICE = "11".repeat(32);
  const BOB = "22".repeat(32);

  it("6. two agents on one paired daemon present one credential and two proofs, each bound to its own agent", async () => {
    const cred = await pair();
    const tokens: string[] = [];
    vi.spyOn(RegistrationManager.prototype, "register").mockImplementation(async (_phone, token) => {
      tokens.push(token as string);
      return { error: "stopped_here_by_test" };
    });
    const register = makeHandler([{ name: "alice", pubkey: ALICE }, { name: "bob", pubkey: BOB }]);
    await register({ agent: "alice" }, "c");
    await register({ agent: "bob" }, "c");
    const [a, b] = tokens.map((t) => decodeRegistrationGrant(t));
    expect(a!.credential).toEqual(cred);
    expect(b!.credential).toEqual(cred);
    const daemonPub = store.daemonKey().pubkeyHex;
    expect(verifyDaemonSignature(registrationProofBytes(ALICE, cred.nonce), a!.proof, daemonPub), "A verifies for alice").toBe(true);
    expect(verifyDaemonSignature(registrationProofBytes(BOB, cred.nonce), b!.proof, daemonPub), "B verifies for bob").toBe(true);
    expect(verifyDaemonSignature(registrationProofBytes(BOB, cred.nonce), a!.proof, daemonPub), "A must FAIL for bob").toBe(false);
  });

  it("8. AGENT_CAP_REACHED reaches the response as that reason, with the directory's guidance verbatim", async () => {
    await pair();
    const G = "This account has 3 agents. Verify a phone number in the portal to add more.";
    vi.spyOn(RegistrationManager.prototype, "register").mockResolvedValue({ error: "AGENT_CAP_REACHED", detail: G });
    const r = (await makeHandler([{ name: "alice", pubkey: ALICE }])({ agent: "alice" }, "c")) as Record<string, unknown>;
    expect(r).toEqual({ ok: false, reason: "AGENT_CAP_REACHED", guidance: G });
  });

  it("9. account_unresolved reaches the response with its guidance", async () => {
    await pair();
    const G = "The directory could not find your account. Run 'cello register-agent <name>' again.";
    vi.spyOn(RegistrationManager.prototype, "register").mockResolvedValue({ error: "account_unresolved", detail: G });
    const r = (await makeHandler([{ name: "alice", pubkey: ALICE }])({ agent: "alice" }, "c")) as Record<string, unknown>;
    expect(r).toEqual({ ok: false, reason: "account_unresolved", guidance: G });
  });

  it("11. a caller-supplied token is ignored: a paired daemon always presents its own grant", async () => {
    await pair();
    const tokens: unknown[] = [];
    vi.spyOn(RegistrationManager.prototype, "register").mockImplementation(async (_p, token) => {
      tokens.push(token);
      return { error: "stopped_here_by_test" };
    });
    const register = makeHandler([{ name: "alice", pubkey: ALICE }]);
    await register({ agent: "alice", preAuthToken: "DEV-local" }, "c");
    expect(tokens).toHaveLength(1);
    expect(String(tokens[0])).toMatch(/^DCRED1\./);
  });

  it("11b. an unpaired daemon given a token is refused not_paired", async () => {
    const register = makeHandler([{ name: "alice", pubkey: ALICE }]);
    expect(await register({ agent: "alice", preAuthToken: "DEV-local" }, "c")).toMatchObject({ ok: false, reason: "not_paired" });
  });

  it("12. CREDENTIAL_INVALID clears the credential and keeps the daemon key", async () => {
    await pair();
    const key = store.daemonKey().pubkeyHex;
    vi.spyOn(RegistrationManager.prototype, "register").mockResolvedValue({ error: "CREDENTIAL_INVALID", detail: "Run 'cello register-agent <name>' again to re-pair." });
    await makeHandler([{ name: "alice", pubkey: ALICE }])({ agent: "alice" }, "c");
    expect(store.credential()).toBeNull();
    expect(store.daemonKey().pubkeyHex).toBe(key);
  });
});
