/**
 * MONIKER-5 — the moniker is LABEL-ONLY, provably (M8C-MONIKER-SPEC §MONIKER-5).
 *
 * AC2 is the load-bearing one: screening outcomes (known/unknown, ABUSE-1 caps,
 * CC-1 promotion) must be BYTE-IDENTICAL with and without a moniker present.
 * A name must never buy trust.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { makeSignedAssignmentFrame } from "./helpers/signed-assignment.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

function silentLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

function makeInjectableSignaling(injectRef: { inject?: (frame: unknown) => void }): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async () => {},
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  injectRef.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

let tempDir = "";
let handle: Awaited<ReturnType<typeof startDaemon>> | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "moniker5-"));
  handle = null;
});
afterEach(async () => {
  for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
  clients.length = 0;
  if (handle) { try { await handle.stop("test_cleanup"); } catch { /* ignore */ } }
  await rm(tempDir, { recursive: true, force: true });
});

async function startHarness(): Promise<{ inject: (f: unknown) => void; client: IpcClient; bobPubkey: string; snm: ReturnType<Awaited<ReturnType<typeof startDaemon>>["getSessionNodeManager"]> }> {
  const dir = join(tempDir, "agents", "bob");
  await mkdir(dir, { recursive: true });
  const kp = await FileKeyProvider.load(join(dir, "key"));
  const bobPubkey = Buffer.from(await kp.getPublicKey()).toString("hex");
  const injectRef: { inject?: (frame: unknown) => void } = {};
  const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
    celloDir: tempDir,
    socketPath: join(tempDir, "daemon.sock"),
    lockFilePath: join(tempDir, "daemon.lock"),
    maxConnections: 16,
    version: "0.0.1-test",
    logger: silentLogger(),
    sessionNodeFactory: new FixedFactory(new FakeNode() as CelloNode),
    signalingConnect: makeInjectableSignaling(injectRef),
  };
  handle = await startDaemon(config);
  await wait(50);
  const snm = handle.getSessionNodeManager();
  await snm.ensureStandingReceiverForAgent("bob");
  const client = await connectToDaemon(config.socketPath);
  clients.push(client);
  await client.send("ipc.connect", { clientType: "mcp" });
  return { inject: injectRef.inject!, client, bobPubkey, snm };
}

/**
 * DOD-M15-RESPONDER-VERIFY-1: the responder now VERIFIES inbound assignments, so this fixture mints
 * a genuinely signed one. The moniker is attached AFTER signing on purpose — it is not covered by
 * the session-establishment TBS, and that is exactly the point of MONIKER-5: the name rides beside
 * the signed document, so it can never be mistaken for something the directory attested.
 */
async function assignmentFrame(
  initiatorHex: string,
  bobHex: string,
  sid: Uint8Array,
  moniker?: string,
): Promise<Record<string, unknown>> {
  const { frame } = await makeSignedAssignmentFrame({
    sessionId: sid,
    initiatorPubkey: Uint8Array.from(Buffer.from(initiatorHex, "hex")),
    responderPubkey: Uint8Array.from(Buffer.from(bobHex, "hex")),
    initiatorSessionPeerId: "alice-session-peer-id",
    // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
    counterpartySessionPeerId: "bob-session-peer-id",
  });
  if (moniker !== undefined) {
    (frame["assignment"] as Record<string, unknown>)["moniker"] = moniker;
  }
  return frame;
}

const sid = (n: number) => Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + n));

describe("MONIKER-5 AC2 — screening outcomes are byte-identical with and without a moniker", () => {
  it("a name buys NO trust: known/unknown, contact membership, and the acceptance bound are unchanged", async () => {
    const h = await startHarness();
    const nameless = "aa".repeat(32);
    const named = "bb".repeat(32);

    // Two strangers: one offers a name, one does not. Same screening inputs otherwise.
    h.inject(await assignmentFrame(nameless, h.bobPubkey, sid(1)));
    h.inject(await assignmentFrame(named, h.bobPubkey, sid(50), "Trusted_Admin"));
    await wait(200);

    // CC-1: neither is auto-added — a name does not promote to "known".
    expect(h.snm.isContact("bob", nameless)).toBe(false);
    expect(h.snm.isContact("bob", named)).toBe(false);

    // ABUSE-1: the named stranger is still COUNTED as unknown. This is the assertion with teeth —
    // comparing the two bound results is vacuous (both sit under the caps, and the bound function
    // takes no moniker), but the count would drop to 1 if an offered name ever made a sender
    // contact-like and exempted its session from the unknown-sender accounting.
    expect(h.snm.countActiveSessionsFromUnknownSenders("bob")).toBe(2);
  });

  it("AC1: cello_list_sessions and cello_contact_list surface the resolved who", async () => {
    const h = await startHarness();
    const initiator = "cc".repeat(32);

    h.inject(await assignmentFrame(initiator, h.bobPubkey, sid(1), "Wonderland_Alice"));
    await wait(150);

    const sessions = (await h.client.send("cello_list_sessions", { agent: "bob" })) as {
      sessions: Array<{ counterpartyPubkey: string; who: string; whoKnown: boolean }>;
    };
    const row = sessions.sessions.find((s) => s.counterpartyPubkey === initiator)!;
    expect(row.who).toBe("Wonderland_Alice"); // offered tier
    expect(row.whoKnown).toBe(false);

    await h.client.send("cello_contact_add", { agent: "bob", pubkey: initiator, moniker: "MyAlice" });
    const contacts = (await h.client.send("cello_contact_list", { agent: "bob" })) as {
      contacts: Array<{ pubkey: string; who: string; whoKnown: boolean }>;
    };
    const c = contacts.contacts.find((x) => x.pubkey === initiator)!;
    expect(c.who).toBe("MyAlice"); // local tier wins
    expect(c.whoKnown).toBe(true);
  });
});
