/**
 * MONIKER-4 AC2 — `who` + `whoKnown` ride EXACTLY the two counterparty-bearing
 * frames (session_state_changed, cello_message), resolved daemon-side.
 *
 * Tests are written RED-first per SPARC Phase R.
 *
 * Part 1 unit-tests the dispatcher frame shapes; part 2 drives the real inbound
 * path (moniker-2 harness) and asserts the notification a live MCP connection
 * receives carries the resolved label.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { NotificationDispatcher } from "../notification-dispatcher.js";
import type { Logger, DaemonConfig, IpcNotification } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

function silentLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

// ─── Part 1: dispatcher frame shapes ─────────────────────────────────────────

describe("MONIKER-4 AC2 — dispatcher stamps who/whoKnown on the two counterparty frames", () => {
  function makeDispatcher(): { d: NotificationDispatcher; sent: IpcNotification[] } {
    const sent: IpcNotification[] = [];
    const d = new NotificationDispatcher({
      logger: silentLogger(),
      sendNotification: (_c, n) => { sent.push(n); return true; },
      getConnectionIds: () => ["c1"],
    });
    d.registerConnection("c1");
    d.setCurrentAgent("c1", "alice");
    return { d, sent };
  }

  it("session_state_changed carries who/whoKnown when provided; counterpartyPubkey stays the anchor", () => {
    const { d, sent } = makeDispatcher();
    d.dispatchSessionStateChanged("alice", "sid1", "created", "ff".repeat(32), { who: "Bob", whoKnown: false });
    expect(sent).toHaveLength(1);
    expect(sent[0].data["who"]).toBe("Bob");
    expect(sent[0].data["whoKnown"]).toBe(false);
    expect(sent[0].data["counterpartyPubkey"]).toBe("ff".repeat(32));
  });

  it("cello_message carries who/whoKnown when provided; from stays the anchor", () => {
    const { d, sent } = makeDispatcher();
    d.dispatchCelloMessage("alice", "sid1", "ee".repeat(32), { who: "MyBob", whoKnown: true });
    expect(sent).toHaveLength(1);
    expect(sent[0].data["who"]).toBe("MyBob");
    expect(sent[0].data["whoKnown"]).toBe(true);
    expect(sent[0].data["from"]).toBe("ee".repeat(32));
  });

  it("legacy call sites (no resolution) omit the fields rather than sending undefined", () => {
    const { d, sent } = makeDispatcher();
    d.dispatchSessionStateChanged("alice", "sid1", "interrupted", null);
    d.dispatchCelloMessage("alice", "sid1", "ee".repeat(32));
    expect("who" in sent[0].data).toBe(false);
    expect("who" in sent[1].data).toBe(false);
  });
});

// ─── Part 2: end-to-end — inbound offer → resolved doorbell notification ────

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
const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));

describe("MONIKER-4 AC2 e2e — the created doorbell carries the resolved who", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  const clients: IpcClient[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "moniker4-"));
    handle = null;
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
    clients.length = 0;
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function startHarness(): Promise<{ inject: (f: unknown) => void; client: IpcClient; bobPubkey: string; notifications: IpcNotification[] }> {
    const dir = join(tempDir, "agents", "bob");
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    const bobPubkey = Buffer.from(await kp.getPublicKey()).toString("hex");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const config: DaemonConfig = {
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
    await handle.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    const client = await connectToDaemon(config.socketPath);
    clients.push(client);
    const notifications: IpcNotification[] = [];
    client.onNotification((n) => notifications.push(n));
    await client.send("ipc.connect", { clientType: "mcp" });
    await client.send("cello_use_agent", { name: "bob" });
    return { inject: injectRef.inject!, client, bobPubkey, notifications };
  }

  function assignmentFrame(initiatorHex: string, bobHex: string, moniker?: string): Record<string, unknown> {
    const assignment: Record<string, unknown> = {
      session_id: SID_BYTES,
      participant_a: { pubkey: Buffer.from(initiatorHex, "hex") },
      participant_b: { pubkey: Buffer.from(bobHex, "hex") },
      session_timestamp: 1_700_000_000_000,
      signature_type: "frost",
      initiator_session_peer_id: "alice-session-peer-id",
      // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
      counterparty_session_peer_id: "bob-session-peer-id",
    };
    if (moniker !== undefined) assignment["moniker"] = moniker;
    return { type: "session_assignment", assignment };
  }

  it("offered name (stranger): who = offered, whoKnown = false; pet name (contact): who = pet, whoKnown = true", async () => {
    const h = await startHarness();
    const initiator = "cd".repeat(32);

    h.inject(assignmentFrame(initiator, h.bobPubkey, "Wonderland_Alice"));
    await wait(150);

    const created = h.notifications.find(
      (n) => n.notification === "session_state_changed" && n.data["state"] === "created",
    );
    expect(created).toBeDefined();
    expect(created!.data["who"]).toBe("Wonderland_Alice");
    expect(created!.data["whoKnown"]).toBe(false);

    // Now the operator sets a pet name — a SECOND offer resolves to it (local wins).
    await h.client.send("cello_contact_set_moniker", { agent: "bob", pubkey: initiator, moniker: "MyAlice" });
    // (the first accept auto…no — CC-1: never auto-added; add explicitly first)
    const contacts = (await h.client.send("cello_contact_list", { agent: "bob" })) as { contacts: Array<{ pubkey: string }> };
    if (!contacts.contacts.some((c) => c.pubkey === initiator)) {
      await h.client.send("cello_contact_add", { agent: "bob", pubkey: initiator, moniker: "MyAlice" });
    }
    const sid2 = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 100));
    const frame2 = assignmentFrame(initiator, h.bobPubkey, "Wonderland_Alice");
    (frame2["assignment"] as Record<string, unknown>)["session_id"] = sid2;
    h.inject(frame2);
    await wait(150);

    const created2 = h.notifications.filter(
      (n) => n.notification === "session_state_changed" && n.data["state"] === "created",
    );
    expect(created2.length).toBeGreaterThanOrEqual(2);
    expect(created2[created2.length - 1].data["who"]).toBe("MyAlice");
    expect(created2[created2.length - 1].data["whoKnown"]).toBe(true);
  });

  it("no name anywhere → who is the fingerprint, whoKnown false", async () => {
    const h = await startHarness();
    const initiator = "ce".repeat(32);

    h.inject(assignmentFrame(initiator, h.bobPubkey));
    await wait(150);

    const created = h.notifications.find(
      (n) => n.notification === "session_state_changed" && n.data["state"] === "created",
    );
    expect(created).toBeDefined();
    expect(created!.data["who"]).toBe(`agent ${initiator.slice(0, 8)}…`);
    expect(created!.data["whoKnown"]).toBe(false);
  });
});
