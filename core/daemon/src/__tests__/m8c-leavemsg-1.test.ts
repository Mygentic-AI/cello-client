/**
 * CELLO-M8C-LEAVEMSG-1 — sender-half response shaping
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 29 design note):
 * - Sender-facing: `cello_send` (and the underlying `sessionNodeManager.sendContent`) reports a
 *   genuine relay-park success as {ok:true, delivered:false, parked:true} — "dispatched to relay"
 *   — instead of the pre-LEAVEMSG-1 {ok:false, reason:"session_stream_unavailable"}. The recipient
 *   half (verify/CONTACT/ABUSE/INBOX) was already covered by RELAYWAKE-1 + ABUSE-1's existing tests
 *   (both funnel through the same `ingestReceivedContent` chokepoint — no new code, no new tests
 *   needed there per the design note's own audit).
 * - The existing "no relay configured" failure path (AC-005, daemon-004-ipc.test.ts) is unchanged —
 *   #parkContent's guard still returns false when the session has no relayPeerId/relayAddrs, so
 *   sendContent still returns the honest {ok:false} it always did in that case.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  constructor(private opts: { newStreamFails?: boolean } = {}) {}
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
    if (this.opts.newStreamFails) throw new Error("connection_lost: counterparty stream dead");
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}
class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

const SID = "ab".repeat(32);

describe("M8C-LEAVEMSG-1: sender-half response shaping", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-leavemsg-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<void> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    await FileKeyProvider.load(join(dir, "key"));
  }

  async function start(node: CelloNode): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger: noopLogger, sessionNodeFactory: new FixedFactory(node),
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  async function connectAs(agent: string): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: agent });
    return client;
  }

  it("sendContent: direct-stream failure + a relay configured + a park hook that resolves → {ok:true, delivered:false, parked:true}", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();

    let parkCalls = 0;
    snm.setContentParkHook(async () => { parkCalls++; return { ok: true }; });

    const kp = generateKeypair();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("leave a message");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send");
    expect(res).toMatchObject({ ok: true, delivered: false, parked: true });
    expect(parkCalls).toBe(1);
  });

  it("sendContent: direct-stream failure + NO relay configured → unchanged {ok:false, reason:session_stream_unavailable} (regression lock)", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: true })); // would deposit, but no relay is wired for this session
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr"); // no relay param

    const content = new TextEncoder().encode("hello");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send");
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });
  });

  it("sendContent: direct-stream failure + a relay configured but the park hook THROWS → honest {ok:false} (never a false success)", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => { throw new Error("relay_deposit_failed: relay unreachable"); });

    const kp = generateKeypair();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("hello");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send");
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });
  });

  it("sendContent: direct-stream failure + a relay configured but the park hook RESOLVES {ok:false} (cello-unit-reviewer HIGH fix) → honest {ok:false}, never a false parked:true", async () => {
    // This is the EXACT production shape: the real contentParkHook (daemon.ts) never throws on its
    // main failure branches (standing receiver unavailable, relay explicitly rejects the deposit)
    // — it logs and resolves normally with a typed {ok:false, reason}. A version of #parkContent
    // that only checked "did the hook throw" would treat this as success and report a message as
    // safely dispatched to relay when nothing was ever deposited (and, worse, skip the durable
    // retry_queue enqueue that only fires on an honest {ok:false} — a silent message loss with a
    // success response). This test drives that exact resolved-not-thrown failure shape.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));

    const kp = generateKeypair();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("hello");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send");
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });
  });

  it("cello_send end-to-end: direct-stream failure + relay park success → ok:true, delivered:false, reason:dispatched_to_relay, guidance names relay recovery; leaf + transcript still committed", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: true })); // deposit succeeds

    const kp = generateKeypair();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const client = await connectAs("alice");
    const res = await client.send("cello_send", { session_id: SID, content: "leave a message for bob" }) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect(res.delivered).toBe(false);
    expect(res.reason).toBe("dispatched_to_relay");
    expect(typeof res.sequence_number).toBe("number");
    expect(String(res.guidance)).toContain("relay");

    // The message IS committed to the daemon-owned tree, exactly as a directly-delivered send would be.
    expect(snm.getSessionTree("alice", SID).size()).toBe(1);
  });
});
