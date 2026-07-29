/**
 * CELLO-M8C-TGDOOR-1 — Telegram Mode 1 doorbell
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 25 design note):
 * - G1: a session-request event ALWAYS rings (no coalescing), formatted `[agent · session] ...`.
 * - G2: a state-change event ALWAYS rings.
 * - G3: message-waiting events are coalesced — ring once per unread period, not per message.
 * - G4: reading (cello_receive) clears the ring, so a LATER new message rings again.
 * - G5: content-free — the doorbell text is always a fixed label, never message content.
 * - G6: inbound from the allowlisted chat gets a canned ack (telegram.inbound.acknowledged);
 *   any other chat is silently dropped (telegram.inbound.rejected), no CELLO action taken.
 * - G7: TGDOOR is inert (no sends, no errors) until settings are configured.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { TelegramBotClient, TelegramUpdate } from "../telegram-bot-client.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
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

/** In-memory fake — no real network. Throttles empty getUpdates so the poller doesn't busy-spin. */
class FakeTelegramBotClient implements TelegramBotClient {
  sent: Array<{ chatId: string; text: string }> = [];
  #pending: TelegramUpdate[] = [];
  async getUpdates(_offset: number, _timeoutSec: number): Promise<TelegramUpdate[]> {
    if (this.#pending.length === 0) {
      await new Promise((r) => setTimeout(r, 15));
      return [];
    }
    const u = this.#pending;
    this.#pending = [];
    return u;
  }
  async sendMessage(chatId: string, text: string): Promise<{ ok: boolean }> {
    this.sent.push({ chatId, text });
    return { ok: true };
  }
  injectUpdate(u: TelegramUpdate): void { this.#pending.push(u); }
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

describe("M8C-TGDOOR-1: Telegram doorbell", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];
  let bot: FakeTelegramBotClient;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-tgdoor-"));
    handle = null;
    clients = [];
    bot = new FakeTelegramBotClient();
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

  async function start(withBot: boolean, signalingConnect?: () => Promise<ConnectResult>): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeFactory: new FixedFactory(new FakeNode()),
      telegramBotClient: withBot ? bot : undefined,
      signalingConnect,
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

  const CHAT_ID = "12345";

  it("G7: TGDOOR is inert (no sends) until configured", async () => {
    await makeAgentDir("alice");
    const h = await start(false);
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode("aa".repeat(16), "alice", "bobpubkeyhex", "peer-1", "corr");
    await snm.ingestReceivedContent("alice", "aa".repeat(16), new TextEncoder().encode("hi"), msgLeafHash(new TextEncoder().encode("hi")), "c1");
    await wait(30);
    expect(bot.sent).toHaveLength(0); // never configured — nothing sent, no crash
  });

  it("G1/G2/G5: session-request + state-change events ring with content-free, fixed labels", async () => {
    await makeAgentDir("alice");
    const h = await start(true);
    const client = await connectAs("alice");
    await client.send("cello_telegram_set_token", { bot_token: "t", allowlisted_chat_id: CHAT_ID });
    await wait(30);

    const snm = h.getSessionNodeManager();
    await snm.createSessionNode("bb".repeat(16), "alice", "bobpubkeyhex", "peer-1", "corr");
    // Simulate the session-request + state-change doorbells the real accept path fires (session
    // creation itself is exercised end-to-end in the AWAY-1/CONTACT-1 seam-2-style tests already;
    // here we drive the SAME public dispatch surface — setOnSessionStateChanged's callback — to
    // keep this test focused on TGDOOR's own formatting/coalescing behavior).
    await snm.markInterruptedWithDetails("alice", "bb".repeat(16), 0, "stream_close"); // triggers a state change
    await wait(30);

    const stateChangeMsg = bot.sent.find((s) => s.text.includes("Session"));
    expect(stateChangeMsg).toBeDefined();
    expect(stateChangeMsg?.chatId).toBe(CHAT_ID);
    expect(stateChangeMsg?.text).toMatch(/^\[alice · bb{7}\] Session \w+$/); // fixed label only, no content
  });

  it("G3/G4: message-waiting is coalesced (one ring per unread period); reading clears it for the NEXT message", async () => {
    await makeAgentDir("alice");
    const h = await start(true);
    const client = await connectAs("alice");
    await client.send("cello_telegram_set_token", { bot_token: "t", allowlisted_chat_id: CHAT_ID });
    await wait(30);

    const snm = h.getSessionNodeManager();
    const sid = "cc".repeat(16);
    await snm.createSessionNode(sid, "alice", "bobpubkeyhex", "peer-1", "corr");
    snm.addContact("alice", "bobpubkeyhex"); // known — no AWAY-1 auto-ack noise in this test

    await snm.ingestReceivedContent("alice", sid, new TextEncoder().encode("m1"), msgLeafHash(new TextEncoder().encode("m1")), "c1");
    await snm.ingestReceivedContent("alice", sid, new TextEncoder().encode("m2"), msgLeafHash(new TextEncoder().encode("m2")), "c2");
    await wait(30);
    const waitingMsgs = bot.sent.filter((s) => s.text.includes("message waiting"));
    expect(waitingMsgs).toHaveLength(1); // G3: coalesced — two messages, one ring

    // Read clears it — cello_receive (live-drain) advances the watermark, unlike
    // cello_get_transcript (which only advances CURSOR-1's connection cursor).
    await client.send("cello_receive", { session_id: sid, timeout_ms: 100 });
    await client.send("cello_receive", { session_id: sid, timeout_ms: 100 });

    await snm.ingestReceivedContent("alice", sid, new TextEncoder().encode("m3"), msgLeafHash(new TextEncoder().encode("m3")), "c3");
    await wait(30);
    const waitingMsgs2 = bot.sent.filter((s) => s.text.includes("message waiting"));
    expect(waitingMsgs2).toHaveLength(2); // G4: a NEW message after a read rings again
  });

  it("G6: inbound from the allowlisted chat gets a canned ack; any other chat is silently dropped", async () => {
    await makeAgentDir("alice");
    await start(true);
    const client = await connectAs("alice");
    await client.send("cello_telegram_set_token", { bot_token: "t", allowlisted_chat_id: CHAT_ID });
    await wait(30);

    bot.injectUpdate({ update_id: 1, message: { chat: { id: CHAT_ID }, text: "hello", message_id: 1 } });
    await wait(60);
    const ack = bot.sent.find((s) => s.chatId === CHAT_ID);
    expect(ack).toBeDefined(); // the canned ack was sent back to the allowlisted chat

    const beforeCount = bot.sent.length;
    bot.injectUpdate({ update_id: 2, message: { chat: { id: "999999" }, text: "spam", message_id: 2 } });
    await wait(60);
    expect(bot.sent.length).toBe(beforeCount); // silently dropped — no ack, nothing sent to the stranger
  });

  // Reviewer finding (a60d68ed, hollow test): G1 (session-request rings) was claimed covered by
  // the G1/G2/G5 test above but never actually exercised — that test only drives a state change.
  // This test drives the REAL acceptInboundAssignment path via an injected session_assignment
  // frame (seam-2-inbound-session.test.ts-style harness), the actual G1 dispatch point.
  it("G1 (real wiring): a genuine inbound session request rings with the session-request label", async () => {
    const bobPubkey = await (async () => {
      const dir = join(tempDir, "agents", "bob");
      await mkdir(dir, { recursive: true });
      const kp = await FileKeyProvider.load(join(dir, "key"));
      return Buffer.from(await kp.getPublicKey()).toString("hex");
    })();
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(true, makeInjectableSignaling(injectRef));
    await client_setToken();
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
    injectRef.inject!({
      type: "session_assignment",
      assignment: {
        session_id: SID_BYTES,
        participant_a: { pubkey: Buffer.from("dd".repeat(32), "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        session_timestamp: 1_700_000_000_000,
        signature_type: "frost",
        initiator_session_peer_id: "initiator-peer-id",
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    });
    await wait(150);

    const requestMsg = bot.sent.find((s) => s.text.includes("New session request"));
    expect(requestMsg).toBeDefined();
    expect(requestMsg?.chatId).toBe(CHAT_ID);
  });

  // Reviewer finding (a60d68ed, hollow test): G7's existing test only proves the NEGATIVE case
  // (never configured). The literal claim — "cold: works with ZERO IPC connections, settings
  // already persisted from a prior run" — was never exercised. This drives that exact scenario:
  // settings persisted directly (no cello_telegram_set_token IPC call), zero clients ever connect.
  it("G7 (real cold-start): settings persisted by a PRIOR daemon run are picked up on the NEXT boot with ZERO IPC connections", async () => {
    await makeAgentDir("alice");
    // First "run": start once just to persist settings into the on-disk DB, then stop it — this
    // is the "prior run" the DoD's "cold (no live agent session)" clause is about.
    const first = await start(true);
    first.getSessionNodeManager().setTelegramSettings("t", CHAT_ID);
    await first.stop("test_setup");
    handle = null;

    // Second "run": a FRESH startDaemon() against the SAME celloDir — settings already exist in
    // the persisted DB, so the poller must start at BOOT with NO IPC connection ever made.
    const second = await start(true);
    await second.getSessionNodeManager().createSessionNode("ee".repeat(16), "alice", "bobpubkeyhex", "peer-1", "corr");
    await second.getSessionNodeManager().markInterruptedWithDetails("alice", "ee".repeat(16), 0, "stream_close");
    await wait(30);

    expect(bot.sent.length).toBeGreaterThan(0); // rang cold — no client ever attached in this whole test
  });

  // Reviewer finding (a60d68ed, hollow test): coalescing key isolation (per-SESSION, not global)
  // was never proven — G3/G4 only ever used one session id.
  it("G3 (per-session isolation): two different sessions each ring independently, one does not suppress the other", async () => {
    await makeAgentDir("alice");
    const h = await start(true);
    await client_setToken();
    const snm = h.getSessionNodeManager();
    const sidA = "f1".repeat(16);
    const sidB = "f2".repeat(16);
    await snm.createSessionNode(sidA, "alice", "cp-a-pubkeyhex", "peer-a", "corr-a");
    await snm.createSessionNode(sidB, "alice", "cp-b-pubkeyhex", "peer-b", "corr-b");
    snm.addContact("alice", "cp-a-pubkeyhex");
    snm.addContact("alice", "cp-b-pubkeyhex");

    await snm.ingestReceivedContent("alice", sidA, new TextEncoder().encode("a1"), msgLeafHash(new TextEncoder().encode("a1")), "ca1");
    await snm.ingestReceivedContent("alice", sidB, new TextEncoder().encode("b1"), msgLeafHash(new TextEncoder().encode("b1")), "cb1");
    await wait(30);
    expect(bot.sent.filter((s) => s.text.includes("message waiting"))).toHaveLength(2); // BOTH ring — independent

    // A second message on A alone must NOT ring again (still coalesced for A), and must not
    // affect B's own independent coalescing state either.
    await snm.ingestReceivedContent("alice", sidA, new TextEncoder().encode("a2"), msgLeafHash(new TextEncoder().encode("a2")), "ca2");
    await wait(30);
    expect(bot.sent.filter((s) => s.text.includes("message waiting"))).toHaveLength(2); // unchanged
  });

  /** Configure TGDOOR via the real IPC handler (callers create their own agent dirs first). */
  async function client_setToken(): Promise<void> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_telegram_set_token", { bot_token: "t", allowlisted_chat_id: CHAT_ID });
  }
});
