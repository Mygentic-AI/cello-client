/**
 * CELLO-M8C-AWAY-1 — away response: unattended Primary auto-answers session requests + messages
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note):
 * - A1: a NEW inbound session request while unattended gets an auto-ack (kind:"request" text)
 *   appended to the transcript; queued via the existing inboundSessionQueues mechanism regardless.
 * - A2: an inbound MESSAGE on an existing active session while unattended gets an auto-ack
 *   (kind:"message" text, distinct from A1's).
 * - A3: while ATTENDED (a connection has claimed the agent via cello_use_agent), no away
 *   response fires for either kind — the agent answers for itself.
 * - A4: coalescing — a second inbound message during the SAME away period does not re-trigger a
 *   second away ack (no reply storm).
 * - A5: becoming attended (cello_use_agent) clears the dedup, so a LATER away period (after the
 *   operator disconnects/attends elsewhere) gets a fresh ack rather than permanent silence.
 * - Deviation (journaled, D14-pattern): opaque privacy mode (silence, indistinguishable from
 *   unreachable) is PARKED on M9-CFG-001 — this unit ships only the DoD's own mandated
 *   transparent default, which is a real, correct, non-fake behavior on its own.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}

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

/** Injectable signaling stub — the directory's push channel (mirrors seam-2-inbound-session.test.ts). */
function makeInjectableSignaling(
  injectRef: { inject?: (frame: unknown) => void },
): () => Promise<ConnectResult> {
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

describe("M8C-AWAY-1: away response", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-away-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function start(logger: Logger, node: CelloNode, signalingConnect?: () => Promise<ConnectResult>): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(node), signalingConnect,
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

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const TS = 1_700_000_000_000;

  function assignmentFrame(initiatorPubkeyHex: string, counterpartyPubkeyHex: string): Record<string, unknown> {
    return {
      type: "session_assignment",
      assignment: {
        session_id: SID_BYTES,
        participant_a: { pubkey: Buffer.from(initiatorPubkeyHex, "hex") },
        participant_b: { pubkey: Buffer.from(counterpartyPubkeyHex, "hex") },
        session_timestamp: TS,
        signature_type: "frost",
        initiator_session_peer_id: "alice-session-peer-id",
      },
    };
  }

  it("A1: an inbound session request while UNATTENDED gets an auto-ack in the transcript", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const initiatorPubkey = "cd".repeat(32);
    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey)); // bob never attended — no client connected yet
    await wait(150);

    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "request")).toBeDefined();
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(1);
    expect(messages[0].direction).toBe("sent");
    expect(messages[0].text).toContain("session request has been received and queued");
  });

  it("A3: an inbound session request while ATTENDED gets NO auto-ack", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    await connectAs("bob"); // bob is now ATTENDED

    const initiatorPubkey = "ef".repeat(32);
    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(150);

    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(0);
  });

  it("A2/A4/A5: message auto-ack while unattended, coalesced on a repeat, fresh after a re-away period", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    // A2: unattended (no connection yet) — an inbound message gets an away ack.
    snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi"), msgLeafHash(new TextEncoder().encode("hi")), "c1");
    await wait(30);
    let sentEvents = events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message");
    expect(sentEvents).toHaveLength(1);

    // A4: a SECOND message in the SAME away period does not re-trigger.
    snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi again"), msgLeafHash(new TextEncoder().encode("hi again")), "c2");
    await wait(30);
    sentEvents = events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message");
    expect(sentEvents).toHaveLength(1); // still just one — coalesced

    let { messages } = snm.readTranscript("alice", SID_HEX);
    let sentMessages = messages.filter((m) => m.direction === "sent");
    expect(sentMessages).toHaveLength(1);
    expect(sentMessages[0].text).toContain("message has been received");

    // A5: attend, then go away again — the dedup clears, so a NEW away period gets a fresh ack.
    const client = await connectAs("alice");
    client.close();
    await wait(50); // let the disconnect propagate (perConnectionState delete) before re-checking away
    // Reconnect check: attending clears dedup immediately on cello_use_agent (not on disconnect),
    // so the agent is "away" again right after this connection closes (no other attends it).
    snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("third"), msgLeafHash(new TextEncoder().encode("third")), "c3");
    await wait(30);
    sentEvents = events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message");
    expect(sentEvents).toHaveLength(2); // a fresh ack after re-attending then going away again

    ({ messages } = snm.readTranscript("alice", SID_HEX));
    expect(messages.filter((m) => m.direction === "sent")).toHaveLength(2);
  });

  it("A3: no auto-ack for a message while ATTENDED", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    await connectAs("alice"); // attended

    snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi"), msgLeafHash(new TextEncoder().encode("hi")), "c1");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    const { messages } = snm.readTranscript("alice", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")).toHaveLength(0);
  });
});
