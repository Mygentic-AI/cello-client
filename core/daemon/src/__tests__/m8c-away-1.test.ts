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
import { TIER } from "../contacts-tier-migration.js";
import type { SecurityGatewayClient, ScreenContext, ScreenVerdict } from "@cello-protocol/gateway";
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
  // Reviewer finding (a9099571): let a test toggle a transient failure on the NEXT newStream call
  // only, to prove the away-ack dedup guard clears on failure and retries on the next arrival.
  failNextStream = false;
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
    if (this.failNextStream) {
      this.failNextStream = false;
      throw new Error("connection_lost: counterparty stream dead");
    }
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

  async function start(logger: Logger, node: CelloNode, signalingConnect?: () => Promise<ConnectResult>, securityGateway?: SecurityGatewayClient): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(node), signalingConnect,
      ...(securityGateway ? { securityGateway } : {}),
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
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
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
    // M8C-CONTACT-1: pre-register as known so this test stays focused on AWAY-1's own template
    // logic — the unknown-sender ("Dispatched.") branch is covered by m8c-contact-1.test.ts.
    h.getSessionNodeManager().addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);
    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey)); // bob never attended — no client connected yet
    await wait(150);

    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "request")).toBeDefined();
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(1);
    expect(messages[0].direction).toBe("sent");
    // DOD-AWAY-WRAP-1 AC1: request away greeting names the agent and gives leave-a-message instructions.
    expect(messages[0].text).toContain("bob is currently away");
    expect(messages[0].text).toContain("[[WRAP]]");
  });

  // A gateway whose OUTBOUND verdict is configurable per test (inbound always allows).
  class StubGateway implements SecurityGatewayClient {
    constructor(private readonly outbound: (c: Uint8Array) => ScreenVerdict) {}
    async screenInbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> { return { disposition: "allow", content }; }
    async screenOutbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> { return this.outbound(content); }
  }

  it("DOD-AWAY-TIER-1 T1: an unattended away response USES the resolution — a per-contact away text is what's sent + contact.away.resolved fires", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = "cd".repeat(32);
    snm.addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);
    snm.setContactAwayMessage("bob", initiatorPubkey, "Hey - reach me on Signal");

    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey)); // unattended
    await wait(150);

    // The RESOLVED custom text is what landed in the transcript — not the system default (bypass:
    // reverting the caller to the constant would send "session request has been received…" here).
    const { messages } = snm.readTranscript("bob", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")[0]?.text).toBe("Hey - reach me on Signal");
    // Observability AC: contact.away.resolved fired with the matched level.
    expect(events.find((e) => e.event === "contact.away.resolved" && e.context.level === "contact")).toBeDefined();
  });

  it("DOD-AWAY-TIER-1 T2 (SI): a BLOCK verdict on the away text means nothing is sent", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const gateway = new StubGateway(() => ({ disposition: "block", reason: "away_pii" }));
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef), gateway);
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = "cd".repeat(32);
    snm.addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);

    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(150);

    expect(events.find((e) => e.event === "session.away.response.screened_out" && e.context.disposition === "block")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    expect(snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(0);
  });

  it("DOD-AWAY-TIER-1 T2 (SI): a REDACT verdict sends the ALTERED bytes, never the pre-redaction draft", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const redacted = new TextEncoder().encode("[redacted away]");
    const gateway = new StubGateway(() => ({ disposition: "redact", content: redacted }));
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef), gateway);
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = "cd".repeat(32);
    snm.addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);
    snm.setContactAwayMessage("bob", initiatorPubkey, "my home address is 123 Main St"); // would-be leak

    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(150);

    const sent = snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")[0];
    expect(sent?.text).toBe("[redacted away]"); // the ALTERED bytes — the draft never went on the wire
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
    // M8C-CONTACT-1: pre-register as known so this test stays focused on AWAY-1's own template
    // logic — the unknown-sender ("Dispatched.") branch is covered by m8c-contact-1.test.ts.
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    // A2: unattended (no connection yet) — an inbound message gets an away ack.
    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi"), msgLeafHash(new TextEncoder().encode("hi")), "c1");
    await wait(30);
    let sentEvents = events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message");
    expect(sentEvents).toHaveLength(1);

    // A4: a SECOND message in the SAME away period does not re-trigger.
    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi again"), msgLeafHash(new TextEncoder().encode("hi again")), "c2");
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
    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("third"), msgLeafHash(new TextEncoder().encode("third")), "c3");
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

    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi"), msgLeafHash(new TextEncoder().encode("hi")), "c1");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    const { messages } = snm.readTranscript("alice", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")).toHaveLength(0);
  });

  // Reviewer finding (a9099571, test-teeth gap): the dedup key is per (agent, SESSION, kind) — a
  // regression that dropped sessionId from the key would incorrectly suppress the SECOND session's
  // ack because the first session's message already consumed that kind's dedup slot.
  it("A4 (per-session isolation): two different unattended sessions on the SAME agent each get their own independent away ack", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const SID_1 = "aa".repeat(32);
    const SID_2 = "bb".repeat(32);
    await snm.createSessionNode(SID_1, "alice", "cp1pubkeyhex", "peer-1", "corr-1");
    await snm.createSessionNode(SID_2, "alice", "cp2pubkeyhex", "peer-2", "corr-2");

    await snm.ingestReceivedContent("alice", SID_1, new TextEncoder().encode("m1"), msgLeafHash(new TextEncoder().encode("m1")), "c1");
    await snm.ingestReceivedContent("alice", SID_2, new TextEncoder().encode("m2"), msgLeafHash(new TextEncoder().encode("m2")), "c2");
    await wait(30);

    const acked = events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message");
    expect(acked.map((e) => e.context.sessionId).sort()).toEqual([SID_1, SID_2].sort());
  });

  // DOD-AWAY-WRAP-1 AC2/AC3/AC4(b): a [[WRAP]]-signalled inbound message must NOT trigger the away reply.
  it("DOD-AWAY-WRAP-1: [[WRAP]]-signalled message skips the away reply and logs skipped_wrap", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    const wrapContent = new TextEncoder().encode("goodbye [[WRAP]]");
    await snm.ingestReceivedContent("alice", SID_HEX, wrapContent, msgLeafHash(wrapContent), "c1");
    await wait(30);

    // No away reply must be sent.
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    // The skip must be logged (observability AC).
    expect(events.find((e) => e.event === "session.away.response.skipped_wrap")).toBeDefined();
    // No sent message in transcript.
    const { messages } = snm.readTranscript("alice", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")).toHaveLength(0);
  });

  // DOD-AWAY-WRAP-1 AC4(c): a non-[[WRAP]] message still triggers the away reply.
  // The complementary skipped_wrap assertion pins the guard: only [[WRAP]] suppresses; [[OVER]] does not.
  it("DOD-AWAY-WRAP-1: a non-[[WRAP]] message still triggers the away reply (and skipped_wrap does NOT fire)", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    const overContent = new TextEncoder().encode("hello [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, overContent, msgLeafHash(overContent), "c1");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "message")).toBeDefined();
    // Revert-test anchor: if the [[WRAP]] guard were absent, skipped_wrap would never fire for any
    // message — this assertion is vacuously true pre-fix. But if the guard were overly broad (e.g.
    // matching any message containing "wrap" or "[["), this would catch the regression.
    expect(events.find((e) => e.event === "session.away.response.skipped_wrap")).toBeUndefined();
    const { messages } = snm.readTranscript("alice", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")).toHaveLength(1);
  });

  // DOD-AWAY-WRAP-1 AC3: combined transcript shape — greeting at seq 0 (sent), [[WRAP]] message at
  // seq 1 (received), NOTHING ELSE. Verifies the dedup guard doesn't double-send and the [[WRAP]]
  // skip leaves no spurious seq 2.
  it("DOD-AWAY-WRAP-1 AC3: sealed transcript shape — exactly greeting(sent) + [[WRAP]]-msg(received), nothing else", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    snm.addContact("bob", "cd".repeat(32), undefined, null, TIER.KNOWN);

    // Step 1: inbound session request → daemon sends away greeting (seq 0, sent).
    injectRef.inject!(assignmentFrame("cd".repeat(32), bobPubkey));
    await wait(150);

    // Step 2: caller sends a [[WRAP]] message → daemon skips away reply.
    const wrapContent = new TextEncoder().encode("leaving my message [[WRAP]]");
    await snm.ingestReceivedContent("bob", SID_HEX, wrapContent, msgLeafHash(wrapContent), "wrap-corr");
    await wait(30);

    const { messages } = snm.readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(2);
    expect(messages[0].direction).toBe("sent");      // seq 0: away greeting
    expect(messages[0].text).toContain("currently away");
    expect(messages[1].direction).toBe("received");  // seq 1: caller's [[WRAP]] message
    expect(messages[1].text).toContain("[[WRAP]]");
    // No seq 2: the away reply was suppressed.
  });

  // DOD-AWAY-WRAP-1 AC1: the request-kind greeting names the agent and gives leave-a-message instructions.
  it("DOD-AWAY-WRAP-1 AC1: request-kind away greeting names the agent and instructs to use [[WRAP]]", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    h.getSessionNodeManager().addContact("bob", "cd".repeat(32), undefined, null, TIER.KNOWN);

    injectRef.inject!(assignmentFrame("cd".repeat(32), bobPubkey));
    await wait(150);

    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    const sent = messages.filter((m) => m.direction === "sent")[0];
    expect(sent).toBeDefined();
    expect(sent!.text).toContain("bob is currently away");
    expect(sent!.text).toContain("[[WRAP]]");
    expect(sent!.text).toContain("Leave a message");
  });

  // Reviewer finding (a9099571, MEDIUM): a transient send failure must not permanently silence the
  // rest of the away period — the dedup guard must clear so the NEXT arrival retries.
  it("dedup clears on a send failure — the next arrival in the same away period retries", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h = await start(logger, node);
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    node.failNextStream = true; // the away-ack's own send will fail
    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi"), msgLeafHash(new TextEncoder().encode("hi")), "c1");
    await wait(30);
    expect(events.find((e) => e.event === "session.away.response.failed")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();

    // Next arrival in the SAME away period (no attend in between) — must retry, not stay silent.
    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi again"), msgLeafHash(new TextEncoder().encode("hi again")), "c2");
    await wait(30);
    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "message")).toBeDefined();
  });
});
