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
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { TIER } from "../contacts-tier-migration.js";
import type { SecurityGatewayClient, ScreenContext, ScreenVerdict } from "@cello-protocol/gateway";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { markAsAutoReply } from "../away-detection.js";

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

// ─── Relay + signaling stubs for DOD-INBOX-ONESHOT-1 relay-path test ─────────
// Minimal in-process fake relay: auth challenge/ok + hash_submit_ack.
// Mirrors the version in seal-unilateral-retry.test.ts (no FROST logic needed here).
const CBOR_ENC = new Encoder({ tagUint8Array: false });
const FAKE_RELAY_PEER_ID_ONESHOT = "12D3KooWFakeRelayForOneshotTest";
const FAKE_RELAY_ADDR_ONESHOT = "/ip4/127.0.0.1/tcp/2/p2p/fake-relay-oneshot";

function makeFakeRelayServerOneshot() {
  let seq = 0;
  const streams: Array<{ push: (frame: Record<string, unknown>) => void }> = [];
  function openStream() {
    const inbound: Uint8Array[] = [];
    let notify: (() => void) | null = null;
    let ended = false;
    const push = (frame: Record<string, unknown>): void => {
      const encoded = lp.encode.single(CBOR_ENC.encode(frame) as Uint8Array);
      inbound.push(encoded instanceof Uint8Array ? encoded : (encoded as { subarray(): Uint8Array }).subarray());
      notify?.();
    };
    const stream = {
      send: (b: { subarray?: () => Uint8Array } | Uint8Array) => {
        const bytes = b instanceof Uint8Array ? b : (b.subarray ? b.subarray() : (b as unknown as Uint8Array));
        void (async () => {
          for await (const chunk of lp.decode([bytes] as unknown as AsyncIterable<Uint8Array>)) {
            const u8 = chunk instanceof Uint8Array ? chunk : (chunk as { subarray(): Uint8Array }).subarray();
            const frame = decode(u8) as Record<string, unknown>;
            if (frame["type"] === "relay_auth_response") push({ type: "relay_auth_ok" });
            else if (frame["type"] === "hash_submit") push({ type: "hash_submit_ack", sequence_number: ++seq });
          }
        })();
      },
      close: async () => { ended = true; notify?.(); },
      async *[Symbol.asyncIterator]() {
        while (!ended) {
          while (inbound.length) yield inbound.shift()!;
          if (ended) return;
          await new Promise<void>((r) => { notify = r; });
          notify = null;
        }
      },
    };
    push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    streams.push({ push });
    return stream;
  }
  return { openStream, ctrlSubmits: () => [] as unknown[] };
}


// A FakeNode variant whose newStream routes to a fake relay server for the relay peer id.
// All other newStream calls return a no-op fake stream.
class FakeRelayAwareNode extends FakeNode {
  constructor(private readonly fakeRelay: ReturnType<typeof makeFakeRelayServerOneshot>) { super(); }
  async dial(_addr: unknown): Promise<{ peerId: string }> { return { peerId: FAKE_RELAY_PEER_ID_ONESHOT }; }
  async newStream(peerId: unknown, _proto: unknown): Promise<Stream> {
    if (String(peerId) === FAKE_RELAY_PEER_ID_ONESHOT) return this.fakeRelay.openStream() as unknown as Stream;
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

function makeRecordingSignalingOneshot(ref: { inject?: (frame: unknown) => void }): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async () => {},
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  ref.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}
// ─────────────────────────────────────────────────────────────────────────────

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
    securityGateway: new PassthroughGatewayClient(),
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

  it("M12-P16: an agent taken OFFLINE refuses the inbound assignment and sends no away reply", async () => {
    // The half the first version of this fix missed, and the one the counterparty actually saw:
    // measured live 2026-08-05, an agent confirmed offline accepted a message, appended a leaf and
    // REPLIED. Tearing down existing sessions was not enough — nothing on the inbound path consulted
    // agent state at all, and `acceptInboundAssignment` called `ensureStandingReceiverForAgent`,
    // whose first line re-added the want-flag the offline handler had just cleared. The receiver came
    // back from the dead and the away reply fired.
    //
    // Driven through the REAL assignment path (the same injected signaling frame A1 uses), because
    // the observable that matters is the counterparty getting no answer.
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const initiatorPubkey = "cd".repeat(32);
    h.getSessionNodeManager().addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);

    // Press the switch.
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_set_agent_offline", { name: "bob" });

    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(200);

    expect(
      events.find((e) => e.event === "session.away.response.sent"),
      "an offline agent must not answer a stranger",
    ).toBeUndefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
    const refused = events.find((e) => e.event === "session.inbound.refused");
    expect(refused?.context.reason).toBe("agent_offline");
  });

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
    // DOD-AWAY-WRAP-1 AC1: request away greeting names the agent and gives leave-a-message
    // instructions. Reviewer F1 (DOD-WRAP-SUBSTRING-1): the greeting instructs `signal: wrap`
    // (the send parameter that APPENDS the token) — never the literal token, which a caller
    // could paste mid-body where the end-anchored detector correctly ignores it.
    expect(messages[0].text).toContain("bob is currently away");
    expect(messages[0].text).toContain("signal: wrap");
    expect(messages[0].text).not.toContain("[[WRAP]]");
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
    // DOD-M12B-AWAY-MARK-1: a CONFIGURED away message is marked too, and this is the test that
    // proves it — an operator's own wording was previously indistinguishable from a person by
    // construction, because the detector could only match this daemon's default strings. Asserted
    // through markAsAutoReply rather than a pasted literal so the resolved text stays exact.
    const { messages } = snm.readTranscript("bob", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")[0]?.text).toBe(markAsAutoReply("Hey - reach me on Signal"));
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
    // The ALTERED bytes — the draft never went on the wire. DOD-M12B-AWAY-MARK-1 moved the
    // auto-reply marking to AFTER screening, so the sent text is the redactor's output with the
    // marker in front of it. Both facts are asserted, because the ordering matters in both
    // directions: marking BEFORE screening let a redact verdict silently strip the marker (an away
    // reply back on the wire indistinguishable from a person), and dropping the redaction here
    // would put the pre-redaction draft on the wire, which is what this test was written for.
    expect(sent?.text).toBe(markAsAutoReply("[redacted away]"));
    expect(sent?.text).toContain("[redacted away]");
    expect(sent?.text).not.toContain("Hey - reach me on Signal");
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

    // A4: a SECOND message in the SAME away period does not re-trigger the away ACK — but
    // DOD-INBOX-ONESHOT-1 fires instead: a [[WRAP]] rejection is sent and the seal is initiated.
    await snm.ingestReceivedContent("alice", SID_HEX, new TextEncoder().encode("hi again"), msgLeafHash(new TextEncoder().encode("hi again")), "c2");
    await wait(100);
    sentEvents = events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message");
    expect(sentEvents).toHaveLength(1); // still just one away ACK — coalesced

    let { messages } = snm.readTranscript("alice", SID_HEX);
    let sentMessages = messages.filter((m) => m.direction === "sent");
    // Two sent messages: the away ack (seq 0) + the one-shot rejection (seq 1 with [[WRAP]]).
    expect(sentMessages).toHaveLength(2);
    expect(sentMessages[0].text).toContain("message has been received");
    expect(sentMessages[1].text).toContain("[[WRAP]]"); // the rejection

    // A5: attend, then go away again — the dedup clears, so a NEW away period gets a fresh ack.
    // However: the session was sealed by the one-shot path above; it is no longer active.
    // A5 is tested on its own fresh session via the per-session-isolation test above.
    // Skip the A5 portion here since the seal already closed the session.
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

  // DOD-WRAP-SUBSTRING-1 AC2 (live defect 2026-07-24, session 9d6f56d7…): a message that merely
  // MENTIONS [[WRAP]] mid-body (sent signal:"over" — the real token is always APPENDED at the
  // END by DOD-SIGNAL-TOKEN-1) must NOT be classified as a close signal. Pre-fix, the
  // includes() substring match skipped the away reply AND the oneshot rejection silently.
  it("DOD-WRAP-SUBSTRING-1: a message MENTIONING [[WRAP]] mid-body still triggers the away reply", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    const mentionContent = new TextEncoder().encode("can you explain the [[WRAP]] token to me? [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, mentionContent, msgLeafHash(mentionContent), "c1");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "message")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.response.skipped_wrap")).toBeUndefined();
  });

  // DOD-WRAP-SUBSTRING-1 AC2 (oneshot arm): a SECOND unattended message mentioning [[WRAP]]
  // mid-body must trigger the oneshot rejection, not the silent skip.
  it("DOD-WRAP-SUBSTRING-1: a second message MENTIONING [[WRAP]] mid-body still triggers the oneshot rejection", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    const first = new TextEncoder().encode("hello, leaving a message [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, first, msgLeafHash(first), "c1");
    await wait(30);
    const second = new TextEncoder().encode("what does [[WRAP]] mean exactly? [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, second, msgLeafHash(second), "c2");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.response.skipped_wrap")).toBeUndefined();
  });

  // DOD-WRAP-SUBSTRING-1 AC3: a genuine trailing [[WRAP]] token (with trailing whitespace
  // tolerated) still skips the away reply.
  it("DOD-WRAP-SUBSTRING-1: a trailing [[WRAP]] token with trailing whitespace still skips", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    const wrapContent = new TextEncoder().encode("done here, thanks [[WRAP]]  \n");
    await snm.ingestReceivedContent("alice", SID_HEX, wrapContent, msgLeafHash(wrapContent), "c1");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.response.skipped_wrap")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
  });

  // DOD-AWAY-ACK-ONESHOT-TEXT-1 (live defect 2026-07-24): the message-kind away ack must state
  // the one-shot rule so a cooperative caller LLM stops after one message instead of walking
  // into the rejection.
  it("DOD-AWAY-ACK-ONESHOT-TEXT-1: the message ack states the one-message rule", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    const overContent = new TextEncoder().encode("hello [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, overContent, msgLeafHash(overContent), "c1");
    await wait(30);

    const { messages } = snm.readTranscript("alice", SID_HEX);
    const ack = messages.find((m) => m.direction === "sent");
    expect(ack).toBeDefined();
    expect(ack!.text).toContain("one message per visit");
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
    expect(sent!.text).toContain("signal: wrap"); // Reviewer F1: instruct the param, not the literal token
    expect(sent!.text).toContain("Leave a message");
  });

  // DOD-INBOX-ONESHOT-1: second inbound message while unattended → [[WRAP]] rejection + seal initiated.
  it("DOD-INBOX-ONESHOT-1 AC1: second unattended message triggers rejection reply and seal initiation", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    // First message: triggers the normal away ack, sets the dedup guard.
    const msg1 = new TextEncoder().encode("hello [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg1, msgLeafHash(msg1), "c1");
    await wait(30);
    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "message")).toBeDefined();

    // Second message: dedup guard is set → rejection path fires.
    const msg2 = new TextEncoder().encode("hello again [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg2, msgLeafHash(msg2), "c2");
    await wait(100);

    // AC1: rejection event logged.
    expect(events.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeDefined();
    // AC2: rejection message contains [[WRAP]].
    const { messages } = snm.readTranscript("alice", SID_HEX);
    const rejectionMsg = messages.filter((m) => m.direction === "sent").at(-1);
    expect(rejectionMsg?.text).toContain("[[WRAP]]");
    // AC1 (seal): in this unit-test environment the agent is not loaded from the DB, so
    // handleActiveSealFlow returns signing_key_unavailable. The honest observable is
    // seal_initiate_FAILED, not seal_initiated. Reverting the .then() split would collapse these
    // back to a single "seal_initiated" event with ok:false — this assertion would then fail,
    // catching the regression.
    expect(events.find((e) => e.event === "session.away.inbox.oneshot.seal_initiate_failed")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.inbox.oneshot.seal_initiated")).toBeUndefined();
    // AC3: no further away ack fired (only one away.response.sent event total).
    expect(events.filter((e) => e.event === "session.away.response.sent")).toHaveLength(1);
    // F3: a third message must NOT trigger a second rejection (rejectedKey guard).
    const msg3 = new TextEncoder().encode("third [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg3, msgLeafHash(msg3), "c3");
    await wait(30);
    expect(events.filter((e) => e.event === "session.away.inbox.oneshot.rejected")).toHaveLength(1);
  });

  // DOD-INBOX-ONESHOT-1 AC4: attended agent — second message does NOT trigger rejection.
  // Revert-anchor: the dedup guard must be SET by an unattended first message before attending.
  // Without the first unattended message the dedup key is never set and the rejection path is
  // unreachable regardless — the test would be vacuously true.
  it("DOD-INBOX-ONESHOT-1 AC4: unattended first message sets dedup; attending then prevents rejection on second", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    // First message arrives UNATTENDED — sets the dedup guard.
    const msg1 = new TextEncoder().encode("hello [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg1, msgLeafHash(msg1), "c1");
    await wait(30);
    expect(events.find((e) => e.event === "session.away.response.sent" && e.context.kind === "message")).toBeDefined();

    // Now attend — isAttended returns true for alice.
    await connectAs("alice");

    // Second message arrives while attended — isAttended() short-circuits, no rejection.
    const msg2 = new TextEncoder().encode("hello again [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg2, msgLeafHash(msg2), "c2");
    await wait(30);

    expect(events.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeUndefined();
    // Only the original away ack fired.
    expect(events.filter((e) => e.event === "session.away.response.sent")).toHaveLength(1);
  });

  // DOD-INBOX-ONESHOT-1 AC5: [[WRAP]] as the second message does NOT trigger the rejection.
  // Revert-anchor: event ORDERING proves the [[WRAP]] check fires BEFORE the dedup/rejection path.
  // If the order were reversed, skipped_wrap would be absent and rejected would appear instead.
  it("DOD-INBOX-ONESHOT-1 AC5: [[WRAP]] as second message — skipped_wrap fires before rejection path, no rejected event", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    // First message: normal away ack — dedup guard is now set.
    const msg1 = new TextEncoder().encode("hello [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg1, msgLeafHash(msg1), "c1");
    await wait(30);
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeDefined();
    const eventCountBeforeWrap = events.length;

    // Second message carries [[WRAP]]: WRAP check (line 845) runs BEFORE dedup check.
    // If order were reversed the dedup would fire first → rejected instead of skipped_wrap.
    const msg2 = new TextEncoder().encode("goodbye [[WRAP]]");
    await snm.ingestReceivedContent("alice", SID_HEX, msg2, msgLeafHash(msg2), "c2");
    await wait(30);

    const newEvents = events.slice(eventCountBeforeWrap);
    // skipped_wrap must appear; rejected must not.
    expect(newEvents.find((e) => e.event === "session.away.response.skipped_wrap")).toBeDefined();
    expect(newEvents.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeUndefined();
    // skipped_wrap arrives before any possible rejected — index ordering proves it.
    const skipIdx = newEvents.findIndex((e) => e.event === "session.away.response.skipped_wrap");
    const rejectIdx = newEvents.findIndex((e) => e.event === "session.away.inbox.oneshot.rejected");
    expect(skipIdx).toBeGreaterThanOrEqual(0);
    expect(rejectIdx).toBe(-1); // absent, confirming correct ordering
  });

  // F1 (reviewer): A5 — cello_use_agent clears awayAckSent so the next away period gets a fresh ack.
  // This is distinct from per-session isolation (which tests dedup-key scope across sessions).
  // This tests attend-clearance ACROSS TIME on the same agent.
  it("A5 (dedicated): cello_use_agent clears the dedup so the next away PERIOD gets a fresh ack", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const SID_A = "aa".repeat(32);
    const SID_B = "bb".repeat(32);
    await snm.createSessionNode(SID_A, "alice", "bobpubkeyhex", "bob-peer-id", "corr-a");
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

    // Away period 1: first message sets dedup for SID_A.
    const m1 = new TextEncoder().encode("hi [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_A, m1, msgLeafHash(m1), "c1");
    await wait(30);
    expect(events.filter((e) => e.event === "session.away.response.sent")).toHaveLength(1);

    // Attend (cello_use_agent) — clears the dedup entries for "alice".
    const client = await connectAs("alice");
    client.close();
    await wait(30);

    // Away period 2: new session, same agent. Dedup was cleared so a fresh ack fires.
    await snm.createSessionNode(SID_B, "alice", "bobpubkeyhex", "bob-peer-id", "corr-b");
    const m2 = new TextEncoder().encode("hi again [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_B, m2, msgLeafHash(m2), "c2");
    await wait(30);

    // Two away acks total — one per away period.
    expect(events.filter((e) => e.event === "session.away.response.sent" && e.context.kind === "message")).toHaveLength(2);
  });

  // DOD-INBOX-ONESHOT-1 AC1 — RELAY PATH: second unattended message goes through the relay-mediated
  // seal path (submitSealLeaf → session_sealed), NOT the signaling-only handleActiveSealFlow.
  //
  // Revert test: reverting the IIFE back to `void handleActiveSealFlow(...).then(...)` would invoke
  // handleActiveSealFlow, which calls submitSealLeaf only in close-session-handler.ts (not reached
  // here), so no hash_submit_ack arrives and the session_sealed injection has no waiter —
  // session.away.inbox.oneshot.sealed is never logged. The test would fail with a timeout.
  it("DOD-INBOX-ONESHOT-1 AC1 (relay path): second unattended message → relay-mediated seal completes", async () => {
    const priorBilateralMs = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "2000"; // short enough for a unit test
    try {
      const { logger, events } = makeLogger();
      const relay = makeFakeRelayServerOneshot();
      const sigRef: { inject?: (frame: unknown) => void } = {};
      await makeAgentDir("alice");
      // Use FakeNode (not a real libp2p node) so content delivery to counterparty succeeds trivially.
      // Relay client is patched in below via patchRelayClientForTest — no real handshake needed.
      const h = await start(logger, new FakeNode(), makeRecordingSignalingOneshot(sigRef));
      const snm = h.getSessionNodeManager();

      await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
      snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);

      // Patch a fake relay client onto the active node entry so submitSealLeaf returns ok:true.
      // The relay's openStream returns an in-process stream that responds to hash_submit.
      // Wire a relay client onto the session node entry so submitSealLeaf can succeed.
      // Use the relay-aware FakeNode variant so AgentRelayClient.#connect can open a stream
      // to the fake relay server without a real libp2p node.
      const aliceKp = await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
      const relayAwareNode = new FakeRelayAwareNode(relay);
      const { AgentRelayClient } = await import("../session-relay-client.js");
      const fakeRelayClient = new AgentRelayClient({
        relayPeerId: FAKE_RELAY_PEER_ID_ONESHOT,
        relayAddrs: [FAKE_RELAY_ADDR_ONESHOT],
        keyProvider: aliceKp,
        senderPubkey: await aliceKp.getPublicKey(),
        logger,
      });
      await fakeRelayClient.connect(relayAwareNode as Parameters<typeof fakeRelayClient.connect>[0]);
      await wait(100); // auth handshake
      snm.patchRelayClientForTest("alice", SID_HEX, fakeRelayClient, SID_BYTES);

      // First message: normal away ack — sets the dedup guard.
      const msg1 = new TextEncoder().encode("hello [[OVER]]");
      await snm.ingestReceivedContent("alice", SID_HEX, msg1, msgLeafHash(msg1), "c1");
      await wait(100);
      expect(events.find((e) => e.event === "session.away.response.sent")).toBeDefined();

      // Second message: triggers the relay-mediated seal path.
      const msg2 = new TextEncoder().encode("hello again [[OVER]]");
      await snm.ingestReceivedContent("alice", SID_HEX, msg2, msgLeafHash(msg2), "c2");
      await wait(100);

      // Rejection must be logged and carry [[WRAP]].
      expect(events.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeDefined();
      const { messages } = snm.readTranscript("alice", SID_HEX);
      expect(messages.filter((m) => m.direction === "sent").at(-1)?.text).toContain("[[WRAP]]");

      // seal_initiated on the relay path must be logged (not seal_initiate_failed).
      await wait(200);
      expect(events.find((e) => e.event === "session.away.inbox.oneshot.seal_initiated" && e.context.path === "relay")).toBeDefined();
      expect(events.find((e) => e.event === "session.away.inbox.oneshot.seal_initiate_failed")).toBeUndefined();

      // Inject session_sealed: the bilateral wait resolves and session.away.inbox.oneshot.sealed fires.
      sigRef.inject!({
        type: "session_sealed",
        session_id: SID_BYTES,
        sealed_root: new Uint8Array(32).fill(0xab),
      });
      await wait(200);
      expect(events.find((e) => e.event === "session.away.inbox.oneshot.sealed")).toBeDefined();
    } finally {
      if (priorBilateralMs === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
      else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = priorBilateralMs;
    }
  }, 15_000);

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

  // M12-P13 — found live 2026-08-05 on the EC2 receiver (M12 Entry 89):
  //   session.relay.leaf.delivered  sequenceNumber=1
  //   session.away.response.failed  reason=session_stream_unavailable
  // and then nothing, forever. The away reply owns the sequence the relay already witnessed for it;
  // when its send failed the leaf was never appended, so this side's tree stayed at size 0 while the
  // counterparty's content arrived claiming canonicalSeq 1. `nextExpected` IS the tree size, so
  // every later message was held behind a gap that nothing could ever fill. The receiver stranded
  // its own session — and the operator was told nothing at all.
  //
  // `sendContent` is stubbed here rather than driven through a real relay: this pins the AWAY path's
  // own decision (commit the leaf when the content is durably queued), and that the `durable` flag
  // it keys on is truthfully produced is pinned separately, against the real queue, in
  // m8c-leavemsg-1.test.ts. Stubbing what is already proven elsewhere beats not testing this at all.
  it("M12-P13: an away reply whose send is DURABLY QUEUED still commits its leaf — otherwise the receiver stalls at its own sequence forever", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    snm.sendContent = async () => ({
      ok: false as const, reason: "session_stream_unavailable", error: "connection_lost", durable: true,
    });

    const hi = new TextEncoder().encode("hi");
    await snm.ingestReceivedContent("alice", SID_HEX, hi, msgLeafHash(hi), "c1");
    await wait(30);

    // The inbound message is leaf 0; the away reply owns leaf 1 whether or not its send landed.
    expect(snm.getSessionTree("alice", SID_HEX).size(), "the away reply's witnessed sequence must exist locally").toBe(2);
    const sent = snm.readTranscript("alice", SID_HEX).messages.filter((m) => m.direction === "sent");
    expect(sent).toHaveLength(1);
    // Deferred is not failed, and it must be visible as its own event — a queued reply that reads
    // as `failed` sends the next investigation looking for a message that is not actually lost.
    expect(events.find((e) => e.event === "session.away.response.deferred")).toBeDefined();
  });

  it("M12-P13: a durably-queued away reply is NOT re-sent on the next arrival — the queued one already owns that sequence", async () => {
    // The pre-existing retry-on-failure behaviour (test above) is correct for a LOST reply and wrong
    // for a queued one: retrying mints a second away message at a second sequence, and the recipient
    // gets the same greeting twice with a hole where the first one was.
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    snm.sendContent = async () => ({
      ok: false as const, reason: "session_stream_unavailable", error: "connection_lost", durable: true,
    });

    const a = new TextEncoder().encode("hi");
    await snm.ingestReceivedContent("alice", SID_HEX, a, msgLeafHash(a), "c1");
    await wait(30);
    const b = new TextEncoder().encode("hi again");
    await snm.ingestReceivedContent("alice", SID_HEX, b, msgLeafHash(b), "c2");
    await wait(30);

    // The second arrival legitimately produces the ONESHOT REJECTION — that is a different message
    // and it must still happen. What must not happen is a second AWAY GREETING at a second
    // sequence, which is what clearing the guard on a queued reply would mint.
    const sent = snm.readTranscript("alice", SID_HEX).messages.filter((m) => m.direction === "sent");
    const REJECTION = "one message per visit. Closing.";
    const greetings = sent.filter((m) => !m.text.includes(REJECTION));
    expect(greetings, "one away period, one away greeting").toHaveLength(1);
    expect(sent.some((m) => m.text.includes(REJECTION)), "the oneshot rejection still fires").toBe(true);
  });

  it("M12-P13 (third caller): a durably-queued ONESHOT REJECTION commits its leaf — this path seals immediately after, so a hole here is a guaranteed root mismatch", async () => {
    // The reject send was the caller I missed on the first pass, and it is the worst of the three:
    // it is followed straight away by submitSealLeaf. A queued rejection whose leaf is not committed
    // means we seal a tree that is one leaf short of the sequence the counterparty receives at —
    // not a stall this time but an unsealable pair of roots, which is precisely the state the two
    // force-abandoned sessions of 2026-08-05 ended in.
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const a = new TextEncoder().encode("first");
    await snm.ingestReceivedContent("alice", SID_HEX, a, msgLeafHash(a), "c1");
    await wait(30);
    const sizeAfterAway = snm.getSessionTree("alice", SID_HEX).size();

    // Only the REJECTION's send fails-but-queues; the away reply above went out normally.
    snm.sendContent = async () => ({
      ok: false as const, reason: "session_stream_unavailable", error: "connection_lost", durable: true,
    });
    const b = new TextEncoder().encode("second");
    await snm.ingestReceivedContent("alice", SID_HEX, b, msgLeafHash(b), "c2");
    await wait(60);

    // +1 for the inbound "second", +1 for the queued rejection that owns its witnessed sequence.
    expect(snm.getSessionTree("alice", SID_HEX).size()).toBe(sizeAfterAway + 2);
  });

  it("M12-P13: a LOST away reply appends nothing and says so at ERROR — silence is what made this cost two sessions", async () => {
    // The mirror of the durable case. A leaf here would commit a sequence the counterparty will
    // never receive content for, which is a permanent root mismatch — the sessions become
    // unsealable and the only exit is a force-abandon with no notarized receipt.
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    snm.sendContent = async () => ({
      ok: false as const, reason: "session_stream_unavailable", error: "connection_lost", durable: false,
    });

    const hi = new TextEncoder().encode("hi");
    await snm.ingestReceivedContent("alice", SID_HEX, hi, msgLeafHash(hi), "c1");
    await wait(30);

    expect(snm.getSessionTree("alice", SID_HEX).size(), "no leaf for content that is gone").toBe(1);
    const failed = events.find((e) => e.event === "session.away.response.failed");
    expect(failed).toBeDefined();
    expect(failed!.level, "a lost message is an error, not a warning").toBe("error");
    expect(String(failed!.context.impact)).toContain("lost");
  });

  // ─── M12-P18: a refused session tells a TRUSTED sender why, and stays silent to a stranger ─────
  async function driveOverCapRefusal(tier: number, preseed: number) {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    const snm = h.getSessionNodeManager();
    const initiatorPubkey = "cd".repeat(32);
    // A KNOWN contact is told; a stranger (no contact row → UNKNOWN) is not.
    if (tier >= TIER.KNOWN) snm.addContact("bob", initiatorPubkey, undefined, null, tier);
    // Pre-seed the sender to their cap so the NEXT assignment is refused for over-cap, not blocked.
    const db = snm.getDb()!;
    const bobId = snm.resolveAgentId("bob");
    const now = Date.now();
    for (let i = 0; i < preseed; i++) {
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', ?, ?, 1, NULL)`,
      ).run(("f" + i.toString(16)).padStart(32, "0"), bobId, initiatorPubkey, now, now);
    }
    injectRef.inject!(assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(150);
    return events;
  }

  it("M12-P18: a KNOWN sender over the cap is NOTIFIED — its own state, no oracle risk", async () => {
    // KNOWN cap is 5; five pre-seeded sessions puts the sixth over.
    const events = await driveOverCapRefusal(TIER.KNOWN, 5);
    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    const notified = events.find((e) => e.event === "session.inbound.refusal.notified");
    expect(notified, "a trusted sender is told why").toBeDefined();
    expect(notified!.context.reason).toBe("abuse_bound_sessions_per_sender");
  });

  it("M12-P18: an UNKNOWN sender over the cap is SILENT — no block/throttle oracle", async () => {
    // UNKNOWN cap is 3; three pre-seeded puts the fourth over, and no contact row keeps it UNKNOWN.
    const events = await driveOverCapRefusal(TIER.UNKNOWN, 3);
    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.refusal.notified"), "a stranger is NEVER told").toBeUndefined();
    expect(events.find((e) => e.event === "session.inbound.refusal.silent")).toBeDefined();
  });
});
