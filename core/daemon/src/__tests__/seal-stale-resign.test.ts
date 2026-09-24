/**
 * `seal_stale` — the relay filed a message from the other side that our close did not include.
 *
 * The reverse order of the 2026-09-13 close-vs-send finding: their message reaches the relay just
 * BEFORE our close, but our close was signed without it. The relay refuses the close; this daemon
 * must wait for that message to land in its record and sign ONCE more — not fall straight through
 * to a seal that notarizes a root missing a message the relay holds.
 *
 * Built on the real `cello_close_session` over IPC and the real `submitSealLeaf`, against the fake
 * relay the SEALPRECOND real-seal test uses.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import { makeFakeRelayServer, FakeRelayAwareNode, FAKE_RELAY_PEER_ID, FAKE_RELAY_ADDR } from "./helpers/fake-relay-server.js";
import { fakeRelayAnchor } from "./relay-client-fake.js";
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { provisionAgentIdentity } from "../testing.js";

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 0x51 & 0xff));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const LEAF_KIND_CTRL = 0x02;

interface LogEvent { event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const rec = (event: string, context?: Record<string, unknown>) => { events.push({ event, context: context ?? {} }); };
  return { logger: { debug: rec, info: rec, warn: rec, error: rec }, events };
}
class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}
function makeSignaling(): () => Promise<ConnectResult> {
  const stream: SignalingStream = { send: async () => {}, onMessage: () => {}, close: () => {} };
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("seal_stale: a close signed before a filed message is re-signed once it lands", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null = null;
  const clients: IpcClient[] = [];
  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-seal-stale-")); handle = null; });
  afterEach(async () => {
    for (const c of clients.splice(0)) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function setUp(opts: { messageLands: boolean; twoFiled?: boolean }) {
    const { logger, events } = makeLogger();
    let ctrlSubmits = 0;
    const closeClaims: number[] = [];
    let relayClientRef: { noteReceivedLeaf(h: string, s: number, c: Uint8Array): void } | null = null;
    const relay = makeFakeRelayServer({
      refuseSubmit: (kind, s1) => {
        if (kind !== LEAF_KIND_CTRL) return undefined;
        ctrlSubmits += 1;
        const d = s1 ? decodeStructure1(s1) : undefined;
        if (d?.ok) closeClaims.push(d.fields.lastSeenSeq);
        if (opts.twoFiled) {
          // Two messages from the other side are filed (positions 5 and 6); they land 100 ms apart.
          if (ctrlSubmits === 1) {
            setTimeout(() => relayClientRef?.noteReceivedLeaf(SID_HEX, 5, new Uint8Array(32).fill(0x41)), 50);
            setTimeout(() => relayClientRef?.noteReceivedLeaf(SID_HEX, 6, new Uint8Array(32).fill(0x42)), 150);
          }
          return closeClaims.at(-1)! >= 6 ? undefined : { reason: "seal_stale", awaited_seq: 6 };
        }
        if (ctrlSubmits > 1) return opts.messageLands ? undefined : { reason: "seal_stale", awaited_seq: 5 };
        // The other side's message is in the relay's log but not yet in our record. When the test
        // lets it land, our acknowledgement moves a moment later, as ingest would move it.
        if (opts.messageLands) setTimeout(() => relayClientRef?.noteReceivedLeaf(SID_HEX, 5, new Uint8Array(32).fill(0x42)), 100);
        return { reason: "seal_stale", awaited_seq: 5 };
      },
    });
    const node = new FakeRelayAwareNode(relay);
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await provisionAgentIdentity(tempDir, "alice");
    handle = await startDaemon({
      celloDir: tempDir, socketPath: join(tempDir, "d.sock"), lockFilePath: join(tempDir, "d.lock"),
      maxConnections: 8, version: "test", logger,
      sessionNodeFactory: new FixedFactory(node as unknown as CelloNode),
      signalingConnect: makeSignaling(), securityGateway: new PassthroughGatewayClient(),
    } as unknown as DaemonConfig);
    const snm = handle.getSessionNodeManager();
    snm.setSessionGenesisForTest("alice", SID_HEX, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.setSessionContentKeyForTest("alice", SID_HEX, new Uint8Array(32).fill(0x7e));
    const kp = await provisionAgentIdentity(tempDir, "alice");
    const { AgentRelayClient } = await import("../session-relay-client.js");
    const relayClient = new AgentRelayClient({
      relayPeerId: FAKE_RELAY_PEER_ID, relayAddrs: [FAKE_RELAY_ADDR], keyProvider: kp,
      senderPubkey: await kp.getPublicKey(), logger,
    });
    relayClientRef = relayClient;
    await relayClient.connect(node as Parameters<typeof relayClient.connect>[0]);
    await wait(100);
    snm.patchRelayClientForTest("alice", SID_HEX, relayClient, SID_BYTES, await fakeRelayAnchor());
    const client = await connectToDaemon(join(tempDir, "d.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: "alice" });
    const sent = await client.send("cello_send", { session_id: SID_HEX, content: "hello" }) as Record<string, unknown>;
    expect(sent.ok, JSON.stringify(sent)).toBe(true);
    return { client, events, ctrlSubmits: () => ctrlSubmits, closeClaims };
  }

  it("★★★ two messages filed: the close waits for the position the relay named, not the first to land", async () => {
    const { client, events, ctrlSubmits, closeClaims } = await setUp({ messageLands: true, twoFiled: true });
    await client.send("cello_close_session", { session_id: SID_HEX });
    await wait(600);
    expect(ctrlSubmits(), "one stale close, one re-signed close").toBe(2);
    expect(closeClaims[1], "the re-signed close claims the awaited position").toBe(6);
    expect(events.find((e) => e.event === "session.seal.leaf.submitted"), "and it was filed").toBeDefined();
  }, 20_000);

  it("★★★ refused stale, the message lands, the close is signed again and filed", async () => {
    const { client, events, ctrlSubmits } = await setUp({ messageLands: true });
    await client.send("cello_close_session", { session_id: SID_HEX });
    await wait(300);
    expect(ctrlSubmits(), "one stale close, one re-signed close").toBe(2);
    const resign = events.find((e) => e.event === "session.seal.leaf.stale_resign");
    expect(resign?.context.advanced, "it waited for the message to land before re-signing").toBe(true);
    expect(events.find((e) => e.event === "session.seal.leaf.submitted"), "and the re-signed close was filed").toBeDefined();
  }, 20_000);

  it("★★ the message never lands: exactly ONE retry, then the ordinary failure path — no loop", async () => {
    const { client, events, ctrlSubmits } = await setUp({ messageLands: false });
    await client.send("cello_close_session", { session_id: SID_HEX });
    await wait(2_800);
    expect(events.find((e) => e.event === "session.seal.leaf.stale_resign")?.context.advanced).toBe(false);
    expect(ctrlSubmits(), "the retry is bounded to one").toBe(2);
  }, 20_000);
});
