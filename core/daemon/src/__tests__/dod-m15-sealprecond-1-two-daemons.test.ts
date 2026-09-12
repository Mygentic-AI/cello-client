/**
 * DOD-M15-SEALPRECOND-1 — THE OTHER HALF OF THE DAMAGE, which is the counterparty's.
 *
 * The order describes a loss that is bilateral and permanent. The closer signs a short root and
 * gets no receipt; that is proven in `dod-m15-sealprecond-1-real-seal.test.ts` against a relay that
 * really orders leaves. This file is about what happened on the OTHER machine:
 *
 *     16:13:28.903  hers  session.seal.autoacknowledged
 *     16:13:29.248  hers  the in-flight CONTENT arrives — too late
 *     16:13:29.249  hers  session.content.quarantined  reason: session_committed, sequence -1
 *
 * She co-signed and locked her copy, and the message that was already on the wire then landed
 * OUTSIDE her chain for good. Her record is one leaf shorter than his forever, and every later
 * attempt by either of them reports `leaf_count_mismatch` — a reason that points them at each other
 * when neither did anything wrong.
 *
 * TWO REAL DAEMONS, two databases, one relay between them. A's direct sends are handed to B's real
 * inbound handler, which is the counterparty's true receiving path; the relay broadcasts each
 * ordered leaf to both, which is how B learns the ordering. Nothing about the seal is stubbed on
 * either side.
 *
 * WHAT IT STILL CANNOT PROVE: no directory, so no certificate and no notarized `sealed_root`. Done
 * When 5 — two machines, quoted output — remains owed, and `scripts/sealprecond-live-smoke.sh` is
 * the one command that runs it.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import { makeFakeRelayServer, FakeRelayAwareNode, FAKE_RELAY_PEER_ID, FAKE_RELAY_ADDR } from "./helpers/fake-relay-server.js";
import { fakeRelayAnchor } from "./relay-client-fake.js";

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 0xa1 & 0xff));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const CONTENT_KEY = new Uint8Array(32).fill(0x7e);
const GENESIS = new Uint8Array(32).fill(0x9c);

interface LogEvent { event: string; context: Record<string, unknown> }
function makeLogger(tag: string): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const rec = (event: string, context?: Record<string, unknown>) => { events.push({ event: `${tag}:${event}`, context: context ?? {} }); };
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

describe("DOD-M15-SEALPRECOND-1: the counterparty's chain must not be left one leaf short", () => {
  const dirs: string[] = [];
  const stops: Array<() => Promise<unknown>> = [];
  const clients: IpcClient[] = [];

  beforeEach(() => { dirs.length = 0; stops.length = 0; });
  afterEach(async () => {
    for (const c of clients.splice(0)) { try { c.close(); } catch { /* closed */ } }
    for (const stop of stops.splice(0)) { try { await stop(); } catch { /* stopped */ } }
    for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
  });

  async function startSide(name: string, node: CelloNode, logger: Logger) {
    const dir = await mkdtemp(join(tmpdir(), `cello-sealprecond-${name}-`));
    dirs.push(dir);
    await mkdir(join(dir, "agents", name), { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "agents", name, "key"));
    const handle = await startDaemon({
      celloDir: dir,
      socketPath: join(dir, "d.sock"),
      lockFilePath: join(dir, "d.lock"),
      maxConnections: 8,
      version: "test",
      logger,
      sessionNodeFactory: new FixedFactory(node),
      signalingConnect: makeSignaling(),
      securityGateway: new PassthroughGatewayClient(),
    } as unknown as DaemonConfig);
    stops.push(() => handle.stop("test_cleanup"));
    return { dir, kp, handle, snm: handle.getSessionNodeManager() };
  }

  it("A closes mid-send: B's record gains the third message instead of quarantining it", async () => {
    // Declared before the relay because the relay's leaf hook reads A's tree, and A's daemon does
    // not exist until several lines later.
    let aliceRef: { snm: ReturnType<Awaited<ReturnType<typeof startDaemon>>["getSessionNodeManager"]> } | null = null;
    const A = makeLogger("A");
    const B = makeLogger("B");
    // ONE relay for both sides, broadcasting every leaf it orders — that is how B learns the
    // ordering, and without it B's tree could never place a message it has not been told about.
    /**
     * The relay also records A's tree at the instant it receives the seal ctrl leaf.
     *
     * ⚠️ WITHOUT THIS THE FILE PROVES NOTHING ABOUT THIS UNIT. The end-state assertions below —
     * both records at three leaves, nothing quarantined — hold with the whole fix reverted, because
     * A's tree reaches three either way; what changes is WHEN the root is signed. Measured first,
     * asserted with the rest.
     */
    let treeAtSealSubmit = -1;
    const relay = makeFakeRelayServer({
      broadcastLeaves: true,
      onLeaf: (leaf) => {
        if (leaf.leafKind === 0x02 && aliceRef) treeAtSealSubmit = aliceRef.snm.getSessionTree("alice", SID_HEX).size();
      },
    });
    const nodeA = new FakeRelayAwareNode(relay);
    const nodeB = new FakeRelayAwareNode(relay);

    const alice = await startSide("alice", nodeA as unknown as CelloNode, A.logger);
    aliceRef = alice;
    const bob = await startSide("bob", nodeB as unknown as CelloNode, B.logger);
    const alicePub = Buffer.from(await alice.kp.getPublicKey()).toString("hex");
    const bobPub = Buffer.from(await bob.kp.getPublicKey()).toString("hex");

    for (const [side, counterparty] of [[alice, bobPub], [bob, alicePub]] as const) {
      side.snm.setSessionGenesisForTest(sideName(side), SID_HEX, GENESIS);
      await side.snm.createSessionNode(SID_HEX, sideName(side), counterparty, "peer", "corr");
      side.snm.setSessionContentKeyForTest(sideName(side), SID_HEX, CONTENT_KEY);
    }

    // A relay client per side, both on the same fake relay and the same session.
    const { AgentRelayClient } = await import("../session-relay-client.js");
    for (const [side, node, logger] of [[alice, nodeA, A.logger], [bob, nodeB, B.logger]] as const) {
      const rc = new AgentRelayClient({
        relayPeerId: FAKE_RELAY_PEER_ID,
        relayAddrs: [FAKE_RELAY_ADDR],
        keyProvider: side.kp,
        senderPubkey: await side.kp.getPublicKey(),
        logger,
      });
      await rc.connect(node as Parameters<typeof rc.connect>[0]);
      await wait(80);
      side.snm.patchRelayClientForTest(sideName(side), SID_HEX, rc, SID_BYTES, await fakeRelayAnchor());
    }

    // A's direct sends ARE B's inbound content. This is the counterparty's real receiving path —
    // the same handler a libp2p stream would drive, with the same framed bytes.
    nodeA.onDirectSend = (bytes) => {
      // The pinned peer id is the one B's session was opened with — a frame from anywhere else is
      // refused before the content layer, which is the pinning working, not a fixture detail.
      void bob.snm.handleContentFrameForTest("bob", SID_HEX, bytes, "peer");
    };

    // B IS ATTENDED. An unattended agent runs the away responder, which posts acks of its own and
    // makes the two trees grow at different rates for a reason that has nothing to do with this
    // order. A live conversation has someone on both ends.
    const bClient = await connectToDaemon(join(bob.dir, "d.sock"));
    clients.push(bClient);
    await bClient.send("ipc.connect", { clientType: "test" });
    await bClient.send("cello_use_agent", { name: "bob" });

    const aClient = await connectToDaemon(join(alice.dir, "d.sock"));
    clients.push(aClient);
    await aClient.send("ipc.connect", { clientType: "test" });
    await aClient.send("cello_use_agent", { name: "alice" });
    const aCloser = await connectToDaemon(join(alice.dir, "d.sock"));
    clients.push(aCloser);
    await aCloser.send("ipc.connect", { clientType: "cli" });
    await aCloser.send("cello_use_agent", { name: "alice" });

    for (const text of ["first", "second"]) {
      const res = await aClient.send("cello_send", { session_id: SID_HEX, content: text }) as Record<string, unknown>;
      expect(res.ok, `${text}: ${JSON.stringify(res)}`).toBe(true);
    }
    await wait(150);
    expect(bob.snm.getSessionTree("bob", SID_HEX).size(), "B has both messages before the close").toBe(2);

    // The journey: the third message is on the wire when A's close arrives.
    let closePromise: Promise<unknown> | null = null;
    nodeA.onDirectStream = async () => {
      closePromise = aCloser.send("cello_close_session", { session_id: SID_HEX });
      await wait(200); // hold A's send open while the daemon takes the close off the socket
    };
    const third = await aClient.send("cello_send", { session_id: SID_HEX, content: "third" }) as Record<string, unknown>;
    expect(third.ok, `third send: ${JSON.stringify(third)}`).toBe(true);
    const closeResult = await closePromise as Record<string, unknown> | null;
    await wait(500);

    expect(closeResult, "the close ran inside the send's window").not.toBeNull();
    // ── A's side ─────────────────────────────────────────────────────────────────────────────
    expect(
      treeAtSealSubmit,
      "A must not sign until its own third message is in the record — 2 here is the 2026-09-11 loss",
    ).toBe(3);
    expect(alice.snm.getSessionTree("alice", SID_HEX).size(), "A signed a complete record").toBe(3);

    // ── B's side, which is what this file is for ─────────────────────────────────────────────
    const quarantined = B.events.filter((e) => e.event === "B:session.content.quarantined");
    expect(
      quarantined.map((e) => e.context["reason"]),
      "B must NOT have locked her copy before the message she was already being sent",
    ).not.toContain("session_committed");
    expect(
      bob.snm.getSessionTree("bob", SID_HEX).size(),
      "B's chain must hold all three — one leaf short is permanent, and it is what leaf_count_mismatch means",
    ).toBe(3);

    // The two records agree, which is the property a bilateral seal needs and the one the incident
    // destroyed. Compared as ROOTS, not counts: two trees of equal size over different leaves are
    // exactly the disagreement `merkle_root_mismatch` reports.
    expect(
      bob.snm.getSessionTreeRootHex("bob", SID_HEX),
      "both sides must hold the same record",
    ).toBe(alice.snm.getSessionTreeRootHex("alice", SID_HEX));
  }, 30_000);
});

function sideName(side: { dir: string }): string {
  return side.dir.includes("-alice-") ? "alice" : "bob";
}
