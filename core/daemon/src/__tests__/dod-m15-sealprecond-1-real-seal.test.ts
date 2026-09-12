/**
 * DOD-M15-SEALPRECOND-1, Done When 1 — the leaf set the seal actually signs.
 *
 * ⚠️ WHY THIS FILE EXISTS SEPARATELY FROM `dod-m15-sealprecond-1.test.ts`. Every close test in that
 * file drives a STUBBED `sealReadiness` and a STUBBED seal flow, so all of them prove the gate's
 * decision and none of them proves the thing the decision is for: that the root put on the wire
 * covers every message the relay ordered. The unit review said so, and the order's first Done-When
 * asks for exactly the missing half — a test that holds a send between the relay ordering it and
 * the tree appending it, then closes.
 *
 * Here the relay is real enough to order leaves, the send is the real `cello_send` handler over a
 * real IPC socket, the close is the real `cello_close_session`, and `submitSealLeaf` really runs.
 * The measurement mirrors the incident log line for line:
 *
 *     16:13:28.790  session.seal.leaf.submitted seq 4   ← SIGNS HERE, tree still 2 leaves
 *
 * so this test records the tree size at the instant the relay receives the seal ctrl leaf. Two
 * means the receipt is already lost. Three means the record was complete when it was signed.
 *
 * WHAT IT CANNOT PROVE, stated rather than implied: no directory takes part, so nothing here
 * verifies a certificate or a counterparty's co-signature. Done When 5 — two agents, two machines,
 * matching `sealed_root` — is the only thing that closes that, and it is still owed.
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
import {
  makeFakeRelayServer, FakeRelayAwareNode, FAKE_RELAY_PEER_ID, FAKE_RELAY_ADDR,
  type OrderedLeaf,
} from "./helpers/fake-relay-server.js";

// The RELAY session id is 16 bytes — `decodeSealPayload` refuses any other length, and a 32-byte
// one makes every seal submit fail as `seal_payload_invalid` long before anything under test runs.
const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 0xe7 & 0xff));
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

describe("DOD-M15-SEALPRECOND-1 Done When 1: the signed root covers every message the relay ordered", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null = null;
  const clients: IpcClient[] = [];

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-sealprecond-real-")); handle = null; });
  afterEach(async () => {
    for (const c of clients.splice(0)) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("a close issued while a send is in flight signs a THREE-leaf record, not a two-leaf one", async () => {
    const { logger, events } = makeLogger();

    // The relay records what it ordered and, for the seal ctrl leaf, what the tree held at that
    // instant. This is the incident's own measurement, taken from the ordering authority's side.
    let treeAtSealSubmit = -1;
    const orderedLeaves: OrderedLeaf[] = [];
    const relay = makeFakeRelayServer({
      onLeaf: (leaf) => {
        orderedLeaves.push(leaf);
        if (leaf.leafKind === LEAF_KIND_CTRL && handle) {
          treeAtSealSubmit = handle.getSessionNodeManager().getSessionTree("alice", SID_HEX).size();
        }
      },
    });
    const node = new FakeRelayAwareNode(relay);

    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    // `load` mints the key when the file is absent — the same call the daemon's own boot makes.
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    handle = await startDaemon({
      celloDir: tempDir,
      socketPath: join(tempDir, "d.sock"),
      lockFilePath: join(tempDir, "d.lock"),
      maxConnections: 8,
      version: "test",
      logger,
      sessionNodeFactory: new FixedFactory(node as unknown as CelloNode),
      signalingConnect: makeSignaling(),
      securityGateway: new PassthroughGatewayClient(),
    } as unknown as DaemonConfig);

    const snm = handle.getSessionNodeManager();
    // The state a completed open leaves: a starting point to chain to, and an agreed content key.
    // Seeded in this order because `createSessionNode` refuses a session it cannot anchor.
    snm.setSessionGenesisForTest("alice", SID_HEX, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.setSessionContentKeyForTest("alice", SID_HEX, new Uint8Array(32).fill(0x7e));

    const kp = await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    const { AgentRelayClient } = await import("../session-relay-client.js");
    const relayClient = new AgentRelayClient({
      relayPeerId: FAKE_RELAY_PEER_ID,
      relayAddrs: [FAKE_RELAY_ADDR],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger,
    });
    await relayClient.connect(node as Parameters<typeof relayClient.connect>[0]);
    await wait(100); // auth handshake
    snm.patchRelayClientForTest("alice", SID_HEX, relayClient, SID_BYTES);

    const client = await connectToDaemon(join(tempDir, "d.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: "alice" });

    // The CLOSER is a second connection, as it was on 2026-09-11: the seal came from a `cello
    // close-session` invocation that lived and died inside the failing send's window.
    const closer = await connectToDaemon(join(tempDir, "d.sock"));
    clients.push(closer);
    await closer.send("ipc.connect", { clientType: "cli" });
    await closer.send("cello_use_agent", { name: "alice" });

    // Two ordinary messages, fully settled.
    for (const text of ["first", "second"]) {
      const res = await client.send("cello_send", { session_id: SID_HEX, content: text }) as Record<string, unknown>;
      expect(res.ok, `${text}: ${JSON.stringify(res)}`).toBe(true);
    }
    expect(snm.getSessionTree("alice", SID_HEX).size(), "two messages are in the record").toBe(2);

    /**
     * THE THIRD SEND, HELD OPEN AT EXACTLY THE POINT THE INCIDENT HAPPENED.
     *
     * `sendContent` submits the hash to the relay FIRST and only then attempts direct delivery, so
     * a hook inside the direct-delivery stream runs after the relay has ordered leaf 3 and before
     * the caller appends it. That is the window — no sleep, no widened timing, the real sequence.
     */
    let closePromise: Promise<unknown> | null = null;
    node.onDirectStream = async () => {
      expect(snm.getSessionTree("alice", SID_HEX).size(), "precondition: the tree has NOT taken leaf 3 yet").toBe(2);
      /**
       * STARTED, NOT AWAITED — and the difference is the whole fidelity of this test.
       *
       * The close is a separate `cello close-session` on its own IPC connection (the incident's own
       * log shows exactly that: a `clientType: "cli"` connection opened at 28.383 and gone by
       * 28.814). Awaiting it here would hold the send open until the close finished, which is a
       * deadlock this fixture invented — the send could never place its leaf, the close could never
       * see it settle, and the test would be measuring its own knot instead of the product.
       */
      closePromise = closer.send("cello_close_session", { session_id: SID_HEX });
      /**
       * HOLD THE SEND HERE while the daemon takes the close off the socket.
       *
       * This is the FIXTURE's stream being held open, not a window being widened in the product —
       * the order's Done When 1 asks for exactly this ("a test that holds a send between
       * relay-ordering and tree-append, then closes"). In production the hold comes for free:
       * direct delivery is real I/O with several suspension points, which is how a `cello
       * close-session` fitted entirely inside one send on 2026-09-11. In-process the fake stream
       * resolves on a microtask, so without this the send's continuation would always place its
       * leaf before the close was even read off the socket, and the test would prove nothing.
       */
      await wait(200);
    };

    const third = await client.send("cello_send", { session_id: SID_HEX, content: "third" }) as Record<string, unknown>;
    expect(third.ok, `the third send must succeed: ${JSON.stringify(third)}`).toBe(true);
    const closeResult = await closePromise as Record<string, unknown> | null;
    await wait(300);

    // ── What the relay saw ────────────────────────────────────────────────────────────────────
    const ctrl = orderedLeaves.filter((l) => l.leafKind === LEAF_KIND_CTRL);
    expect(ctrl.length, "exactly one seal ctrl leaf was submitted").toBe(1);
    expect(
      treeAtSealSubmit,
      "THE MEASUREMENT: the tree held 2 leaves when the 2026-09-11 seal was signed. It must hold 3.",
    ).toBe(3);
    expect(snm.getSessionTree("alice", SID_HEX).size(), "and the third message really is in the record").toBe(3);

    // ── What the operator got ─────────────────────────────────────────────────────────────────
    expect(closeResult, "the close ran inside the window").not.toBeNull();
    expect(
      closeResult!.reason,
      "it must not be refused for a condition that resolves in milliseconds",
    ).not.toBe("session_record_settling");

    // The wait happened and it is visible — the whole unit is invisible in a log without this.
    expect(events.find((e) => e.event === "session.seal.settled"), "the close waited for its own record").toBeDefined();
    expect(events.find((e) => e.event === "session.seal.leaf.refused_settling"), "and then it was not refused").toBeUndefined();
  }, 20_000);
});
