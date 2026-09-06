import { LEAF_KIND_MSG } from "../session-relay-client.js";
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
import { RetryQueue } from "../retry-queue.js";
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
    captured.length = 0;
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

  const captured: Array<{ event: string; context: Record<string, unknown> }> = [];
  async function start(node: CelloNode): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const noopLogger: Logger = {
      debug(event, context) { captured.push({ event, context: context ?? {} }); },
      info(event, context) { captured.push({ event, context: context ?? {} }); },
      warn(event, context) { captured.push({ event, context: context ?? {} }); },
      error(event, context) { captured.push({ event, context: context ?? {} }); },
    };
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
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("leave a message");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: true, delivered: false, parked: true });
    expect(parkCalls).toBe(1);
  });

  it("a park NAMES THE CAUSE of the direct-send failure — silence here hid a defect for a night", async () => {
    // Measured 2026-08-17: 212 parks on one daemon, and not ONE of them recorded why the direct
    // send failed. The catch that parks the content discarded the error entirely, so every surface
    // said "dispatched to relay" — the exit point — and nothing anywhere said what went wrong.
    //
    // The project rule is that errors name their cause, not their exit point. This is the send
    // path's version of it. The peer id we FAILED TO REACH is the load-bearing field: a session
    // records its counterparty's peer id once at establishment and never refreshes it, so a stale
    // id is invisible today and would be a one-line read here.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: true }));

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("why did this park?");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: true, delivered: false, parked: true });

    const failed = captured.filter((e) => e.event === "session.content.direct.send.failed");
    expect(failed).toHaveLength(1);
    // The peer we could not reach, and the reason we could not — both, or the event is decoration.
    expect(failed[0]!.context).toMatchObject({
      sessionId: SID,
      counterpartySessionPeerId: "bob-peer-id",
    });
    expect(String(failed[0]!.context["error"] ?? "")).not.toHaveLength(0);
  });

  it("sendContent: direct-stream failure + NO relay configured → unchanged {ok:false, reason:session_stream_unavailable} (regression lock)", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: true })); // would deposit, but no relay is wired for this session
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr"); // no relay param

    const content = new TextEncoder().encode("hello");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });
  });

  it("sendContent: direct-stream failure + a relay configured but the park hook THROWS → honest {ok:false} (never a false success)", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => { throw new Error("relay_deposit_failed: relay unreachable"); });

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("hello");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
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
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("hello");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });
  });

  it("M12-P12: a park hook that resolves {ok:false} ENQUEUES the content durably — the response shape is not the whole contract", async () => {
    // Found live 2026-08-05, two machines through the GCP relay (M12 Entry 84). The sender's park
    // deposit failed with `standing_receiver_unavailable` and was never retried; the recipient then
    // held every later message behind the missing sequence, permanently, and neither side was told.
    //
    // The test directly above this one already drove this exact resolved-not-thrown shape, and its
    // own comment says the danger is skipping "the durable retry_queue enqueue that only fires on
    // an honest {ok:false}". It never asserted that enqueue — so the response shape was pinned and
    // the durability was not, and the production path did no enqueue at all.
    //
    // Asserted against the REAL retry queue via getStatus(), not an injected hook: overriding
    // setAwaitingAckHooks here would test a double and leave the daemon's own wiring unproven,
    // which is the same gap that let this ship.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("must not vanish");
    const hashHex = Buffer.from(msgLeafHash(content)).toString("hex");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);

    // The honest failure response is unchanged — this is additive durability, not a shape change.
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });

    // Assert the DURABLE row, not an in-memory counter: surviving a restart is the whole point,
    // and getStatus().retryQueueDepth counts the nonce queue, not the awaiting store — an assertion
    // there would have passed on a purely in-memory fix and read as proof of durability.
    const row = snm.getDb()!
      .prepare("SELECT agent_id, content_hash_hex, awaiting_ack, content_blob FROM retry_queue WHERE session_id = ? AND content_hash_hex = ?")
      .get(SID, hashHex) as { agent_id: string | null; content_hash_hex: string; awaiting_ack: number; content_blob: Buffer } | undefined;
    expect(row).toBeDefined();
    expect(row!.awaiting_ack).toBe(1);

    // agent_id is the ONE field the whole drain path keys on: getAwaitingSessions →
    // flushAwaitingContent(name) filters by resolveAgentId, and startupParkFn resolves the owner
    // from it. A row written under any other value is durable, drains never, and looks identical to
    // a working one in a query that omits this column — which is how a green test can ship a lost
    // message (review, bypass 1).
    expect(row!.agent_id).toBe(snm.resolveAgentId("alice"));

    // And the CONTENT has to survive, not just the row. An empty blob satisfies every other
    // assertion here while the eventual re-park seals nothing and the recipient refuses it on
    // unseal (review, bypass 2). The blob is sealed at rest, so assert through the queue's own
    // reader rather than comparing ciphertext.
    expect(row!.content_blob.length).toBeGreaterThan(0);

    // Round-trip it through the REAL consumer: a fresh RetryQueue over the same database, hydrated
    // from disk exactly as a restarted daemon would, drained through the same parkFn the flush uses.
    // That is what proves the bytes — and the ordering record — actually come back.
    const replay = new RetryQueue(snm.getDb()!, { debug() {}, info() {}, warn() {}, error() {} });
    replay.loadFromDb();
    const seen: Array<{ content: Uint8Array; s1?: Uint8Array; s2?: Uint8Array }> = [];
    await replay.drainAwaitingToPark(snm.resolveAgentId("alice"), SID, async (entry) => {
      seen.push({ content: entry.contentBlob, s1: entry.structure1Cbor, s2: entry.structure2Cbor });
      return { parked: true };
    });
    expect(seen).toHaveLength(1);
    expect(Buffer.from(seen[0].content).equals(Buffer.from(content))).toBe(true);
    // This session has no relay witness, so there is no ordering record to carry — assert that
    // explicitly rather than leaving it unstated. The witnessed case is pinned separately below,
    // where reverting the durable columns turns it red.
    expect(seen[0].s1).toBeUndefined();
  });

  it("M12-P12 (review pass 2, F6): a session with NO relay configured writes no durable row — it would never drain", async () => {
    // "unconfigured" is not "refused". Queuing it grows the database forever with rows whose only
    // possible outcome is no_persisted_relay_endpoint, retried on every boot and every agent start.
    // A one-line regression to `if (attempt !== "parked")` restores that silently.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr"); // no relay

    const content = new TextEncoder().encode("nowhere to park");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });

    const rows = snm.getDb()!
      .prepare("SELECT COUNT(*) AS n FROM retry_queue WHERE session_id = ? AND awaiting_ack = 1")
      .get(SID) as { n: number };
    expect(rows.n).toBe(0);
  });

  // M12-P12 (review pass 2, F1) — KNOWN COVERAGE GAP, deliberately not faked.
  // The reconnect half of the sender flush IS unit-tested (dod-park-drain-1). The other half — the
  // `flushAwaitingContent` call inside daemon.ts's setParkedDrainHook — is NOT, and deleting that
  // line leaves this suite green. Reaching it needs a standing receiver that actually builds, which
  // needs a live relay: `ensureStandingReceiverForAgent` no-ops for an agent that was never started,
  // and starting the agent fires the long-standing agent-start flush, which would mask a missing
  // hook and make the test pass for the wrong reason. It is covered by the two-machine live run that
  // DOD-PARK-DRAIN-1 requires anyway — watch for `content.park.flush.completed` under a
  // `standing_receiver_ready` trigger. Recorded here so the gap is visible at the point of absence.

  it("M12-P12 verification: an INJECTED park refusal takes the durable path, and the gate refuses without the env var", async () => {
    // The fault exists so the failure can be produced on demand — it is a race in production and no
    // CLI lever reaches it. This test pins two things: the injected refusal is indistinguishable
    // from a real one (same durable outcome), and the IPC gate is closed by default so a normal
    // daemon cannot be told to drop messages.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    // A park hook that would SUCCEED — so anything durable here came from the injected fault, not
    // from a hook that happened to fail.
    let hookCalls = 0;
    snm.setContentParkHook(async () => { hookCalls++; return { ok: true }; });

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    expect(snm.injectParkFault(1)).toBe(1);
    const content = new TextEncoder().encode("injected refusal");
    const hashHex = Buffer.from(msgLeafHash(content)).toString("hex");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);

    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable" });
    expect(hookCalls, "the fault must short-circuit BEFORE the deposit, like a real refusal").toBe(0);
    expect(snm.getParkFaultRemaining(), "the armed fault must be consumed, not left latched").toBe(0);

    const row = snm.getDb()!
      .prepare("SELECT agent_id, awaiting_ack FROM retry_queue WHERE session_id = ? AND content_hash_hex = ?")
      .get(SID, hashHex) as { agent_id: string; awaiting_ack: number } | undefined;
    expect(row, "an injected refusal must leave the same durable row a real one does").toBeDefined();
    expect(row!.awaiting_ack).toBe(1);
    expect(row!.agent_id).toBe(snm.resolveAgentId("alice"));

    // The gate: closed unless the daemon was started with the env var.
    delete process.env.CELLO_FAULT_INJECTION;
    const client = await connectAs("alice");
    const denied = await client.send("debug_inject_park_fault", { count: 3 });
    expect(denied).toMatchObject({ error: "fault_injection_disabled" });
  });

  it("M12-P13: a durably-queued send reports `durable` as a FIELD — the caller must not have to read prose to know", async () => {
    // M12-P12 shipped the durable/lost distinction in the `guidance` SENTENCE only. Every caller
    // that has to act on it — append the leaf or not — would have to substring-match English to
    // find out, so in practice no caller acted on it at all. This is the machine-readable half.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("queued, not lost");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: false, reason: "session_stream_unavailable", durable: true });

    // Review (hollow test): asserting the FLAG alone pins "the park was refused", never "the content
    // is queued" — deleting the `#onParkFailed?.()` call entirely left this green while every
    // durably-queued message was silently lost AND had its leaf committed. Assert the row.
    const row = snm.getDb()!
      .prepare("SELECT COUNT(*) AS n FROM retry_queue WHERE session_id = ? AND awaiting_ack = 1")
      .get(SID) as { n: number };
    expect(row.n, "durable:true must mean the content is actually in the queue").toBe(1);

    // MEDIUM-5: the standing-receiver state is carried to the caller, not discarded at the mapping
    // site. `reason` names where this surfaced; `cause` names what actually blocked it.
    expect((res as { cause?: string }).cause).toBe("standing_receiver_unavailable");
  });

  it("M12-P13: an UNCONFIGURED park reports durable:false — the two failures must never read alike", async () => {
    // The whole point of the field is that it separates "we are retrying this" from "it is gone".
    // A `durable: true` constant would satisfy the test above and lose messages here.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr"); // no relay

    const content = new TextEncoder().encode("nowhere to go");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: false, durable: false });
  });

  it("M12-P13: a durably-queued cello_send COMMITS ITS LEAF — the relay already witnessed the sequence, so an unappended tree stalls the receiver forever", async () => {
    // Found live 2026-08-05 (M12 Entry 89, sessions 4c28edcd / dcd0aadc). `nextExpected` is
    // literally `getSessionTree(...).size()` (session-node-manager.ts:4178). The relay witnesses the
    // content hash BEFORE direct delivery is attempted, so the sequence is committed whether or not
    // the send succeeds. Skipping the append on a failed-but-queued send leaves this side's tree one
    // short of the sequence the counterparty will receive at, and every later message is held behind
    // the gap — permanently, silently, and unsealably (both live sessions ended in force-abandon).
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const client = await connectAs("alice");
    const res = await client.send("cello_send", { session_id: SID, content: "queued but committed" }) as Record<string, unknown>;

    // Still an honest failure — the message is NOT delivered and NOT parked. What changes is that
    // the sequence it already occupies is recorded locally instead of being left as a hole.
    expect(res.ok).toBe(false);
    expect(res.queued).toBe(true);
    expect(typeof res.sequence_number).toBe("number");
    expect(snm.getSessionTree("alice", SID).size(), "the committed sequence must exist locally, or nextExpected stalls").toBe(1);
    // And the operator must be able to read back what they sent, exactly as for a parked message.
    const { messages } = snm.readTranscript("alice", SID);
    expect(messages).toHaveLength(1);
    expect(messages[0].direction).toBe("sent");
  });

  it("M12-P13: a LOST cello_send appends NOTHING — a leaf for content no one will ever receive is a permanent root mismatch", async () => {
    // The mirror image, and the reason the fix keys on `durable` rather than on "the send failed".
    // Appending unconditionally would trade a stalled receiver for two trees that can never seal.
    //
    // Review finding: this must be driven through a session that HAS a relay, whose durable enqueue
    // then FAILS. Routed through an unconfigured session instead, it lands on #parkContent's
    // "unconfigured" branch — which appended nothing long before this fix — so it would stay green
    // against a `durable` that is never computed at all, and an implementation that ignores the
    // enqueue outcome entirely would pass it.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });
    // A persist that throws is the production shape of "not durable" on a relay-configured session:
    // enqueueAwaitingContent fails loud on a real DB failure precisely because the content is lost.
    snm.setAwaitingAckHooks({ onParkFailed: () => { throw new Error("disk full"); } });

    const client = await connectAs("alice");
    const res = await client.send("cello_send", { session_id: SID, content: "this one is gone" }) as Record<string, unknown>;
    expect(res.ok).toBe(false);
    expect(res.queued).toBeUndefined();
    expect(String(res.guidance)).toContain("lost");
    expect(snm.getSessionTree("alice", SID).size(), "no leaf for content that is gone").toBe(0);
  });

  it("M12-P13 (review HIGH-1): a DEDUPED enqueue reports durable:false and commits no leaf — the queue dropping it must not read as queued", async () => {
    // The dedupe key is SHA-256(0x00 ‖ content) — content-derived, no sequence, no nonce. Two
    // identical messages in one session collide and the SECOND IS DROPPED (retry-queue.ts logs
    // `message.retry.enqueue.deduped` and returns). `durable` was set to true regardless, which
    // after this commit means committing a leaf for content that was silently discarded — the exact
    // permanent-root-mismatch outcome the durable gate exists to prevent. `durable` has to be
    // OBSERVED from the enqueue, not asserted around it.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const same = new TextEncoder().encode("ok");
    const first = await snm.sendContent("alice", SID, same, msgLeafHash(same), "corr-1", LEAF_KIND_MSG);
    expect(first).toMatchObject({ ok: false, durable: true });

    const second = await snm.sendContent("alice", SID, same, msgLeafHash(same), "corr-2", LEAF_KIND_MSG);
    expect(second, "the queue dropped this copy — saying otherwise commits a leaf for nothing").toMatchObject({ ok: false, durable: false });

    // Exactly one durable row, and therefore exactly one message that can ever be re-parked.
    const rows = snm.getDb()!
      .prepare("SELECT COUNT(*) AS n FROM retry_queue WHERE session_id = ? AND awaiting_ack = 1")
      .get(SID) as { n: number };
    expect(rows.n).toBe(1);
  });

  it("M12-P13 (review HIGH-1): an UNWIRED durable hook reports durable:false — an optional call that no-ops is not a queue", async () => {
    // `this.#onParkFailed?.(...)` followed by an unconditional `durable = true` claims durability
    // from a hook that may not exist at all. The `?.` silently substitutes "did nothing" for
    // "queued it", which is the same silent-fallback shape as the defect under repair.
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: false, reason: "standing_receiver_unavailable" }));
    snm.setAwaitingAckHooks({}); // as if the composition root never wired it

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr", false, {
      relayPeerId: "12D3KooWFakeRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFakeRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: Buffer.from(SID, "hex"),
    });

    const content = new TextEncoder().encode("no hook, no queue");
    const res = await snm.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG);
    expect(res).toMatchObject({ ok: false, durable: false });
  });

  it("cello_send end-to-end: direct-stream failure + relay park success → ok:true, delivered:false, reason:dispatched_to_relay, guidance names relay recovery; leaf + transcript still committed", async () => {
    await makeAgentDir("alice");
    const h = await start(new FakeNode({ newStreamFails: true }));
    const snm = h.getSessionNodeManager();
    snm.setContentParkHook(async () => ({ ok: true })); // deposit succeeds

    const kp = generateKeypair();
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
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
