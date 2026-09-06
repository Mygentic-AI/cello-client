/**
 * The M8D enforcer: TWO IPC connections attending ONE agent on ONE real daemon.
 *
 * Every M8D assertion is about what the SECOND attached session sees, so a harness that can only
 * build the first connection cannot observe any of them. This is that harness.
 *
 * WHY IT LOOKS LIKE THIS (M8D-D1, journal Entry 1). CLAUDE.md's fixture rule points at
 * `packages/e2e-tests/src/session-fixture.ts` — "never write a new makeFixture() from scratch, use
 * and extend it". That file no longer exists in either repo; grep finds it only in M5/M6/M7
 * archaeology and in cello-client's own dead-code report. The live two-connections-on-one-agent
 * harness is the in-file pattern in `m8c-cursor-1.test.ts` (real `startDaemon`, a real IPC socket,
 * `connectAs()` called twice for the same agent), so this module EXTRACTS that pattern rather than
 * inventing a second one, and `m8c-cursor-1.test.ts` is repointed at it. Extending the established
 * fixture is what the rule is for.
 *
 * Real daemon, real IPC socket, real SQLCipher DB. The libp2p node is faked because M8D is about the
 * daemon's own delivery bookkeeping — no crypto is stubbed.
 */

import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider, msgLeafHash, generateKeypair } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../../daemon.js";
import { connectToDaemon, type IpcClient } from "../../ipc-client.js";
import type { Logger, DaemonConfig } from "../../types.js";
import type { SessionNodeManager, ISessionNodeFactory, SessionNodeConfig } from "../../session-node-manager.js";
import type { SecurityGatewayClient } from "../../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

/** A libp2p node that goes nowhere. The daemon-side bookkeeping under test never dials. */
export class FakeNode implements Partial<CelloNode> {
  sent: Uint8Array[] = [];
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  /**
   * `newStreamFails` makes every direct send fail, which is the only way to reach the PARK route —
   * the route a message takes when the counterparty is not there to receive it directly. Optional
   * and defaulted off, so every existing caller keeps a node whose streams succeed.
   */
  /**
   * `onNewStream` fires INSIDE `newStream`, i.e. between a caller reading session state and using
   * it. That is the only way to drive a window that exists purely because an `await` sits in the
   * middle of one — a test that mutates state before or after the send cannot reach it.
   * Optional and defaulted off, so every existing caller is unchanged (fixture rule).
   */
  constructor(private readonly opts: { newStreamFails?: boolean; onNewStream?: () => void } = {}) {}
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  // DOD-M15-IDLE-CONNS-1 widened the shape: direction/openedAt/streamCount are what the idle
  // sweep judges a connection on. Empty here, so this fixture asserts nothing about reaping.
  getConnections(): Array<{
    id: string;
    peerId: string;
    encryption: string | undefined;
    status: string;
    direction: "inbound" | "outbound";
    openedAt: number;
    streamCount: number;
  }> { return []; }
  async hangUp(_peerId: string): Promise<void> {}
  /**
   * ⚠️ THE HANDLER IS CAPTURED, NOT DISCARDED — B2b-2 review, hollow-test finding.
   *
   * This was `onPeerConnect(_h) {}`. Throwing the handler away meant the daemon's peer-connect path
   * never ran in ANY daemon test — and that path is the only production route that registers a
   * pending salt agreement. The line that does it could be deleted and the whole suite stayed green,
   * which is to say nothing measured whether the salt feature can ever turn on in production.
   *
   * `firePeerConnect` is how a test drives it. Non-breaking: a fixture that never calls it behaves
   * exactly as before.
   */
  #peerConnectHandlers: Array<(p: string) => void> = [];
  onPeerConnect(h: (p: string) => void): void { this.#peerConnectHandlers.push(h); }
  /** Drive the real `onPeerConnect` path — what a counterparty coming online does. */
  firePeerConnect(peerId: string): void { for (const h of this.#peerConnectHandlers) h(peerId); }
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    this.opts.onNewStream?.();
    if (this.opts.newStreamFails) throw new Error("connection_lost: counterparty stream dead");
    const sink = this.sent;
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

export class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/** One captured log line. `level` is kept because M8D asserts on it — a theft must WARN. */
export interface CapturedEvent {
  level: "debug" | "info" | "warn" | "error";
  event: string;
  ctx: Record<string, unknown>;
}

/**
 * Options. Every field is optional with a non-breaking default, so a later unit adds behavior here
 * without touching any existing caller (CLAUDE.md fixture rule).
 */
export interface TwoConnectionFixtureOpts {
  /** Agents to create key material for. Default `["alice"]`. */
  agents?: string[];
  /** Replace the capturing logger. Default: captures into `events`. */
  logger?: Logger;
  /** Replace the fake libp2p node. Default: a fresh `FakeNode`. */
  node?: CelloNode;
  /** Temp-dir prefix, so a failing run is identifiable. Default `"cello-m8d-"`. */
  dirPrefix?: string;
  /**
   * Replace the outbound/inbound screening client. Default: `PassthroughGatewayClient`.
   *
   * DOD-COATTEND-SENDWINDOW-1 needs to HOLD a send inside `screenOutbound` while a second
   * connection races it — the gateway round trip is the wide half of the window the race lives in,
   * and with a passthrough it closes faster than any test can aim at.
   */
  securityGateway?: SecurityGatewayClient;
}

export interface TwoConnectionFixture {
  readonly tempDir: string;
  readonly socketPath: string;
  readonly snm: SessionNodeManager;
  /** Every log line the daemon emitted, in order. Empty when `opts.logger` was supplied. */
  readonly events: CapturedEvent[];
  /** Open ANOTHER IPC connection and attend `agent` on it. Call twice for the M8D case. */
  connectAs(agent: string): Promise<IpcClient>;
  /** Open a connection WITHOUT attending — the un-attended observer case. */
  connect(): Promise<IpcClient>;
  /**
   * `relay: true` configures the session with a relay target and real signing key material, which is
   * what makes the PARK route reachable — without it a failed direct send returns
   * `session_stream_unavailable` and the park hook is never consulted at all. Default `false`, so no
   * existing caller changes behaviour (fixture rule: new options carry non-breaking defaults).
   */
  createSession(
    sessionId: string,
    agent: string,
    counterpartyPubkey?: string,
    peerId?: string,
    opts?: { relay?: boolean },
  ): Promise<void>;
  /** Seed a RECEIVED message exactly as the inbound path does: tree leaf + transcript row. */
  seedReceived(agent: string, sessionId: string, text: string): number;
  /** Append a leaf this agent SENT, with its transcript row — what a sibling connection's send produces. */
  seedSent(agent: string, sessionId: string, text: string): number;
  /** Append a leaf with NO transcript row — a security-gateway terminal block; a permanent sequence hole. */
  seedLeafWithoutTranscriptRow(agent: string, sessionId: string): number;
  /** Drive the real inbound-content path, so the delivery buffer and the doorbell both fire. */
  ingestReceived(agent: string, sessionId: string, text: string, correlationId?: string): Promise<unknown>;
  eventsNamed(event: string): CapturedEvent[];
  /** DOD-M12B-CLOSE-SILENT-WAIT-1: put a session into the state a normal close sits in for up to
   *  eleven minutes, without waiting eleven minutes. Marks the real waiter map the status surface
   *  reads, and emits the same start-of-wait log the close emits. */
  markSealInFlightForTest(agent: string, sessionId: string): void;
  cleanup(): Promise<void>;
}

/**
 * The msg-leaf hash the content path binds.
 *
 * Re-exported from `@cello-protocol/crypto` rather than re-derived from `createHash` (review LOW).
 * The inline copy was carried over from `m8c-cursor-1`, and promoting it into a SHARED fixture
 * would have made the duplication load-bearing: if the production leaf rule ever changed, every
 * test built on this fixture would keep passing against the old one.
 */
export { msgLeafHash };

export async function startTwoConnectionFixture(
  opts: TwoConnectionFixtureOpts = {},
): Promise<TwoConnectionFixture> {
  const tempDir = await mkdtemp(join(tmpdir(), opts.dirPrefix ?? "cello-m8d-"));
  const events: CapturedEvent[] = [];
  const capturing: Logger = {
    debug(event, ctx) { events.push({ level: "debug", event, ctx: ctx ?? {} }); },
    info(event, ctx) { events.push({ level: "info", event, ctx: ctx ?? {} }); },
    warn(event, ctx) { events.push({ level: "warn", event, ctx: ctx ?? {} }); },
    error(event, ctx) { events.push({ level: "error", event, ctx: ctx ?? {} }); },
  };

  for (const name of opts.agents ?? ["alice"]) {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    await FileKeyProvider.load(join(dir, "key"));
  }

  const socketPath = join(tempDir, "daemon.sock");
  const config: DaemonConfig = {
    securityGateway: opts.securityGateway ?? new PassthroughGatewayClient(),
    celloDir: tempDir,
    socketPath,
    lockFilePath: join(tempDir, "daemon.lock"),
    maxConnections: 16,
    version: "0.0.1-test",
    logger: opts.logger ?? capturing,
    sessionNodeFactory: new FixedFactory(opts.node ?? (new FakeNode() as unknown as CelloNode)),
  };
  const handle = await startDaemon(config);
  const clients: IpcClient[] = [];

  async function connect(): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    return client;
  }

  return {
    tempDir,
    socketPath,
    snm: handle.getSessionNodeManager(),
    events,
    connect,
    async connectAs(agent: string): Promise<IpcClient> {
      const client = await connect();
      await client.send("cello_use_agent", { name: agent });
      return client;
    },
    async createSession(sessionId, agent, counterpartyPubkey = "bobpubkeyhex", peerId = "bob-peer-id", sessionOpts) {
      const snm = handle.getSessionNodeManager();
      /**
       * 007-CRYPTO: put the session into the state a COMPLETED key exchange leaves it in.
       *
       * A live send requires an agreed content key — there is no plaintext path to fall back to. In
       * production the exchange completes on connect, before any send; a fixture whose counterparty
       * is a `FakeNode` never completes it, so without this every content test built on this
       * fixture would silently be exercising the refusal path instead of the thing it was written
       * for. The state produced is exactly the production one; only how it got there is
       * short-circuited, which is why `setSaltContributionForTest` exists in the same shape.
       *
       * Tests of the EXCHANGE itself drive the real signed frames and must not rely on this.
       */
      const agreeKey = () =>
        snm.setSessionContentKeyForTest(agent, sessionId, new Uint8Array(32).fill(0x7e));
      /**
       * 033-ACKEMIT: put the session's GENESIS where a completed session open leaves it — same
       * short-circuit, same reason as the key above.
       *
       * Production derives it from the directory-signed relay assignment and writes it to the
       * session row; a fixture that builds a session node directly never sees an assignment. Without
       * it every send on this fixture is refused for having no starting point to acknowledge, and
       * every inbound frame it builds is a v1 claim the receiver refuses — so the tests would be
       * exercising two refusal paths instead of the behaviour they were written for.
       */
      const agreeGenesis = () =>
        snm.setSessionGenesisForTest(agent, sessionId, new Uint8Array(32).fill(0x9c));
      /**
       * ⚠️ THE GENESIS IS SEEDED BEFORE THE SESSION NODE, and the order is load-bearing —
       * `DOD-M15-SELFCHAIN-1`.
       *
       * `createSessionNode` registers the session with the relay client, and the client seeds its
       * acknowledgement state from the session's starting point AT THAT MOMENT. Seeding afterwards
       * leaves that state empty, and every send on the fixture is then refused for having nothing
       * to chain to — the fixture would exercise a refusal path instead of the behaviour it was
       * written for, which is the failure this seam exists to prevent.
       *
       * ⚠️ AND IT IS CALLED AGAIN AFTERWARDS, which is not a belt-and-braces duplicate. The seam
       * does two things: it holds the value in memory (what the registration above needs) and it
       * writes it to the session ROW. The row does not exist until `createSessionNode` inserts it,
       * so the first call's write updates nothing — and a session with an empty column is one whose
       * chain cannot be resumed after a restart. The second call is what puts it on disk.
       */
      agreeGenesis();
      if (!sessionOpts?.relay) {
        await snm.createSessionNode(sessionId, agent, counterpartyPubkey, peerId, "fixture");
        agreeKey();
        agreeGenesis();
        return;
      }
      // A REAL keypair, not a stub: the park path signs the entry, and `sealParkEnvelope` is the
      // sole producer of that signature. A fake signer here would make every park test pass against
      // a producer that signs the wrong statement — the exact hollow-test finding that made
      // `sealParkEnvelope` a single producer in the first place.
      const kp = generateKeypair();
      await snm.createSessionNode(sessionId, agent, counterpartyPubkey, peerId, "fixture", false, {
        relayPeerId: "12D3KooWFixtureRelay",
        relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWFixtureRelay"],
        keyProvider: kp,
        senderPubkey: await kp.getPublicKey(),
        sessionIdBytes: Buffer.from(sessionId, "hex"),
      });
      agreeKey();
      agreeGenesis();
    },
    seedSent(agent, sessionId, text) {
      const snm = handle.getSessionNodeManager();
      const { leafIndex } = snm.appendSessionLeaf(agent, sessionId, "msg", "bb".repeat(32), "seed");
      snm.recordTranscriptMessage(agent, sessionId, leafIndex, "sent", new TextEncoder().encode(text), "seed");
      return leafIndex;
    },
    seedLeafWithoutTranscriptRow(agent, sessionId) {
      // A leaf with NO transcript row is what the security gateway produces when it terminal-blocks
      // an inbound message: the leaf is committed to the hash chain, the plaintext never lands. It
      // is therefore a PERMANENT hole in the transcript's sequence space, and any walk that stops
      // at the first gap stops there for the lifetime of the session.
      return handle.getSessionNodeManager().appendSessionLeaf(agent, sessionId, "msg", "cc".repeat(32), "seed").leafIndex;
    },
    seedReceived(agent, sessionId, text) {
      const snm = handle.getSessionNodeManager();
      const { leafIndex } = snm.appendSessionLeaf(agent, sessionId, "msg", "aa".repeat(32), "seed");
      snm.recordTranscriptMessage(agent, sessionId, leafIndex, "received", new TextEncoder().encode(text), "seed");
      return leafIndex;
    },
    async ingestReceived(agent, sessionId, text, correlationId = "fixture-inbound") {
      const bytes = new TextEncoder().encode(text);
      return handle.getSessionNodeManager().ingestReceivedContent(agent, sessionId, bytes, msgLeafHash(bytes), correlationId);
    },
    markSealInFlightForTest(agent, sessionId) {
      handle.markSealInFlightForTest(agent, sessionId);
    },
    eventsNamed(event) {
      return events.filter((e) => e.event === event);
    },
    async cleanup() {
      for (const c of clients) { try { c.close(); } catch { /* already closed */ } }
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
      await rm(tempDir, { recursive: true, force: true });
    },
  };
}
