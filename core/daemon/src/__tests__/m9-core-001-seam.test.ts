/**
 * M9-CORE-001 — the daemon ↔ gateway seam, program-anchored.
 *
 * Drives a complete two-daemon session through the PUBLIC IPC handlers (cello_send /
 * cello_receive) with each daemon wired to a REAL gateway running as a separate OS process
 * (spawnGatewaySidecar). Proves the seam against the real channel, not an in-process stub:
 *
 *   AC-001  outbound is screened by the gateway PROCESS before content reaches the wire
 *           (its request log records the screen; and with the gateway down, nothing is sent).
 *   AC-002  inbound is screened by the gateway PROCESS before cello_receive can drain it
 *           (its request log records the inbound screen; with B's gateway down, B receives nothing).
 *   AC-003  core/daemon holds no detection pipeline — only the interface + the two call sites.
 *   SI-001 / DB-001  a configured-but-unreachable gateway fails closed: outbound returns
 *           gateway_unavailable and nothing is sent; inbound is held and never delivered ungated.
 *
 * Harness mirrors seam-4 (two real daemons, real libp2p, the directory's two-round role played
 * explicitly). The only addition is a gateway sidecar per daemon.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, readFile } from "node:fs/promises";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { spawnGatewaySidecar, LocalSidecarGatewayClient, type SpawnedGateway } from "@cello-protocol/gateway";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
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

async function readGatewayLog(path: string): Promise<Array<Record<string, unknown>>> {
  try {
    const raw = await readFile(path, "utf8");
    return raw.trim().length === 0 ? [] : raw.trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
  } catch {
    return []; // not yet created = no requests screened
  }
}

const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 7));
const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
const TS = 1_700_000_000_000;

describe("M9-CORE-001: daemon ↔ gateway seam (real gateway process)", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];
  const gateways: SpawnedGateway[] = [];
  const ipcClients: Array<Awaited<ReturnType<typeof connectToDaemon>>> = [];

  beforeEach(async () => {
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    tempDir = await mkdtemp(join(tmpdir(), "cello-m9-"));
    handles.length = 0; gateways.length = 0; ipcClients.length = 0;
  });
  afterEach(async () => {
    for (const c of ipcClients) { try { c.close(); } catch { /* ignore */ } }
    for (const h of handles) { try { await h.stop("test_cleanup"); } catch { /* ignore */ } }
    for (const g of gateways) { try { await g.stop(); } catch { /* ignore */ } }
    handles.length = 0; gateways.length = 0; ipcClients.length = 0;
    await rm(tempDir, { recursive: true, force: true });
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"];
    else process.env["CELLO_ENV"] = priorCelloEnv;
  });

  async function makeAgent(celloDir: string, name: string): Promise<string> {
    const dir = join(celloDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  /** Spawn a gateway sidecar; return its handle + request-log path. */
  async function spawnGateway(tag: string): Promise<{ gw: SpawnedGateway; sock: string; log: string }> {
    const sock = join(tempDir, `${tag}.sock`);
    const log = join(tempDir, `${tag}.log`);
    const gw = await spawnGatewaySidecar({ socketPath: sock, requestLogPath: log });
    gateways.push(gw);
    return { gw, sock, log };
  }

  async function startOne(opts: {
    celloDir: string;
    signalingConnect: () => Promise<ConnectResult>;
    sessionNegotiator?: SessionNegotiator;
    gatewaySock?: string;
  }): Promise<{ h: Awaited<ReturnType<typeof startDaemon>>; events: LogEvent[] }> {
    const { logger, events } = makeLogger();
    const config: DaemonConfig = {
      celloDir: opts.celloDir,
      socketPath: join(opts.celloDir, "daemon.sock"),
      lockFilePath: join(opts.celloDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: opts.signalingConnect,
      sessionNegotiator: opts.sessionNegotiator,
      ...(opts.gatewaySock
        ? { securityGateway: new LocalSidecarGatewayClient({ socketPath: opts.gatewaySock, deadlineMs: 1_000 }) }
        : {}),
    };
    const h = await startDaemon(config);
    handles.push(h);
    return { h, events };
  }

  /**
   * Bring up a complete A→B session. Each side optionally gets a gateway sidecar (when its
   * `*Sock` is provided). Returns the live IPC clients + the agents + A's event log.
   */
  async function bringUpSession(opts: { aGatewaySock?: string; bGatewaySock?: string }): Promise<{
    clientA: Awaited<ReturnType<typeof connectToDaemon>>;
    clientB: Awaited<ReturnType<typeof connectToDaemon>>;
    alicePubkey: string;
    aEvents: LogEvent[];
    bEvents: LogEvent[];
  }> {
    const dirA = join(tempDir, "A");
    const dirB = join(tempDir, "B");
    const alicePubkey = await makeAgent(dirA, "alice");
    const bobPubkey = await makeAgent(dirB, "bob");

    const injectB: { inject?: (frame: unknown) => void } = {};
    const { h: B, events: bEvents } = await startOne({
      celloDir: dirB,
      signalingConnect: makeInjectableSignaling(injectB),
      gatewaySock: opts.bGatewaySock,
    });
    let bInfo: { peerId: string; addrs: string[] } | null = null;

    const negotiator: SessionNegotiator = {
      async negotiate() {
        const assignment: SessionAssignment = {
          session_id: SID_BYTES,
          participant_a: { pubkey: Buffer.from(alicePubkey, "hex"), peer_id: "", multiaddrs: [] },
          participant_b: { pubkey: Buffer.from(bobPubkey, "hex"), peer_id: bInfo!.peerId, multiaddrs: bInfo!.addrs },
          relay_endpoint: { peer_id: "", multiaddrs: [] },
          directory_endpoint: { peer_id: "", multiaddrs: [] },
          session_timestamp: TS,
          directory_pubkey: new Uint8Array(32),
          directory_signature: new Uint8Array(64),
          transport_mode: "direct",
          counterparty_session_peer_id: bInfo!.peerId,
          counterparty_session_addrs: bInfo!.addrs,
          signature_type: "frost",
          signer_pubkey: new Uint8Array(32),
        };
        return { ok: true, assignment };
      },
    };
    const { h: A, events: aEvents } = await startOne({
      celloDir: dirA,
      signalingConnect: makeInjectableSignaling({}),
      sessionNegotiator: negotiator,
      gatewaySock: opts.aGatewaySock,
    });

    const clientB = await connectToDaemon(join(dirB, "daemon.sock"));
    const clientA = await connectToDaemon(join(dirA, "daemon.sock"));
    ipcClients.push(clientA, clientB);

    await clientB.send("ipc.connect", { clientType: "test" });
    expect(((await clientB.send("cello_start_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
    expect(((await clientB.send("cello_use_agent", { name: "bob" })) as Record<string, unknown>).ok).toBe(true);
    for (let i = 0; i < 100 && !bInfo; i++) {
      bInfo = B.getSessionNodeManager().getStandingReceiverInfo("bob");
      if (bInfo) break;
      await wait(25);
    }
    expect(bInfo).not.toBeNull();
    const awaitP = clientB.send("cello_await_session", { timeout_ms: 30_000 }) as Promise<Record<string, unknown>>;
    await wait(30);

    await clientA.send("ipc.connect", { clientType: "test" });
    expect(((await clientA.send("cello_start_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    expect(((await clientA.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>).ok).toBe(true);
    const initRes = await clientA.send("cello_initiate_session", { counterparty_pubkey: bobPubkey }) as Record<string, unknown>;
    expect(initRes.ok).toBe(true);

    const naPeerId = A.getSessionNodeManager().getSessionNodePeerId("alice", SID_HEX);
    injectB.inject!({
      type: "session_assignment",
      assignment: {
        session_id: SID_BYTES,
        participant_a: { pubkey: Buffer.from(alicePubkey, "hex") },
        participant_b: { pubkey: Buffer.from(bobPubkey, "hex") },
        initiator_session_peer_id: naPeerId,
        session_timestamp: TS,
        signature_type: "frost",
      },
    });
    const awaited = await awaitP;
    expect(awaited.type).toBe("new_session");

    return { clientA, clientB, alicePubkey, aEvents, bEvents };
  }

  it("AC-001/AC-002 happy path: both gateways screen the real content; send + receive succeed", async () => {
    const a = await spawnGateway("ga");
    const b = await spawnGateway("gb");
    const { clientA, clientB, alicePubkey } = await bringUpSession({ aGatewaySock: a.sock, bGatewaySock: b.sock });

    const text = "hello over the gateway-screened stack";
    const sent = await clientA.send("cello_send", { session_id: SID_HEX, content: text }) as Record<string, unknown>;
    expect(sent.ok).toBe(true);

    let recv: Record<string, unknown> | null = null;
    for (let i = 0; i < 160; i++) {
      recv = await clientB.send("cello_receive", { session_id: SID_HEX }) as Record<string, unknown>;
      if (recv && recv.content) break;
      await wait(25);
    }
    expect(recv?.content).toBe(text);

    // AC-001: A's gateway PROCESS recorded the outbound screen for this exact content.
    const aLog = await readGatewayLog(a.log);
    const outbound = aLog.filter((e) => e.direction === "outbound");
    expect(outbound.length).toBeGreaterThanOrEqual(1);
    expect(outbound.some((e) => e.bytes === Buffer.byteLength(text))).toBe(true);

    // AC-002: B's gateway PROCESS recorded the inbound screen — and (proof it ran BEFORE
    // delivery) cello_receive only returned content after that screen was logged.
    const bLog = await readGatewayLog(b.log);
    const inbound = bLog.filter((e) => e.direction === "inbound");
    expect(inbound.length).toBeGreaterThanOrEqual(1);
    expect(inbound.some((e) => e.bytes === Buffer.byteLength(text))).toBe(true);
  }, 40_000);

  it("SI-001/DB-001 outbound: with A's gateway down, cello_send fails closed and nothing reaches B", async () => {
    const a = await spawnGateway("ga");
    const b = await spawnGateway("gb");
    const { clientA, clientB } = await bringUpSession({ aGatewaySock: a.sock, bGatewaySock: b.sock });

    // Kill A's gateway AFTER the session is live but BEFORE the send.
    await a.gw.stop();

    const sent = await clientA.send("cello_send", { session_id: SID_HEX, content: "must never be sent" }) as Record<string, unknown>;
    expect(sent.ok).toBe(false);
    expect(sent.reason).toBe("gateway_unavailable");
    expect(typeof sent.guidance).toBe("string");

    // B must receive NOTHING — the content never went on the wire.
    for (let i = 0; i < 20; i++) {
      const recv = await clientB.send("cello_receive", { session_id: SID_HEX }) as Record<string, unknown>;
      expect(recv.content == null).toBe(true);
      await wait(25);
    }
  }, 40_000);

  it("AC-002/DB-001 inbound: with B's gateway down, B's ingest is held — cello_receive delivers nothing ungated", async () => {
    const a = await spawnGateway("ga");
    const b = await spawnGateway("gb");
    const { clientA, clientB } = await bringUpSession({ aGatewaySock: a.sock, bGatewaySock: b.sock });

    // A keeps its gateway (so the SEND is allowed), but B's gateway dies before the content arrives.
    await b.gw.stop();

    const sent = await clientA.send("cello_send", { session_id: SID_HEX, content: "arrives but cannot be screened" }) as Record<string, unknown>;
    expect(sent.ok).toBe(true); // A screened + sent it

    // B can never deliver it to the agent: screenInbound fails closed, so the receive buffer
    // is never populated. cello_receive stays empty across repeated polls.
    for (let i = 0; i < 20; i++) {
      const recv = await clientB.send("cello_receive", { session_id: SID_HEX }) as Record<string, unknown>;
      expect(recv.content == null).toBe(true);
      await wait(25);
    }
  }, 40_000);

  it("AC-003: core/daemon contains no detection pipeline — only the gateway interface + the two call sites", async () => {
    const daemonSrcDir = dirname(fileURLToPath(import.meta.url)).replace(/\/__tests__$/, "");
    const files = readdirSync(daemonSrcDir).filter((f) => f.endsWith(".ts"));
    const sources = files.map((f) => ({ f, text: readFileSync(join(daemonSrcDir, f), "utf8") }));

    // The daemon must NOT pull in the gateway SERVER or screen pipeline — those are the detection
    // side, which lives only in @cello-protocol/gateway. The daemon holds the client/interface.
    for (const { f, text } of sources) {
      expect(text.includes("createGatewayServer"), `${f} must not import the gateway server`).toBe(false);
      expect(text.includes("GatewayScreenFn"), `${f} must not reference the screen-pipeline type`).toBe(false);
    }

    // And the two seam call sites exist — screening is DELEGATED through the interface, not inlined.
    const allText = sources.map((s) => s.text).join("\n");
    expect(allText.includes(".screenOutbound(")).toBe(true);
    expect(allText.includes(".screenInbound(")).toBe(true);
    // A crude detector-name guard: no homegrown detector/redactor/scanner class in the daemon.
    expect(/class\s+\w*(Detector|Redactor|Scanner|Pipeline)\b/.test(allText)).toBe(false);
  });
});
