/**
 * M9-GATE-1 — the Phase-1 end-to-end gate (one machine, no directory attestation).
 *
 * The DoD's gate: "the whole loop is green against the real daemon + gateway on one machine." The
 * four-outcome send/receive loop through two real daemon PROCESSES + two real gateway PROCESSES is
 * proven in m9-core-001-seam.test.ts (clean / redact-secret / warn+governance-resend / block, the
 * inbound-redact mirror, and the inbound terminal block). The INV-5 funnel — that all THREE inbound
 * producers (direct / park-recovery / held-then-released) screen — is proven at the SessionNodeManager
 * layer in m9-core-001-inbound-funnel.test.ts.
 *
 * This gate closes the one remaining real-process gap those two leave (procedure §7): the
 * PARK-RECOVERY producer must be screened by a REAL gateway PROCESS, the SAME as direct — not only by
 * an in-process gateway double. The daemon recover loop (daemon.ts) recovers parked content by calling
 * `sessionNodeManager.ingestReceivedContent` — the exact method this gate drives. So driving it against
 * a real spawned `cello-gateway` proves a recovered message is screened identically to a direct one:
 * a clean recovered message is delivered, a recovered terminal-block (non-English) records its leaf but
 * is never delivered, and the gateway's ENCRYPTED RECORD STORE holds the inbound security-pass record
 * for the recovered bytes — hash-chained, keyed by contentHash. (It used to read a plaintext request
 * log; that file is gone with M8C DOD-CRYPTO-AT-REST-1, and asserting on the durable audit trail is
 * the stronger claim: a record that is absent is itself evidence of suppression.)
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { spawnGatewaySidecar, LocalSidecarGatewayClient, type SpawnedGateway } from "@cello-protocol/gateway";
import { seedAgents } from "./helpers/seed-agents.js";

function makeLogger(): Logger { return { debug() {}, info() {}, warn() {}, error() {} }; }
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}
const enc = (s: string) => new TextEncoder().encode(s);

class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(): void {}
  onPeerDisconnect(): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(): () => void { return () => {}; }
  async newStream(): Promise<Stream> {
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}
class SharedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/**
 * Proof-of-screening now comes from the gateway's ENCRYPTED record store, not a plaintext request
 * log. The request log was a debug side-channel writing metadata and a content fingerprint to a
 * file outside the encrypted store — it duplicated this store and kept M8C's
 * DOD-CRYPTO-AT-REST-1 open, so it was removed rather than guarded.
 */
async function gatewayRecords(dbPath: string, keyPath: string): Promise<Array<{ direction: string; contentHash: string }>> {
  const { GatewayRecordStore } = await import("@cello-protocol/gateway");
  try {
    const store = new GatewayRecordStore(dbPath, keyPath);
    try { return store.all().map((r) => ({ direction: r.direction, contentHash: r.contentHash })); }
    finally { store.close(); }
  } catch (err) {
    // Review L7: do NOT swallow into `[]`. Every assertion on this helper today is positive, so a
    // store fault fails loud by accident — but the first negative assertion (`toHaveLength(0)`,
    // `.some(...)).toBe(false)`) would read a store that cannot open as "correctly nothing was
    // recorded". That is the screened-but-unrecorded shape this milestone exists to prevent,
    // reproduced inside its own test helper.
    throw new Error(`could not read the gateway record store at ${dbPath}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

const SID = "44".repeat(16);

describe("M9-GATE-1: the park-recovery producer is screened by a REAL gateway process (INV-5)", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];
  const gateways: SpawnedGateway[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-m9gate1-"));
    managers.length = 0; gateways.length = 0;
  });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* down */ } }
    for (const g of gateways) { try { await g.stop(); } catch { /* down */ } }
    managers.length = 0; gateways.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  async function setup(): Promise<{ mgr: SessionNodeManager; storeDb: string; storeKey: string }> {
    const sock = join(tempDir, "gw.sock");
    const storeDb = join(tempDir, "gw-store.db");
    const storeKey = join(tempDir, "gw-store.key");
    writeFileSync(storeKey, randomBytes(32), { mode: 0o600 });
    const gw = await spawnGatewaySidecar({
      socketPath: sock,
      env: { CELLO_GATEWAY_STORE_DB: storeDb, CELLO_GATEWAY_STORE_KEY_FILE: storeKey },
    });
    gateways.push(gw);
    const client = new LocalSidecarGatewayClient({ socketPath: sock, deadlineMs: 2_000 });
    const dbPath = join(tempDir, "snm.db");
    const mgr = new SessionNodeManager({ factory: new SharedFactory(new FakeNode() as unknown as CelloNode), logger: makeLogger(), dbPath, securityGateway: client });
    managers.push(mgr);
    await mgr.initialize();
    // DOD-AGENT-ID-JOINKEY-1: production always has an `agents` row before any session exists.
    await seedAgents(mgr.getDb(), ["alice"]);
    await mgr.createSessionNode(SID, "alice", "bobpubkey", "bob-peer-id", "corr-gate1");
    return { mgr, storeDb, storeKey };
  }

  it("a CLEAN recovered message is screened by the real gateway and DELIVERED to the agent", async () => {
    const { mgr, storeDb, storeKey } = await setup();
    const content = enc("recovered-from-park, perfectly fine");
    const res = await mgr.ingestReceivedContent("alice", SID, content, msgLeafHash(content));
    expect(res.ok).toBe(true);
    expect(mgr.getSessionTree("alice", SID).size()).toBe(1); // leafed
    const drained = mgr.takeReceivedContent("alice", SID);
    expect(drained && Buffer.from(drained.contentHex, "hex").toString()).toBe("recovered-from-park, perfectly fine");

    // The REAL gateway process logged the inbound screen of these exact bytes (proof-of-screening).
    const fp = createHash("sha256").update(content).digest("hex");
    const records = await gatewayRecords(storeDb, storeKey);
    expect(records.some((e) => e.direction === "inbound" && e.contentHash === fp)).toBe(true);
  }, 30_000);

  it("a recovered TERMINAL-block (non-English) is screened the SAME as direct: leaf recorded, NEVER delivered", async () => {
    const { mgr } = await setup();
    const cjk = enc("这是一条通过中继恢复的中文消息它必须像直达消息一样被语言过滤器拦截");
    const res = await mgr.ingestReceivedContent("alice", SID, cjk, msgLeafHash(cjk));
    // Terminal block via the REAL gateway: durably acknowledged (ok) + leafed for chain parity, but
    // screened OUT — never buffered for the agent. Identical handling to a direct terminal block.
    expect(res.ok).toBe(true);
    expect(res.ok && res.screenedOut).toBe(true);
    expect(mgr.getSessionTree("alice", SID).size()).toBe(1); // one tamper-evident leaf
    expect(mgr.takeReceivedContent("alice", SID)).toBeNull(); // the agent never sees it
  }, 30_000);
});
