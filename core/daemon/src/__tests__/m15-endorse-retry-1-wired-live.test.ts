/**
 * DOD-M15-ENDORSE-RETRY-1 — the retry, over a LIVE daemon and a real socket.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM THE UNIT TESTS. `m15-endorse-retry-1-submission-retry`
 * proves the QUEUE works when something drives it. It cannot prove that anything does. The two
 * wiring points — `submitForAgent` handing a retryable failure to the queue, and the agent's
 * `onConnected` waking it — are single call sites in a 5,000-line composition root, and this
 * milestone's own record says a fix for "the wiring has no test" shipped with no test.
 *
 * So this drives the real IPC handlers against a directory whose signaling stream is DOWN, then
 * brings it up, and asserts on the responses the operator actually reads. Deleting either call site
 * fails it.
 *
 * The stream is controlled through `signalingConnect`, the daemon's own test seam: it rejects while
 * the node is "down" (the SignalingManager then answers `signaling_reconnecting` to every send) and
 * resolves afterwards, which is what a node restarting looks like from this side.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider, InMemoryKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { randomBytes } from "node:crypto";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Stream } from "@libp2p/interface";

const DAY = 24 * 60 * 60 * 1000;
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface LogEvent { event: string; ctx: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (event: string, ctx?: Record<string, unknown>): void => { events.push({ event, ctx: ctx ?? {} }); };
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
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

/**
 * A directory that can be taken down and brought back.
 *
 * While `up` is false the connect REJECTS, which is what puts the SignalingManager into
 * 'reconnecting' — the state in which `sendRaw` answers `signaling_reconnecting` without touching
 * the network. That is the production shape of "the node this daemon is connected to is down",
 * reached the same way production reaches it rather than by stubbing the send.
 */
function makeControllableDirectory() {
  const state = { up: false, writes: [] as Array<Record<string, unknown>>, storedAnswer: true };
  const connect = async (): Promise<ConnectResult> => {
    if (!state.up) throw new Error("node_down");
    let inbound: ((frame: unknown) => void) | null = null;
    const stream: SignalingStream = {
      send: async (frame: unknown) => {
        const f = frame as Record<string, unknown>;
        if (f["type"] !== "submission_write") return;
        state.writes.push(f);
        // The node's ack, on the same shared stream every other component uses.
        inbound?.({
          type: "submission_write_result",
          submission_id: f["submission_id"],
          stored: state.storedAnswer,
        });
      },
      onMessage: (h: (frame: unknown) => void) => { inbound = h; },
      close: () => {},
    };
    return { stream, directoryNodeId: "fake-dir", manifestVersion: 1 };
  };
  return { state, connect };
}

describe("DOD-M15-ENDORSE-RETRY-1 — over a live daemon", () => {
  let dir: string;
  let handle: DaemonHandle | null;
  const clients: IpcClient[] = [];

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-endorse-retry-"));
    handle = null;
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    clients.length = 0;
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    handle = null;
    await rm(dir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const d = join(dir, "agents", name);
    await mkdir(d, { recursive: true });
    const kp = await FileKeyProvider.load(join(d, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  /** A REAL Ed25519 key, because `sealToRecipient` converts it and would refuse a hex placeholder. */
  async function intakeKey(): Promise<{ key_id: string; pubkey: string }> {
    const kp = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    return { key_id: "intake-0", pubkey: Buffer.from(await kp.getPublicKey()).toString("hex") };
  }

  async function boot(connect: () => Promise<ConnectResult>, logger: Logger, expiresInMs = 400 * DAY): Promise<DaemonHandle> {
    const manifest = {
      version: 1,
      not_before: new Date(Date.now() - DAY).toISOString(),
      expires: new Date(Date.now() + expiresInMs).toISOString(),
      nodes: [{ nodeId: "n1", pubkey: "b".repeat(64), region: "r", provider: "p", endpoint: "http://127.0.0.1:1" }],
      signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
      intake_key: await intakeKey(),
    };
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNodeFactory: new FixedFactory(new FakeNode() as unknown as CelloNode),
      signalingConnect: connect,
      manifestProvider: {
        loadAndVerify: async () => manifest,
        getCurrentManifest: () => manifest,
        updateManifest: () => {},
      },
      manifestRootKeys: ["a".repeat(64)],
      manifestThreshold: 1,
      // Deterministic timings. Without them this test's green depends on the real SignalingManager
      // reconnect ladder (1s → 2s → 4s → 8s → 16s, cap 30s) landing before the queue's own first
      // attempt — and when it lands after, the next attempt is a full minute away and a CORRECT
      // implementation goes red. A 2-second backstop under a 2-second local-precondition retry
      // means the queue keeps trying throughout the poll window whichever order they fall in.
      submissionRetryIntervalsMs: { staggerMs: 2_000, localPreconditionRetryMs: 2_000 },
      fetchFn: (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch,
    } as unknown as DaemonConfig;
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  async function attach(agent: string): Promise<IpcClient> {
    const c = await connectToDaemon(join(dir, "daemon.sock"));
    clients.push(c);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_use_agent", { name: agent });
    await c.send("cello_start_agent", { name: agent });
    return c;
  }

  it("★ CLAUSES 1 + 5 — the node is down, the operator is told it is HELD, and it goes out by itself when the node returns", async () => {
    const dirNode = makeControllableDirectory();
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    await boot(dirNode.connect, logger);
    const c = await attach("alice");

    // ── The node is down. This is the whole defect: before this unit the command simply failed.
    const issued = (await c.send("cello_attestations_issue", {
      subject_pubkey: "ab".repeat(32),
      body: "worked with them on the migration",
    })) as Record<string, unknown>;

    expect(issued["ok"], `the operator was told this failed: ${JSON.stringify(issued)}`).toBe(true);
    // NAME THE VALUE. `ok:true` alone would also be true of a response claiming a node accepted it.
    expect(issued["delivery"]).toBe("retrying");
    expect(issued["queued"]).toBe(false);
    expect(issued["submission_id"]).toMatch(/^[0-9a-f]{64}$/);
    // Clause 5's actual requirement: the surface says it is retrying, and says what to do.
    expect(String(issued["guidance"])).toMatch(/do NOT need to run this again/i);
    expect(String(issued["guidance"])).toMatch(/cello_attestations_issued/);
    // Nothing reached the node, so nothing may claim it did.
    expect(dirNode.state.writes).toHaveLength(0);

    // ── The list surface shows it as in flight, not as nothing.
    const before = (await c.send("wallet_list_issued", {})) as Record<string, unknown>;
    expect(before["issued"]).toEqual([]);
    const inFlight = before["in_flight"] as Array<Record<string, unknown>>;
    expect(inFlight, "a held submission was INVISIBLE — the operator reads 'you sent nothing'").toHaveLength(1);
    expect(inFlight[0]["delivery"]).toBe("retrying");
    expect(inFlight[0]["submission_id"]).toBe(issued["submission_id"]);
    expect(inFlight[0]["op"]).toBe("submit");

    /**
     * ── THE NODE COMES BACK. NOTHING ELSE HAPPENS — no operator action, no second command.
     *
     * NAME THE WRITER, because there are two and this seam only exercises one. The queue has a
     * timer of its own AND a wake on the agent's `onConnected`, and on THIS path only the timer can
     * fire: injecting `signalingConnect` makes the daemon use `sharedSignaling`, which carries no
     * `onConnected` callback at all (see daemon.ts — the shared manager is the in-process test
     * path; production builds a per-agent manager that has one). So deleting the wake leaves this
     * test green, and an earlier version of it claimed the wake as proven when the timer had done
     * the work. The wake is pinned separately, below.
     *
     * What this DOES prove, and it is the clause: the operator does nothing, and the submission
     * reaches a node by itself. The timer is a production writer too — it is what covers a stream
     * that comes back without the callback landing.
     */
    dirNode.state.up = true;

    let landed: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 80 && landed.length === 0; i++) {
      await wait(250);
      const now = (await c.send("wallet_list_issued", {})) as Record<string, unknown>;
      landed = now["issued"] as Array<Record<string, unknown>>;
    }

    expect(dirNode.state.writes, "nothing carried the held submission to the node once it was back").toHaveLength(1);
    // THE SAME content-derived id the operator was given, and the same intake key — a re-compose
    // would have produced a different id, which is a second endorsement rather than a retry.
    expect(dirNode.state.writes[0]["submission_id"]).toBe(issued["submission_id"]);
    expect(landed).toHaveLength(1);
    expect(landed[0]["submission_id"]).toBe(issued["submission_id"]);
    expect(landed[0]["delivery"]).toBe("accepted");
    // And it leaves the in-flight list, or the operator sees one submission twice in two states.
    const after = (await c.send("wallet_list_issued", {})) as Record<string, unknown>;
    expect(after["in_flight"]).toEqual([]);
  }, 60_000);

  it("a submission is NOT held when its intake key expires inside the retry window", async () => {
    /**
     * The sealed bytes are opened by the portal's intake key from THIS manifest. Holding them
     * across that key's expiry produces a submission the portal cannot open and cannot attribute —
     * poison, with no reply possible — while the operator has been told it is held and needs
     * nothing from them. The plain failure is the better answer, because they can act on it.
     *
     * `composeSealedSubmission` refuses an ALREADY-expired manifest, so this is specifically the
     * gap between "still valid" and "valid for longer than we would hold it": thirty minutes,
     * against a one-hour window.
     */
    const dirNode = makeControllableDirectory();
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    await boot(dirNode.connect, logger, 30 * 60_000);
    const c = await attach("alice");

    const issued = (await c.send("cello_attestations_issue", {
      subject_pubkey: "ef".repeat(32),
      body: "vouching just before the key rotates",
    })) as Record<string, unknown>;

    // The compose SUCCEEDED — the manifest is still valid — so this is the retry declining to hold,
    // not the expiry gate refusing to seal.
    expect(issued["ok"]).toBe(false);
    expect(issued["reason"]).toBe("signaling_reconnecting");
    expect(String(issued["guidance"])).toMatch(/NOT\s+holding it/);
    expect(String(issued["guidance"])).toMatch(/cannot open or even attribute/);

    const list = (await c.send("wallet_list_issued", {})) as Record<string, unknown>;
    expect(list["in_flight"], "a blob was held past the key that can open it").toEqual([]);
  }, 30_000);

  it("CLAUSE 3 — a node that REFUSES on the merits is answered as a failure, and never retried", async () => {
    // The node is UP and answers `submission_write_error`. That is a decision about the submission,
    // so it must reach the operator as a failure — not be swallowed into a retry that reports
    // "hold on" about something already refused.
    const state = { writes: 0 };
    const connect = async (): Promise<ConnectResult> => {
      let inbound: ((frame: unknown) => void) | null = null;
      const stream: SignalingStream = {
        send: async (frame: unknown) => {
          const f = frame as Record<string, unknown>;
          if (f["type"] !== "submission_write") return;
          state.writes += 1;
          inbound?.({ type: "submission_write_error", submission_id: f["submission_id"], reason: "quota_exceeded" });
        },
        onMessage: (h: (frame: unknown) => void) => { inbound = h; },
        close: () => {},
      };
      return { stream, directoryNodeId: "fake-dir", manifestVersion: 1 };
    };
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    await boot(connect, logger);
    const c = await attach("alice");

    const issued = (await c.send("cello_attestations_issue", {
      subject_pubkey: "cd".repeat(32),
      body: "a claim the node will not take",
    })) as Record<string, unknown>;

    expect(issued["ok"]).toBe(false);
    expect(issued["reason"]).toBe("submission_refused_by_node");
    // THE NODE'S OWN REASON SURVIVES — a retry would have replaced it with "hold on, reconnecting".
    expect(String(issued["guidance"])).toContain("quota_exceeded");
    expect(issued["delivery"]).toBeUndefined();

    // Nothing is held, and no reconnect can resurrect it.
    const list = (await c.send("wallet_list_issued", {})) as Record<string, unknown>;
    expect(list["in_flight"], "a refusal on the merits was queued for retry").toEqual([]);
    await wait(500);
    expect(state.writes, "the refusal was re-sent to a node that had already decided").toBe(1);
  }, 30_000);
});

/**
 * THE ONE LINK THE LIVE TEST ABOVE CANNOT REACH — the reconnect wake.
 *
 * `SubmissionRetryQueue.onSignalingConnected` is proven by the unit tests: it wakes THAT agent's
 * held submissions and not another's. What no in-process test can reach is the daemon CALLING it,
 * because the only seam for driving the signaling stream (`signalingConnect`) routes through
 * `sharedSignaling`, and that manager is constructed with no `onConnected` callback of any kind.
 * The production manager — one per agent, built from `directoryEndpointResolver` — is the one that
 * has it, and reaching that path needs a real directory handshake, which is the journey enforcer's
 * job rather than this file's.
 *
 * So the call site is pinned exactly, and the pin is deliberately NOT a loose "the name appears
 * somewhere in the file": it must sit inside the SAME `onConnected` block as the park drain, which
 * is the only place that runs on every connect and every reconnect. Moving it out of that block —
 * to agent start, say — would leave a reconnect delivering nothing, and that is precisely the
 * defect that cost 46 of 48 reconnects their standing-receiver registration in the 2026-07-31
 * incident.
 *
 * Made to fail on purpose: deleting the call from `onConnected` reddens this, and it reddens by
 * reporting the callback body rather than by throwing on a missing file.
 */
describe("DOD-M15-ENDORSE-RETRY-1 — the reconnect wake is wired into onConnected", () => {
  it("the agent's onConnected wakes the retry queue, in the same block as the park drain", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, resolve } = await import("node:path");
    const src = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "..", "daemon.ts"), "utf8");

    // POSITIVE CONTROL FIRST: prove this search can see. An empty result from a path that does not
    // exist reads exactly like an absent call site.
    expect(src.length, "daemon.ts was not read").toBeGreaterThan(1000);
    expect(src).toContain("onSignalingConnected(agentName)");

    // The `onConnected` callback body, taken as the text between `onConnected: () => {` and its
    // closing brace — not the whole file, which is what makes this an assertion about WHERE.
    // EXACTLY ONE, so the pin cannot be silently repointed. `indexOf` takes the first match, and a
    // second `onConnected` block added above this one would move the pin to code it says nothing
    // about while staying green.
    const declarations = src.split("onConnected: () => {").length - 1;
    expect(declarations, "there is no longer exactly one onConnected block for this pin to name").toBe(1);
    const at = src.indexOf("onConnected: () => {");
    const body = src.slice(at, src.indexOf("},", at));
    expect(
      body,
      "the retry queue is not woken on reconnect — a held submission then waits for the queue's own " +
        "timer instead of going out when the stream returns",
    ).toContain("submissionRetries.onSignalingConnected(agentName)");
  });
});
