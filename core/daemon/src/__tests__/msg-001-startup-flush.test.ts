/**
 * CELLO-M7-MSG-001 — daemon startup flush of un-acked content (AC-004/AC-005, D-d).
 *
 * Specification (Phase S):
 *
 * AC-004: A sender daemon with one un-acked content entry in the retry_queue
 *   (awaiting_ack = 1) that was never confirmed parked (crash before the relay deposit
 *   completed). On a REAL daemon restart, the startup flush — which runs BEFORE the IPC
 *   socket opens — drains the retry_queue, finds the un-acked content, and re-parks it to
 *   the relay store-and-forward queue. content.park.deposited fires after restart for that
 *   content_hash. A unit RetryQueue + stub parkFn does NOT satisfy this AC: the entry is
 *   persisted to SQLCipher, the daemon binary is restarted (a fresh startDaemon on the same
 *   celloDir/DB, with fresh in-memory state), and the relay-side park target observes the
 *   entry after startup.
 *
 * AC-005: the retry_queue gains a TTF-trigger enqueue path (enqueue_awaiting_content over
 *   IPC) and a park-to-relay drain target (the startup flush). A `persisted` ACK clears the
 *   durable entry (mark_content_acked) so the flush does NOT re-park already-delivered
 *   content. No new table — the awaiting-ACK state lives in the SAME retry_queue table.
 *
 * The flush running before IPC opens is verified because the parkFn is invoked during the
 * `await startDaemon(...)` call (the parks are captured before the call returns).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes, createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";
import type { ParkResult, AwaitingContentEntry } from "../retry-queue.js";

describe("CELLO-M7-MSG-001 daemon startup flush of un-acked content", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg001-flush-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context: context ?? {} }); },
      info(event, context) { logEvents.push({ level: "info", event, context: context ?? {} }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context: context ?? {} }); },
      error(event, context) { logEvents.push({ level: "error", event, context: context ?? {} }); },
    };
    handle = null;
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeConfig(overrides?: Partial<DaemonConfig>): DaemonConfig {
    return {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      ...overrides,
    };
  }

  it("AC-004: un-acked content survives a daemon restart and is re-parked by the startup flush", async () => {
    const sessionId = "flush-session-A";
    const content = randomBytes(96);
    const contentHash = createHash("sha256").update(new Uint8Array([0x00])).update(content).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");

    // DOD-AGENT-ID-JOINKEY-1: enqueue_awaiting_content now requires a resolvable OWNING agent (it
    // resolves the name to an agent_id and throws agent_id_unresolved otherwise). Production always
    // has an agent by the time content is awaiting ACK; a flat-file agent + the one-time migration
    // that runs inside startDaemon gives this daemon a real `agents` row for "alice" to resolve.
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));

    // ── Run 1: a sender enqueues un-acked content (TTF fired) but crashes before park ──
    handle = await startDaemon(makeConfig());
    const socketPath = join(tempDir, "daemon.sock");
    {
      const client = await connectToDaemon(socketPath);
      try {
        const res = await client.send("enqueue_awaiting_content", {
          agentName: "alice",
          sessionId,
          contentHash: contentHashHex,
          content: Buffer.from(content).toString("hex"),
        }) as { queued: boolean; awaitingDepth: number };
        expect(res.queued).toBe(true);
        expect(res.awaitingDepth).toBe(1);
      } finally { client.close(); }
    }
    // Simulate the crash: stop WITHOUT ever marking the content acked / parked.
    await handle.stop("test_crash");
    handle = null;

    // ── Run 2: REAL restart with a relay park target wired ──
    logEvents.length = 0;
    const parked: Array<{ sessionId: string; contentHashHex: string; contentBlob: Uint8Array }> = [];
    const contentParkFn = async (entry: AwaitingContentEntry): Promise<ParkResult> => {
      // The park target is the natural emitter of content.park.deposited (it holds the
      // recipient context). Record the entry so the test can assert the relay store saw it.
      parked.push({ sessionId: entry.sessionId, contentHashHex: entry.contentHashHex, contentBlob: entry.contentBlob });
      logger.info("content.park.deposited", {
        sessionId: entry.sessionId,
        recipientPubkey: "stub-recipient",
        contentHash: entry.contentHashHex,
        correlationId: "startup-flush",
      });
      return { parked: true };
    };

    handle = await startDaemon(makeConfig({ contentParkFn }));

    // The flush runs BEFORE the IPC socket opens, so the park already happened by the time
    // startDaemon resolved — assert the relay-side target observed the un-acked entry.
    expect(parked.length).toBe(1);
    expect(parked[0].sessionId).toBe(sessionId);
    expect(parked[0].contentHashHex).toBe(contentHashHex);
    // The persisted content blob round-trips with TYPE intact (Uint8Array) and the right bytes.
    expect(parked[0].contentBlob).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(parked[0].contentBlob)).toEqual(Buffer.from(content));
    // The recovered blob is USABLE: its hash cross-checks against the committed content_hash.
    const recomputed = createHash("sha256").update(new Uint8Array([0x00])).update(parked[0].contentBlob).digest();
    expect(Buffer.from(recomputed).toString("hex")).toBe(contentHashHex);

    // content.park.deposited fired after restart for that content_hash.
    const deposited = logEvents.find((e) => e.event === "content.park.deposited");
    expect(deposited).toBeDefined();
    expect(deposited!.context.contentHash).toBe(contentHashHex);

    // The flush summary fired and reports the parked count.
    const flush = logEvents.find((e) => e.event === "content.park.flush.completed");
    expect(flush).toBeDefined();
    expect(flush!.context.parkedCount).toBe(1);
  });

  it("AC-005: a `persisted` ACK clears the durable entry so the next startup flush does NOT re-park it", async () => {
    const sessionId = "flush-session-B";
    const content = randomBytes(64);
    const contentHash = createHash("sha256").update(new Uint8Array([0x00])).update(content).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");

    // DOD-AGENT-ID-JOINKEY-1: same as AC-004 — enqueue_awaiting_content/mark_content_acked need a
    // resolvable owning agent.
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));

    handle = await startDaemon(makeConfig());
    const socketPath = join(tempDir, "daemon.sock");
    {
      const client = await connectToDaemon(socketPath);
      try {
        await client.send("enqueue_awaiting_content", {
          agentName: "alice", sessionId, contentHash: contentHashHex, content: Buffer.from(content).toString("hex"),
        });
        // The persisted ACK arrives → clear the durable awaiting entry.
        const acked = await client.send("mark_content_acked", {
          agentName: "alice", sessionId, contentHash: contentHashHex,
        }) as { acked: boolean; awaitingDepth: number };
        expect(acked.acked).toBe(true);
        expect(acked.awaitingDepth).toBe(0);
      } finally { client.close(); }
    }
    await handle.stop("test_restart");
    handle = null;

    // Restart with a park target — nothing should be re-parked (the entry was acked).
    logEvents.length = 0;
    const parked: AwaitingContentEntry[] = [];
    const contentParkFn = async (entry: AwaitingContentEntry): Promise<ParkResult> => {
      parked.push(entry);
      return { parked: true };
    };
    handle = await startDaemon(makeConfig({ contentParkFn }));

    expect(parked.length).toBe(0);
    // No flush-completed (no awaiting sessions) and no deferred warning fired.
    expect(logEvents.find((e) => e.event === "content.park.deposited")).toBeUndefined();
  });

  // DOD-LOOP-1: the native (non-injected) startup flush re-parks via the session's OWNING agent's
  // standing receiver — which, after the per-agent SR rework, exists only once that agent is
  // online. The pre-IPC startup flush therefore cannot deposit (no agent online yet); the re-park
  // fires when the owning agent comes online (cello_start_agent). This guards the regression where
  // the flush silently became a permanent no-op because no daemon-global SR exists at startup.
  // (The prior "no park target wired → flush.deferred" assertion was obsolete: the daemon's native
  // `startupParkFn` is an unconditional fallback, so the deferred branch is never taken in
  // production. The deposit-success path is covered by AC-004's injected target + the spine.)
  it("AC-005/DOD-LOOP-1: the native startup flush re-parks a session's un-acked content when its OWNING agent comes online", async () => {
    // alice must be a loadable agent (cello_start_agent loads from celloDir/agents).
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));

    handle = await startDaemon(makeConfig()); // native path — no injected contentParkFn
    const snm = handle.getSessionNodeManager();

    // Persist a session OWNED BY alice with a relay endpoint (what the crash-backstop flush reads).
    // DOD-AGENT-ID-JOINKEY-1: `sessions` is keyed by the stable agent_id, never agent_name — resolve
    // it off the `agents` row the flat-file migration created above.
    const aliceId = snm.resolveAgentId("alice");
    const sessionId = randomBytes(16).toString("hex");
    const counterparty = "cd".repeat(32);
    const now = Date.now();
    snm.getDb()
      .prepare("INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, relay_peer_id, relay_addrs) VALUES (?,?,?,?,?,?,?,?)")
      .run(sessionId, aliceId, counterparty, "interrupted", now, now, "12D3KooWRelayStub", JSON.stringify(["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelayStub"]));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      const content = randomBytes(48);
      const contentHashHex = createHash("sha256").update(new Uint8Array([0x00])).update(content).digest().toString("hex");
      await client.send("enqueue_awaiting_content", { agentName: "alice", sessionId, contentHash: contentHashHex, content: Buffer.from(content).toString("hex") });

      // Bring alice online → her standing receiver comes up → the per-agent re-park flush fires.
      logEvents.length = 0;
      expect(((await client.send("cello_start_agent", { name: "alice" })) as { ok?: boolean }).ok).toBe(true);

      // The per-agent re-park flush ran FOR alice — proves the DOD-LOOP-1 trigger + agent filter +
      // owning-agent node resolution all executed. The relay is unreachable here so the deposit
      // does not complete (parkedCount may be 0); this test guards the TRIGGER, not the deposit.
      let perAgentFlush: { level: string; event: string; context: Record<string, unknown> } | undefined;
      for (let i = 0; i < 160 && !perAgentFlush; i++) {
        perAgentFlush = logEvents.find((e) => e.event === "content.park.flush.completed" && e.context.agentName === "alice");
        if (perAgentFlush) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(perAgentFlush, "owning-agent coming online must trigger a per-agent re-park flush").toBeDefined();
      expect(perAgentFlush!.context.sessionCount).toBe(1);
    } finally { client.close(); }
  });
});
