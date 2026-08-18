/**
 * DOD-M12B-LEAF-TRIGGERS-FETCH-1 — we are TOLD a message exists and then wait 100 seconds for it.
 *
 * MEASURED LIVE 2026-08-18, Test 2, with two real agents on daemon 0.0.177:
 *
 *   13:15:02  the counterparty sends
 *   13:15:03  session.relay.leaf.delivered  seq 5      ← we know: it exists, its hash, its sequence
 *   13:15:55  a plain cello_receive returns NOTHING, and says the counterparty may have crashed
 *   13:16:45  content.recovered             seq 5      ← the bytes, 102 seconds later
 *
 * The relay pushes the WITNESS LEAF within a second — the ordering record, the content hash, the
 * canonical sequence. The plaintext travels separately over the direct content stream, and after an
 * interruption the two session nodes have no direct connection, so the bytes go to the relay's park
 * instead. Nothing connects those two facts: the leaf handler records the sequence and stops.
 *
 * So the daemon knew, one second in, that a specific message existed and where it was parked — and
 * then waited for a five-minute background sweep to stumble across it.
 *
 * WHY THIS AND NOT "READING SHOULD PULL". Andre stopped that proposal twice, correctly. Making the
 * client ask more often is a workaround for a signal we already receive and discard; it also does
 * nothing when nobody happens to read, which is most of the time. The leaf IS the push. Acting on it
 * needs no new wire traffic, no timer, and no operator action.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig, type ParkedDrainReason } from "../session-node-manager.js";
import { FakeNode } from "./helpers/two-connection-fixture.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { seedAgents } from "./helpers/seed-agents.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const SID = "a1".repeat(16);
const HASH = "cc".repeat(32);

class PlainFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return new FakeNode() as unknown as CelloNode; }
}

let tempDir: string;
let mgr: SessionNodeManager | undefined;
let drains: Array<{ agentName: string; reason: ParkedDrainReason }>;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "cello-msg029-"));
  drains = [];
  mgr = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory: new PlainFactory(),
    logger: silent,
    dbPath: join(tempDir, "sessions.db"),
  });
  await mgr.initialize();
  await seedAgents(mgr.getDb(), ["alice"]);
  mgr.setParkedDrainHook((agentName, reason) => { drains.push({ agentName, reason }); });
  // Collapse the grace window. It exists so the DIRECT path gets first refusal, and it has its own
  // case below — every other test here is about the decision, not the delay.
  mgr.setLeafFetchGraceMsForTest(0);
});
afterEach(async () => {
  await mgr?.gracefulShutdown();
  mgr = undefined;
  await rm(tempDir, { recursive: true, force: true });
});

/** Let the zero-delay timer fire. */
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 5));

describe("DOD-M12B-LEAF-TRIGGERS-FETCH-1: a witnessed leaf we cannot read is a fetch order", () => {
  it("a leaf for content we do NOT hold fetches it immediately", async () => {
    // The live case. We have the hash and the sequence; the bytes are parked at the very relay that
    // just told us about them. Waiting for a background sweep is a choice, and it cost 102 seconds.
    mgr!.recordWitnessedSequence("alice", SID, HASH, 4);
    await settle();

    expect(
      drains.map((d) => d.reason),
      "we were told a specific message exists and did nothing about it",
    ).toContain("witnessed_leaf_unresolved");
  });

  it("a leaf for content we ALREADY hold fetches nothing", async () => {
    // The common case by far: the direct path worked and the plaintext is already here. The witness
    // leaf still arrives, and it must not send us to the relay for something we have — that would
    // put a fetch on the hot path of every healthy message in every session.
    mgr!.markContentPresentForTest("alice", SID, HASH);
    mgr!.recordWitnessedSequence("alice", SID, HASH, 4);
    await settle();

    expect(drains, "a fetch per delivered message is a self-inflicted load problem").toEqual([]);
  });

  it("repeated leaves for the same unresolved content fetch ONCE", async () => {
    // The relay redelivers, and a redelivery carries the same sequence. Fetching per redelivery
    // turns a slow relay into a storm against itself.
    mgr!.recordWitnessedSequence("alice", SID, HASH, 4);
    mgr!.recordWitnessedSequence("alice", SID, HASH, 4);
    mgr!.recordWitnessedSequence("alice", SID, HASH, 4);
    await settle();

    expect(drains.filter((d) => d.reason === "witnessed_leaf_unresolved").length).toBe(1);
  });

  it("our OWN leaf echoed back fetches nothing", async () => {
    // The relay echoes our own submissions. Our content is already in our tree by construction, so
    // this must never look like something to go and collect.
    mgr!.markContentPresentForTest("alice", SID, "dd".repeat(32));
    mgr!.recordWitnessedSequence("alice", SID, "dd".repeat(32), 5);
    await settle();

    expect(drains).toEqual([]);
  });

  it("THE GRACE WINDOW: content arriving on the direct path cancels the fetch", async () => {
    /**
     * The case that keeps this off the hot path. On a healthy session the witness leaf and the
     * plaintext are separate deliveries milliseconds apart, so a fetch fired the instant a leaf
     * lands would mean a relay round trip for EVERY message in EVERY session — trading a 102-second
     * tail for a permanent load problem.
     *
     * A real grace window is used here rather than the zero used above, because the thing under test
     * IS the window.
     */
    mgr!.setLeafFetchGraceMsForTest(60);
    mgr!.recordWitnessedSequence("alice", SID, HASH, 7);

    // The direct path lands well inside the window, as it does on a healthy session.
    mgr!.markContentPresentForTest("alice", SID, HASH);
    await new Promise((r) => setTimeout(r, 120));

    expect(
      drains,
      "the bytes arrived on their own — asking the relay for them anyway is pure waste on the " +
      "overwhelmingly common path",
    ).toEqual([]);
  });

  /**
   * THE WIRING AT THE REAL RECEIPT SITE.
   *
   * Every case above marks content present through the test seam, so the production call — the one
   * in `ingestReceivedContent` that cancels a pending fetch when the bytes actually land — could be
   * deleted and all five would stay green. That is the failure this whole file is about: a signal
   * the code receives and does not act on.
   *
   * A source assertion because the behavioural path needs a two-node transport fixture to reach one
   * line, and because what is being pinned is "this call exists on that path", which is a property
   * of the source. Revert test (RUN): remove the call and this fails.
   */
  it("WIRING: content arriving on the real ingest path marks it resolved", async () => {
    const { readFileSync } = await import("node:fs");
    const code = readFileSync(join(import.meta.dirname, "..", "session-node-manager.ts"), "utf-8")
      .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    const a = code.indexOf("session.content.received");
    expect(a, "the receipt site moved — this test must follow it").toBeGreaterThan(-1);
    // Look back from the log line to the start of that block.
    const before = code.slice(Math.max(0, a - 1200), a);

    expect(
      before.includes("#markContentResolved("),
      "without this, content that arrives on the direct path never cancels its scheduled fetch — " +
      "so every healthy message costs a relay round trip two seconds later",
    ).toBe(true);
  });
});
