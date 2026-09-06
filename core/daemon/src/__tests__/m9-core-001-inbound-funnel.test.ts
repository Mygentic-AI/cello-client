/**
 * M9-CORE-001 — INV-5 inbound funnel, at the SessionNodeManager layer.
 *
 * INV-5 says EVERY producer of the agent-facing receive buffer passes the gateway screen — not
 * just direct libp2p delivery. There are three producers, all routed through
 * `ingestReceivedContent`:
 *   1. direct stream  (session-node-manager content handler → ingestReceivedContent)
 *   2. park-recovery  (daemon recover loop → ingestReceivedContent, the SAME method)
 *   3. held-then-released out-of-order content (#heldContent → #releaseHeld → buffer)
 *
 * These tests inject a controllable gateway double straight into the SessionNodeManager and drive
 * each producer, so a regression that moved the screen into ONLY the direct stream handler (the
 * recover path would then bypass it) or placed it AFTER the hold branch (released content would
 * bypass it) is caught — not left to a comment. The separate-PROCESS proof is m9-core-001-seam.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { SessionNodeManager, ABUSE_MAX_SESSION_RECEIVED_BYTES } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgents } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { SecurityGatewayClient, ScreenVerdict } from "@cello-protocol/gateway";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}
const enc = (s: string) => new TextEncoder().encode(s);
const hx = (h: Uint8Array) => Buffer.from(h).toString("hex");

/** A gateway double that counts screens and can be flipped to block, so tests can prove the
 *  screen ran (count) and that a block actually prevents delivery on each producer path. */
class CountingGateway implements SecurityGatewayClient {
  outbound = 0;
  inbound = 0;
  constructor(private mode: "allow" | "block" = "allow") {}
  async screenOutbound(content: Uint8Array): Promise<ScreenVerdict> {
    this.outbound++;
    return this.mode === "block" ? { disposition: "block", reason: "test_block" } : { disposition: "allow", content };
  }
  async screenInbound(content: Uint8Array): Promise<ScreenVerdict> {
    this.inbound++;
    return this.mode === "block" ? { disposition: "block", reason: "test_block" } : { disposition: "allow", content };
  }
}

/** Allows, but slowly — the delay holds the screen await open so two concurrent ingests of the
 *  same hash are both past the dedup check before either resumes (the B1 race window). */
class SlowAllowGateway implements SecurityGatewayClient {
  async screenOutbound(content: Uint8Array): Promise<ScreenVerdict> { return { disposition: "allow", content }; }
  async screenInbound(content: Uint8Array): Promise<ScreenVerdict> {
    await new Promise((r) => setTimeout(r, 30));
    return { disposition: "allow", content };
  }
}

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

const SID = "33".repeat(16);

describe("M9-CORE-001 INV-5: every inbound producer passes the gateway screen", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-m9funnel-"));
    managers.length = 0;
  });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* already down */ } }
    managers.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  async function setup(gw: SecurityGatewayClient): Promise<SessionNodeManager> {
    const dbPath = join(tempDir, `snm-${Math.random().toString(36).slice(2)}.db`);
    const mgr = new SessionNodeManager({ factory: new SharedFactory(new FakeNode() as unknown as CelloNode), logger: makeLogger(), dbPath, securityGateway: gw });
    managers.push(mgr);
    await mgr.initialize();
    // DOD-AGENT-ID-JOINKEY-1: ingestReceivedContent/createSessionNode resolve the NAME against a
    // real `agents` row — production always has one by the time a session exists.
    await seedAgents(mgr.getDb(), ["alice"]);
    // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
    // session it cannot anchor, and a fixture builds one below the paths that record it.
    mgr.setSessionAnchorForTest("alice", SID, "bobpubkey", "bobpubkey", 1_700_000_000_000);
    await mgr.createSessionNode(SID, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    return mgr;
  }

  it("recover/direct path: a blocking gateway blocks ingestReceivedContent — no buffer, no leaf", async () => {
    // The daemon recover loop calls ingestReceivedContent DIRECTLY (daemon.ts), exactly as this
    // test does. If the screen lived only in the libp2p stream handler, this call would bypass it
    // and the blocked content would still be buffered + leaf'd. It must not.
    const gw = new CountingGateway("block");
    const mgr = await setup(gw);
    const content = enc("recovered-from-park");
    const res = await mgr.ingestReceivedContent("alice", SID, content, msgLeafHash(content));
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("test_block");
    expect(gw.inbound).toBe(1); // the funnel screened it
    expect(mgr.takeReceivedContent("alice", SID)).toBeNull(); // never reached the agent buffer
    expect(mgr.getSessionTree("alice", SID).size()).toBe(0); // no leaf for blocked transient content
  });

  it("held path: a blocking gateway prevents the out-of-order HOLD — held content is screened before it is held", async () => {
    // Force a hold: canonical seq 2 with nextExpected 0. If the screen were placed AFTER the hold
    // branch, this content would be held then later released UNSCREENED. The block must stop it
    // before it is ever held.
    const gw = new CountingGateway("block");
    const mgr = await setup(gw);
    const c2 = enc("out-of-order-2");
    const h2 = msgLeafHash(c2);
    mgr.recordWitnessedSequence("alice", SID, hx(h2), 2);
    const res = await mgr.ingestReceivedContent("alice", SID, c2, h2);
    expect(res.ok).toBe(false);
    expect(gw.inbound).toBe(1);
    expect(mgr.getSessionTree("alice", SID).size()).toBe(0);
    expect(mgr.takeReceivedContent("alice", SID)).toBeNull();
  });

  it("release path: every delivered message is screened exactly once across hold + release", async () => {
    // Out-of-order arrival c2(held), c0, c1 → c1 fills the gap and RELEASES c2. All three reach
    // the agent. The screen count must be exactly 3 — not 2 (a released message skipping the
    // screen) and not 4 (a double screen). This proves released content was screened at ingest.
    const gw = new CountingGateway("allow");
    const mgr = await setup(gw);
    const c0 = enc("m0"), c1 = enc("m1"), c2 = enc("m2");
    const h0 = msgLeafHash(c0), h1 = msgLeafHash(c1), h2 = msgLeafHash(c2);
    mgr.recordWitnessedSequence("alice", SID, hx(h0), 0);
    mgr.recordWitnessedSequence("alice", SID, hx(h1), 1);
    mgr.recordWitnessedSequence("alice", SID, hx(h2), 2);

    await mgr.ingestReceivedContent("alice", SID, c2, h2); // held (seq 2 ahead of 0)
    await mgr.ingestReceivedContent("alice", SID, c0, h0); // appends leaf 0
    await mgr.ingestReceivedContent("alice", SID, c1, h1); // appends leaf 1, releases held c2 → leaf 2

    expect(mgr.getSessionTree("alice", SID).size()).toBe(3);
    expect(gw.inbound).toBe(3);
    const drained = [0, 1, 2].map(() => mgr.takeReceivedContent("alice", SID));
    expect(drained.map((d) => d && Buffer.from(d!.contentHex, "hex").toString())).toEqual(["m0", "m1", "m2"]);
  });

  it("B1: two concurrent ingests of the SAME content hash produce exactly ONE leaf (dedup survives the screen await)", async () => {
    // The screen is the only suspension point in ingestReceivedContent. Fire two ingests of the
    // same hash so BOTH pass the initial dedup check, then BOTH await the (slow) screen. On resume
    // the dedup re-check must let only one append — otherwise the direct-retry + park-recovery race
    // on reconnect would write two leaves for one hash (DOD-MSG-5 break → root divergence).
    const mgr = await setup(new SlowAllowGateway());
    const content = enc("dup-race");
    const hash = msgLeafHash(content);
    const [r1, r2] = await Promise.all([
      mgr.ingestReceivedContent("alice", SID, content, hash),
      mgr.ingestReceivedContent("alice", SID, content, hash),
    ]);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(mgr.getSessionTree("alice", SID).size()).toBe(1); // ONE leaf, not two
    const appended = [r1, r2].filter((r) => r.ok && r.appendedCount === 1).length;
    const deduped = [r1, r2].filter((r) => r.ok && r.appendedCount === 0).length;
    expect(appended).toBe(1);
    expect(deduped).toBe(1);
  });

  it("M8C-ABUSE-1 (cello-unit-reviewer HIGH fix, post-M9INT-1): two concurrent DIFFERENT-content ingests from a non-contact cannot jointly exceed the per-session size cap", async () => {
    // Same B1 race window (the screen await), different failure mode: the size cap's pre-await
    // check used totals that go stale across the suspension. Two concurrent ingests of DIFFERENT
    // content, each individually under the cap but summing over it, must not both be accepted —
    // exactly the drip-feed ABUSE-1 exists to stop, just via two racing arrivals instead of many
    // sequential ones.
    const mgr = await setup(new SlowAllowGateway());
    const half = new Uint8Array(Math.floor(ABUSE_MAX_SESSION_RECEIVED_BYTES / 2) + 1024); // > half each, < cap each
    const contentA = half;
    const contentB = new Uint8Array(half); // distinct Uint8Array instance, same size, different hash source
    contentB[0] = 0xff; // ensure a different content hash than contentA
    const hashA = msgLeafHash(contentA);
    const hashB = msgLeafHash(contentB);
    const [r1, r2] = await Promise.all([
      mgr.ingestReceivedContent("alice", SID, contentA, hashA),
      mgr.ingestReceivedContent("alice", SID, contentB, hashB),
    ]);
    const accepted = [r1, r2].filter((r) => r.ok).length;
    const rejected = [r1, r2].filter((r) => !r.ok && (r as { reason: string }).reason === "session_size_limit_exceeded").length;
    // Exactly one may win the race; the other must be rejected by the cap, not silently accepted too.
    expect(accepted).toBe(1);
    expect(rejected).toBe(1);
  });

  // ─── DOD-UNREAD-1 D4a (M8C-PHANTOM-SESSION-FIX-PLAN §4, producer-first) ─────────────────────
  // Never record content you cannot attribute. Pre-fix, ingest for a session with NO sessions row
  // wrote a received transcript row with senderPubkey="unknown" — an unattributable, unreadable,
  // permanently-unread artifact (the transcript has no counterparty column, so the attribution is
  // gone for good). After D3 this path is unreachable from the wire, which makes the guard a
  // fail-loud assertion exactly where one belongs.
  describe("DOD-UNREAD-1 D4a: ingest refuses content for a session with no sessions row", () => {
    interface LogEvent { level: string; event: string; context: Record<string, unknown> }
    function makeCapturingLogger(): { logger: Logger; events: LogEvent[] } {
      const events: LogEvent[] = [];
      const logger: Logger = {
        debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
        info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
        warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
        error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
      };
      return { logger, events };
    }

    async function setupCapturing(): Promise<{ mgr: SessionNodeManager; events: LogEvent[] }> {
      const { logger, events } = makeCapturingLogger();
      const dbPath = join(tempDir, `snm-orphan-${Math.random().toString(36).slice(2)}.db`);
      const mgr = new SessionNodeManager({ factory: new SharedFactory(new FakeNode() as unknown as CelloNode), logger, dbPath, securityGateway: new CountingGateway("allow") });
      managers.push(mgr);
      await mgr.initialize();
      // DOD-AGENT-ID-JOINKEY-1: "alice" must be a REAL agent — the AC under test is a MISSING
      // SESSION row, not a missing agent (a name that was never created is a different, unrelated
      // failure — agent_id_unresolved — and would not exercise session_orphaned at all).
      await seedAgents(mgr.getDb(), ["alice"]);
      return { mgr, events };
    }

    it("AC1-AC4: no sessions row → refused loudly; no DELIVERABLE row, no leaf, no buffer, no unread minted", async () => {
      const { mgr, events } = await setupCapturing();
      // Deliberately NO createSessionNode — the session does not exist for alice.
      const content = enc("reply into the void");
      const res = await mgr.ingestReceivedContent("alice", SID, content, msgLeafHash(content), "corr-orphan");

      // AC1: refused, with a distinct reason.
      expect(res.ok).toBe(false);
      expect((res as { reason: string }).reason).toBe("session_orphaned");
      // AC2/SI: loud, at warn, with the spec'd fields — distinguishable from a dropped frame.
      const orphaned = events.find((e) => e.event === "session.content.orphaned");
      expect(orphaned).toBeDefined();
      expect(orphaned!.level).toBe("warn");
      expect(orphaned!.context["agentName"]).toBe("alice");
      expect(orphaned!.context["sessionId"]).toBe(SID);
      expect(orphaned!.context["correlationId"]).toBe("corr-orphan");
      /**
       * ─── AC3, RESTATED BY DOD-M15-REFUSEDEVIDENCE-1 ───────────────────────────────────────────
       *
       * This used to read "nothing was recorded anywhere", asserting an EMPTY transcript. That was
       * the right way to state D4a's invariant while a refused message was thrown away, and it is
       * now the wrong way: the message IS retained, flagged `quarantined`, because a probe at a
       * session this daemon has never heard of is exactly the thing an operator would want to show
       * someone and had no way to.
       *
       * **The invariant itself is unchanged and is asserted more sharply below.** D4a's harm was
       * never "a row exists" — it was a row that LOOKS DELIVERABLE: unattributable forever, counted
       * unread by `getUnreadSummary`, unreadable by `cello_receive`. A quarantined row causes none
       * of those, and each is checked here rather than inferred from an empty table.
       */
      const rows = mgr.readTranscript("alice", SID).messages;
      expect(rows, "the refused message is KEPT — one row, not none").toHaveLength(1);
      expect(rows[0]!.direction, "and it is flagged, which is what keeps it out of every delivery path").toBe("quarantined");
      expect(rows[0]!.text, "the transcript read is redacted; the payload never travels on it").not.toContain("reply into the void");
      // The three D4a harms, each asserted directly.
      expect(mgr.findNextReceivedAfter("alice", SID, -1), "cello_receive's reader never sees it").toBeNull();
      expect(mgr.getSessionTree("alice", SID).size()).toBe(0);
      expect(mgr.takeReceivedContent("alice", SID)).toBeNull();
      // THE INVARIANT: no unread is minted for a session cello_receive cannot read.
      expect(mgr.getUnreadSummary("alice")).toHaveLength(0);
      // AC4: "unknown" was never papered in.
      expect(events.find((e) => e.event === "session.content.sender_unresolved")).toBeUndefined();
    });

    it("regression: with a sessions row, ingest still delivers and attributes the sender from the record", async () => {
      const { mgr } = await setupCapturing();
      // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
      // session it cannot anchor, and a fixture builds one below the paths that record it.
      mgr.setSessionAnchorForTest("alice", SID, "bobpubkey", "bobpubkey", 1_700_000_000_000);
      await mgr.createSessionNode(SID, "alice", "bobpubkey", "bob-peer-id", "corr-2");
      const content = enc("attributed message");
      const res = await mgr.ingestReceivedContent("alice", SID, content, msgLeafHash(content), "corr-2");
      expect(res.ok).toBe(true);
      const entry = mgr.takeReceivedContent("alice", SID);
      expect(entry).not.toBeNull();
      expect(entry!.senderPubkey).toBe("bobpubkey"); // from the session record, never "unknown"
      expect(mgr.readTranscript("alice", SID).messages).toHaveLength(1);
    });

    // D4 review F1: #insertSessionRow swallows a DB write failure (logs + returns false) and both
    // creators ignored the boolean — a session node could go fully live with NO sessions row.
    // Post-D4a a rowless session refuses every ingest (session_orphaned) while looking healthy to
    // both operators. The failure must happen ONCE, at creation, not per-message forever.
    it("F1: a session whose row write fails is refused at creation (session_persist_failed), not left live-but-orphaned", async () => {
      const { mgr } = await setupCapturing();
      mgr.getDb().exec("DROP TABLE sessions"); // force the row write to fail
      const res = // The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
 // session it cannot anchor, and a fixture builds one below the paths that record it.
 mgr.setSessionAnchorForTest("alice", SID, "bobpubkey", "bobpubkey", 1_700_000_000_000);
 await mgr.createSessionNode(SID, "alice", "bobpubkey", "bob-peer-id", "corr-f1");
      expect(res.ok).toBe(false);
      expect((res as { reason: string }).reason).toBe("session_persist_failed");
      // No live node remains — a rowless session is a dead session by definition after D4a.
      expect(mgr.getSessionNodePeerId("alice", SID)).toBeNull();
    });
  });

  /**
   * DOD-DOC-SCREEN-CLASSIFY-1 — a DOCUMENT frame skips the gateway content screen; everything else
   * still takes it. Both directions asserted, because each failure mode is silent: skip a message
   * and it bypasses screening it needs; screen a document frame and a blocking gateway holds
   * document traffic whose real screen (the gate + screenText) is in-process and cannot be down.
   */
  it("document frame: skips the gateway screen and still routes to the document layer", async () => {
    const gw = new CountingGateway("block"); // blocking — would refuse if consulted
    const mgr = await setup(gw);
    let routed = 0;
    mgr.setOnDocumentFrame(
      () => { routed++; return { consumed: true, kind: "reconcile", ok: true }; },
      () => true, // classify: document
    );
    const frame = enc("stand-in-document-frame-bytes");
    // The ingest cross-check is over the CONTENT, not the leaf kind — the kind is decided further
    // down, by the router. Same hash a message would carry.
    const res = await mgr.ingestReceivedContent("alice", SID, frame, msgLeafHash(frame));
    expect(res.ok).toBe(true);
    expect(gw.inbound).toBe(0); // the gateway was never consulted
    expect(routed).toBe(1); // the document layer got the frame
    expect(mgr.getSessionTree("alice", SID).size()).toBe(1); // the doc leaf was still taken
    expect(mgr.takeReceivedContent("alice", SID)).toBeNull(); // never conversation content
  });

  it("message: still takes the full gateway screen when the classifier says not-a-document", async () => {
    const gw = new CountingGateway("block");
    const mgr = await setup(gw);
    mgr.setOnDocumentFrame(
      () => ({ consumed: false }),
      () => false, // classify: not a document
    );
    const content = enc("ordinary message");
    const res = await mgr.ingestReceivedContent("alice", SID, content, msgLeafHash(content));
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("test_block");
    expect(gw.inbound).toBe(1);
  });

  it("no classifier injected: every frame takes the screen — the pre-document behaviour", async () => {
    const gw = new CountingGateway("allow");
    const mgr = await setup(gw);
    const content = enc("any bytes at all");
    await mgr.ingestReceivedContent("alice", SID, content, msgLeafHash(content));
    expect(gw.inbound).toBe(1);
  });
});
