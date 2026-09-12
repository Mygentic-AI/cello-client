/**
 * DOD-M15-AWAYSCOPE-1 — the answering machine must not answer a conversation it is already in.
 *
 * ── THE DEFECT, MEASURED ─────────────────────────────────────────────────────────────────────────
 *
 * Session `e7dd3f43…`, 2026-09-11, two machines. An operator's Claude session ended; their agent
 * stayed online and unattended. The counterparty answered their question and signalled `[[OVER]]`.
 * The away responder then sent *"Agent is currently away… please close the session now"* INTO the
 * live session, and that greeting took a hash-chain leaf at 16:13:28.804 with `kind: "message"`.
 * The seal over that chain could not be certified — `merkle_root_mismatch` on both sides — and the
 * ack's content reached the counterparty 345ms after it had locked its own copy, where it was
 * quarantined outside the record permanently. Neither operator ever got a receipt.
 *
 * ── WHAT THIS FILE PINS ──────────────────────────────────────────────────────────────────────────
 *
 * The rule the eight design principles collapse into: **machine traffic must never take a chain
 * leaf.** A daemon's status announcement is not what the receipt attests.
 *
 * So: an inbound message on an EXISTING accepted session, arriving at an unattended agent, produces
 * NOTHING — no greeting, no one-shot rejection, no leaf, no transcript row, no seal. The tree size
 * after the inbound message is the tree size the inbound message alone produced.
 *
 * The answering machine for a NEW session REQUEST is untouched and is pinned here too, because the
 * whole risk of this change is deleting the wrong one of the two mechanisms. A caller who knocks on
 * an empty desk still gets the greeting, and that greeting still takes its leaf — it is the only
 * thing this side says and it belongs in the receipt, exactly like a voicemail outgoing message.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { TIER } from "../contacts-tier-migration.js";
import type { IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { AWAY_AUTO_REPLY_TEXTS } from "../away-detection.js";
import { makeSignedAssignmentFrame, registerFixtureSigner, fixtureIdentity } from "./helpers/signed-assignment.js";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
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

describe("DOD-M15-AWAYSCOPE-1: an unattended agent says nothing into a session it is already in", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-awayscope-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    registerFixtureSigner(hex, kp);
    return hex;
  }

  async function start(logger: Logger, node: CelloNode, signalingConnect?: () => Promise<ConnectResult>) {
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(node), signalingConnect,
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const TS = 1_700_000_000_000;

  async function assignmentFrame(initiatorPubkeyHex: string, counterpartyPubkeyHex: string): Promise<Record<string, unknown>> {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId: SID_BYTES,
      initiatorPubkey: Uint8Array.from(Buffer.from(initiatorPubkeyHex, "hex")),
      responderPubkey: Uint8Array.from(Buffer.from(counterpartyPubkeyHex, "hex")),
      initiatorSessionPeerId: "alice-session-peer-id",
      counterpartySessionPeerId: "bob-session-peer-id",
      sessionTimestamp: TS,
    });
    return frame;
  }

  /** An active session with an agreed content key — the state a live exchange is already in. */
  async function seedActiveSession(h: Awaited<ReturnType<typeof startDaemon>>, sid: string) {
    const snm = h.getSessionNodeManager();
    snm.setSessionGenesisForTest("alice", sid, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(sid, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    snm.addContact("alice", "bobpubkeyhex", undefined, null, TIER.KNOWN);
    return snm;
  }

  /**
   * ★★ DoD clause 1 — the assertion the live failure is measured against.
   *
   * The tree size is named, not compared to a recorded "before": the inbound message is leaf 0 and
   * NOTHING else may exist. A before/after delta of zero would also pass if the away reply had
   * replaced the inbound leaf rather than been added beside it.
   */
  it("★★ an inbound message on an existing session appends the INBOUND leaf and nothing else", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = await seedActiveSession(h, SID_HEX);

    const hi = new TextEncoder().encode("here is the answer you asked for [[OVER]]");
    await snm.ingestReceivedContent("alice", SID_HEX, hi, msgLeafHash(hi), "c1");
    await wait(80);

    expect(snm.getSessionTree("alice", SID_HEX).size(), "the inbound message alone").toBe(1);
    const { messages } = snm.readTranscript("alice", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent"), "the machine said nothing").toHaveLength(0);
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    expect(events.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeUndefined();
  });

  /**
   * ★★ The session must stay OPEN and sealable. The old path closed it: one-shot rejection, then a
   * seal the counterparty had already diverged from. Principles 4 and 6 — a session with nobody
   * live must not be terminal.
   */
  it("★★ a second and third message still produce nothing, and the session stays active", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = await seedActiveSession(h, SID_HEX);

    for (const [i, body] of ["first [[OVER]]", "second [[OVER]]", "third [[OVER]]"].entries()) {
      const bytes = new TextEncoder().encode(body);
      await snm.ingestReceivedContent("alice", SID_HEX, bytes, msgLeafHash(bytes), `c${i}`);
      await wait(60);
    }

    expect(snm.getSessionTree("alice", SID_HEX).size(), "three inbound leaves, no outbound").toBe(3);
    expect(snm.readTranscript("alice", SID_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(0);
    expect(events.filter((e) => e.event.startsWith("session.away.inbox.oneshot"))).toHaveLength(0);
    expect(snm.getSessionRecord("alice", SID_HEX)?.status, "still resumable when the operator returns").toBe("active");
  });

  /**
   * ★★ DoD clause 7 — the mutual-seal property, and it now holds BY CONSTRUCTION rather than by a
   * guard. Saying that plainly is the point of this comment, because the test below cannot tell the
   * difference and a reader would assume the guard is what passed it.
   *
   * Two away agents: the far side's away GREETING arrives here as an ordinary inbound message.
   * Before, `isOwnAwayAutoReply` recognised it and returned silently, so the one-shot did not fire
   * and no second ctrl leaf was minted. Now NOTHING answers ANY inbound message, so the greeting is
   * not a special case — it takes the same path as a person's sentence. The outcome clause 7 names
   * is unchanged and is asserted; the mechanism holding it is not the guard any more.
   *
   * ⚠️ TWO THINGS WERE LOST WITH THAT CALL SITE, both recorded rather than discovered later:
   *   - `session.away.mutual.skipped` can never fire again. Its `matched: "marker" | "legacy_exact"`
   *     field was added by DOD-M12B-AWAY-MARK-1 precisely so a peer prefixing EVERY message with
   *     the marker — a 15-character attack on the one-shot auto-close — became visible in the log.
   *     There is no one-shot left to attack, so the attack is gone with its signal; but the marker
   *     is also no longer counted anywhere, and that belongs on AWAY-MARK-1's line, not this one.
   *   - an un-upgraded peer's unmarked one-shot is no longer classified as machine traffic at all.
   *
   * This test therefore asserts the OUTCOME and makes no claim about which code held it.
   */
  it("★★ a far-side away greeting arriving as a message notarizes nothing", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = await seedActiveSession(h, SID_HEX);

    const theirGreeting = new TextEncoder().encode(AWAY_AUTO_REPLY_TEXTS.offerFor("bob"));
    await snm.ingestReceivedContent("alice", SID_HEX, theirGreeting, msgLeafHash(theirGreeting), "c1");
    await wait(80);

    expect(snm.getSessionTree("alice", SID_HEX).size()).toBe(1);
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    expect(events.find((e) => e.event === "session.away.inbox.oneshot.rejected")).toBeUndefined();
    expect(snm.getSessionRecord("alice", SID_HEX)?.status).toBe("active");
  });

  /**
   * ★★ THE OTHER HALF — the one this order must NOT break. A stranger knocking on an empty desk
   * still gets the greeting, and it still takes its leaf. Deleting the wrong mechanism is the whole
   * risk of this change, so the surviving one is asserted here beside the deleted one rather than
   * only in the file that always covered it.
   */
  it("★★ a NEW session request to an unattended agent still gets its greeting, and it still takes a leaf", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const caller = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", caller, undefined, null, TIER.KNOWN);

    injectRef.inject!(await assignmentFrame(caller, bobPubkey));
    await wait(5400); // AWAYSALT-1: a request-triggered ack waits out the salt agreement first

    const { messages } = snm.readTranscript("bob", SID_HEX);
    const sent = messages.filter((m) => m.direction === "sent");
    expect(sent, "the answering machine still picks up a call nobody answered").toHaveLength(1);
    expect(sent[0]!.text).toContain("bob is currently away");
    expect(snm.getSessionTree("bob", SID_HEX).size(), "and the greeting is in the receipt").toBe(1);
  });

  /**
   * ★ DoD clause 5 — `kind: "message"` does not exist. A type narrowing is the real enforcement
   * (a caller passing it no longer compiles), and this reads the shipped source so a future hand
   * cannot widen the parameter back without the suite saying so.
   *
   * The scan asserts the SIGNATURE it expects to find rather than only the absence of a token: a
   * regex that matches nothing reads exactly like a clean tree.
   */
  it("★ sendAwayResponse takes no `kind` — the request answerer is the only one left", async () => {
    const src = await readFile(join(import.meta.dirname, "..", "attendance-wiring.ts"), "utf8");
    const signature = src.split("\n").find((l) => l.includes("async function sendAwayResponse("));
    expect(signature, "the scan must actually find the function").toBeDefined();
    expect(signature!, "a `kind` parameter is what let the answering machine into a live session")
      .not.toContain("kind");
    expect(src).not.toContain(`kind === "message"`);
  });
});
