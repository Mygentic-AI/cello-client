/**
 * CELLO-M8C-AWAY-1 — away response: an unattended Primary auto-answers inbound session REQUESTS
 *
 * ⚠️ CLAUSES A2, A4 AND A5 ARE GONE, DELETED BY DOD-M15-AWAYSCOPE-1, and that is not a coverage
 * loss — it is the behaviour they described being removed. They said an inbound MESSAGE on an
 * ALREADY-ACCEPTED session got its own auto-ack, coalesced on a repeat and re-armed after a
 * re-attend. Sending that ack is what cost session `e7dd3f43…` its receipt on both machines: the
 * greeting took a hash-chain leaf in a live conversation and no seal over that chain could be
 * certified. The replacement behaviour — an unattended agent says NOTHING into a session it is
 * already in — is asserted in `dod-m15-awayscope-1.test.ts`, which also re-pins the half kept here.
 *
 * What this file still covers:
 * - A1: a NEW inbound session request while unattended gets an auto-ack appended to the transcript;
 *   queued via the existing inboundSessionQueues mechanism regardless.
 * - A3: while ATTENDED (a connection has claimed the agent via cello_use_agent), no away response
 *   fires — the agent answers for itself.
 * - The greeting's leaf-commitment decision on a durably-queued vs. a lost send (M12-P13).
 * - Deviation (journaled, D14-pattern): opaque privacy mode (silence, indistinguishable from
 *   unreachable) is PARKED on M9-CFG-001 — this unit ships only the DoD's own mandated
 *   transparent default, which is a real, correct, non-fake behavior on its own.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { TIER } from "../contacts-tier-migration.js";
import type { SecurityGatewayClient, ScreenContext, ScreenVerdict } from "@cello-protocol/gateway";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { markAsAutoReply } from "../away-detection.js";
// ONE definition of the go-nowhere node. It was inline here; DOD-M15-SEALPRECOND-1 needed the same
// one for a two-daemon test and moved it to a helper rather than writing a second.
import { FakeNode } from "./helpers/fake-relay-server.js";
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

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/** Injectable signaling stub — the directory's push channel (mirrors seam-2-inbound-session.test.ts). */
function makeInjectableSignaling(
  injectRef: { inject?: (frame: unknown) => void },
): () => Promise<ConnectResult> {
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


describe("M8C-AWAY-1: away response", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-away-"));
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
    // 038-KEYBIND: a REAL agent, so the assignment fixture can sign a key binding as it.
    registerFixtureSigner(hex, kp);
    return hex;
  }

  async function start(logger: Logger, node: CelloNode, signalingConnect?: () => Promise<ConnectResult>, securityGateway?: SecurityGatewayClient): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(node), signalingConnect,
      ...(securityGateway ? { securityGateway } : {}),
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

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const TS = 1_700_000_000_000;

  /**
   * DOD-M15-RESPONDER-VERIFY-1: the responder now VERIFIES inbound assignments, so this fixture
   * injects a genuinely signed one instead of a frame with no directory signature at all. Nothing
   * about away mode is under test in the signature — it is only what gets the frame past the door
   * the production path now makes every assignment pass through.
   */
  async function assignmentFrame(initiatorPubkeyHex: string, counterpartyPubkeyHex: string, sessionId: Uint8Array = SID_BYTES): Promise<Record<string, unknown>> {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId,
      initiatorPubkey: Uint8Array.from(Buffer.from(initiatorPubkeyHex, "hex")),
      responderPubkey: Uint8Array.from(Buffer.from(counterpartyPubkeyHex, "hex")),
      initiatorSessionPeerId: "alice-session-peer-id",
      // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
      counterpartySessionPeerId: "bob-session-peer-id",
      sessionTimestamp: TS,
    });
    return frame;
  }

  it("M12-P16: an agent taken OFFLINE refuses the inbound assignment and sends no away reply", async () => {
    // The half the first version of this fix missed, and the one the counterparty actually saw:
    // measured live 2026-08-05, an agent confirmed offline accepted a message, appended a leaf and
    // REPLIED. Tearing down existing sessions was not enough — nothing on the inbound path consulted
    // agent state at all, and `acceptInboundAssignment` called `ensureStandingReceiverForAgent`,
    // whose first line re-added the want-flag the offline handler had just cleared. The receiver came
    // back from the dead and the away reply fired.
    //
    // Driven through the REAL assignment path (the same injected signaling frame A1 uses), because
    // the observable that matters is the counterparty getting no answer.
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    h.getSessionNodeManager().addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);

    // Press the switch.
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_set_agent_offline", { name: "bob" });

    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(200);

    expect(
      events.find((e) => e.event === "session.away.response.sent"),
      "an offline agent must not answer a stranger",
    ).toBeUndefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
    const refused = events.find((e) => e.event === "session.inbound.refused");
    expect(refused?.context.reason).toBe("agent_offline");
  });

  it("A1: an inbound session request while UNATTENDED gets an auto-ack in the transcript", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    // M8C-CONTACT-1: pre-register as known so this test stays focused on AWAY-1's own template
    // logic — the unknown-sender ("Dispatched.") branch is covered by m8c-contact-1.test.ts.
    h.getSessionNodeManager().addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);
    // 007-CRYPTO: an away auto-reply is a live send, and a live send needs an agreed key. The
    // key map is keyed by (agent, session) and does not need the session to exist yet, so this
    // pre-registers what a completed exchange would leave. Without it the reply parks — correct
    // behaviour, but this fixture has no relay for it to park to, so nothing is recorded.
    h.getSessionNodeManager().setSessionContentKeyForTest("bob", SID_HEX, new Uint8Array(32).fill(0x7e));
    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey)); // bob never attended — no client connected yet
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    /**
     * DOD-M15-AWAYSCOPE-1: `kind` is a CONSTANT in the code now, and this is the only assertion on
     * its value. It is read off the event rather than filtered inside the `find` predicate so a
     * wrong value says "expected 'message' to be 'request'" instead of "expected undefined to be
     * defined" — the tell of the live failure was `kind: "message"` on a daemon log line, and an
     * operator re-diagnosing greps for exactly that string.
     */
    const sentEvent = events.find((e) => e.event === "session.away.response.sent");
    expect(sentEvent, "the greeting must actually be sent, or everything below is vacuous").toBeDefined();
    expect(sentEvent!.context.kind).toBe("request");
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(1);
    expect(messages[0].direction).toBe("sent");
    // DOD-AWAY-WRAP-1 AC1: request away greeting names the agent and gives leave-a-message
    // instructions. Reviewer F1 (DOD-WRAP-SUBSTRING-1): the greeting instructs `signal: wrap`
    // (the send parameter that APPENDS the token) — never the literal token, which a caller
    // could paste mid-body where the end-anchored detector correctly ignores it.
    expect(messages[0].text).toContain("bob is currently away");
    expect(messages[0].text).toContain("signal: wrap");
    expect(messages[0].text).not.toContain("[[WRAP]]");
  });

  /**
   * A4, RE-POINTED — review finding. The old version of this drove TWO inbound MESSAGES on two
   * sessions, and it was deleted with the message trigger. Its SUBJECT is still live: the dedup key
   * is `agent:session:request`, and dropping the session id from it is a one-token change.
   *
   * What that costs, and why a deleted test here is worse than it looks: two people knock on the
   * same away agent, the first gets the greeting, and the SECOND is met with silence — no greeting,
   * no explanation, nothing in their transcript — because the first caller consumed the agent's one
   * dedup slot. Nothing else in the suite uses two sessions on one agent, so that narrowing would
   * ship with everything green.
   */
  it("A4 (per-session isolation): two callers knocking on the SAME away agent each get their own greeting", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");

    const caller = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", caller, undefined, null, TIER.KNOWN);

    const SID_2_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 101));
    const SID_2_HEX = Buffer.from(SID_2_BYTES).toString("hex");
    snm.setSessionContentKeyForTest("bob", SID_HEX, new Uint8Array(32).fill(0x7e));
    snm.setSessionContentKeyForTest("bob", SID_2_HEX, new Uint8Array(32).fill(0x7e));

    injectRef.inject!(await assignmentFrame(caller, bobPubkey));
    injectRef.inject!(await assignmentFrame(caller, bobPubkey, SID_2_BYTES));
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    // BOTH sessions, named — a count of two would also pass if one session were greeted twice.
    const greeted = events
      .filter((e) => e.event === "session.away.response.sent")
      .map((e) => e.context.sessionId)
      .sort();
    expect(greeted, "each caller is answered on their own session").toEqual([SID_HEX, SID_2_HEX].sort());
    expect(snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(1);
    expect(snm.readTranscript("bob", SID_2_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(1);
  }, 15_000);

  // A gateway whose OUTBOUND verdict is configurable per test (inbound always allows).
  class StubGateway implements SecurityGatewayClient {
    constructor(private readonly outbound: (c: Uint8Array) => ScreenVerdict) {}
    async screenInbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> { return { disposition: "allow", content }; }
    async screenOutbound(content: Uint8Array, _ctx: ScreenContext): Promise<ScreenVerdict> { return this.outbound(content); }
  }

  it("DOD-AWAY-TIER-1 T1: an unattended away response USES the resolution — a per-contact away text is what's sent + contact.away.resolved fires", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);
    snm.setContactAwayMessage("bob", initiatorPubkey, "Hey - reach me on Signal");

    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey)); // unattended
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    // The RESOLVED custom text is what landed in the transcript — not the system default (bypass:
    // reverting the caller to the constant would send "session request has been received…" here).
    // DOD-M12B-AWAY-MARK-1: a CONFIGURED away message is marked too, and this is the test that
    // proves it — an operator's own wording was previously indistinguishable from a person by
    // construction, because the detector could only match this daemon's default strings. Asserted
    // through markAsAutoReply rather than a pasted literal so the resolved text stays exact.
    const { messages } = snm.readTranscript("bob", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")[0]?.text).toBe(markAsAutoReply("Hey - reach me on Signal"));
    // Observability AC: contact.away.resolved fired with the matched level.
    expect(events.find((e) => e.event === "contact.away.resolved" && e.context.level === "contact")).toBeDefined();
  });

  it("DOD-AWAY-TIER-1 T2 (SI): a BLOCK verdict on the away text means nothing is sent", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const gateway = new StubGateway(() => ({ disposition: "block", reason: "away_pii" }));
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef), gateway);
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);

    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    expect(events.find((e) => e.event === "session.away.response.screened_out" && e.context.disposition === "block")).toBeDefined();
    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    expect(snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(0);
  });

  it("DOD-AWAY-TIER-1 T2 (SI): a REDACT verdict sends the ALTERED bytes, never the pre-redaction draft", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const redacted = new TextEncoder().encode("[redacted away]");
    const gateway = new StubGateway(() => ({ disposition: "redact", content: redacted }));
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef), gateway);
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", initiatorPubkey, undefined, null, TIER.KNOWN);
    snm.setContactAwayMessage("bob", initiatorPubkey, "my home address is 123 Main St"); // would-be leak

    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    const sent = snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")[0];
    // The ALTERED bytes — the draft never went on the wire. DOD-M12B-AWAY-MARK-1 moved the
    // auto-reply marking to AFTER screening, so the sent text is the redactor's output with the
    // marker in front of it. Both facts are asserted, because the ordering matters in both
    // directions: marking BEFORE screening let a redact verdict silently strip the marker (an away
    // reply back on the wire indistinguishable from a person), and dropping the redaction here
    // would put the pre-redaction draft on the wire, which is what this test was written for.
    expect(sent?.text).toBe(markAsAutoReply("[redacted away]"));
    expect(sent?.text).toContain("[redacted away]");
    expect(sent?.text).not.toContain("Hey - reach me on Signal");
  });

  it("A3: an inbound session request while ATTENDED gets NO auto-ack", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    await connectAs("bob"); // bob is now ATTENDED

    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(150);

    expect(events.find((e) => e.event === "session.away.response.sent")).toBeUndefined();
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(0);
  });

  /**
   * DOD-AWAY-WRAP-1 AC3: combined transcript shape — greeting at seq 0 (sent), message at seq 1
   * (received), NOTHING ELSE. The shape is what a leave-a-message visit is supposed to look like in
   * the sealed receipt, and a spurious seq 2 is what broke the seal.
   *
   * ⚠️ THE REASON THERE IS NO SEQ 2 CHANGED, and the assertion is stronger for it. It used to be
   * the [[WRAP]] skip: a closing message was the one kind the away responder declined to answer.
   * After DOD-M15-AWAYSCOPE-1 there is nothing to decline — no message on an accepted session gets
   * a reply, [[WRAP]] or not. So this now pins the general rule rather than one exemption from it.
   */
  it("DOD-AWAY-WRAP-1 AC3: sealed transcript shape — exactly greeting(sent) + caller's message(received), nothing else", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const caller = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", caller, undefined, null, TIER.KNOWN);

    // Step 1: inbound session request → daemon sends away greeting (seq 0, sent).
    injectRef.inject!(await assignmentFrame(caller, bobPubkey));
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    // Step 2: the caller leaves its message. The daemon answers nothing into the accepted session.
    const wrapContent = new TextEncoder().encode("leaving my message [[WRAP]]");
    await snm.ingestReceivedContent("bob", SID_HEX, wrapContent, msgLeafHash(wrapContent), "wrap-corr");
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    const { messages } = snm.readTranscript("bob", SID_HEX);
    expect(messages).toHaveLength(2);
    expect(messages[0].direction).toBe("sent");      // seq 0: away greeting
    expect(messages[0].text).toContain("currently away");
    expect(messages[1].direction).toBe("received");  // seq 1: the caller's message
    expect(messages[1].text).toContain("[[WRAP]]");
    // No seq 2: the answering machine does not talk into a session it has already answered.
    expect(snm.getSessionTree("bob", SID_HEX).size(), "the receipt covers one greeting and one message").toBe(2);
  });

  // DOD-AWAY-WRAP-1 AC1: the request-kind greeting names the agent and gives leave-a-message instructions.
  it("DOD-AWAY-WRAP-1 AC1: request-kind away greeting names the agent and instructs to use [[WRAP]]", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    const caller = fixtureIdentity().pubkeyHex;
    h.getSessionNodeManager().addContact("bob", caller, undefined, null, TIER.KNOWN);

    injectRef.inject!(await assignmentFrame(caller, bobPubkey));
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first

    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    const sent = messages.filter((m) => m.direction === "sent")[0];
    expect(sent).toBeDefined();
    expect(sent!.text).toContain("bob is currently away");
    expect(sent!.text).toContain("signal: wrap"); // Reviewer F1: instruct the param, not the literal token
    expect(sent!.text).toContain("Leave a message");
  });

  /**
   * M12-P13 — found live 2026-08-05 on the EC2 receiver (M12 Entry 89):
   *   session.relay.leaf.delivered  sequenceNumber=1
   *   session.away.response.failed  reason=session_stream_unavailable
   * and then nothing, forever. The away reply owns the sequence the relay already witnessed for it;
   * when its send failed the leaf was never appended, so this side's tree stayed at size 0 while the
   * counterparty's content arrived claiming canonicalSeq 1. `nextExpected` IS the tree size, so every
   * later message was held behind a gap that nothing could ever fill.
   *
   * ⚠️ BOTH OF THESE WERE MEASURED ON THE MESSAGE PATH AND ARE NOW DRIVEN BY A SESSION REQUEST.
   * DOD-M15-AWAYSCOPE-1 deleted the message trigger, so the request greeting is the only away reply
   * left — and the durable/lost decision it makes is the same code, reached the only way it can
   * still be reached. Driving them through a stale trigger would have deleted the coverage instead
   * of moving it.
   *
   * `sendContent` is stubbed rather than driven through a real relay: this pins the AWAY path's own
   * decision, and that the `durable` flag it keys on is truthfully produced is pinned separately,
   * against the real queue, in m8c-leavemsg-1.test.ts.
   */
  async function awayGreetingWithSendResult(durable: boolean) {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    const snm = h.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const caller = fixtureIdentity().pubkeyHex;
    snm.addContact("bob", caller, undefined, null, TIER.KNOWN);

    snm.sendContent = async () => ({
      ok: false as const, reason: "session_stream_unavailable", error: "connection_lost", durable,
    });

    injectRef.inject!(await assignmentFrame(caller, bobPubkey));
    await wait(5400); // AWAYSALT-1: a request-triggered ack may wait out the salt agreement first
    return { snm, events };
  }

  it("M12-P13: an away greeting whose send is DURABLY QUEUED still commits its leaf — otherwise the caller stalls at its own sequence forever", async () => {
    const { snm, events } = await awayGreetingWithSendResult(true);

    // The greeting owns the sequence the relay witnessed for it whether or not its send landed.
    expect(snm.getSessionTree("bob", SID_HEX).size(), "the greeting's witnessed sequence must exist locally").toBe(1);
    expect(snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(1);
    // Deferred is not failed, and it must be visible as its own event — a queued reply that reads
    // as `failed` sends the next investigation looking for a message that is not actually lost.
    expect(events.find((e) => e.event === "session.away.response.deferred")).toBeDefined();
  }, 15_000);

  it("M12-P13: a LOST away greeting appends nothing and says so at ERROR — silence is what made this cost two sessions", async () => {
    // The mirror of the durable case. A leaf here would commit a sequence the counterparty will
    // never receive content for, which is a permanent root mismatch — the sessions become
    // unsealable and the only exit is a force-abandon with no notarized receipt.
    const { snm, events } = await awayGreetingWithSendResult(false);

    expect(snm.getSessionTree("bob", SID_HEX).size(), "no leaf for content that is gone").toBe(0);
    expect(snm.readTranscript("bob", SID_HEX).messages.filter((m) => m.direction === "sent")).toHaveLength(0);
    const failed = events.find((e) => e.event === "session.away.response.failed");
    expect(failed).toBeDefined();
    expect(failed!.level, "a lost message is an error, not a warning").toBe("error");
    expect(String(failed!.context.impact)).toContain("lost");
  }, 15_000);

  // ─── M12-P18: a refused session tells a TRUSTED sender why, and stays silent to a stranger ─────
  async function driveOverCapRefusal(tier: number, preseed: number) {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start(logger, new FakeNode(), makeInjectableSignaling(injectRef));
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");
    const snm = h.getSessionNodeManager();
    const initiatorPubkey = fixtureIdentity().pubkeyHex;
    // A KNOWN contact is told; a stranger (no contact row → UNKNOWN) is not.
    if (tier >= TIER.KNOWN) snm.addContact("bob", initiatorPubkey, undefined, null, tier);
    // Pre-seed the sender to their cap so the NEXT assignment is refused for over-cap, not blocked.
    const db = snm.getDb()!;
    const bobId = snm.resolveAgentId("bob");
    const now = Date.now();
    for (let i = 0; i < preseed; i++) {
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', ?, ?, 1, NULL)`,
      ).run(("f" + i.toString(16)).padStart(32, "0"), bobId, initiatorPubkey, now, now);
    }
    injectRef.inject!(await assignmentFrame(initiatorPubkey, bobPubkey));
    await wait(150);
    return events;
  }

  it("M12-P18: a KNOWN sender over the cap is NOTIFIED — its own state, no oracle risk", async () => {
    // KNOWN cap is 5; five pre-seeded sessions puts the sixth over.
    const events = await driveOverCapRefusal(TIER.KNOWN, 5);
    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    const notified = events.find((e) => e.event === "session.inbound.refusal.notified");
    expect(notified, "a trusted sender is told why").toBeDefined();
    expect(notified!.context.reason).toBe("abuse_bound_sessions_per_sender");
  });

  it("M12-P18: an UNKNOWN sender over the cap is SILENT — no block/throttle oracle", async () => {
    // UNKNOWN cap is 3; three pre-seeded puts the fourth over, and no contact row keeps it UNKNOWN.
    const events = await driveOverCapRefusal(TIER.UNKNOWN, 3);
    expect(events.find((e) => e.event === "session.inbound.accept.failed" && e.context.reason === "abuse_bound_sessions_per_sender")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.refusal.notified"), "a stranger is NEVER told").toBeUndefined();
    expect(events.find((e) => e.event === "session.inbound.refusal.silent")).toBeDefined();
  });
});
