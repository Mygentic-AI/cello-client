/**
 * M16 027-JOINSEQ — a sent join frame takes its place in the sender's own record.
 *
 * Every daemon path that sends session content commits its own leaf afterwards with `placeOwnLeaf`.
 * The channel join-frame sender did not: it discarded the send result, so after a daemon sent a
 * join request/acceptance/refusal/re-key its own tree never gained the leaf the relay had already
 * witnessed. `nextExpected` stayed one short and every later message — in both directions — was held
 * behind the gap forever. On the live test this deadlocked the admin's working conversation the
 * moment the admin approved a member.
 *
 * These tests drive the extracted sender (`createChannelFrameSender`) over the REAL
 * `SessionNodeManager`, tree and transcript from `startTwoConnectionFixture`. The ONLY stub is
 * `sendContent` — the network hand-off — replaced per case. `contentHashForSession` and
 * `placeOwnLeaf` are the fixture's real ones.
 *
 * Revert test: remove the `placeOwnLeaf` call → 1, 2, 4 red; remove the throw → 3 red; remove the
 * Part C condition → 2 red on the transcript assertion.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, msgLeafHash, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { receivedRows } from "./helpers/received-rows.js";
import { encodeChannelJoinRefused } from "@cello-protocol/protocol-types";
import { createChannelFrameSender, type ChannelFrameSendDeps } from "../channel-frame-send.js";
import type { Logger } from "../types.js";

const SID = "8a".repeat(32);
const AGENT = "alice";
const hx = (b: Uint8Array) => Buffer.from(b).toString("hex");

type SendResult = Awaited<ReturnType<ChannelFrameSendDeps["sessions"]["sendContent"]>>;

interface CapturedEvent { level: string; event: string; ctx: Record<string, unknown>; }

function makeLogger(): { events: CapturedEvent[]; logger: Logger } {
  const events: CapturedEvent[] = [];
  const logger: Logger = {
    debug: (event, ctx) => events.push({ level: "debug", event, ctx: ctx ?? {} }),
    info: (event, ctx) => events.push({ level: "info", event, ctx: ctx ?? {} }),
    warn: (event, ctx) => events.push({ level: "warn", event, ctx: ctx ?? {} }),
    error: (event, ctx) => events.push({ level: "error", event, ctx: ctx ?? {} }),
  };
  return { events, logger };
}

/** The sender wired over the fixture's real snm, with `sendContent` stubbed for the case. */
function makeSender(fx: TwoConnectionFixture, sendResult: SendResult): {
  send: (agentName: string, sessionId: string, content: Uint8Array) => Promise<void>;
  events: CapturedEvent[];
} {
  const { snm } = fx;
  const { events, logger } = makeLogger();
  const sessions: ChannelFrameSendDeps["sessions"] = {
    contentHashForSession: snm.contentHashForSession.bind(snm),
    sendContent: async () => sendResult,
    placeOwnLeaf: snm.placeOwnLeaf.bind(snm),
  };
  return { send: createChannelFrameSender({ sessions, logger }), events };
}

const REFUSED = () =>
  encodeChannelJoinRefused({ channel_pubkey: new Uint8Array(32).fill(7), reason: "channel_is_public" });

function transcriptRows(fx: TwoConnectionFixture): Array<{ sequence: number; direction: string }> {
  return fx.snm.getDb()
    .prepare("SELECT sequence, direction FROM transcript WHERE session_id = ? ORDER BY sequence ASC")
    .all(SID) as Array<{ sequence: number; direction: string }>;
}

describe("DOD-M16-JOIN-1: a sent join frame takes its place in the sender's own record", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("the live deadlock: after our join frame at 0, their message at 1 is delivered, not held", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-027a-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    // Our join frame goes out and the relay assigns it position 0 — no gap, so it commits at once.
    const { send } = makeSender(fx, { ok: true, delivered: true, sequenceNumber: 0, authorship: undefined });
    await send(AGENT, SID, REFUSED());

    // Their message at 1 arrives next. It must slot in at 1 behind our committed leaf 0 — not stall.
    const theirs = new TextEncoder().encode("theirs at 1");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs)), 1);
    await snm.ingestReceivedContent(AGENT, SID, theirs, msgLeafHash(theirs), "corr");

    // Red today: the frame placed nothing, so the gap at 0 held their message and the tree is 0.
    expect(snm.getSessionTree(AGENT, SID).size(), "our frame at 0, then their message at 1").toBe(2);
    expect(receivedRows(snm, AGENT, SID).map((r) => r.text)).toEqual(["theirs at 1"]);
    // The join frame is NOT something a person said — no transcript row for it, only their message.
    expect(transcriptRows(fx)).toEqual([{ sequence: 1, direction: "received" }]);
  }, 60_000);

  it("a join frame sent into a gap is held, then released with no transcript row", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-027b-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    // Their message at 1 arrives first, so this tree has a gap at 0 and stays empty.
    const theirs1 = new TextEncoder().encode("theirs at 1");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs1)), 1);
    await snm.ingestReceivedContent(AGENT, SID, theirs1, msgLeafHash(theirs1), "corr");

    // We send our frame; the relay assigns position 2. Ahead of the tail, so it is HELD.
    const frame = REFUSED();
    const frameHashHex = hx((await snm.contentHashForSession(AGENT, SID, frame)).hash);
    const { send } = makeSender(fx, { ok: true, delivered: true, sequenceNumber: 2, authorship: undefined });
    await send(AGENT, SID, frame);
    expect(snm.getSessionTree(AGENT, SID).size(), "held behind the open gap at 0").toBe(0);

    // Their message at 0 fills the gap. Everything drains: their 1, then our frame at 2.
    const theirs0 = new TextEncoder().encode("theirs at 0");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs0)), 0);
    await snm.ingestReceivedContent(AGENT, SID, theirs0, msgLeafHash(theirs0), "corr");

    expect(snm.getSessionTree(AGENT, SID).size()).toBe(3);
    expect(snm.getSessionTree(AGENT, SID).leaves()[2]!.hashHex, "leaf 2 is our join frame").toBe(frameHashHex);
    // A released join frame gets a leaf and NO transcript row — only their two messages are rows.
    expect(transcriptRows(fx)).toEqual([
      { sequence: 0, direction: "received" },
      { sequence: 1, direction: "received" },
    ]);
  }, 60_000);

  it("a lost send throws and logs, committing nothing", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-027c-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    const { send, events } = makeSender(fx, { ok: false, durable: false, reason: "no_route", error: "no_route" });
    await expect(send(AGENT, SID, REFUSED())).rejects.toThrow(/^channel_frame_send_failed: no_route/);
    expect(events.some((e) => e.event === "channel.frame.send.failed" && e.level === "error")).toBe(true);
    expect(snm.getSessionTree(AGENT, SID).size(), "a lost send commits no leaf").toBe(0);
  }, 60_000);

  it("a durably queued send still takes its position", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-027d-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    const { send } = makeSender(fx, { ok: false, durable: true, reason: "queued", error: "queued", sequenceNumber: 0 });
    await expect(send(AGENT, SID, REFUSED())).resolves.toBeUndefined();
    expect(snm.getSessionTree(AGENT, SID).size(), "a durable queue still owns its relay position").toBe(1);
  }, 60_000);
});
