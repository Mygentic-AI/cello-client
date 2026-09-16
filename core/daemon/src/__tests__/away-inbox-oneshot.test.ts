/**
 * `DOD-INBOX-ONESHOT-1` — the away inbox accepts ONE message, then closes itself.
 *
 * ─── Why this file exists ──────────────────────────────────────────────────────────────────────
 *
 * The behaviour shipped once, was deleted as collateral damage by `DOD-M15-AWAYSCOPE-1`, and
 * NOTHING WENT RED. The rejection and the seal it initiated were only ever exercised through the
 * branch that also sent the away greeting mid-conversation; when that branch went, its tests went
 * with it, and the promise the away text makes to every caller — "one message per visit" — became
 * unenforced in production for four days without a single failing assertion.
 *
 * So these tests drive the one-shot on its own, through the seam the daemon calls, and every one of
 * them fails if the wiring is removed again.
 *
 * ─── The stub ─────────────────────────────────────────────────────────────────────────────────
 *
 * The session-node manager is stubbed, deliberately and only here: what is under test is a DECISION
 * — whether to close, on which arrival — not the crypto or the transport, which have their own live
 * fixtures. The stub records what the decision asked for, so an assertion about "it sealed" is an
 * assertion about the call that seals, not about a log line.
 */
import { describe, it, expect } from "vitest";
import { createAwayInboxOneshot, type AwayInboxOneshotDeps } from "../away-inbox-oneshot.js";
import { AWAY_AUTO_REPLY_MARKER } from "../away-detection.js";
import type { SessionNodeManager } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { SessionRecord } from "../types.js";

const AGENT = "alice";
const SID = "5e".repeat(16);

interface Harness {
  close: (agentName: string, sessionId: string) => Promise<void>;
  sent: string[];
  sealSubmits: number;
  events: string[];
  awayAckSent: Set<string>;
}

function makeHarness(opts: {
  received: string[];
  /** What THIS side has already said. The away greeting is machine traffic; anything else is a human. */
  weSent?: string[];
  awayAcked?: boolean;
  status?: SessionRecord["status"];
  diverged?: boolean;
}): Harness {
  const sent: string[] = [];
  const events: string[] = [];
  let sealSubmits = 0;
  const messages = [
    ...(opts.weSent ?? []).map((text, i) => ({ sequence: i, direction: "sent" as const, text, createdAt: 0 })),
    ...opts.received.map((text, i) => ({ sequence: 100 + i, direction: "received" as const, text, createdAt: 0 })),
  ];

  const record = { status: opts.status ?? "active", counterparty_pubkey: "bb".repeat(32) } as unknown as SessionRecord;
  const manager = {
    readTranscript: () => ({ messages, undecryptable: 0 }),
    getSessionRecord: () => record,
    contentHashForSession: async (_a: string, _s: string, bytes: Uint8Array) => ({ hash: new Uint8Array(32).fill(bytes.length % 251), alg: "sha256" }),
    sendContent: async (_a: string, _s: string, bytes: Uint8Array) => {
      sent.push(new TextDecoder().decode(bytes));
      return { ok: true, durable: true, sequenceNumber: messages.length };
    },
    placeOwnLeaf: () => ({ placed: true, leafIndex: messages.length }),
    recordTranscriptMessage: () => {},
    sealReadiness: () => ({ diverged: opts.diverged ?? false, treeSize: messages.length, highWaterSeq: messages.length }),
    submitSealLeaf: async () => { sealSubmits += 1; return { ok: true, reportedRootHex: "ab".repeat(32), sequenceNumber: messages.length + 1 }; },
  } as unknown as SessionNodeManager;

  const logger: Logger = {
    debug() {}, info(e: string) { events.push(e); }, warn(e: string) { events.push(e); }, error(e: string) { events.push(e); },
  };

  const awayAckSent = new Set<string>();
  if (opts.awayAcked !== false) awayAckSent.add(`${AGENT}:${SID}:request`);

  const deps: AwayInboxOneshotDeps = {
    logger,
    sessionNodeManager: manager,
    awayAckSent,
    keyProviders: new Map(),
    sealKey: (a, s) => `${a}:${s}`,
    sealInterruptedInProgress: new Set<string>(),
    // Resolved immediately, so the bilateral wait does not hold the test open.
    pendingSealWaiters: new Map(),
    pendingUnilateralWaiters: new Map(),
    sendOver: async () => ({ ok: true }),
    handleActiveSealFlow: async () => ({ ok: true }) as never,
  };
  const { closeInboxIfIgnored } = createAwayInboxOneshot(deps);
  // The seal waits for the counterparty to co-seal; resolve it as soon as it is registered so the
  // assertions are about the DECISION to seal, not about how long the ceremony takes.
  const waiters = deps.pendingSealWaiters;
  const originalSet = waiters.set.bind(waiters);
  waiters.set = ((k: string, fn: (c: unknown) => void) => {
    const r = originalSet(k, fn as never);
    queueMicrotask(() => fn({ rootHex: "cd".repeat(32) }));
    return r;
  }) as never;

  return { close: closeInboxIfIgnored, sent, get sealSubmits() { return sealSubmits; }, events, awayAckSent };
}

describe("DOD-INBOX-ONESHOT-1: an away inbox accepts one message, then closes itself", () => {
  it("★★★ their ONE message closes the inbox — one rejection carrying [[WRAP]], and a seal", async () => {
    const h = makeHarness({ received: ["the message the away text invited"] });
    await h.close(AGENT, SID);

    expect(h.sent, "exactly one line, and never the away greeting").toHaveLength(1);
    expect(h.sent[0], "the caller must be told why the session closed").toContain("one message per visit");
    expect(
      h.sent[0]!.trimEnd().endsWith("[[WRAP]]"),
      "the token goes at the END — the counterparty's close detector is anchored there",
    ).toBe(true);
    expect(h.sent[0]!.startsWith(AWAY_AUTO_REPLY_MARKER), "machine-generated, and it says so").toBe(true);
    expect(h.sealSubmits, "the session must SEAL, not merely be answered").toBe(1);
  });

  it("★★★ a session THIS SIDE SPOKE IN is a conversation — the machine never closes it", async () => {
    const h = makeHarness({
      weSent: [`${AWAY_AUTO_REPLY_MARKER} alice is currently away.`, "Sorry, I am here now — what did you need?"],
      received: ["their reply to a human"],
    });
    await h.close(AGENT, SID);
    expect(
      h.sealSubmits,
      "principle 4: a machine greeting that ended a live exchange is what cost a completed conversation its receipt",
    ).toBe(0);
    expect(h.sent, "principle 8: the party who comes back is the one who closes").toEqual([]);
  });

  it("nothing has arrived yet — the greeting alone never closes anything", async () => {
    const h = makeHarness({ weSent: [`${AWAY_AUTO_REPLY_MARKER} alice is currently away.`], received: [] });
    await h.close(AGENT, SID);
    expect(h.sent).toEqual([]);
    expect(h.sealSubmits).toBe(0);
  });

  it("★★★ an AUTO-REPLY arrival never triggers it — two away agents must not seal a conversation nobody had", async () => {
    const h = makeHarness({
      received: [`${AWAY_AUTO_REPLY_MARKER} CELLO_Coder_H1 is currently away.`],
    });
    await h.close(AGENT, SID);
    expect(h.sent, "answering a machine continues the ping-pong").toEqual([]);
    expect(h.sealSubmits, "two ctrl leaves from two away agents is exactly what notarizes a session").toBe(0);
    expect(h.events).toContain("session.away.mutual.skipped");
  });

  it("a message CARRYING [[WRAP]] is the caller closing — the one-shot is not spent on it", async () => {
    const h = makeHarness({ received: ["I am done here [[WRAP]]"] });
    await h.close(AGENT, SID);
    expect(h.sent).toEqual([]);
    expect(h.events).toContain("session.away.inbox.oneshot.skipped_wrap");
  });

  /**
   * THE TIER CASE, which is why attendance is not the discriminator. A private agent IS attended and
   * still answers with the away text, because this caller's tier says do not engage. An attendance
   * test would exclude exactly the case the away message exists for.
   */
  it("★★★ an ATTENDED agent whose TIER said away still closes the visit", async () => {
    const h = makeHarness({ received: ["hello from an unknown caller"], weSent: [`${AWAY_AUTO_REPLY_MARKER} Dispatched.`] });
    await h.close(AGENT, SID);
    expect(h.sent, "the tier refused the conversation; the visit still ends").toHaveLength(1);
    expect(h.sealSubmits).toBe(1);
  });

  it("a session the machine never answered is NOT an away session — hands off", async () => {
    const h = makeHarness({ received: ["a message in an ordinary conversation"], awayAcked: false });
    await h.close(AGENT, SID);
    expect(h.sent, "the away reply is what promises one message per visit; without it there is no promise").toEqual([]);
    expect(h.sealSubmits).toBe(0);
  });

  it("★★ it fires ONCE — later arrivals do not send a second rejection or a second seal", async () => {
    const h = makeHarness({ received: ["first"] });
    await h.close(AGENT, SID);
    await h.close(AGENT, SID);
    await h.close(AGENT, SID);
    expect(h.sent, "a rapid-fire sender must not trigger concurrent sends").toHaveLength(1);
    expect(h.sealSubmits, "or concurrent seal submits").toBe(1);
  });

  it("★★ a DIVERGED session is not sealed by a path with no operator to warn", async () => {
    const h = makeHarness({ received: ["first"], diverged: true });
    await h.close(AGENT, SID);
    expect(h.sealSubmits, "cello_close_session refuses a diverged record; the autonomous path must too").toBe(0);
    expect(h.events).toContain("session.away.inbox.oneshot.seal_skipped_diverged");
  });
});

/**
 * THE WIRING ITSELF, because the deletion that caused this was a wiring deletion. Every assertion
 * above passes on a daemon that never calls the seam, which is exactly the state production was in.
 */
describe("DOD-INBOX-ONESHOT-1: the daemon calls it when content arrives", () => {
  it("★★★ daemon.ts calls closeInboxIfIgnored from the content-arrival hook", async () => {
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const src = readFileSync(join(import.meta.dirname, "..", "daemon.ts"), "utf8");
    const hook = src.slice(src.indexOf("setOnContentArrived"));
    const body = hook.slice(0, hook.indexOf("});"));
    expect(
      body.includes("closeInboxIfIgnored"),
      "an arriving message is the only thing that can reveal the caller ignored the instruction — " +
      "without this call the whole unit is unreachable, which is how it was lost last time",
    ).toBe(true);
  });
});
