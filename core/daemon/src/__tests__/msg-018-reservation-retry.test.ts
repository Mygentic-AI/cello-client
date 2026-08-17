/**
 * DOD-M12B-RESERVATION-RETRY-1 — an agent nobody can dial, and nothing ever tries again.
 *
 * MEASURED over 17 days of one operator's log: `session.standing_receiver.relay.rejected` **2,215
 * times, every one of them `relay_granted_no_reservation`** — which `#startReceiverNode`'s own
 * comment explains exactly:
 *
 *   "a relay that is out of reservation slots completes the handshake and simply grants nothing,
 *    leaving a node that looks started and is reachable by nobody."
 *
 * The fallback is a plain TCP node with **no circuit address**. Behind NAT that agent is dialable by
 * nobody — every counterparty falls back to the relay's store-and-forward, which is the parked-message
 * behaviour this milestone has been chasing from the other end.
 *
 * AND THE WATCHDOG SKIPS IT, deliberately:
 *
 *   `if (!sr.hasReservation || sr.relayPeerId === undefined) continue; // never had one — not a LOSS`
 *
 * justified as *"already degraded and already loud (reservation.none)."* **Loud is not enough.**
 * `session.standing_receiver.reservation.none` fired **481 times** and nothing ever acted, while
 * three lines below the same file calls this *"precisely the silent-loss-of-inbound failure this
 * whole story exists to kill."*
 *
 * WHAT MUST NOT BREAK — a reservation is a SCARCE resource. The relay holds it for its full TTL even
 * after the client disconnects, and it has a finite number of slots; `#startReceiverNode` already
 * records that burning two slots per agent is "how a fleet exhausts a relay". So the retry is on a
 * BACKOFF and is BOUNDED — never the watchdog's 30-second grid.
 *
 * Revert test: restore the unconditional `continue` for a receiver with no reservation and the first
 * case fails — nothing is ever re-attempted.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { FakeNode } from "./helpers/two-connection-fixture.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

interface LogEvent { event: string; ctx: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (event: string, ctx?: Record<string, unknown>): void => { events.push({ event, ctx: ctx ?? {} }); };
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
}

/**
 * A node whose listen addresses depend on whether the relay GRANTED a reservation. That is the only
 * signal `#startReceiverNode` trusts, and it is what a relay out of slots withholds while still
 * completing the handshake.
 */
class ReservationNode extends FakeNode {
  constructor(private readonly granted: boolean) { super(); }
  override listenAddresses(): string[] {
    return this.granted
      ? ["/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWRelay/p2p-circuit"]
      : ["/ip4/127.0.0.1/tcp/4002"];
  }
  /** A granted reservation implies a LIVE connection to the relay. Without this the watchdog reads
   *  the reservation as lost on its very next tick and rebuilds forever — which is the fixture
   *  lying, not the code churning. */
  override getConnections(): Array<{ peerId: string; encryption: string | undefined }> {
    return this.granted ? [{ peerId: "12D3KooWRelay", encryption: "noise" }] : [];
  }
}

/** Refuses every reservation until `grantFrom` calls have been made, then grants. */
class SlotStarvedFactory implements ISessionNodeFactory {
  calls = 0;
  circuitAttempts = 0;
  constructor(private readonly grantFrom = Number.POSITIVE_INFINITY) {}
  async createNode(c: SessionNodeConfig): Promise<CelloNode> {
    this.calls += 1;
    const wantsRelay = (c.circuitRelayListenAddrs?.length ?? 0) > 0;
    if (wantsRelay) this.circuitAttempts += 1;
    return new ReservationNode(wantsRelay && this.circuitAttempts >= this.grantFrom) as unknown as CelloNode;
  }
}

async function makeManager(opts: { factory: ISessionNodeFactory; logger: Logger; retryMs?: number }) {
  const dir = await mkdtemp(join(tmpdir(), "cello-msg018-"));
  const snm = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory: opts.factory,
    logger: opts.logger,
    dbPath: join(dir, "s.db"),
    standingReceiverWatchdogIntervalMs: 20,
    standingReceiverReservationTimeoutMs: 50,
    ...(opts.retryMs !== undefined ? { standingReceiverReservationRetryMs: opts.retryMs } : {}),
  });
  await snm.initialize();
  await seedAgents(snm.getDb(), ["alice"]);
  snm.setDirectoryRelayEndpoints("alice", [{ relayPeerId: "12D3KooWRelay", relayAddrs: ["/ip4/127.0.0.1/tcp/4001"] }]);
  return { snm, dir };
}

describe("DOD-M12B-RESERVATION-RETRY-1: a receiver with no reservation is tried again", () => {
  let cleanup: (() => Promise<void>) | null = null;
  afterEach(async () => { if (cleanup) await cleanup(); cleanup = null; });

  it("RE-ATTEMPTS a reservation the relay refused — 481 agents were left undialable for good", async () => {
    const { logger, events } = makeLogger();
    // Every attempt refused: the measured `relay_granted_no_reservation` shape.
    const factory = new SlotStarvedFactory();
    const { snm, dir } = await makeManager({ factory, logger, retryMs: 40 });
    cleanup = async () => { await snm.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); };

    await snm.ensureStandingReceiverForAgent("alice");
    const afterFirst = factory.circuitAttempts;
    expect(afterFirst, "the first attempt happens at creation").toBeGreaterThan(0);

    await new Promise((r) => setTimeout(r, 400));

    expect(
      factory.circuitAttempts,
      "a relay out of slots at boot may have one minutes later — nothing ever asked again",
    ).toBeGreaterThan(afterFirst);
    expect(
      events.filter((e) => e.event === "session.standing_receiver.reservation.retry").length,
      "and the re-attempt must be visible, not silent",
    ).toBeGreaterThan(0);
    expect(snm.getStandingReceiverReachability("alice"), "and the operator can see it is still trying").toBe("retrying");
  }, 30_000);

  it("STOPS after a bounded number of attempts, and says the agent is undialable", async () => {
    // A reservation is scarce — the relay holds it for its full TTL even after the client goes.
    // Retrying forever on a fleet is how a relay is exhausted, which the code already warns about.
    const { logger, events } = makeLogger();
    const factory = new SlotStarvedFactory();
    const { snm, dir } = await makeManager({ factory, logger, retryMs: 20 });
    cleanup = async () => { await snm.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); };

    await snm.ensureStandingReceiverForAgent("alice");
    await new Promise((r) => setTimeout(r, 800));

    const gaveUp = events.filter((e) => e.event === "session.standing_receiver.reservation.gave_up");
    expect(gaveUp.length, "an unbounded retry is how a fleet exhausts a relay").toBe(1);
    expect(
      String(gaveUp[0]!.ctx["impact"]),
      "and the operator has to be told what it MEANS — not that a reservation failed, but that nobody can reach them",
    ).toMatch(/reach|dial/i);

    const attemptsAtGiveUp = factory.circuitAttempts;
    await new Promise((r) => setTimeout(r, 300));
    expect(factory.circuitAttempts, "nothing may keep asking after the budget is spent").toBe(attemptsAtGiveUp);

    // AND IT REACHES A SURFACE THE OPERATOR READS, not only the log — which is where this was
    // visible 481 times while nobody acted. `standing_receiver_ready` is TRUE for this agent: a
    // receiver exists. It is simply one nobody behind NAT can dial, and that is the distinction.
    expect(snm.getStandingReceiverReady("alice"), "a receiver DOES exist — that is the trap").toBe(true);
    expect(snm.getStandingReceiverReachability("alice")).toBe("unreachable");
  }, 30_000);

  it("STOPS as soon as a reservation is granted — no churn once the agent is reachable", async () => {
    const { logger } = makeLogger();
    // Refuses the first two attempts, grants the third.
    const factory = new SlotStarvedFactory(3);
    const { snm, dir } = await makeManager({ factory, logger, retryMs: 30 });
    cleanup = async () => { await snm.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); };

    await snm.ensureStandingReceiverForAgent("alice");
    await new Promise((r) => setTimeout(r, 400));
    const settled = factory.circuitAttempts;
    expect(settled, "it should have kept trying until one was granted").toBeGreaterThanOrEqual(3);

    await new Promise((r) => setTimeout(r, 300));
    expect(
      factory.circuitAttempts,
      "a granted reservation ends the retry — burning slots on a healthy receiver is the hazard the code already names",
    ).toBe(settled);
    expect(snm.getStandingReceiverReachability("alice"), "and the agent reads as dialable again").toBe("reserved");
  }, 30_000);
});

describe("DOD-M12B-RESERVATION-RETRY-1: the backoff and the budget", () => {
  let cleanup: (() => Promise<void>) | null = null;
  afterEach(async () => { if (cleanup) await cleanup(); cleanup = null; });

  it("the wait GROWS between attempts — a fixed interval is what churns a scarce relay", async () => {
    // THE CLAUSE THAT PROTECTS THE SCARCE RESOURCE, and it was the one with no assertion: replacing
    // the doubling with a flat `now + retryMs` left every other case green. A reservation is held by
    // the relay for its full TTL even after the client disconnects, so a fleet re-asking on a fixed
    // short interval is exactly how one is exhausted.
    const { logger, events } = makeLogger();
    const factory = new SlotStarvedFactory();
    const { snm, dir } = await makeManager({ factory, logger, retryMs: 30 });
    cleanup = async () => { await snm.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); };

    await snm.ensureStandingReceiverForAgent("alice");
    const at: number[] = [];
    const started = Date.now();
    // Record when each retry fires, by watching the event count change.
    let seen = 0;
    for (let i = 0; i < 120 && seen < 4; i++) {
      await new Promise((r) => setTimeout(r, 10));
      const n = events.filter((e) => e.event === "session.standing_receiver.reservation.retry").length;
      while (seen < n) { at.push(Date.now() - started); seen += 1; }
    }
    expect(at.length, "needs at least three retries to compare two gaps").toBeGreaterThanOrEqual(3);

    const gaps = at.slice(1).map((v, i) => v - at[i]!);
    expect(
      gaps[1]! > gaps[0]!,
      `each wait must be longer than the last — got gaps ${gaps.join(", ")}ms. A flat interval passes every other test in this file.`,
    ).toBe(true);
  }, 30_000);

  it("taking the agent OFFLINE and back re-arms the budget — a spent latch must not survive", async () => {
    // Without clearing the state on removal, a fresh receiver inherits a spent budget: the watchdog
    // finds `attempts` past the cap and returns having done NOTHING — no retry, and not even a
    // second give-up. The agent is undialable and the machinery is inert and mute until a daemon
    // restart, while the relay may have had slots free for hours.
    const { logger, events } = makeLogger();
    const factory = new SlotStarvedFactory();
    const { snm, dir } = await makeManager({ factory, logger, retryMs: 20 });
    cleanup = async () => { await snm.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); };

    await snm.ensureStandingReceiverForAgent("alice");
    await new Promise((r) => setTimeout(r, 800));
    expect(
      events.filter((e) => e.event === "session.standing_receiver.reservation.gave_up").length,
      "the budget must be spent before this test means anything",
    ).toBe(1);

    await snm.removeStandingReceiverForAgent("alice");
    const before = events.filter((e) => e.event === "session.standing_receiver.reservation.retry").length;
    await snm.ensureStandingReceiverForAgent("alice");
    await new Promise((r) => setTimeout(r, 300));

    expect(
      events.filter((e) => e.event === "session.standing_receiver.reservation.retry").length,
      "a restarted agent must get a fresh budget — the relay may have had slots free for hours",
    ).toBeGreaterThan(before);
  }, 30_000);
});
