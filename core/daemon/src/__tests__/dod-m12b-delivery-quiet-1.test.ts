/**
 * DOD-M12B-DELIVERY-QUIET-1 — a session the DOCUMENT DELIVERY worker opened is not a signal.
 *
 * THE CIRCULARITY. Session creation fires a party-became-reachable trigger that calls
 * `ReconcileScheduler.onReachable`, which sets `failures = 0` and `nextAttemptMs = 0` and sweeps
 * every shared document immediately. That is right when the PEER caused the session — "the backoff
 * modeled 'they do not answer', and here they demonstrably just did" (SYNC-P5 R39 trigger 2). It is
 * wrong when our own delivery worker opened it: the signal is our outbound act reflected back, we
 * learn nothing about the peer, and we wipe a backoff a refusal may have set seconds earlier.
 *
 *   sweep needs a session → opens one → creation fires the trigger → trigger zeroes the backoff and
 *   sweeps every document → sweep needs sessions → …
 *
 * Measured 2026-08-17: 321 attempts / 85 min, 53 sessions, 63 standing-receiver rebuilds. After the
 * refusal storm was fixed, still 55 attempts in 20 minutes with 0 refusals — this trigger is the
 * volume that fix did not reach.
 *
 * Two more consequences ride the same path and are in scope: the conversation DOORBELL and the
 * TELEGRAM PUSH are dispatched identically whether a human or the delivery worker opened the
 * session, so the operator is told "someone wants to connect" — and their phone buzzes — for
 * machine traffic. The surface that should carry this already exists and delivery does not use it:
 * `document_notices` in the inbox, whose own guidance reads "Nothing is waiting on a reply."
 *
 * ── THE FALSIFICATION, WHICH IS THE POINT OF THIS FILE ───────────────────────────────────────────
 *
 * A session opened by the PEER must STILL reset the backoff and STILL ring, or documents stop
 * syncing promptly when someone comes back online — exactly what R39 trigger 2 exists to deliver.
 * So both directions are asserted here, and the negative one is the one that matters: a fix that
 * silences everything would pass half these tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";
import { createDeliveryOpenRegistry, DELIVERY_OPEN_STALE_MS } from "../delivery-open-registry.js";

const SID64 = (a: string) => a.repeat(64).slice(0, 64);
const PEER = "cd".repeat(32);
const US = "ef".repeat(32);

describe("DOD-M12B-DELIVERY-QUIET-1: the delivery-open registry", () => {
  it("reports an open in flight only between begin and release", () => {
    const reg = createDeliveryOpenRegistry();
    expect(reg.isDeliveryOpening(US, PEER)).toBe(false);
    const release = reg.begin(US, PEER);
    expect(reg.isDeliveryOpening(US, PEER)).toBe(true);
    release();
    expect(reg.isDeliveryOpening(US, PEER)).toBe(false);
    expect(reg.inFlight()).toBe(0);
  });

  it("COUNTS — two documents delivering to one peer must not un-suppress each other", () => {
    const reg = createDeliveryOpenRegistry();
    const releaseA = reg.begin(US, PEER);
    const releaseB = reg.begin(US, PEER);
    releaseA();
    // A boolean cleared by whichever finished first would re-open the loop for the other.
    expect(reg.isDeliveryOpening(US, PEER)).toBe(true);
    releaseB();
    expect(reg.isDeliveryOpening(US, PEER)).toBe(false);
  });

  it("a double release cannot drive the count negative and wedge suppression on forever", () => {
    const reg = createDeliveryOpenRegistry();
    const release = reg.begin(US, PEER);
    release();
    release();
    expect(reg.inFlight()).toBe(0);
    const second = reg.begin(US, PEER);
    expect(reg.isDeliveryOpening(US, PEER)).toBe(true);
    second();
  });

  it("is scoped per opener and per target — one pair never silences another", () => {
    const reg = createDeliveryOpenRegistry();
    const release = reg.begin(US, PEER);
    expect(reg.isDeliveryOpening("ab".repeat(32), PEER)).toBe(false);
    expect(reg.isDeliveryOpening(US, "ab".repeat(32))).toBe(false);
    release();
  });

  it("compares pubkeys case-insensitively — the two sides do not agree on case", () => {
    const reg = createDeliveryOpenRegistry();
    const release = reg.begin(US, PEER.toUpperCase());
    expect(reg.isDeliveryOpening(US.toUpperCase(), PEER.toLowerCase())).toBe(true);
    release();
  });
});

describe("DOD-M12B-DELIVERY-QUIET-1: creation does not ring when delivery caused it", () => {
  let tempDir: string;
  let logger: Logger;
  let events: Array<{ event: string; context: Record<string, unknown> }>;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-delivery-quiet-"));
    events = [];
    const rec = () => (msg: string, context?: Record<string, unknown>) => {
      events.push({ event: msg, context: context ?? {} });
    };
    logger = { debug: rec(), info: rec(), warn: rec(), error: rec() };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function setup(...names: string[]): Promise<DaemonConfig> {
    for (const name of names) {
      await mkdir(join(tempDir, "agents", name), { recursive: true });
      await FileKeyProvider.load(join(tempDir, "agents", name, "key"));
    }
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger,
    };
  }

  async function connectWatching(socketPath: string): Promise<{ client: IpcClient; notifications: Array<Record<string, unknown>> }> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    const notifications: Array<Record<string, unknown>> = [];
    client.onNotification((n) => notifications.push(n as unknown as Record<string, unknown>));
    await client.send("ipc.connect", { clientType: "mcp" });
    return { client, notifications };
  }

  const stateChanges = (n: Array<Record<string, unknown>>) =>
    n.filter((x) => x["notification"] === "session_state_changed");
  const suppressed = () => events.filter((e) => e.event === "session.doorbell.suppressed_delivery");

  /**
   * THE PRODUCTION TUPLE, and the reason every test below is written this way.
   *
   * `state === "created"` is emitted from exactly ONE place in production — the INBOUND accept in
   * `inbound-sessions.ts` — and it names the LOCAL RECEIVING agent plus the INITIATOR's pubkey.
   * The delivery worker that caused the dial is on the OTHER side of that pair.
   *
   * So a test must register the open as `alice → bob` and then emit the created event as
   * `agentName: "bob", counterpartyPubkey: <alice>`. An earlier version of this file registered and
   * emitted with the SAME agent first, which is a tuple production never produces: it exercised the
   * guard's boolean logic, proved nothing about the wiring, and stayed green against a guard whose
   * two halves compared different pairs and could never match.
   */
  async function beginDeliveryOpen(client: IpcClient, opener: string, target: string): Promise<string> {
    const res = (await client.send("__test_delivery_open_begin", { openerAgent: opener, targetAgent: target })) as Record<string, unknown>;
    const openerPubkey = res["openerPubkey"] as string;
    expect(openerPubkey, "the opener must resolve to a real pubkey or the test proves nothing").toMatch(/^[0-9a-f]{64}$/);
    return openerPubkey;
  }

  it("a delivery-opened session rings NOTHING on the side that accepts it", async () => {
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client, notifications } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    // alice's delivery worker dials bob...
    const alicePubkey = await beginDeliveryOpen(client, "alice", "bob");
    // ...and bob is the side that accepts and would ring.
    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("a"), counterpartyPubkey: alicePubkey,
    });
    await new Promise((r) => setTimeout(r, 50));

    expect(stateChanges(notifications)).toHaveLength(0);
    // Suppression must be VISIBLE — a doorbell that silently does not ring is the next defect, and
    // a log line that never fires is how the first version of this guard hid being unreachable.
    expect(suppressed().length).toBeGreaterThan(0);
  });

  it("...and a PEER-opened session STILL rings — the falsification", async () => {
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client, notifications } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    // No delivery open in flight: a real counterparty dialling in.
    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("b"), counterpartyPubkey: PEER,
    });
    await new Promise((r) => setTimeout(r, 50));

    expect(stateChanges(notifications).length).toBeGreaterThan(0);
    expect(suppressed()).toHaveLength(0);
  });

  it("the OPPOSITE direction does not suppress — alice dialling bob never mutes bob dialling alice", async () => {
    // The bug this file exists to stop was an argument-order mistake, so the order is asserted
    // directly: an open registered one way must not answer the question asked the other way.
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client, notifications } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    // alice's worker is dialling bob. Now BOB dials ALICE for real — alice must still be told.
    await beginDeliveryOpen(client, "alice", "bob");
    const bobPubkey = (await client.send("__test_delivery_open_begin", { openerAgent: "bob", targetAgent: "alice" })) as Record<string, unknown>;
    await client.send("__test_delivery_open_end", { openerAgent: "bob", targetAgent: "alice" });

    await client.send("__test_emit_session_event", {
      type: "created", agentName: "alice", sessionId: SID64("g"), counterpartyPubkey: bobPubkey["openerPubkey"] as string,
    });
    await new Promise((r) => setTimeout(r, 50));

    expect(stateChanges(notifications)).toHaveLength(1);
    expect(suppressed()).toHaveLength(0);
  });

  it("suppression is released — the NEXT session from that peer rings again", async () => {
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client, notifications } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    const alicePubkey = await beginDeliveryOpen(client, "alice", "bob");
    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("c"), counterpartyPubkey: alicePubkey,
    });
    await client.send("__test_delivery_open_end", { openerAgent: "alice", targetAgent: "bob" });
    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("d"), counterpartyPubkey: alicePubkey,
    });
    await new Promise((r) => setTimeout(r, 50));

    // Exactly one rang: the second. A suppression that never lifts is the same outage as the storm,
    // one direction over.
    const rung = stateChanges(notifications);
    expect(rung).toHaveLength(1);
    expect(JSON.stringify(rung[0])).toContain(SID64("d"));
  });

  it("only the peer being delivered to is quiet — another peer's session still rings", async () => {
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client, notifications } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    await beginDeliveryOpen(client, "alice", "bob");
    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("e"), counterpartyPubkey: PEER,
    });
    await new Promise((r) => setTimeout(r, 50));

    expect(stateChanges(notifications)).toHaveLength(1);
  });

  it("a NON-created state still dispatches while a delivery open is in flight", async () => {
    // The exemption is about "this session coming up is not news". A session going DOWN is news
    // whoever opened it, and it is the operator's only signal that a conversation was cut off.
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client, notifications } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    const alicePubkey = await beginDeliveryOpen(client, "alice", "bob");
    await client.send("__test_emit_session_event", {
      type: "destroyed", state: "interrupted", agentName: "bob", sessionId: SID64("f"), counterpartyPubkey: alicePubkey,
    });
    await new Promise((r) => setTimeout(r, 50));

    expect(stateChanges(notifications)).toHaveLength(1);
  });

  it("a STALE delivery open stops muting — a wedged dial must not silence a peer forever", async () => {
    // openSessionAs carries no deadline, so without a staleness bound a dial that never settles
    // would suppress that peer's doorbell for the life of the process.
    const reg = createDeliveryOpenRegistry(() => 1_000_000);
    reg.begin(US, PEER);
    expect(reg.isDeliveryOpening(US, PEER)).toBe(true);
    const later = createDeliveryOpenRegistry(() => 1_000_000);
    later.begin(US, PEER);
    expect(later.inFlight()).toBe(1);

    let clock = 1_000_000;
    const aging = createDeliveryOpenRegistry(() => clock);
    aging.begin(US, PEER);
    clock += DELIVERY_OPEN_STALE_MS + 1;
    expect(aging.isDeliveryOpening(US, PEER)).toBe(false);
    expect(aging.inFlight()).toBe(0);
  });

  /**
   * THE BACKOFF HALF — the DoD names it first, and it is the actual storm driver.
   *
   * `onReachable` is not a nudge: it sets `failures = 0` and `nextAttemptMs = 0` and sweeps every
   * shared document immediately. Suppressing the doorbell without suppressing this would leave the
   * loop running silently — quieter, not fixed. Both directions are asserted, because a change that
   * suppressed the trigger unconditionally would stop documents syncing when a peer comes back
   * online, which is the whole point of R39 trigger 2.
   */
  it("a delivery-opened session does NOT fire the reachability trigger", async () => {
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    const alicePubkey = await beginDeliveryOpen(client, "alice", "bob");
    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("h"), counterpartyPubkey: alicePubkey,
    });
    await new Promise((r) => setTimeout(r, 50));

    expect(events.filter((e) => e.event === "document.reconcile.reachable_trigger_fired")).toHaveLength(0);
    expect(suppressed().length).toBeGreaterThan(0);
  });

  it("...and a PEER-opened session DOES fire it — documents must still sync on reconnect", async () => {
    const config = await setup("alice", "bob");
    handle = await startDaemon(config);
    const { client } = await connectWatching(config.socketPath);
    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "bob" });

    await client.send("__test_emit_session_event", {
      type: "created", agentName: "bob", sessionId: SID64("i"), counterpartyPubkey: PEER,
    });
    await new Promise((r) => setTimeout(r, 50));

    const fired = events.filter((e) => e.event === "document.reconcile.reachable_trigger_fired");
    expect(fired).toHaveLength(1);
    expect(fired[0].context["trigger"]).toBe("inbound_session_created");
  });
});
