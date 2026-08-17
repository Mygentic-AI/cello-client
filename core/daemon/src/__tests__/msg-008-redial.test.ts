/**
 * DOD-M12B-REDIAL-1 — a lost connection must not end the conversation.
 *
 * Only the initiator dials, once, at establishment (`connectToCounterparty`). `newStream` never
 * dials: it looks for an already-open connection filed under the recorded peer id and throws
 * `connection_lost` when there is none. Nothing re-dials on `session.liveness.changed → gone`,
 * nothing on signaling reconnect, nothing on agent offline→online, nothing in the drain hook.
 *
 * So once a session's direct connection is lost for any reason, that session parks EVERY message
 * for the rest of its life, on both sides, permanently. The relay backstop keeps the messages
 * moving, which is why this hid: nothing is lost, the conversation just quietly stops being a
 * conversation and becomes store-and-forward, for good.
 *
 * The re-dial is DEMAND-DRIVEN — attempted when a send actually needs the connection, never on a
 * timer. A background re-dial loop is what produced the 2026-08-17 notification storm, where
 * surviving halves of abandoned sessions dialled continuously and the operator saw connection
 * requests from agents nobody was driving. A cooldown bounds a burst of sends against a peer that
 * is genuinely gone.
 *
 * Revert test: remove the re-dial from the `connection_lost` branch and the first case fails — the
 * message parks instead of delivering, on a peer that was listening the whole time.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair, msgLeafHash } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgents } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function pollFor<T>(fn: () => T | null | undefined | false, tries = 200, stepMs = 25): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    const v = fn();
    if (v) return v as T;
    await wait(stepMs);
  }
  return null;
}

describe("DOD-M12B-REDIAL-1: a lost connection is re-dialled on demand", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-msg008-")); managers.length = 0; });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* already down */ } }
    managers.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeManager(): { manager: SessionNodeManager; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `snm-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new RealNodeFactory(), logger, dbPath });
    managers.push(manager);
    return { manager, events };
  }

  const SID = "9a".repeat(16);
  const A_PUB = "aa".repeat(32);
  const B_PUB = "bb".repeat(32);

  async function liveSession() {
    const A = makeManager();
    const B = makeManager();
    await A.manager.initialize();
    await B.manager.initialize();
    await seedAgents(A.manager.getDb(), ["alice"]);
    await seedAgents(B.manager.getDb(), ["bob"]);
    await B.manager.ensureStandingReceiverForAgent("bob");
    const bInfo = B.manager.getStandingReceiverInfo("bob");
    expect(bInfo).not.toBeNull();
    const created = await A.manager.createSessionNode(SID, "alice", B_PUB, bInfo!.peerId, "corr-A");
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("createSessionNode failed");
    expect((await A.manager.connectToCounterparty("alice", SID, bInfo!.addrs)).ok).toBe(true);
    expect((await B.manager.acceptSession(SID, "bob", A_PUB, created.peerId, "corr-B")).ok).toBe(true);
    return { A, B };
  }

  async function send(A: { manager: SessionNodeManager }, text: string) {
    const content = new TextEncoder().encode(text);
    return A.manager.sendContent("alice", SID, content, msgLeafHash(content), `corr-${text}`);
  }

  it("a send that finds no connection re-dials and delivers, instead of parking for the rest of the session", async () => {
    const { A, B } = await liveSession();

    // Baseline: the session works.
    await send(A, "before");
    expect(await pollFor(() => B.manager.takeReceivedContent("bob", SID))).not.toBeNull();

    // The connection is gone as far as the send path is concerned — exactly what `newStream`
    // reports after any blip. The peer is still listening the whole time, which is the point: this
    // is a recoverable condition that used to be permanent.
    A.manager.injectConnectionLoss(1);
    const sent = await send(A, "after the blip");
    expect(sent.ok).toBe(true);
    expect("delivered" in sent && sent.delivered, "the re-dial must restore DIRECT delivery, not fall back to the relay").toBe(true);

    const redial = A.events.find((e) => e.event === "session.transport.redial.attempted");
    expect(redial, "the re-dial must be visible — a silent recovery is unmeasurable").toBeDefined();
    expect(A.events.find((e) => e.event === "session.transport.redial.succeeded")).toBeDefined();

    const arrived = await pollFor(() => B.manager.takeReceivedContent("bob", SID));
    expect(arrived, "the message must actually reach the counterparty").not.toBeNull();
    expect(Buffer.from(arrived!.contentHex, "hex").toString()).toBe("after the blip");
  }, 60_000);

  it("a peer that is genuinely gone is not dialled once per send — the cooldown bounds a burst", async () => {
    const { A, B } = await liveSession();
    await B.manager.gracefulShutdown(); // the counterparty really is gone now
    await wait(100);

    A.manager.injectConnectionLoss(5);
    for (let i = 0; i < 5; i++) await send(A, `into the void ${i}`);

    // Continuous re-dialling is what produced the 2026-08-17 notification storm, where surviving
    // halves of abandoned sessions called forever and the operator saw connection requests from
    // agents nobody was driving. Recovery must not become that.
    const attempts = A.events.filter((e) => e.event === "session.transport.redial.attempted");
    expect(attempts.length, `5 sends produced ${attempts.length} dials — the cooldown is not holding`).toBeLessThanOrEqual(2);
    const skipped = A.events.filter((e) => e.event === "session.transport.redial.cooldown");
    expect(skipped.length, "a suppressed re-dial must say so rather than look like no attempt at all").toBeGreaterThan(0);
  }, 60_000);

  it("a re-dial that fails still parks the message — recovery must not cost delivery", async () => {
    const { A, B } = await liveSession();
    await B.manager.gracefulShutdown();
    await wait(100);

    A.manager.injectConnectionLoss(1);
    const sent = await send(A, "nobody home");

    // A re-dial in front of the park must not swallow the failure or skip the park. This harness
    // configures no relay, so the park has nowhere to go either — which is exactly the case that
    // must still be REPORTED rather than dressed up as a success. `ok: false` with a named reason
    // is the honest answer; the recovery attempt does not change what actually happened.
    expect(sent.ok, "a message that reached nobody must not report success").toBe(false);
    expect(!sent.ok && sent.reason).toBe("session_stream_unavailable");
    expect(A.events.find((e) => e.event === "session.transport.redial.failed"), "the failed recovery must be visible").toBeDefined();
    expect(A.events.find((e) => e.event === "session.content.direct.send.failed"), "the park path must still run").toBeDefined();
  }, 60_000);
});
