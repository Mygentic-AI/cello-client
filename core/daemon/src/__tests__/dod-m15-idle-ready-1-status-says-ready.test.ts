/**
 * DOD-M15-IDLE-READY-1 — **`retrying` STOPPED BEING A FAULT SIGNAL, SO IT STOPPED BEING A SIGNAL.**
 *
 * ─── The defect is not the word, it is what the word costs ────────────────────────────────────
 *
 * `standing_receiver_reachability` is the field an operator reads to answer "can people reach my
 * agent?". It had four values and the logic falls through in order: `absent`, `reserved`,
 * `unreachable`, and `retrying` as the final fallback.
 *
 * Before 055-ONDEMAND an agent took a relay slot at login, so reaching that fallback meant something
 * specific and rare: **we want a slot, we cannot get one, we are still trying.** An idle agent now
 * holds no slot BY DESIGN — it takes one when somebody calls and gives it back at the seal — so it
 * has no reservation, no live session and no retry in flight, and lands on that same fallback.
 *
 * **So `retrying` became the resting state of every healthy idle agent on the fleet.** That is worse
 * than a cosmetic lie: an agent that genuinely cannot get a slot now reports exactly what a
 * perfectly healthy one reports, and the field can no longer distinguish them. A status that says
 * the same thing whether or not anything is wrong is not a status.
 *
 * Observed directly on 2026-09-11: the same two agents, on the same machine, minutes apart — both
 * `reserved` on the published build, both `retrying` on the on-demand build. Same health, different
 * word, and nothing had changed about whether anyone could reach them.
 *
 * ─── The fix, and why a FIFTH value rather than re-pointing an existing one ────────────────────
 *
 * Idle-and-ready is a genuinely different state from the other four, so it gets its own name:
 * **`ready`** (Andre's choice, 2026-09-11). Widening `reserved` to cover it would have been the
 * tempting one-liner and it is the wrong shape — `reserved` means a slot is held and a NAT'd
 * counterparty can dial in right now, which is false for an idle agent and is exactly the claim an
 * operator would act on.
 *
 * `retrying` keeps its old meaning and its old rarity, which is the entire point of the change.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import { ProductionSessionNodeFactory } from "../daemon.js";
import { seedAgents } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("DOD-M15-IDLE-READY-1: an idle agent says ready, not retrying", () => {
  let tempDir = "";
  let manager: SessionNodeManager | null = null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-idle-ready-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    if (manager) await manager.gracefulShutdown();
    manager = null;
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeManager(): Promise<SessionNodeManager> {
    const m = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger: silent,
      dbPath: join(tempDir, "sessions.db"),
      standingReceiverRetryDelaysMs: [],
    });
    await m.initialize();
    await seedAgents(m.getDb(), ["alice"]);
    return m;
  }

  it("★★★ a freshly logged-in agent holding nothing reports READY — the healthy resting state", async () => {
    manager = await makeManager();
    await manager.ensureStandingReceiverForAgent("alice");

    expect(
      manager.getStandingReceiverReachability("alice"),
      "an idle agent holds no relay slot BY DESIGN — it takes one when somebody calls. Reporting " +
        "`retrying` says the daemon is chasing something it is deliberately not chasing, and makes " +
        "every healthy idle agent indistinguishable from one that genuinely cannot get a slot",
    ).toBe("ready");
  });

  it("★★★ READY is NOT reserved — it must not claim a NAT'd caller can dial in right now", async () => {
    manager = await makeManager();
    await manager.ensureStandingReceiverForAgent("alice");

    /**
     * The tempting one-line fix was to widen `reserved` to cover the idle case. `reserved` is a
     * claim an operator acts on — a slot is held, so somebody behind a home router can reach this
     * agent this second — and for an idle agent that is false. The two states are different facts
     * and the field has to keep telling them apart.
     */
    expect(manager.getStandingReceiverReachability("alice")).not.toBe("reserved");
    expect(manager.getStandingReceiverRelayIds("alice"), "and it really is holding nothing").toEqual([]);
  });

  it("an agent with NO receiver is still absent — ready means ready, not merely not-broken", async () => {
    manager = await makeManager();
    expect(
      manager.getStandingReceiverReachability("alice"),
      "no receiver has been installed, so there is nothing standing by; `ready` here would report " +
        "an agent as reachable before it can accept anything at all",
    ).toBe("absent");
  });
});
