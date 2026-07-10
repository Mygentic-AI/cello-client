/**
 * CELLO-M7-SESSION-003 — direct-session liveness via session-node peer events (AC-004)
 *
 * AC-004: a direct session's session-node connection is the liveness authority.
 * The client ACTS on the session node's onPeerConnect/onPeerDisconnect (today it
 * acts on neither): on connect it tracks counterparty_liveness 'alive', and on
 * disconnect it flips to 'gone' and emits session.liveness.changed at WARN with
 * transportPath:'direct', observedBy:'session_node'. Verified with two REAL
 * session-node libp2p nodes where B is terminated and A's tracked liveness flips
 * to 'gone' — no handler called directly without a real transport disconnect.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgents } from "./helpers/seed-agents.js";

async function waitFor(fn: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("waitFor: condition not met in time");
}

interface LogEntry { level: string; event: string; ctx: Record<string, unknown> }
function makeLogger() {
  const entries: LogEntry[] = [];
  const mk = (level: string) => (event: string, ctx?: Record<string, unknown>) =>
    entries.push({ level, event, ctx: ctx ?? {} });
  return { entries, logger: { debug: mk("debug"), info: mk("info"), warn: mk("warn"), error: mk("error") } as Logger };
}

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const kp = generateKeypair();
    return createNode({
      keyProvider: kp,
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      // short keepalive so an ungraceful drop would also surface (AC-005)
      keepAliveIntervalMs: 500,
    });
  }
}

describe("AC-004: direct-session liveness flips to 'gone' on real session-node disconnect", () => {
  it("tracks 'alive' on connect and 'gone' on a real peer disconnect, emitting WARN", async () => {
    const { entries, logger } = makeLogger();
    const dbPath = join(mkdtempSync(join(tmpdir(), "cello-session-003-")), "sessions.db");
    const mgr = new SessionNodeManager({ factory: new RealNodeFactory(), logger, dbPath });
    await mgr.initialize();
    // DOD-AGENT-ID-JOINKEY-1: production always has an `agents` row before any session exists.
    await seedAgents(mgr.getDb(), ["agentA"]);

    // B is the counterparty — a real session node dialing A's session node.
    const kpB = generateKeypair();
    const nodeB = await createNode({ keyProvider: kpB, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await nodeB.start();
    const bPeerId = nodeB.getPeerId();

    try {
      const sessionId = "a".repeat(32);
      const res = await mgr.createSessionNode(
        sessionId,
        "agentA",
        "bb".repeat(32),     // counterparty pubkey (hex)
        bPeerId,             // gater allows only B
        "corr-1",
      );
      expect(res.ok).toBe(true);
      if (!res.ok) return;

      // B dials A's session node — onPeerConnect fires → 'alive'
      await nodeB.dial(res.addrs[0]!);
      await waitFor(() => mgr.getSessionLiveness("agentA", sessionId) === "alive", 5000);
      expect(mgr.getSessionLiveness("agentA", sessionId)).toBe("alive");

      // B is terminated — A's session node observes peer:disconnect → 'gone'
      await nodeB.stop();
      await waitFor(() => mgr.getSessionLiveness("agentA", sessionId) === "gone", 8000);
      expect(mgr.getSessionLiveness("agentA", sessionId)).toBe("gone");

      const goneEvt = entries.find(
        (e) => e.event === "session.liveness.changed" && e.ctx["liveness"] === "gone",
      );
      expect(goneEvt).toBeDefined();
      expect(goneEvt!.level).toBe("warn");
      expect(goneEvt!.ctx["transportPath"]).toBe("direct");
      expect(goneEvt!.ctx["observedBy"]).toBe("session_node");
      expect(goneEvt!.ctx["sessionId"]).toBe(sessionId);
    } finally {
      await nodeB.stop().catch(() => {});
      await mgr.gracefulShutdown().catch(() => {});
    }
  });

  it("returns 'unknown' for a session with no node / no observation", () => {
    const { logger } = makeLogger();
    const dbPath = join(mkdtempSync(join(tmpdir(), "cello-session-003-")), "sessions.db");
    const mgr = new SessionNodeManager({ factory: new RealNodeFactory(), logger, dbPath });
    expect(mgr.getSessionLiveness("agentA", "never-tracked")).toBe("unknown");
  });
});
