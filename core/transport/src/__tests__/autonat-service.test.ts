/**
 * CELLO-M7-TRANSPORT-001 — autonat-service.test.ts
 *
 * Tests for NodeAutoNatService — the real IAutoNatService over a live CelloNode.
 *
 * ─── Specification (Phase S) — what these tests pin down ──────────────────────
 * C2  — transport.autonat.result (INFO) is emitted on every probe cycle with
 *       { dialable, publicAddr, nodeType }; transport.autonat.unavailable (WARN)
 *       is emitted (alongside the INFO) when no directory probers are reachable.
 * AC-003/AC-004 — dialability gating: with probers, getDialability reflects the
 *       node; with NO probers (reconnecting), getDialability is the conservative
 *       default regardless of what the node's raw observable says, and BOTH the
 *       result(dialable:false) and the unavailable WARN fire (dual-event).
 * SI-002 — a rogue (non-manifest) responder cannot push the node to dialable:true:
 *       the prober set is exclusively what was injected from the manifest, and
 *       dialability is gated on it being non-empty.
 */

import { describe, it, expect } from "@claude-flow/testing";
import { NodeAutoNatService, type AutoNatLogger } from "../autonat-service.js";
import type { CelloNode } from "../types.js";
import type { Dialability, Unsubscribe } from "../autonat.js";

// ─── Fakes ────────────────────────────────────────────────────────────────────

interface LogEvent {
  level: "info" | "warn";
  event: string;
  context: Record<string, unknown>;
}

function makeLogger(): { logger: AutoNatLogger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: AutoNatLogger = {
    info: (event, context) => events.push({ level: "info", event, context }),
    warn: (event, context) => events.push({ level: "warn", event, context }),
  };
  return { logger, events };
}

/**
 * Minimal fake CelloNode: only the dialability surface NodeAutoNatService reads.
 * setDialability simulates an AutoNAT probe-cycle update.
 */
class FakeCelloNode {
  #dialability: Dialability;
  readonly #listeners = new Set<(d: Dialability) => void>();
  constructor(initial: Dialability = { dialable: false, publicAddr: null }) {
    this.#dialability = initial;
  }
  getDialability(): Dialability {
    return { ...this.#dialability };
  }
  onDialabilityChange(listener: (d: Dialability) => void): Unsubscribe {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }
  // Test driver: simulate an AutoNAT probe-cycle result.
  setDialability(next: Dialability): void {
    this.#dialability = { ...next };
    for (const l of this.#listeners) l(this.getDialability());
  }
}

function asNode(fake: FakeCelloNode): CelloNode {
  return fake as unknown as CelloNode;
}

const DIR_PROBERS = [
  "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWDirA",
  "/ip4/203.0.113.20/tcp/4001/p2p/12D3KooWDirB",
];

// ─── C2: result event with probers present ───────────────────────────────────

describe("C2: NodeAutoNatService emits transport.autonat.result on each probe", () => {
  it("emitInitialResult logs transport.autonat.result with dialable, publicAddr, nodeType", () => {
    const { logger, events } = makeLogger();
    const node = new FakeCelloNode({ dialable: true, publicAddr: "/ip4/203.0.113.5/tcp/4001/p2p/PEER" });
    const svc = new NodeAutoNatService({ node: asNode(node), logger, nodeType: "standing_receiver", probers: DIR_PROBERS });

    svc.emitInitialResult();

    const result = events.find((e) => e.event === "transport.autonat.result");
    expect(result).toBeDefined();
    expect(result!.level).toBe("info");
    expect(result!.context).toMatchObject({
      dialable: true,
      publicAddr: "/ip4/203.0.113.5/tcp/4001/p2p/PEER",
      nodeType: "standing_receiver",
    });
    // No unavailable WARN when probers are present.
    expect(events.find((e) => e.event === "transport.autonat.unavailable")).toBeUndefined();
    svc.stop();
  });

  it("a probe-cycle dialability change re-emits transport.autonat.result", () => {
    const { logger, events } = makeLogger();
    const node = new FakeCelloNode();
    const svc = new NodeAutoNatService({ node: asNode(node), logger, nodeType: "session", probers: DIR_PROBERS });

    node.setDialability({ dialable: true, publicAddr: "/ip4/198.51.100.7/tcp/4001/p2p/PEER" });

    const results = events.filter((e) => e.event === "transport.autonat.result");
    expect(results).toHaveLength(1);
    expect(results[0]!.context).toMatchObject({
      dialable: true,
      publicAddr: "/ip4/198.51.100.7/tcp/4001/p2p/PEER",
      nodeType: "session",
    });
    svc.stop();
  });
});

// ─── AC-004 / DB-001 / C2: unavailable dual-event when no probers ─────────────

describe("AC-004/DB-001: NodeAutoNatService gates on probers and emits the dual unavailable event", () => {
  it("with NO probers, getDialability is the conservative default and both events fire", () => {
    const { logger, events } = makeLogger();
    // The node itself claims dialable:true — but AutoNAT cannot run without probers,
    // so the service must NOT trust it.
    const node = new FakeCelloNode({ dialable: true, publicAddr: "/ip4/203.0.113.5/tcp/4001/p2p/PEER" });
    const svc = new NodeAutoNatService({ node: asNode(node), logger, nodeType: "standing_receiver", probers: [] });

    expect(svc.getDialability()).toEqual({ dialable: false, publicAddr: null });

    svc.emitInitialResult();

    const result = events.find((e) => e.event === "transport.autonat.result");
    expect(result!.context).toMatchObject({ dialable: false, publicAddr: null, nodeType: "standing_receiver" });
    expect(result!.context["note"]).toMatch(/autonat_unavailable/);

    const unavailable = events.find((e) => e.event === "transport.autonat.unavailable");
    expect(unavailable).toBeDefined();
    expect(unavailable!.level).toBe("warn");
    expect(unavailable!.context).toMatchObject({ nodeType: "standing_receiver" });
    expect(unavailable!.context["directorySignalingStatus"]).toBeDefined();
    svc.stop();
  });
});

// ─── SI-002: rogue prober cannot confirm dialability ──────────────────────────

describe("SI-002: probers are exclusively the injected manifest directory nodes", () => {
  it("a rogue responder is never in the prober set and cannot push dialable:true", () => {
    const { logger } = makeLogger();
    const node = new FakeCelloNode();
    const svc = new NodeAutoNatService({ node: asNode(node), logger, nodeType: "standing_receiver", probers: DIR_PROBERS });

    const rogue = "/ip4/192.0.2.66/tcp/4001/p2p/12D3KooWRogue";
    expect(svc.getProbers()).toEqual(DIR_PROBERS);
    expect(svc.getProbers()).not.toContain(rogue);

    // Simulate the directory dropping (reconnecting) — probers cleared. Even if the
    // node's raw observable later flips to dialable:true (e.g. a rogue dial-back),
    // the gated service stays NOT dialable.
    svc.setProbers([]);
    node.setDialability({ dialable: true, publicAddr: "/ip4/192.0.2.66/tcp/4001/p2p/PEER" });
    expect(svc.getDialability()).toEqual({ dialable: false, publicAddr: null });
    svc.stop();
  });
});

// ─── onChange forwards the gated value; stop() unsubscribes ───────────────────

describe("NodeAutoNatService.onChange / stop", () => {
  it("onChange observers receive the gated dialability and stop() releases the node subscription", () => {
    const { logger } = makeLogger();
    const node = new FakeCelloNode();
    const svc = new NodeAutoNatService({ node: asNode(node), logger, nodeType: "session", probers: DIR_PROBERS });

    const seen: Dialability[] = [];
    const unsub = svc.onChange((d) => seen.push(d));

    node.setDialability({ dialable: true, publicAddr: "/ip4/203.0.113.9/tcp/4001/p2p/PEER" });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({ dialable: true, publicAddr: "/ip4/203.0.113.9/tcp/4001/p2p/PEER" });

    unsub();
    node.setDialability({ dialable: false, publicAddr: null });
    expect(seen).toHaveLength(1); // unsubscribed

    // stop() releases the node subscription — no further service-side emits.
    svc.stop();
    const seenAfterStop: Dialability[] = [];
    svc.onChange((d) => seenAfterStop.push(d));
    node.setDialability({ dialable: true, publicAddr: "/ip4/203.0.113.11/tcp/4001/p2p/PEER" });
    expect(seenAfterStop).toHaveLength(0);
  });
});
