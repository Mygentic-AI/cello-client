/**
 * STARTUP ORDER IS A CORRECTNESS CONSTRAINT. These tests pin it.
 *
 * WHY THESE ARE SOURCE-ORDER TESTS AND NOT BEHAVIOUR TESTS — read this before "improving" them.
 *
 * The bug they exist to prevent (introduced by the 2026-07-13 daemon decomposition, caught in
 * review, fixed in 5f2dfad): the eager per-agent directory connect got moved BELOW
 * `await flushAwaitingContent()`. That await does real relay network I/O, sequentially, for every
 * parked item. Below it, every agent's directory handshake — `directory.signaling.connected`,
 * `agent.online`, the standing receiver — is serialized behind the entire drain. On a daemon
 * booting with parked content and a slow or unreachable relay, agents come online late and NOTHING
 * in the log says the relay is the reason. Above it, the two overlap, as they always did.
 *
 * The full suite passed the whole time it was broken, and it could not have failed:
 *
 *   1. The connect loop is guarded `if (!sharedSignaling)`. Every in-process test injects a
 *      signalingConnect, which SETS sharedSignaling — so the loop never executes under test at all.
 *      Only the production path (a real directoryEndpointResolver, per-agent streams) runs it.
 *   2. Even driving that path, the defect is a LATENCY regression, not a wrong answer. Everything
 *      still works; it just works late. There is no assertion a functional test would naturally make
 *      that goes red.
 *
 * So a behavioural test would need a live libp2p signaling stack stood up purely to observe an
 * ordering property of the source. The property IS the source order. Assert it there, honestly,
 * rather than build an elaborate rig that pins it by accident.
 *
 * These are deliberately crude, and they have teeth: move the connect loop back below the flush and
 * the first one goes red immediately. That is the entire job.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const DAEMON_SRC = readFileSync(join(import.meta.dirname, "../daemon.ts"), "utf-8");

/** Index of the first line matching `needle`, or -1. Line-based so a stray match in a comment elsewhere is unlikely. */
function lineOf(needle: string): number {
  const lines = DAEMON_SRC.split("\n");
  return lines.findIndex((l) => l.includes(needle) && !l.trim().startsWith("//") && !l.trim().startsWith("*"));
}

describe("startDaemon ordering — constraints the type system cannot express", () => {
  it("the eager per-agent connect runs BEFORE `await flushAwaitingContent()`, so handshakes overlap the relay drain", () => {
    const connect = lineOf("getAgentSignaling(agent.name, agent.keyProvider, agent.pubkey)");
    const flush = lineOf("await flushAwaitingContent();");

    expect(connect, "the boot-time per-agent connect loop must exist").toBeGreaterThan(-1);
    expect(flush, "the startup flush must exist").toBeGreaterThan(-1);

    // THE ASSERTION. Below the flush, every agent's directory handshake is serialized behind a
    // sequential relay drain — agents come online late, and the log never blames the relay.
    expect(
      connect,
      `The per-agent connect loop (daemon.ts:${connect + 1}) must run BEFORE ` +
      `await flushAwaitingContent() (daemon.ts:${flush + 1}). Below it, a daemon booting with parked ` +
      `content and a slow relay delays EVERY agent coming online by the whole drain, silently. ` +
      `If you moved the loop down to escape a temporal-dead-zone error, that is the wrong fix: ` +
      `split the module it needs into construction + registration (see content-park.ts) and move ` +
      `the CONSTRUCTION up instead.`,
    ).toBeLessThan(flush);
  });

  it("the inbound-session module is CONSTRUCTED before the connect loop that wires into it", () => {
    const construct = lineOf("= createInboundSessions({");
    const connect = lineOf("getAgentSignaling(agent.name, agent.keyProvider, agent.pubkey)");

    expect(construct).toBeGreaterThan(-1);

    // The loop's signaling wiring calls wirePerAgentSessionInbound. That used to be a HOISTED
    // function declaration, which is what silently allowed it to be called ~2,600 lines before its
    // definition. It is a const now, so it must genuinely exist first — otherwise every loaded agent
    // crashes the daemon at boot with "cannot access before initialization" (it did: 253 red tests).
    expect(
      construct,
      "createInboundSessions() must be constructed before the per-agent connect loop wires into it — " +
      "the wiring is no longer a hoisted function declaration, so calling it earlier is a TDZ crash.",
    ).toBeLessThan(connect);
  });

  it("handler REGISTRATION happens after the handler map exists — the other half of the two-phase split", () => {
    const map = lineOf("const handlers = new Map<string, IpcHandler>()");
    const registerInbound = lineOf("registerInboundSessionHandlers(handlers)");
    const registerPark = lineOf("contentPark.registerHandlers(handlers)");

    expect(map).toBeGreaterThan(-1);
    // Both modules are constructed early (they have boot-time callers) but register late. That
    // separation is precisely what lets construction move above the flush without dragging the
    // handler map — and the whole daemon — up with it.
    expect(registerInbound, "inbound-session handlers register after the map exists").toBeGreaterThan(map);
    expect(registerPark, "content-park handlers register after the map exists").toBeGreaterThan(map);
  });

  it("the content park is CONSTRUCTED before its boot-time callers (autoRecoverForAgent)", () => {
    const construct = lineOf("= createContentPark({");
    const sealCoordinator = lineOf("= createSealCoordinator({");

    expect(construct).toBeGreaterThan(-1);
    // autoRecoverForAgent is handed to the seal coordinator as its content-recovery gate, and is
    // also called from an agent's onConnected. Both run before the handler map exists, which is why
    // the park is two-phase at all.
    expect(
      construct,
      "createContentPark() must precede createSealCoordinator(), which takes autoRecoverForAgent as a dep.",
    ).toBeLessThan(sealCoordinator);
  });
});
