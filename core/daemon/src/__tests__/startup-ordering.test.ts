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
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const DAEMON_SRC = readFileSync(join(import.meta.dirname, "../daemon.ts"), "utf-8");
// 040-DAEMONROOT unit 5: `getAgentSignaling` — and the `onConnected` callback that delegates to the
// reconnect drain — moved into signaling-wiring.ts. The ORDERING constraints below are still about
// daemon.ts; only the delegation itself is read from the module that now contains it.
const WIRING_SRC = readFileSync(join(import.meta.dirname, "../signaling-wiring.ts"), "utf-8");
// 040-DAEMONROOT unit 7 (phase 2): the reconnect drain and the content park are constructed inside
// boot-agents.ts now. The ORDER between them is still the constraint; only the file moved.
const BOOT_AGENTS_SRC = readFileSync(join(import.meta.dirname, "../boot-agents.ts"), "utf-8");

/** Index of the first line matching `needle`, or -1. Line-based so a stray match in a comment elsewhere is unlikely. */
function lineOf(needle: string, src: string = DAEMON_SRC): number {
  const lines = src.split("\n");
  return lines.findIndex((l) => l.includes(needle) && !l.trim().startsWith("//") && !l.trim().startsWith("*"));
}

describe("every module this daemon exports a factory for is actually WIRED", () => {
  /**
   * 040-DAEMONROOT turned inline statements into call sites, and a call site can be deleted while
   * the module still compiles, still ships, and still passes its own tests. Unit 9 shipped exactly
   * that: deleting the revival sweep's call left 5,036 tests green while the sweep never ran.
   *
   * ⚠️ THIS IS THE THIRD VERSION, AND EACH REWRITE CLOSED A HOLE THE PREVIOUS ONE HID. A hand-typed
   * list of thirteen names missed the sixteen `register*Handlers` sites. A derived list filtered to
   * `create|startBoot|register` missed SEVEN more — `startRegistryPoll`, `startRosterSweep`,
   * `startManifestValidityWatch`, `startHttpManifestPoll` and the three `wire*Handler`s — four of
   * which are sweeps or polls, the same category as the bug that caused this test to exist. And an
   * EXEMPT entry claimed `registerInitiateSessionHandler` was wired elsewhere when it is called from
   * the root, so the one verb the guard skipped was the one that starts every session.
   *
   * So: EVERY `export function` in the corpus, no prefix filter, and EXEMPT stays empty until a red
   * run proves an entry necessary.
   */
  const SRC_DIR = join(import.meta.dirname, "..");

  /**
   * An entry needs a reason AND a red run that proves it. One entry, and it is a HOMONYM rather than
   * an exception: `wireContentHashHex` is about the WIRE FORMAT, not about wiring something up. The
   * red run that produced it also found something worth knowing — the function has no caller
   * anywhere in either repo, is not re-exported from the package index, and is referenced by no
   * test. It is dead, and deleting it is a job for an order that is allowed to delete.
   */
  const EXEMPT: Record<string, string> = {
    wireContentHashHex: "not wiring — 'wire' here means the wire format. Separately: it is DEAD, no caller in either repo.",
  };

  function sourcesUnder(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
      if (e.isDirectory()) return e.name === "__tests__" ? [] : sourcesUnder(join(dir, e.name));
      return e.name.endsWith(".ts") ? [join(dir, e.name)] : [];
    });
  }

  const FILES = sourcesUnder(SRC_DIR);

  /**
   * A CALL, not a mention. Block comments and string literals are stripped before the search:
   * commenting a call site out is the natural way a unit gets reverted, and a guard that reads
   * `/* was createX() here *​/` as a call is worse than no guard.
   */
  const CALLERS = FILES.map((f) => readFileSync(f, "utf-8"))
    .join("\n")
    // Block comments FIRST — commenting a call site out is the natural way a unit gets reverted,
    // and a guard that reads `/* was createX() here *​/` as a call is worse than no guard.
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .map((l) => l.replace(/\/\/.*$/, ""))
    // A call is never preceded by a quote on its own line. Whole-string stripping was tried and is
    // NOT safe here: an apostrophe in prose or a multi-line template ate real code and reported
    // wired modules as dead — a false alarm is how a guard gets ignored.
    .filter((l) => !/["'`]\s*\w+\s*\($/.test(l.trim()))
    .join("\n");

  /**
   * WIRING verbs, not every export. The previous version filtered to `create|startBoot|register`
   * and missed seven live call sites; this covers the verbs this codebase actually uses to mean
   * "this does something at boot". Both declaration shapes are matched, because an arrow factory
   * would otherwise be invisible to the discovery half AND to the call half.
   */
  const WIRING = /^(create|start|register|wire|make|build|install|mount|attach|setup|init)[A-Z]/;
  const exporters = new Set<string>();
  for (const file of FILES) {
    const src = readFileSync(file, "utf-8");
    for (const m of src.matchAll(/^export (?:async )?function (\w+)/gm)) {
      if (WIRING.test(m[1]!)) exporters.add(m[1]!);
    }
    for (const m of src.matchAll(/^export const (\w+)\s*=\s*(?:async\s*)?\(/gm)) {
      if (WIRING.test(m[1]!)) exporters.add(m[1]!);
    }
  }
  const checked = [...exporters].filter((n) => !EXEMPT[n]).sort();

  it("the corpus is the size it was when this ratchet was set — a shrinking sweep is a silent hole", () => {
    // EXACT, like max-lines, and for the same reason: a regex that stops matching makes the loop
    // SHORTER, never red. Raise it when modules are added; a DROP is the thing to look at.
    expect(exporters.size, `wiring factories discovered: ${exporters.size}`).toBeGreaterThanOrEqual(31);
    expect(
      exporters.size - checked.length,
      "EXEMPT has grown — every entry needs a reason and a red run that proves it",
    ).toBe(1);
  });

  for (const name of checked) {
    it(`something calls ${name}`, () => {
      const called = new RegExp(`(?<!function )(?<!const )\\b${name}\\s*\\(`).test(CALLERS);
      expect(
        called,
        `${name} is exported and never called. The module compiles, ships, and passes its own tests; ` +
        `what it does not do is run. If that is deliberate, put it in EXEMPT with the reason.`,
      ).toBe(true);
    });
  }
});

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

  it("DOD-PARK-DRAIN-1: onConnected DELEGATES to the reconnect drain — it does not re-inline two voids", () => {
    const construct = lineOf("= createReconnectDrain({", BOOT_AGENTS_SRC);
    const delegate = lineOf("onSignalingConnected(agentName)", WIRING_SRC);
    const hook = lineOf("sessionNodeManager.setParkedDrainHook(", BOOT_AGENTS_SRC);

    expect(construct, "createReconnectDrain() must be constructed in the boot-agents phase").toBeGreaterThan(-1);
    expect(hook, "the parked-drain hook must be wired — an unwired hook reverts the whole unit").toBeGreaterThan(-1);

    // THE ASSERTION. The ensure→drain ORDER is the contract, and it lives in reconnect-drain.ts
    // precisely so a refactor of this 3,000-line file cannot quietly turn it back into two
    // concurrent `void`s — which is what it was when the drain lost the race 102 times in one log
    // (2026-08-04). If onConnected stops delegating, the module still passes its own unit tests
    // and production silently regresses. This is the line that notices.
    expect(
      delegate,
      "getAgentSignaling's onConnected must call onSignalingConnected(agentName) — the ensure→drain " +
      "ordering contract lives in reconnect-drain.ts, not inline here.",
    ).toBeGreaterThan(-1);
    // The two now live in different files, so a line comparison would compare nothing. What has to
    // hold is that the root still CONSTRUCTS the drain and passes it in — a module that resolved the
    // drain itself would be the re-inlining this test exists to prevent.
    expect(
      DAEMON_SRC,
      "the composition root must still hand onSignalingConnected to the signaling wiring — if the " +
      "module reaches for the drain itself, the ensure→drain contract stops being the root's to keep.",
    ).toContain("onSignalingConnected,");
  });

  it("the content park is CONSTRUCTED before its boot-time callers (autoRecoverForAgent)", () => {
    // The park moved into boot-agents.ts; the seal coordinator is still in the root. What has to
    // hold is unchanged — the park exists before the coordinator that takes autoRecoverForAgent —
    // and it is now guaranteed by construction rather than by line order: the phase RETURNS the
    // recovery function, so the root cannot reach it before the phase has run.
    const construct = lineOf("= createContentPark({", BOOT_AGENTS_SRC);
    const sealCoordinator = lineOf("= createSealCoordinator({");

    expect(construct).toBeGreaterThan(-1);
    // autoRecoverForAgent is handed to the seal coordinator as its content-recovery gate, and is
    // also called from an agent's onConnected. Both run before the handler map exists, which is why
    // the park is two-phase at all.
    expect(sealCoordinator, "the seal coordinator must still be constructed in the root").toBeGreaterThan(-1);
    // THE ASSERTION, and it is a line comparison again on purpose. A first cut replaced it with
    // "the root mentions autoRecoverForAgent", which is position-independent: moving the phase call
    // below the coordinator left all three assertions green. Both needles live in daemon.ts — the
    // phase CALL and the coordinator — so the original constraint translates directly.
    const phaseCall = lineOf("await startBootAgents(");
    expect(phaseCall, "the boot-agents phase must be called in the composition root").toBeGreaterThan(-1);
    expect(
      phaseCall,
      "startBootAgents() must run BEFORE createSealCoordinator(), which takes autoRecoverForAgent " +
      "as a dep. Below it, the coordinator reads a value the phase has not produced yet.",
    ).toBeLessThan(sealCoordinator);
  });
});
