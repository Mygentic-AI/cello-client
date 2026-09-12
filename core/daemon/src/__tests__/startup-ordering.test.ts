/**
 * STARTUP ORDER IS A CORRECTNESS CONSTRAINT. These tests pin it.
 *
 * WHY THESE ARE SOURCE-ORDER TESTS AND NOT BEHAVIOUR TESTS — read this before "improving" them.
 *
 * The bug they exist to prevent (introduced by the 2026-07-13 daemon decomposition, caught in
 * review, fixed in 5f2dfad): the eager per-agent directory connect got moved BELOW
 * `await flushAwaitingContent()`. That await does real relay network I/O, sequentially, for every
 * parked item. Below it, every agent's directory handshake — `directory.signaling.authenticated`,
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
import { existsSync, readFileSync, readdirSync } from "node:fs";
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
   * ⚠️ THIS IS THE FOURTH VERSION, AND EACH REWRITE CLOSED A HOLE THE PREVIOUS ONE HID. A hand-typed
   * list of thirteen names missed the sixteen `register*Handlers` sites. A derived list filtered to
   * `create|startBoot|register` missed SEVEN more — `startRegistryPoll`, `startRosterSweep`,
   * `startManifestValidityWatch`, `startHttpManifestPoll` and the three `wire*Handler`s — four of
   * which are sweeps or polls, the same category as the bug that caused this test to exist. And an
   * EXEMPT entry claimed `registerInitiateSessionHandler` was wired elsewhere when it is called from
   * the root, so the one verb the guard skipped was the one that starts every session.
   *
   * The third version was checking 72 names against a ratchet of 31, so most of the sweep could be
   * switched off without a red run; it could not see the twenty-four `acquire|poll|run|open|ensure|
   * load|migrate|bootstrap|connect` exports at all; and its string filter matched nothing in the
   * whole corpus. The fixes are the exact corpus count, the widened verb list, and blanking string
   * contents rather than dropping lines — each documented at the line that carries it.
   */
  const SRC_DIR = join(import.meta.dirname, "..");
  const CORE_DIR = join(SRC_DIR, "..", "..");

  /**
   * An entry needs a reason AND a red run that proves it. Each of these three was produced by a red
   * run, and two of them are findings in their own right rather than exceptions.
   */
  const EXEMPT: Record<string, string> = {
    // A test seam, not dead-but-tolerated: reachable ONLY from `__tests__`, which this scan
    // deliberately does not read — counting a test as a caller is how a deleted production call site
    // reads green, which is the entire failure this guard exists for. So it cannot be discovered,
    // and it cannot be silently dropped either; naming it here is the record.
    //
    // Two entries left with it on 2026-09-07 by being DELETED rather than exempted:
    // `wireContentHashHex` (a homonym — `wire` the noun) and `bootstrapNetworkKeyShares` (which threw
    // "uses trustedDealer which is test-only" as its first statement). Both were dead in both repos.
    // An EXEMPT entry is where a discovery goes to be forgotten; deleting is the better close.
    openEncryptedDatabaseAtPath: "test seam — production opens via openEncryptedDatabase(celloDir); only __tests__ (both repos) pass an explicit path.",
  };

  function sourcesUnder(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
      if (e.isDirectory()) return e.name === "__tests__" ? [] : sourcesUnder(join(dir, e.name));
      return e.name.endsWith(".ts") ? [join(dir, e.name)] : [];
    });
  }

  const FILES = sourcesUnder(SRC_DIR);

  /**
   * CALLERS is every production source in `core/*​/src`, not just the daemon's own.
   *
   * The daemon is a LIBRARY as well as a process — `connectOrStart` is exported from `index.ts` and
   * called from `core/cli/src/commands.ts`, so a daemon-only scan reported the function that decides
   * whether `cello login` connects or spawns as never called. Widening can only turn red into green,
   * never the reverse, and it makes the scan agree with what actually runs.
   *
   * `__tests__` stays out on purpose: a test calling a factory is not the factory running in
   * production, and letting one count is exactly how a deleted call site reads green.
   */
  const CALLER_FILES = readdirSync(CORE_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(CORE_DIR, e.name, "src")))
    .flatMap((e) => sourcesUnder(join(CORE_DIR, e.name, "src")));

  /**
   * A CALL, not a mention. Comments and string CONTENTS are removed before the search.
   */
  const CALLERS = CALLER_FILES.map((f) => readFileSync(f, "utf-8"))
    .join("\n")
    // Block comments FIRST — commenting a call site out is the natural way a unit gets reverted,
    // and a guard that reads `/* was createX() here *​/` as a call is worse than no guard.
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .map((l) => l.replace(/\/\/.*$/, ""))
    /**
     * String contents are BLANKED IN PLACE — never stripped, and no line is ever dropped.
     *
     * Two earlier versions of this step were wrong in opposite directions. Deleting whole strings ate
     * real code the moment an apostrophe appeared in prose, and reported wired modules as dead; a
     * false alarm is how a guard gets ignored. The version that replaced it — dropping lines ENDING
     * in `"name(` — matched zero lines in the whole corpus, so the hole it claimed to close was
     * still open: deleting a call site and leaving `logger.debug("wireDisconnectCleanup() was here")`
     * behind kept this test green.
     *
     * Blanking the contents has neither failure. By this point comments are already gone, so an
     * apostrophe can only be inside a string, which is precisely what is being emptied.
     *
     * The one shape left uncovered is a template literal containing `${...}` — those are skipped
     * whole, because `${createX()}` is a REAL call and blanking it would be the apostrophe bug again.
     * A mention parked inside an interpolated template still reads as a call. Narrow, and the safe
     * side of the trade.
     */
    .map((l) =>
      l
        .replace(/"(?:[^"\\]|\\.)*"/g, '""')
        .replace(/'(?:[^'\\]|\\.)*'/g, "''")
        .replace(/`(?:[^`\\$]|\\.)*`/g, "``"),
    )
    .join("\n");

  /**
   * WIRING verbs, not every export. The first version filtered to `create|startBoot|register` and
   * missed seven live call sites; the second stopped at the boot verbs and could not see the twenty-
   * four `acquire|poll|run|open|ensure|load|migrate|bootstrap|connect` exports at all — among them
   * `acquireSingletonLock`, which is what keeps two daemons off one SQLCipher write lock. Both
   * declaration shapes are matched, because an arrow factory would otherwise be invisible to the
   * discovery half AND to the call half.
   *
   * ─── ⚠️ WHAT THIS PROVES IS REACHABILITY, NOT THAT EVERY CALL SITE SURVIVES ───────────────────
   *
   * A caller inside the defining file counts. `acquireSingletonLock` is the worked example: delete
   * its call in `daemon.ts` and this stays green, because `probeSingletonLock` two hundred lines
   * below still calls it. The daemon would boot with no lock; what notices is
   * `dod-single-daemon-1.test.ts`, which spawns a real second process.
   *
   * Excluding the defining file was tried and is worse: it turns 3 exemptions into 11, because eight
   * exports are legitimately called by a sibling in their own module (`startRegistryPoll` →
   * `pollRegistryOverHttp`) or only from the OTHER repo (`buildRelayAuthPayload` and the wire-format
   * builders, which the directory and relay consume). Eight standing false alarms is how a guard
   * stops being read.
   */
  const WIRING =
    /^(create|start|register|wire|make|build|install|mount|attach|setup|init|acquire|poll|run|open|ensure|load|migrate|bootstrap|connect)[A-Z]/;
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
    /**
     * ⚠️ EXACT, and it has to be. This was `toBeGreaterThanOrEqual(31)` against a real corpus of 72 —
     * 41 names of slack — which made the one regression the comment named the one it could not catch.
     * Measured, not argued: dropping `create` from WIRING above silently stopped checking 37 of the
     * 72, dropping `register` stopped checking all sixteen handler modules, and dropping `start`
     * stopped checking every sweep and poll — the exact bug class this file was written for. All
     * three left the suite green.
     *
     * Raise the number deliberately when a module is added. That is what makes a DROP visible.
     */
    // 94 → 96 across 043-SIGNALDELIVERY C: trust-signal-pickup-listener.ts (C1) and
    // trust-signal-sweep.ts (C2). Raised deliberately, and both are modules this guard exists for —
    // C1's listener was registered inline on one stream type and nowhere else, so the visiting
    // connection dropped every pickup, and C2's sweep is useless the moment nothing calls it.
    // "A factory that exists and is not wired" is precisely the defect this order is closing.
    //
    // 96 → 97 for 048-SWEEPTICK's trust-signal-sweep-tick.ts, and this guard caught the addition on
    // the first full run. The module is the single most on-point occupant of this corpus: C2's sweep
    // WAS wired, to one trigger, and the defect was that nothing ran it often enough to matter — so
    // a ticker that exists and is not reached from the composition root would restore the exact bug
    // it was written to remove. `sweeptick.test.ts` carries the companion assertion that daemon.ts
    // hands the wiring the TICKING sweep rather than the bare one.
    //
    // 97 → 99 for 051-LOGBOUND: `createCollapsingLogger` (log-collapse.ts) and `openLogHandle`
    // (log-rotate.ts). This guard caught both on the first full run, and for this unit that is
    // more than bookkeeping — BOTH of them are silent when unwired. A collapser that is built and
    // not wrapped around the composition root leaves the log growing exactly as before, and a
    // rotate-then-open that is written but never reached at spawn leaves the file unbounded; in
    // neither case does anything fail, warn, or look different until someone measures the file
    // months later. That is the shape this corpus exists to catch.
    //
    // 99 → 100 for 074-DOCSFLAG's `wireDocumentGate` (document-gate-wiring.ts), and this guard caught
    // it on the first full run. It is the most literal occupant of the corpus to date: the module's
    // whole job is to decide whether the document layer is constructed, so a version of it that is
    // never called leaves fourteen IPC verbs registered and a 120-second timer running — the exact
    // state the order exists to end — with nothing failing and nothing looking different.
    expect(exporters.size, `wiring factories discovered: ${exporters.size}`).toBe(100);
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
