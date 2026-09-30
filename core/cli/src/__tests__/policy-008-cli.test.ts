/**
 * 008-POLICY clauses 16, 23, 24, 25 — `cello policy propose|pending|approve|list` against a REAL
 * daemon over its IPC socket, with only the terminal prompt injected (the `gatewayConfigSet`
 * precedent: the prompt is the one thing a test cannot supply). The pseudo-terminal run against a
 * separate daemon process is the live smoke, quoted in the order.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";
import { startDaemon, type DaemonHandle, type Logger } from "@cello-protocol/daemon";
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import { createAgent } from "../commands.js";
import {
  policyApprove, policyList, policyPending, policyPropose, gatewayConfigSet, gatewayConfigGet,
  policyExpiryPhrase, PROPOSAL_TTL_MS,
} from "../parity-commands.js";

/**
 * Swap `process.stdin` for a fake interactive TTY that answers the prompt the moment the command
 * subscribes. `answer` is the line typed (`"\n"` is a bare Enter, `"maybe"` a stray key); `null` is
 * end-of-input (Ctrl-D). Restores the real stdin afterwards. This exercises the REAL prompt helpers
 * through their public path, which is what proves the mapping from a keystroke to an outcome.
 */
async function withFakeTty<T>(answer: string | null, fn: () => Promise<T>): Promise<T> {
  const fake = new EventEmitter() as unknown as NodeJS.ReadStream & { once: EventEmitter["once"] };
  (fake as unknown as { isTTY: boolean }).isTTY = true;
  (fake as unknown as { resume: () => void }).resume = () => {};
  (fake as unknown as { pause: () => void }).pause = () => {};
  (fake as unknown as { setEncoding: () => void }).setEncoding = () => {};
  const realOnce = EventEmitter.prototype.once.bind(fake);
  (fake as unknown as { once: EventEmitter["once"] }).once = ((event: string, cb: (...a: unknown[]) => void) => {
    realOnce(event, cb as (...a: unknown[]) => void);
    if (answer !== null && event === "data") queueMicrotask(() => fake.emit("data", answer));
    if (answer === null && event === "end") queueMicrotask(() => fake.emit("end"));
    return fake;
  }) as EventEmitter["once"];
  const orig = Object.getOwnPropertyDescriptor(process, "stdin");
  Object.defineProperty(process, "stdin", { value: fake, configurable: true });
  try {
    return await fn();
  } finally {
    if (orig) Object.defineProperty(process, "stdin", orig);
  }
}

/** Capture everything written to the real stderr while `fn` runs — the "Left pending" lines land there. */
async function withStderrCapture<T>(fn: () => Promise<T>): Promise<{ result: T; stderr: string }> {
  const chunks: string[] = [];
  const orig = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: unknown) => boolean }).write = (s: unknown) => {
    chunks.push(String(s));
    return true;
  };
  try {
    const result = await fn();
    return { result, stderr: chunks.join("") };
  } finally {
    (process.stderr as unknown as { write: typeof orig }).write = orig;
  }
}

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
type R = Record<string, unknown>;
const out = (o: { stdout: string; stderr: string }): R => JSON.parse(o.stdout.trim() || o.stderr.trim()) as R;

describe("008-POLICY — the CLI's propose → approve at a terminal", () => {
  let dir: string;
  let handle: DaemonHandle | undefined;
  const opts = { agent: "alice" };

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-policy-cli-"));
    handle = await startDaemon({
      celloDir: dir, socketPath: join(dir, "daemon.sock"), lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 8, version: "0.0.1-test", logger: silent, securityGateway: new PassthroughGatewayClient(),
    });
    await createAgent(dir, "alice");
  });
  afterEach(async () => {
    if (handle) { await handle.stop("test"); handle = undefined; }
    await rm(dir, { recursive: true, force: true });
  });

  const tierKnown = async (): Promise<unknown> =>
    ((out(await policyList(dir, opts))["winning"] as { tiers: Record<string, R> }).tiers["known"]!["conduct"]);

  it("23: `y` applies it; the prompt shows level, type, cadence, was: and now: with the real texts", async () => {
    expect(out(await policyPropose(dir, ["tier", "known", "conduct", "--text", "OLD RULE"], opts))).toMatchObject({ ok: true, proposal_id: "p1" });
    await policyApprove(dir, "p1", opts, async () => "yes");
    const p = out(await policyPropose(dir, ["tier", "known", "conduct", "--text", "NEW RULE", "--every", "4"], opts));
    expect(p).toMatchObject({ ok: true, proposal_id: "p2", proposed_by: "operator" });
    expect(await tierKnown()).toEqual({ level: "tier", text: "OLD RULE" });

    let question = "";
    const res = out(await policyApprove(dir, undefined, opts, async (q) => { question = q; return "yes"; }));
    expect(res).toMatchObject({ ok: true });
    expect(question).toContain("tier known");
    expect(question).toContain("conduct");
    expect(question).toContain("every 4 messages");
    expect(question).toMatch(/was:\s+OLD RULE/);
    expect(question).toMatch(/now:\s+NEW RULE/);
    expect(await tierKnown()).toEqual({ level: "tier", text: "NEW RULE" });
    expect(out(await policyPending(dir, opts))["pending"]).toEqual([]);
  }, 30_000);

  it("23: `n` discards it — store unchanged, proposal gone", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "NEVER"], opts);
    const res = out(await policyApprove(dir, "p1", opts, async () => "no"));
    expect(res).toMatchObject({ ok: true });
    expect(await tierKnown()).toBeNull();
    expect(out(await policyPending(dir, opts))["pending"]).toEqual([]);
  }, 30_000);

  it("24: without a TTY → not_a_tty naming the command; store unchanged, proposal still pending", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "X"], opts);
    const o = await policyApprove(dir, "p1", opts, async () => "no_tty");
    expect(o.exitCode).toBe(1);
    const res = out(o);
    expect(res).toMatchObject({ ok: false, reason: "not_a_tty" });
    expect(String(res["guidance"])).toContain("cello policy approve p1");
    expect(await tierKnown()).toBeNull();
    expect((out(await policyPending(dir, opts))["pending"] as R[]).map((x) => x["proposal_id"])).toEqual(["p1"]);
  }, 30_000);

  it("25: --none and --clear are proposals too, and channel-default maps to its scope", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "T"], opts);
    await policyApprove(dir, "p1", opts, async () => "yes");
    await policyPropose(dir, ["tier", "known", "conduct", "--clear"], opts);
    expect(await tierKnown()).toEqual({ level: "tier", text: "T" });
    await policyApprove(dir, "p2", opts, async () => "yes");
    expect(await tierKnown()).toBeNull();
    const n = out(await policyPropose(dir, ["channel-default", "conduct", "--none"], opts));
    expect(n).toMatchObject({ ok: true, scope: "channel_default", mode: "none" });
  }, 30_000);

  it("a malformed propose is refused before it reaches the daemon", async () => {
    const o = await policyPropose(dir, ["tier", "known", "conduct"], opts);
    expect(o.exitCode).toBe(1);
    expect(out(o)).toMatchObject({ ok: false, reason: "policy_value_missing" });
  }, 30_000);

  // ─── 085-POLICYSKIP: a decision can be put off without discarding the draft ──────────────────

  it("085: a bare Enter leaves the draft pending — no approve, no decline, and it says when it expires", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "KEEP ME"], opts);
    const { result, stderr } = await withStderrCapture(() =>
      withFakeTty("\n", () => policyApprove(dir, "p1", opts)));
    const res = out(result);
    expect(res).toMatchObject({ ok: true });
    expect((res["results"] as R[])[0]).toMatchObject({ proposal_id: "p1", outcome: "skipped" });
    // Nothing was applied and nothing was discarded: the draft is still in force-less limbo, listed.
    expect(await tierKnown()).toBeNull();
    expect((out(await policyPending(dir, opts))["pending"] as R[]).map((x) => x["proposal_id"])).toEqual(["p1"]);
    expect(stderr).toContain("Left pending. p1 expires in");
    expect(stderr).toContain("cello policy approve p1 --agent alice");
  }, 30_000);

  it("085: Ctrl-D and a stray answer (`maybe`) skip exactly like Enter", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "KEEP ME"], opts);
    // End-of-input.
    const eof = out(await withFakeTty(null, () => policyApprove(dir, "p1", opts)));
    expect((eof["results"] as R[])[0]).toMatchObject({ outcome: "skipped" });
    expect(await tierKnown()).toBeNull();
    // A stray typed key is never read as yes or no.
    const stray = out(await withFakeTty("maybe", () => policyApprove(dir, "p1", opts)));
    expect((stray["results"] as R[])[0]).toMatchObject({ outcome: "skipped" });
    expect(await tierKnown()).toBeNull();
    expect((out(await policyPending(dir, opts))["pending"] as R[]).map((x) => x["proposal_id"])).toEqual(["p1"]);
  }, 30_000);

  it("085: only a typed `y` approves and only a typed `n` discards", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "APPLIED"], opts);
    const yes = out(await withFakeTty("y", () => policyApprove(dir, "p1", opts)));
    expect((yes["results"] as R[])[0]).toMatchObject({ outcome: "approved" });
    expect(await tierKnown()).toEqual({ level: "tier", text: "APPLIED" });

    await policyPropose(dir, ["tier", "unknown", "conduct", "--text", "GONE"], opts);
    const no = out(await withFakeTty("n", () => policyApprove(dir, "p2", opts)));
    expect((no["results"] as R[])[0]).toMatchObject({ outcome: "declined" });
    expect(out(await policyPending(dir, opts))["pending"]).toEqual([]);
  }, 30_000);

  it("085: walking three drafts y/s/n gives approved, skipped, declined — the skipped one stays pending", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "A"], opts);
    await policyPropose(dir, ["tier", "unknown", "conduct", "--text", "B"], opts);
    await policyPropose(dir, ["default", "admission", "--text", "C"], opts);
    const answers: Array<"yes" | "skip" | "no"> = ["yes", "skip", "no"];
    let i = 0;
    const res = out(await policyApprove(dir, undefined, opts, async () => answers[i++]!));
    expect(res).toMatchObject({ ok: true });
    expect((res["results"] as R[]).map((r) => r["outcome"])).toEqual(["approved", "skipped", "declined"]);
    expect((out(await policyPending(dir, opts))["pending"] as R[]).map((x) => x["proposal_id"])).toEqual(["p2"]);
  }, 30_000);

  it("085: an all-skipped run is ok:true and its guidance says nothing changed and how many are pending", async () => {
    await policyPropose(dir, ["tier", "known", "conduct", "--text", "A"], opts);
    await policyPropose(dir, ["tier", "unknown", "conduct", "--text", "B"], opts);
    const res = out(await policyApprove(dir, undefined, opts, async () => "skip"));
    expect(res).toMatchObject({ ok: true });
    expect((res["results"] as R[]).every((r) => r["outcome"] === "skipped")).toBe(true);
    expect(String(res["guidance"])).toMatch(/nothing was changed/i);
    expect(String(res["guidance"])).toContain("2");
    expect((out(await policyPending(dir, opts))["pending"] as R[]).length).toBe(2);
  }, 30_000);

  it("085 regression: `cello config set` for a weakening change still reads a bare Enter as NO and stores nothing", async () => {
    // Drives the UNCHANGED confirmAtTty through its public path — its own default prompt, a real TTY,
    // a bare Enter. A weakening change (autonomous_override → true) must stay declined on Enter.
    const before = out(await gatewayConfigGet(dir, "autonomous_override", opts));
    const res = out(await withFakeTty("\n", () =>
      gatewayConfigSet(dir, "autonomous_override", "true", opts)));
    expect(res).toMatchObject({ ok: false });
    expect(out(await gatewayConfigGet(dir, "autonomous_override", opts))).toEqual(before);
  }, 30_000);

  it("085: expiry text clamps to `expires now` and never goes negative; ttl is pinned to the daemon's", () => {
    expect(policyExpiryPhrase(23 * 60 * 60 * 1000 + 50 * 60 * 1000)).toBe("expires in 0h 10m");
    expect(policyExpiryPhrase(25 * 60 * 60 * 1000)).toBe("expires now");
    expect(policyExpiryPhrase(PROPOSAL_TTL_MS)).toBe("expires now");
    // Pin the CLI's copy against the daemon's source constant so the two cannot drift.
    const here = dirname(fileURLToPath(import.meta.url));
    const daemonSrc = readFileSync(join(here, "..", "..", "..", "daemon", "src", "policy-proposals.ts"), "utf8");
    const m = daemonSrc.match(/export const PROPOSAL_TTL_MS\s*=\s*([^;]+);/);
    expect(m, "daemon PROPOSAL_TTL_MS not found — the pin lost its anchor").not.toBeNull();
    const daemonTtl = eval(m![1]!) as number;
    expect(PROPOSAL_TTL_MS).toBe(daemonTtl);
  });
});
