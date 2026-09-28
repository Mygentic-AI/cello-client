/**
 * 008-POLICY clauses 16, 23, 24, 25 — `cello policy propose|pending|approve|list` against a REAL
 * daemon over its IPC socket, with only the terminal prompt injected (the `gatewayConfigSet`
 * precedent: the prompt is the one thing a test cannot supply). The pseudo-terminal run against a
 * separate daemon process is the live smoke, quoted in the order.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle, type Logger } from "@cello-protocol/daemon";
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import { createAgent } from "../commands.js";
import { policyApprove, policyList, policyPending, policyPropose } from "../parity-commands.js";

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
});
