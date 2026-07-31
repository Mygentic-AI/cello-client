/**
 * DOD-M9B-SURFACE-1 — the CLI confirmation flow. The reviewer found this entirely untested: the
 * `prompt` parameter of `gatewayConfigSet` existed for injection and nothing in the repo ever
 * called it, so the two-phase flow, the declined path and the non-TTY refusal were all unproven.
 *
 * These drive a REAL daemon over its real IPC socket, with only the prompt injected — because the
 * prompt is the one thing a test genuinely cannot supply (there is no human).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { startDaemon, type DaemonHandle, type Logger } from "@cello-protocol/daemon";
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import { gatewayConfigSet, gatewayConfigGet } from "../parity-commands.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/**
 * What the operator actually reads. A refusal renders to STDERR, a success to STDOUT — so a test
 * that only looked at stdout would silently miss every failure path, which is the half of this
 * surface that matters most.
 */
function emitted(out: { stdout: string; stderr: string }): Record<string, unknown> {
  const text = out.stdout.trim() || out.stderr.trim();
  return JSON.parse(text) as Record<string, unknown>;
}

describe("DOD-M9B-SURFACE-1 — the CLI two-phase confirmation", () => {
  let dir: string;
  let handle: DaemonHandle | undefined;

  /** Read the stored state back through the PUBLIC surface — no reaching into the store file. */
  const storedVersion = async (key: string): Promise<number> => {
    return emitted(await gatewayConfigGet(dir, key, {})).version as number;
  };

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-m9b-cliconfirm-"));
    await mkdir(join(dir, "agents"), { recursive: true });
    // The store is opened with the daemon's key; seed it so the handlers can reach it.
    await writeFile(join(dir, "sessions.db.key"), randomBytes(32), { mode: 0o600 });
    handle = await startDaemon({
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 8,
      version: "0.0.1-test",
      logger: silent,
      securityGateway: new PassthroughGatewayClient(),
    });
  });
  afterEach(async () => {
    if (handle) { await handle.stop("test"); handle = undefined; }
    await rm(dir, { recursive: true, force: true });
  });

  it("a NON-TTY caller gets not_a_tty with the command to run — never 'declined'", async () => {
    let prompted = false;
    const out = await gatewayConfigSet(dir, "autonomous_override", "true", {}, async () => {
      prompted = true;
      return "no_tty";
    });
    const res = emitted(out);

    expect(prompted).toBe(true);
    // The distinction the reviewer flagged: a CI job or an agent was never SHOWN a prompt, so
    // telling it the operator declined is a lie about what happened.
    expect(res.reason).toBe("not_a_tty");
    expect(String(res.guidance)).toContain("cello config set autonomous_override true");

    // Version 0 means no row was ever written — the refusal persisted nothing.
    expect(await storedVersion("autonomous_override")).toBe(0);
  }, 30_000);

  it("a human who says NO leaves the guard unchanged, and no row is written", async () => {
    const out = await gatewayConfigSet(dir, "autonomous_override", "true", {}, async () => "no");
    const res = emitted(out);
    expect(res.reason).toBe("declined");

    expect(await storedVersion("autonomous_override")).toBe(0);
  }, 30_000);

  it("a human who says YES applies the loosening, and the row is marked confirmed", async () => {
    const out = await gatewayConfigSet(dir, "autonomous_override", "true", {}, async () => "yes");
    const res = emitted(out);
    expect(res.ok).toBe(true);
    expect(res.direction).toBe("loosen");
    expect(res.confirmed).toBe(true);

    expect(await storedVersion("autonomous_override")).toBe(1);
    const got = emitted(await gatewayConfigGet(dir, "autonomous_override", {}));
    expect(got.value).toBe(true);
    expect(got.confirmed).toBe(true);
  }, 30_000);

  it("a TIGHTENING never reaches the prompt at all", async () => {
    // Get it loose first, so the next call is unambiguously a tightening.
    await gatewayConfigSet(dir, "autonomous_override", "true", {}, async () => "yes");

    let prompted = false;
    const out = await gatewayConfigSet(dir, "autonomous_override", "false", {}, async () => {
      prompted = true;
      return "yes";
    });
    const res = emitted(out);
    expect(res.ok).toBe(true);
    expect(res.direction).toBe("tighten");
    expect(prompted, "tightening must not ask permission — it is always allowed").toBe(false);
  }, 30_000);

  it("the prompt is shown the CURRENT value, so a list replacement cannot hide what it drops", async () => {
    await gatewayConfigSet(dir, "pii_whitelist", "a@x.example,b@x.example", {}, async () => "yes");

    let question = "";
    await gatewayConfigSet(dir, "pii_whitelist", "c@x.example", {}, async (q) => {
      question = q;
      return "no";
    });
    // Without the `from` value the operator would see only "c@x.example" and never learn that two
    // entries are about to disappear.
    expect(question).toContain("a@x.example");
    expect(question).toContain("b@x.example");
    expect(question).toContain("c@x.example");
  }, 30_000);
});
