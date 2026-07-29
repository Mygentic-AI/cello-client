/**
 * DOD-M9C-STORE-1 — the gateway bin REFUSES to start half-configured.
 *
 * The reviewer proved this guard was hollow: deleting it left every test in both repos green. It
 * is also the guard that carried the empty-string hole — `CELLO_GATEWAY_STORE_DB=""` with a valid
 * key file passed a `=== undefined` check and then produced NO stores, so the gateway screened
 * every message with no audit trail and no config governance while printing READY as if healthy.
 *
 * These spawn the REAL bin, because the behaviour under test is the process's exit code.
 */
import { describe, it, expect, beforeEach, beforeAll, afterEach } from "vitest";
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
/** The BUILT bin — the artifact that actually ships and the one the daemon spawns. */
const BIN = join(PKG_ROOT, "dist", "bin", "cello-gateway.js");

/** Run the bin with `env` and resolve its exit code plus stderr. */
function runBin(env: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf8"); });
    // A bin that wrongly starts would run forever; kill it and report what it did.
    const timer = setTimeout(() => child.kill("SIGKILL"), 20_000);
    child.once("exit", (code) => { clearTimeout(timer); resolve({ code, stderr }); });
  });
}

describe("DOD-M9C-STORE-1 — the bin refuses half-configured storage", () => {
  let dir: string;
  let keyPath: string;

  beforeAll(() => {
    execFileSync("npx", ["tsc", "--build"], { cwd: PKG_ROOT, stdio: "pipe", timeout: 180_000 });
  }, 200_000);

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-m9c-bin-"));
    keyPath = join(dir, "store.key");
    await writeFile(keyPath, randomBytes(32), { mode: 0o600 });
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("REFUSES (exit 2) when the store path is set but the key file path is not", async () => {
    const { code, stderr } = await runBin({
      CELLO_GATEWAY_SOCKET: join(dir, "gw.sock"),
      CELLO_GATEWAY_STORE_DB: join(dir, "gateway.db"),
      CELLO_GATEWAY_STORE_KEY_FILE: "",
    });
    expect(code).toBe(2);
    expect(stderr).toContain("must be set together");
  }, 40_000);

  it("REFUSES (exit 2) when the store path is EMPTY but a key file is given — the silent-no-store hole", async () => {
    // Before the `|| undefined` normalisation this exited 0 with both stores absent: READY, and
    // not one security record for the rest of the process's life.
    const { code, stderr } = await runBin({
      CELLO_GATEWAY_SOCKET: join(dir, "gw.sock"),
      CELLO_GATEWAY_STORE_DB: "",
      CELLO_GATEWAY_STORE_KEY_FILE: keyPath,
    });
    expect(code).toBe(2);
    expect(stderr).toContain("must be set together");
  }, 40_000);

  it("a MISSING key file is a refusal that NAMES ITSELF — code and guidance both reach stderr", async () => {
    const { code, stderr } = await runBin({
      CELLO_GATEWAY_SOCKET: join(dir, "gw.sock"),
      CELLO_GATEWAY_STORE_DB: join(dir, "gateway.db"),
      CELLO_GATEWAY_STORE_KEY_FILE: join(dir, "absent.key"),
    });
    expect(code).toBe(1);
    expect(stderr).toContain("store_key_unavailable");     // the CAUSE, not an exit-point label
    expect(stderr).toContain("never falls back to a plaintext store"); // the guidance survived
  }, 40_000);
});
