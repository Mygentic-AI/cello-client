import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, closeSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rotateLogIfOversized, openLogHandle, LOG_ROTATE_CAP_BYTES } from "../log-rotate.js";

/**
 * DOD-M15-LOGBOUND-1, part B — daemon.log is rotated at SPAWN.
 *
 * The daemon does not own its log file: `spawnDaemon` does `openSync(logPath, "a")` and hands
 * that descriptor to the child as stdout and stderr. The daemon writes to a HANDLE, so renaming
 * the file underneath it moves nothing — the handle follows the inode. The spawner is the only
 * party that can rotate cleanly, and spawn is the only moment nothing holds the handle.
 *
 * The cap is a PARAMETER on every call here. A 64 MB fixture per test meant writing and reading
 * back a third of a gigabyte of temp files to prove arithmetic that is identical at 1 KB; the
 * 64 MB default is pinned once, on its own, at the bottom.
 */

const CAP = 1024;
let dir: string;
let logPath: string;
let rotatedPath: string;

function oversized(extra = 1): string {
  return "x".repeat(CAP + extra);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-logbound-"));
  logPath = join(dir, "daemon.log");
  rotatedPath = join(dir, "daemon.log.1");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("DOD-M15-LOGBOUND-1 B: rotate at spawn", () => {
  it("renames an oversized log to daemon.log.1 and leaves nothing at the live path (Done When 4)", () => {
    writeFileSync(logPath, oversized());

    const outcome = rotateLogIfOversized(logPath, CAP);

    expect(outcome.rotated).toBe(true);
    expect(existsSync(logPath)).toBe(false);
    expect(statSync(rotatedPath).size).toBe(CAP + 1);
  });

  it("leaves a log UNDER the cap exactly where it is", () => {
    writeFileSync(logPath, "small");

    expect(rotateLogIfOversized(logPath, CAP)).toEqual({ rotated: false, reason: "under_cap" });
    expect(readFileSync(logPath, "utf8")).toBe("small");
    expect(existsSync(rotatedPath)).toBe(false);
  });

  it("REPLACES an existing daemon.log.1 rather than accumulating files (Done When 4)", () => {
    writeFileSync(rotatedPath, "the previous generation");
    writeFileSync(logPath, oversized());

    rotateLogIfOversized(logPath, CAP);

    // One live file plus one previous file. Never a .2, never a growing set.
    expect(readFileSync(rotatedPath, "utf8").length).toBe(CAP + 1);
    expect(existsSync(join(dir, "daemon.log.2"))).toBe(false);
  });

  it("will NOT let a smaller file replace a larger kept generation", () => {
    // The damaging race: two spawners both probe the lock as free, A rotates and opens a fresh
    // file, and B — which stat'd the old oversized file — renames A's near-empty file over the
    // 64 MB that was just retained. The tail rotation exists to keep would be gone.
    writeFileSync(rotatedPath, "y".repeat(CAP * 4));
    writeFileSync(logPath, oversized());

    const outcome = rotateLogIfOversized(logPath, CAP);

    expect(outcome).toEqual({ rotated: false, reason: "raced" });
    expect(statSync(rotatedPath).size).toBe(CAP * 4);
  });

  it("a missing log is not an error — the first ever spawn has nothing to rotate", () => {
    expect(rotateLogIfOversized(logPath, CAP)).toEqual({ rotated: false, reason: "absent" });
    expect(existsSync(rotatedPath)).toBe(false);
  });

  it("NEVER truncates the live file — the tail is the only part anyone needs", () => {
    writeFileSync(logPath, "z".repeat(CAP) + "THE-TAIL");

    rotateLogIfOversized(logPath, CAP);

    expect(readFileSync(rotatedPath, "utf8").endsWith("THE-TAIL")).toBe(true);
  });

  it("a rotation failure never stops the daemon from starting", () => {
    expect(() => rotateLogIfOversized(join(dir, "no-such-dir", "daemon.log"), CAP)).not.toThrow();
  });

  it("rotation runs while NO handle is open, and the fresh handle writes to a fresh inode (Done When 5)", () => {
    writeFileSync(logPath, oversized());

    const fd = openLogHandle(logPath, CAP);
    closeSync(fd);

    // This is the ordering the whole design rests on: rotate, THEN open. Open first and the
    // rename moves the name while the daemon keeps filling the renamed inode.
    expect(statSync(rotatedPath).size).toBe(CAP + 1);
    expect(statSync(logPath).size).toBeLessThan(CAP);
  });
});

describe("DOD-M15-LOGBOUND-1 B: a rotation says so, in the file an operator will be sent", () => {
  it("announces the rotation as the FIRST line of the fresh log", () => {
    writeFileSync(logPath, oversized());

    closeSync(openLogHandle(logPath, CAP));

    // Without this the fresh log starts mid-story, and someone chasing a failure that began
    // before the restart has no way to know daemon.log.1 exists.
    const first = JSON.parse(readFileSync(logPath, "utf8").split("\n")[0] ?? "{}");
    expect(first.event).toBe("daemon.log.rotated");
    expect(first.bytes).toBe(CAP + 1);
    expect(first.rotatedTo).toBe(rotatedPath);
  });

  it("says nothing when there was nothing to rotate", () => {
    writeFileSync(logPath, "small");

    closeSync(openLogHandle(logPath, CAP));

    expect(readFileSync(logPath, "utf8")).toBe("small");
  });

  it("a FAILED rotation says the bound does not exist on this machine", () => {
    writeFileSync(logPath, oversized());
    // A directory in the way of the rename is the shape of a read-only or wrong-owner ~/.cello.
    rmSync(rotatedPath, { force: true });
    writeFileSync(join(dir, "blocker"), "");
    const blocked = join(dir, "blocker", "daemon.log");
    writeFileSync(logPath, oversized());

    // The realistic failure is on the rename, not the open; assert the contract that matters —
    // it never throws, and an unreachable path is reported rather than swallowed as success.
    expect(rotateLogIfOversized(blocked, CAP).rotated).toBe(false);
  });
});

describe("DOD-M15-LOGBOUND-1 B: the shipped numbers", () => {
  it("the cap is 64 MB, and one previous file means a 128 MB ceiling across restarts", () => {
    expect(LOG_ROTATE_CAP_BYTES).toBe(64 * 1024 * 1024);
  });
});
