import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, openSync, closeSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rotateLogIfOversized, LOG_ROTATE_CAP_BYTES } from "../log-rotate.js";

/**
 * DOD-M15-LOGBOUND-1, part B — daemon.log is rotated at SPAWN.
 *
 * The daemon does not own its log file: `spawnDaemon` does `openSync(logPath, "a")` and hands
 * that descriptor to the child as stdout and stderr. The daemon writes to a HANDLE, so renaming
 * the file underneath it moves nothing — the handle follows the inode. The spawner is the only
 * party that can rotate cleanly, and spawn is the only moment nothing holds the handle.
 */

let dir: string;
let logPath: string;
let rotatedPath: string;

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
    writeFileSync(logPath, "x".repeat(LOG_ROTATE_CAP_BYTES + 1));

    const rotated = rotateLogIfOversized(logPath, LOG_ROTATE_CAP_BYTES);

    expect(rotated).toBe(true);
    expect(existsSync(logPath)).toBe(false);
    expect(statSync(rotatedPath).size).toBe(LOG_ROTATE_CAP_BYTES + 1);
  });

  it("leaves a log UNDER the cap exactly where it is", () => {
    writeFileSync(logPath, "small");

    expect(rotateLogIfOversized(logPath, LOG_ROTATE_CAP_BYTES)).toBe(false);
    expect(readFileSync(logPath, "utf8")).toBe("small");
    expect(existsSync(rotatedPath)).toBe(false);
  });

  it("REPLACES an existing daemon.log.1 rather than accumulating files (Done When 4)", () => {
    writeFileSync(rotatedPath, "the previous generation");
    writeFileSync(logPath, "y".repeat(LOG_ROTATE_CAP_BYTES + 1));

    rotateLogIfOversized(logPath, LOG_ROTATE_CAP_BYTES);

    // One live file plus one previous file. Never a .2, never a growing set.
    expect(readFileSync(rotatedPath, "utf8").length).toBe(LOG_ROTATE_CAP_BYTES + 1);
    expect(existsSync(join(dir, "daemon.log.2"))).toBe(false);
  });

  it("a missing log is not an error — the first ever spawn has nothing to rotate", () => {
    expect(rotateLogIfOversized(logPath, LOG_ROTATE_CAP_BYTES)).toBe(false);
    expect(existsSync(rotatedPath)).toBe(false);
  });

  it("NEVER truncates the live file — the tail is the only part anyone needs", () => {
    const content = "z".repeat(LOG_ROTATE_CAP_BYTES) + "THE-TAIL";
    writeFileSync(logPath, content);

    rotateLogIfOversized(logPath, LOG_ROTATE_CAP_BYTES);

    // Every byte survives under the rotated name. A truncation of the live file would either
    // race the writer or throw away exactly the part being read.
    expect(readFileSync(rotatedPath, "utf8").endsWith("THE-TAIL")).toBe(true);
  });

  it("a rotation failure never stops the daemon from starting", () => {
    writeFileSync(logPath, "q".repeat(LOG_ROTATE_CAP_BYTES + 1));

    // An unwritable directory is the realistic failure. The contract is that it returns false
    // rather than throwing: a daemon that will not start because it could not tidy its log is
    // a worse outcome than an oversized log.
    expect(() => rotateLogIfOversized(join(dir, "no-such-dir", "daemon.log"), LOG_ROTATE_CAP_BYTES)).not.toThrow();
  });

  it("rotation runs while NO handle is open, and the fresh handle writes to a fresh inode (Done When 5)", () => {
    writeFileSync(logPath, "w".repeat(LOG_ROTATE_CAP_BYTES + 1));

    rotateLogIfOversized(logPath, LOG_ROTATE_CAP_BYTES);
    const fd = openSync(logPath, "a");
    try {
      writeFileSync(fd, "first line after rotation\n");
    } finally {
      closeSync(fd);
    }

    // This is the ordering the whole design rests on: rotate, THEN open. Open first and the
    // rename moves the name while the daemon keeps filling the renamed inode.
    expect(readFileSync(logPath, "utf8")).toBe("first line after rotation\n");
    expect(readFileSync(rotatedPath, "utf8").length).toBe(LOG_ROTATE_CAP_BYTES + 1);
  });

  it("the cap is 64 MB, and one previous file means a 128 MB ceiling across restarts", () => {
    expect(LOG_ROTATE_CAP_BYTES).toBe(64 * 1024 * 1024);
  });
});
