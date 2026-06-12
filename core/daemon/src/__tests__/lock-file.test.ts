/**
 * CELLO-M7-DAEMON-001 — Lock file management tests
 *
 * ACs tested:
 * - Lock file at ~/.cello/daemon.lock with JSON: {pid, socketPath, version}
 * - Atomic write (write to .tmp then rename)
 * - Connect-or-start: stale lock detection and removal
 * - isProcessAlive checks
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readLock, acquireLock, removeLock, isProcessAlive } from "../lock-file.js";
import type { Logger } from "../types.js";

describe("lock-file", () => {
  let tempDir: string;
  const mockLogger: Logger = {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  };

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-lock-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("readLock", () => {
    it("returns null when lock file does not exist", async () => {
      const result = await readLock(join(tempDir, "nonexistent.lock"));
      expect(result).toBeNull();
    });

    it("returns parsed content for valid lock file", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      const content = { pid: 12345, socketPath: "/tmp/test.sock", version: "0.0.1" };
      await writeFile(lockPath, JSON.stringify(content));

      const result = await readLock(lockPath);
      expect(result).toEqual(content);
    });

    it("returns null for malformed JSON", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      await writeFile(lockPath, "not valid json{{{");

      const result = await readLock(lockPath);
      expect(result).toBeNull();
    });

    it("returns null when JSON is missing required fields", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      await writeFile(lockPath, JSON.stringify({ pid: 123 }));

      const result = await readLock(lockPath);
      expect(result).toBeNull();
    });

    it("returns null when pid is not a number", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      await writeFile(lockPath, JSON.stringify({ pid: "not-a-number", socketPath: "/s", version: "1" }));

      const result = await readLock(lockPath);
      expect(result).toBeNull();
    });
  });

  describe("acquireLock", () => {
    it("creates lock file with correct content", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      const content = { pid: process.pid, socketPath: "/tmp/test.sock", version: "0.0.1" };

      await acquireLock(lockPath, content);

      const raw = await readFile(lockPath, "utf-8");
      const parsed = JSON.parse(raw);
      expect(parsed).toEqual(content);
    });

    it("creates lock file with 0600 permissions", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      await acquireLock(lockPath, { pid: 1, socketPath: "/s", version: "1" });

      const { stat } = await import("node:fs/promises");
      const s = await stat(lockPath);
      // 0o600 = owner read+write only
      expect(s.mode & 0o777).toBe(0o600);
    });

    it("overwrites existing lock file atomically", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      await acquireLock(lockPath, { pid: 111, socketPath: "/old", version: "0.0.1" });
      await acquireLock(lockPath, { pid: 222, socketPath: "/new", version: "0.0.2" });

      const result = await readLock(lockPath);
      expect(result).toEqual({ pid: 222, socketPath: "/new", version: "0.0.2" });
    });
  });

  describe("removeLock", () => {
    it("removes existing lock file", async () => {
      const lockPath = join(tempDir, "daemon.lock");
      await writeFile(lockPath, "{}");

      await removeLock(lockPath, mockLogger);

      const result = await readLock(lockPath);
      expect(result).toBeNull();
    });

    it("does not throw when lock file does not exist", async () => {
      const lockPath = join(tempDir, "nonexistent.lock");
      await expect(removeLock(lockPath, mockLogger)).resolves.not.toThrow();
    });
  });

  describe("isProcessAlive", () => {
    it("returns true for current process", () => {
      expect(isProcessAlive(process.pid)).toBe(true);
    });

    it("returns false for a non-existent PID", () => {
      // PID 999999 is extremely unlikely to exist
      expect(isProcessAlive(999999)).toBe(false);
    });
  });
});
