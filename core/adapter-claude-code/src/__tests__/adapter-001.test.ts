/**
 * CELLO-ADAPTER-001 — key file generation and persistence
 *
 * AC-001: key file generation and persistence
 * SI-002: key file written with 0o600
 *
 * DEAD-CODE PURGE (2026-07-13): AC-002 and AC-003 were DELETED. They drove `createClient` from
 * `@cello-protocol/client` — the M6-era in-process client, now deleted in full. Nothing at runtime
 * constructed it: the shipped path is `bin/cello-mcp.ts` (a stdio→IPC proxy) in front of the daemon,
 * and the daemon reimplements the protocol natively ("the daemon never imports
 * @cello-protocol/client" — daemon.ts). Those two cases drove real libp2p and a real send/receive —
 * of an implementation no operator runs.
 *
 * Nothing they guarded is lost. The doorbell payload contract they touched (`buildChannelParams`:
 * content-free body, routing-only meta, INV-CONTENTFREE) is asserted directly, with no client, in
 * `adapter-002.test.ts` (AC-002 + the SI-001 tripwire). The real send/receive path over the SHIPPED
 * binaries is covered by the live spine in trustless-cello (`packages/e2e-tests/src/spine/`), which
 * spawns the actual daemon, MCP shim, directory and relay as processes.
 *
 * What remains is the only thing in this file that was ever about live code: FileKeyProvider.
 */

import {
  setupV3Tests,
  createTestScope,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import type { TestScope } from "@claude-flow/testing";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stat, rm, mkdir } from "node:fs/promises";
import { FileKeyProvider } from "@cello-protocol/crypto";

setupV3Tests();

let scope: TestScope;
beforeEach(() => { scope = createTestScope(); });
afterEach(() => scope.run(async () => {}));

describe("AC-001 + SI-002: key file generation and persistence", () => {
  it("AC-001a: no key file → generates one with 0o600; same pubkey on reload", async () => {
    const dir = join(tmpdir(), `cello-test-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    scope.addCleanup(async () => { try { await rm(dir, { recursive: true }); } catch {} });

    const keyPath = join(dir, "key");

    const kp1 = await FileKeyProvider.load(keyPath);
    const pubkey1 = Buffer.from(await kp1.getPublicKey()).toString("hex");

    const kp2 = await FileKeyProvider.load(keyPath);
    const pubkey2 = Buffer.from(await kp2.getPublicKey()).toString("hex");

    expect(pubkey1).toBe(pubkey2);
  });

  it("SI-002: key file written with 0o600 permissions", async () => {
    const dir = join(tmpdir(), `cello-test-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    scope.addCleanup(async () => { try { await rm(dir, { recursive: true }); } catch {} });

    const keyPath = join(dir, "key");
    await FileKeyProvider.load(keyPath);

    const s = await stat(keyPath);
    // mode & 0o777 strips file type bits; 0o600 = owner read+write only
    expect(s.mode & 0o777).toBe(0o600);
  });
});
