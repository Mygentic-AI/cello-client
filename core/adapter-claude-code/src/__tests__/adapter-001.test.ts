/**
 * CELLO-ADAPTER-001 — Adapter unit and integration tests
 *
 * AC-001: key file generation and persistence
 * AC-002: inbound message → claude/channel doorbell payload (content-free)
 * AC-003: CelloClient.receive() after onMessageQueued fires
 * SI-001: notification payload never contains message content
 * SI-002: key file written with 0o600
 *
 * DOD-LEGACY-MCP-1 (2026-07-12): AC-004, AC-005, AC-006 and SI-003 were DELETED. They asserted the
 * tool registry, the `cello_status` response shape, and the capability declaration of
 * `createMcpServer` — the legacy in-process MCP server, now gone. Their subject no longer exists.
 * (The live `cello_status` is the daemon's, proxied by `bin/cello-mcp.ts`, and is tested there.)
 *
 * AC-002 was RE-POINTED, not deleted. It used to drive the dead server and assert on the MCP wire.
 * What it actually guards is live: that `client.ts` fires `onMessageQueued` with the SENDER's pubkey,
 * and that the doorbell payload `buildChannelParams` builds from it is CONTENT-FREE (INV-CONTENTFREE
 * / SI-001 — the operator's message text must never ride the wake-up). Both survive; only the dead
 * MCP delivery leg is gone, so the test now calls the live producer directly.
 */

import {
  setupV3Tests,
  createTestScope,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  waitFor,
} from "@claude-flow/testing";
import type { TestScope } from "@claude-flow/testing";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stat, rm, mkdir } from "node:fs/promises";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { createClient } from "@cello-protocol/client";
import { buildChannelParams } from "../channel-params.js";

setupV3Tests();

let scope: TestScope;
beforeEach(() => { scope = createTestScope(); });
afterEach(() => scope.run(async () => {}));

// ─── AC-001 / SI-002: key file generation and 0o600 permissions ───────────────

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

// ─── AC-002 / SI-001: inbound message → content-free doorbell payload ──────────
// Two real libp2p nodes, two real CelloClients, a real send. The hook that fires is live
// (`client.ts` → onMessageQueued) and the payload builder is live (`channel-params.ts`). The dead
// MCP server used to sit between them; it added nothing this test asserts.

describe("AC-002 + SI-001: an inbound message produces a content-free claude/channel doorbell", () => {
  it("AC-002: onMessageQueued fires with the SENDER's pubkey and builds {type:'cello_message', from}; no message text anywhere", async () => {
    const kpA = generateKeypair();
    const kpB = generateKeypair();
    const nodeA = await createNode({ keyProvider: kpA, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    const nodeB = await createNode({ keyProvider: kpB, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await nodeA.start();
    await nodeB.start();
    scope.addCleanup(async () => { try { await nodeA.stop(); } catch {} });
    scope.addCleanup(async () => { try { await nodeB.stop(); } catch {} });

    const ownPubkeyA = Buffer.from(await kpA.getPublicKey()).toString("hex");
    const ownPubkeyB = Buffer.from(await kpB.getPublicKey()).toString("hex");

    // The doorbell payloads the live hook would push. This is exactly what `bin/cello-mcp.ts` sends
    // on the wire — it calls buildChannelParams and hands the result to server.notification().
    const doorbells: Array<ReturnType<typeof buildChannelParams>> = [];

    const clientB = createClient(nodeB, kpB, {
      onMessageQueued: (from) => { doorbells.push(buildChannelParams({ type: "cello_message", from })); },
    });
    await clientB.registerHandler();

    const clientA = createClient(nodeA, kpA);
    await clientA.registerHandler();

    const dialResult = await nodeA.dial(nodeB.listenAddresses()[0]!);
    clientA.addPeer(ownPubkeyB, dialResult.peerId, nodeB.listenAddresses());

    await clientA.send(ownPubkeyB, new TextEncoder().encode("hello"));

    await waitFor(() => doorbells.length > 0, { timeout: 5000 });

    const params = doorbells[0]!;

    // Claude Code channel contract: params MUST carry `content` (the <channel> tag body) — without
    // it the event is silently dropped and the doorbell never surfaces (BUILD-JOURNAL Entry 43).
    expect(typeof params.content).toBe("string");
    expect((params.content as string).length).toBeGreaterThan(0);
    // Routing rides in `meta` (becomes <channel> attributes): exactly type + from here.
    expect(params.meta?.type).toBe("cello_message");
    // The hook must report the SENDER, not the receiver. Getting this backwards would wake the agent
    // pointing at itself.
    expect(params.meta?.from).toBe(ownPubkeyA);
    expect(params.meta?.from).not.toBe(ownPubkeyB);
    expect(Object.keys(params.meta ?? {}).sort()).toEqual(["from", "type"]);
    // SI-001 / INV-CONTENTFREE: the announcement carries NO message text — the operator sent
    // "hello"; it must not appear anywhere in the pushed payload (content or meta).
    expect(params.content as string).not.toContain("hello");
    expect(JSON.stringify(params.meta)).not.toContain("hello");
  }, 20_000);
});

// ─── AC-003: CelloClient.receive() works after onMessageQueued fires ───────────

describe("AC-003: CelloClient.receive() returns message after onMessageQueued fires", () => {
  it("AC-003: receive after onMessageQueued fires returns message with correct sender pubkey", async () => {
    const kpA = generateKeypair();
    const kpB = generateKeypair();
    const nodeA = await createNode({ keyProvider: kpA, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    const nodeB = await createNode({ keyProvider: kpB, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await nodeA.start();
    await nodeB.start();
    scope.addCleanup(async () => { try { await nodeA.stop(); } catch {} });
    scope.addCleanup(async () => { try { await nodeB.stop(); } catch {} });

    const ownPubkeyA = Buffer.from(await kpA.getPublicKey()).toString("hex");
    const ownPubkeyB = Buffer.from(await kpB.getPublicKey()).toString("hex");
    let notified = false;

    const clientB = createClient(nodeB, kpB, { onMessageQueued: () => { notified = true; } });
    await clientB.registerHandler();
    const clientA = createClient(nodeA, kpA);
    await clientA.registerHandler();

    // Dial and register peer at client level (M0 path, not via MCP tool)
    const dialResult = await nodeA.dial(nodeB.listenAddresses()[0]!);
    clientA.addPeer(ownPubkeyB, dialResult.peerId, nodeB.listenAddresses());

    await clientA.send(ownPubkeyB, new TextEncoder().encode("ping"));

    await waitFor(() => notified, { timeout: 5000 });

    // Receive via CelloClient.receive() directly (M0 API still works at client level)
    const envelope = clientB.receive(ownPubkeyA);
    expect(envelope).not.toBeNull();
    const content = new TextDecoder().decode(envelope!.content);
    expect(content).toBe("ping");
  }, 20_000);
});
