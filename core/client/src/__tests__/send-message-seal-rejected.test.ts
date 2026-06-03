/**
 * sendMessage on seal_rejected session → session_sealed
 *
 * Verifies that the #sendMessageLocked guard includes seal_rejected.
 * A seal_rejected session is permanently closed — sendMessage must return
 * session_sealed (not transport_unavailable or session_not_found).
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
import { randomBytes } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { createClient } from "../client.js";
import type { CelloClient } from "../types.js";

setupV3Tests();

let scope: TestScope;
beforeEach(() => { scope = createTestScope(); });
afterEach(() => scope.run(async () => {}));

type ClientWithEscapes = CelloClient & {
  injectTestSession(
    sessionIdHex: string,
    sessionId: Uint8Array,
    myPubkeyHex: string,
    directoryPubkey: Uint8Array,
    status?: string,
  ): void;
};

describe("sendMessage on seal_rejected session returns session_sealed", () => {
  it("sendMessage on a seal_rejected session returns { ok: false, reason: 'session_sealed' }", async () => {
    const kp = generateKeypair();
    const node = await createNode({ keyProvider: kp, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const client = createClient(node, kp) as unknown as ClientWithEscapes;
    await client.registerHandler();

    const sessionId = new Uint8Array(randomBytes(16));
    const sessionIdHex = Buffer.from(sessionId).toString("hex");
    const myPubkeyHex = Buffer.from(await kp.getPublicKey()).toString("hex");

    client.injectTestSession(sessionIdHex, sessionId, myPubkeyHex, new Uint8Array(32), "seal_rejected");

    const result = await client.sendMessage(sessionIdHex, new TextEncoder().encode("hello"));

    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toBe("session_sealed");
  });
});
