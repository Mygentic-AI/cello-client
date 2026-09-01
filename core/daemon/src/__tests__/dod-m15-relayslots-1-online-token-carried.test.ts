/**
 * DOD-M15-RELAYSLOTS-1 (client half) — the daemon carries the directory's online token to the relay.
 *
 * ─── What this is for ────────────────────────────────────────────────────────────────────────
 *
 * A relay will no longer let a peer keep a circuit reservation slot on the strength of a signature
 * alone — signing is free, so an attacker minted a keypair per slot and took the whole table. It now
 * requires a short-lived token, signed by a directory, saying the key belongs to a registered agent.
 *
 * The daemon's job in that exchange is small and entirely mechanical: the directory hands it the
 * token when it authenticates the signaling stream, and it hands the same bytes to every relay it
 * authenticates to. It never parses them. That is deliberate — a format the client does not read is
 * a format the client cannot get wrong.
 *
 * ─── The two ways this plumbing fails silently, both asserted below ──────────────────────────
 *
 *  1. **The token is never sent.** Everything on the client side looks healthy: the receiver comes
 *     up, reports itself online, and is refused its slot by a relay whose log the operator will
 *     never read. So the assertion is on the bytes the RELAY received, not on a client log line.
 *  2. **The token is captured once and goes stale.** It is short-lived by design and refreshed on
 *     every signaling reconnect, which happens far more often than a relay auth. A snapshot taken at
 *     construction would work for the first hour of an agent's life and then quietly stop.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, createHash } from "node:crypto";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import { AgentRelayClient } from "../session-relay-client.js";
import { ProductionSessionNodeFactory } from "../daemon.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";
import type { Stream } from "@libp2p/interface";
import { seedAgents } from "./helpers/seed-agents.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
const AUTH_DOMAIN = "CELLO-RELAY-AUTH-v1";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn: () => boolean, timeoutMs: number, everyMs = 50): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await wait(everyMs);
  }
  return fn();
}

/**
 * An in-process relay that speaks the auth handshake and records the `online_token` on each
 * response — as hex, so an assertion can name the exact bytes rather than "something arrived".
 */
async function startTokenRecordingRelay(): Promise<{
  node: CelloNode;
  peerId: string;
  addr: string;
  /** One entry per completed auth: the token hex, or `null` when the field was absent. */
  tokensSeen: Array<string | null>;
}> {
  const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  await node.start();
  const tokensSeen: Array<string | null> = [];

  await node.handle(RELAY_PROTOCOL_ID, (stream: Stream) => {
    void (async () => {
      try {
        const nonce = new Uint8Array(32).fill(7);
        stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_challenge", nonce }) as Uint8Array));
        for await (const chunk of lp.decode(stream)) {
          const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
          const frame = decode(bytes) as Record<string, unknown>;
          if (frame["type"] !== "relay_auth_response") continue;
          const pubkey = frame["pubkey"] as Uint8Array;
          const signature = frame["signature"] as Uint8Array;
          // Verify as the real relay does — an unsigned response must not be recorded as an auth.
          const { verify } = await import("@cello-protocol/crypto");
          const authMsg = new Uint8Array(Buffer.concat([Buffer.from(AUTH_DOMAIN, "utf8"), nonce, pubkey]));
          const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
          if (!verify(pubkey, msgHash, signature)) break;
          const tok = frame["online_token"];
          tokensSeen.push(tok instanceof Uint8Array ? Buffer.from(tok).toString("hex") : null);
          stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_ok" }) as Uint8Array));
          break;
        }
      } catch { /* the assertion is on what was recorded, not on teardown */ }
    })();
  });

  const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
  if (!addr) throw new Error("relay node has no addressed multiaddr");
  return { node, peerId: node.getPeerId(), addr, tokensSeen };
}

describe("DOD-M15-RELAYSLOTS-1: the daemon carries the directory's online token to its relay", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-relayslots-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  /** A manager wired the way daemon.ts wires it, with a standing receiver reserving on `relay`. */
  async function managerReservingOn(relay: { peerId: string; addr: string }): Promise<{
    manager: SessionNodeManager;
    agentName: string;
    stop: () => Promise<void>;
  }> {
    const logger = makeLogger();
    const dbPath = join(tempDir, `sessions-${randomUUID()}.db`);
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath,
    });
    await manager.initialize();

    const agentKp = generateKeypair();
    const agentPubkey = await agentKp.getPublicKey();
    // Exactly the shape daemon.ts uses: the composition root holds K_local, and the manager hands
    // the builder everything else the client needs — including the online-token accessor, so a
    // builder cannot construct a client that has no way to reach it.
    manager.setDetachedRelayClientBuilder((_agentName, relayPeerId, relayAddrs, deps) =>
      new AgentRelayClient({
        relayPeerId,
        relayAddrs,
        keyProvider: agentKp,
        senderPubkey: agentPubkey,
        logger,
        receiptStore: deps.receiptStore,
        sealLeafStore: deps.sealLeafStore,
        onlineToken: deps.onlineToken,
      }),
    );

    // Same seeding the sibling proactive-auth test uses: a real `agents` row plus one sealed session
    // naming this relay, which is what makes the standing receiver reserve HERE. No live session is
    // ever created — the reservation alone is what triggers the auth under test.
    const agentName = "TokenCarrier";
    const db = manager.getDb();
    const ids = await seedAgents(db, [agentName]);
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
       VALUES (?, ?, ?, 'sealed', ?, ?, 0, ?, ?)`,
    ).run(randomUUID().replaceAll("-", ""), ids.get(agentName)!, "cc".repeat(32), now, now, relay.peerId, JSON.stringify([relay.addr]));

    return { manager, agentName, stop: async () => { await manager.gracefulShutdown(); } };
  }

  it("★★★ the token the directory issued reaches the relay in the auth response", async () => {
    const relay = await startTokenRecordingRelay();
    const token = new Uint8Array(104).fill(0xa5);

    const { manager, agentName, stop } = await managerReservingOn(relay);
    try {
      manager.setDirectoryOnlineToken(agentName, token);
      await manager.ensureStandingReceiverForAgent(agentName);

      const sawAuth = await waitUntil(() => relay.tokensSeen.length > 0, 15_000);
      expect(sawAuth, "the standing receiver never authenticated at all").toBe(true);
      expect(
        relay.tokensSeen[0],
        "the relay refuses an auth with no online token, so a daemon that does not forward it has " +
          "an agent that comes up, reports itself online, and is reachable by nobody — with the " +
          "only explanation sitting in a relay log the operator will never see.",
      ).toBe(Buffer.from(token).toString("hex"));
    } finally {
      await stop();
      await relay.node.stop();
    }
  }, 40_000);

  it("★★★ a REFRESHED token is the one that gets sent — not the one captured at construction", async () => {
    const relay = await startTokenRecordingRelay();
    const first = new Uint8Array(104).fill(0x11);
    const second = new Uint8Array(104).fill(0x22);

    const { manager, agentName, stop } = await managerReservingOn(relay);
    try {
      manager.setDirectoryOnlineToken(agentName, first);
      await manager.ensureStandingReceiverForAgent(agentName);
      await waitUntil(() => relay.tokensSeen.length > 0, 15_000);

      // The signaling stream turns over far more often than a relay auth, so by the time a receiver
      // re-authenticates the token it was built with is usually gone.
      manager.setDirectoryOnlineToken(agentName, second);
      const before = relay.tokensSeen.length;
      await manager.removeStandingReceiverForAgent(agentName);
      await manager.ensureStandingReceiverForAgent(agentName);

      const sawSecond = await waitUntil(() => relay.tokensSeen.length > before, 15_000);
      expect(sawSecond, "the rebuilt receiver never authenticated").toBe(true);
      expect(
        relay.tokensSeen[relay.tokensSeen.length - 1],
        "these tokens expire in an hour. A client that snapshots one at construction works until " +
          "that hour is up and then loses its slot for reasons nothing on this side reports.",
      ).toBe(Buffer.from(second).toString("hex"));
    } finally {
      await stop();
      await relay.node.stop();
    }
  }, 40_000);

  it("with no token yet, the auth still goes out — the relay's refusal is what the operator needs to see", async () => {
    const relay = await startTokenRecordingRelay();

    const { manager, agentName, stop } = await managerReservingOn(relay);
    try {
      // No setDirectoryOnlineToken: the directory has not answered yet, or this key is unregistered.
      await manager.ensureStandingReceiverForAgent(agentName);

      const sawAuth = await waitUntil(() => relay.tokensSeen.length > 0, 15_000);
      expect(
        sawAuth,
        "declining to try would replace a NAMED relay refusal with silence on both sides. The relay " +
          "answers `online_token_required`, which says what is wrong and what to do about it.",
      ).toBe(true);
      expect(relay.tokensSeen[0]).toBeNull();
    } finally {
      await stop();
      await relay.node.stop();
    }
  }, 40_000);
});
