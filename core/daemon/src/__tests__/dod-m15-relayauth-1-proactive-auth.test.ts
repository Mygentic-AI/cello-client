/**
 * DOD-M15-RELAYAUTH-1 (client half) — a standing receiver authenticates to its reservation relay
 * as soon as it HAS a reservation, not when a session first needs one.
 *
 * ─── Why this exists ─────────────────────────────────────────────────────────────────────────
 *
 * The relay now time-boxes a reservation held by a peer that has never proven Ed25519 key
 * possession (see relay-connection-gater.ts in trustless-cello — reservations cannot be DENIED at
 * grant time without stranding every brand-new agent, so they are granted and then revoked if
 * unproven). Before this unit the client only ever spoke `/cello/relay/1.0.0` to a relay when a
 * SESSION needed one — which, traced end to end, can be much later than the reservation, against a
 * DIFFERENT relay, or never. A receiver that reserved and then sat quiet would have its
 * reservation reclaimed and go unreachable.
 *
 * ⚠️ Asserting the log line alone would be hollow — a `logger.info` fires whether or not the relay
 * ever saw a byte. This drives a REAL in-process relay node and asserts the relay's own
 * `relay_auth_response` handling ran, by observing the authenticated stream server-side.
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

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; context: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
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
 * An in-process HOP relay that ALSO speaks the CELLO relay auth protocol, recording which pubkeys
 * completed it. Deliberately minimal — the real relay's own half is tested in trustless-cello; what
 * this must prove is that the CLIENT initiates it, unprompted by any session.
 */
async function startAuthRecordingRelay(): Promise<{
  node: CelloNode;
  peerId: string;
  addr: string;
  authenticatedPubkeys: string[];
}> {
  const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  await node.start();
  const authenticatedPubkeys: string[] = [];

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
          // Verify exactly as the relay does — a client that sends a malformed or unsigned
          // response must not be recorded as authenticated.
          const { verify } = await import("@cello-protocol/crypto");
          const authMsg = new Uint8Array(Buffer.concat([Buffer.from(AUTH_DOMAIN, "utf8"), nonce, pubkey]));
          const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
          if (verify(pubkey, msgHash, signature)) {
            authenticatedPubkeys.push(Buffer.from(pubkey).toString("hex"));
            stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_ok" }) as Uint8Array));
          }
          break;
        }
      } catch { /* the stream went away — the assertion is on what was recorded, not on teardown */ }
    })();
  });

  const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
  if (!addr) throw new Error("relay node has no addressed multiaddr");
  return { node, peerId: node.getPeerId(), addr, authenticatedPubkeys };
}

describe("DOD-M15-RELAYAUTH-1: the standing receiver authenticates to its reservation relay proactively", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-relayauth-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  it("★★★ completes relay_auth with NO session in existence — the reservation alone triggers it", async () => {
    const relay = await startAuthRecordingRelay();
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-${randomUUID()}.db`);
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath,
    });
    await manager.initialize();

    // The manager holds no K_local by design — the composition root supplies the relay client,
    // exactly as daemon.ts does in production (setDetachedRelayClientBuilder).
    const agentKp = generateKeypair();
    const agentPubkey = await agentKp.getPublicKey();
    manager.setDetachedRelayClientBuilder((agentName, relayPeerId, relayAddrs, stores) =>
      new AgentRelayClient({
        relayPeerId,
        relayAddrs,
        keyProvider: agentKp,
        senderPubkey: agentPubkey,
        logger,
        receiptStore: stores.receiptStore,
        sealLeafStore: stores.sealLeafStore,
      }),
    );

    try {
      // Seed a relay endpoint so the receiver reserves with THIS relay, then bring the agent up.
      // No session is ever created — that is the whole point.
      const db = manager.getDb();
      const ids = await seedAgents(db, ["alice"]);
      const now = Date.now();
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
         VALUES (?, ?, ?, 'sealed', ?, ?, 0, ?, ?)`,
      ).run(randomUUID().replaceAll("-", ""), ids.get("alice")!, "cc".repeat(32), now, now, relay.peerId, JSON.stringify([relay.addr]));

      await manager.ensureStandingReceiverForAgent("alice");

      const reserved = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(reserved, "precondition: the receiver must actually hold a reservation").toBe(true);

      // THE ASSERTION: the RELAY saw a valid relay_auth_response for this agent's pubkey, with no
      // session ever created. Server-side observation, not a client-side log line.
      const authed = await waitUntil(
        () => relay.authenticatedPubkeys.includes(Buffer.from(agentPubkey).toString("hex")),
        10_000,
      );
      expect(
        authed,
        "the receiver must prove key possession to its reservation relay unprompted — otherwise the " +
          "relay's grace-window revoke reclaims the reservation and the agent goes unreachable",
      ).toBe(true);

      expect(events.some((e) => e.event === "session.standing_receiver.relay_auth.result")).toBe(true);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 30_000);
});
