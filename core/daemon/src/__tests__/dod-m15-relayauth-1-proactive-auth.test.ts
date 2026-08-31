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
  /**
   * ⚠️ **PEER IDS, NOT JUST PUBKEYS — and the distinction IS the review finding.** Every standing
   * receiver an agent builds signs with the SAME K_local, so a pubkey-only record cannot tell the
   * first receiver from its replacement. The relay's reservation gate keys on the TRANSPORT peer
   * id, so that is what has to be observed: HIGH-1 was precisely that the replacement receiver's
   * peer id never appeared here, while the pubkey did (from the first one).
   */
  authenticatedPeerIds: string[];
  /** Whether each auth declared itself a reservation proof — it must not claim the delivery stream. */
  purposes: Array<string | undefined>;
  /**
   * Session ids this relay was handed a `client_record_assignment` for. HIGH-2's subject: the relay
   * that gates inbound circuit dials must hold the assignment authorizing them, and it is not
   * always the relay the directory named.
   */
  recordedSessionIds: string[];
}> {
  const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  await node.start();
  const authenticatedPubkeys: string[] = [];
  const authenticatedPeerIds: string[] = [];
  const purposes: Array<string | undefined> = [];
  const recordedSessionIds: string[] = [];

  await node.handle(RELAY_PROTOCOL_ID, (stream: Stream, remotePeerId?: string) => {
    void (async () => {
      try {
        const nonce = new Uint8Array(32).fill(7);
        stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_challenge", nonce }) as Uint8Array));
        let authed = false;
        for await (const chunk of lp.decode(stream)) {
          const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
          const frame = decode(bytes) as Record<string, unknown>;
          if (!authed) {
            if (frame["type"] !== "relay_auth_response") continue;
            const pubkey = frame["pubkey"] as Uint8Array;
            const signature = frame["signature"] as Uint8Array;
            // Verify exactly as the relay does — a client that sends a malformed or unsigned
            // response must not be recorded as authenticated.
            const { verify } = await import("@cello-protocol/crypto");
            const authMsg = new Uint8Array(Buffer.concat([Buffer.from(AUTH_DOMAIN, "utf8"), nonce, pubkey]));
            const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
            if (!verify(pubkey, msgHash, signature)) break;
            authenticatedPubkeys.push(Buffer.from(pubkey).toString("hex"));
            if (remotePeerId) authenticatedPeerIds.push(remotePeerId);
            const purpose = typeof frame["purpose"] === "string" ? (frame["purpose"] as string) : undefined;
            purposes.push(purpose);
            stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_ok" }) as Uint8Array));
            authed = true;
            // A reservation proof says nothing further — mirrors the real relay, which closes here.
            if (purpose === "reservation") break;
            continue;
          }
          if (frame["type"] === "client_record_assignment") {
            const sid = frame["session_id"];
            if (sid instanceof Uint8Array) recordedSessionIds.push(Buffer.from(sid).toString("hex"));
            stream.send(lp.encode.single(CBOR_ENC.encode({ type: "assignment_ok" }) as Uint8Array));
          }
        }
      } catch { /* the stream went away — the assertion is on what was recorded, not on teardown */ }
    })();
  });

  const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
  if (!addr) throw new Error("relay node has no addressed multiaddr");
  return { node, peerId: node.getPeerId(), addr, authenticatedPubkeys, authenticatedPeerIds, purposes, recordedSessionIds };
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

      /**
       * ⚠️ AWAITED, not asserted directly. The relay records the auth the moment it VERIFIES it;
       * the client writes this line only after the ack has round-tripped back. So the server-side
       * observation above can legitimately land first, and asserting this synchronously failed
       * under full-suite load while passing when the file ran alone — a race in the test, not in
       * the product (the assertion that matters, the relay seeing the proof, had already passed).
       */
      const logged = await waitUntil(
        () => events.some((e) => e.event === "session.standing_receiver.relay_auth.result"),
        5_000,
      );
      expect(logged, "the client must report the outcome of its own reservation proof").toBe(true);

      // It must declare itself a reservation proof — otherwise the relay would rebind this agent's
      // delivery target to whichever receiver authenticated last, stealing a live session's leaves.
      expect(relay.purposes).toContain("reservation");
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 30_000);

  it("★★★ the REPLACEMENT receiver authenticates too — the case a shared relay client silently skipped", async () => {
    /**
     * ⚠️ **THIS IS THE CASE THAT WAS BROKEN, AND THE FIRST TEST COULD NOT SEE IT.**
     *
     * The first test covers the very first receiver, when no relay client exists yet — the one
     * situation the defect did NOT affect. Once a session starts, the standing receiver is promoted
     * into it and a REPLACEMENT is built behind it. Both share one `AgentRelayClient` (cached per
     * agent+relay), and the original fix called `connect()`, which returns immediately when the
     * client already holds a stream — the promoted node's. So the replacement sent nothing, the
     * relay never saw its transport identity, and its reservation was revoked ~15s later: the agent
     * churned reserve→revoke→rebuild for the life of the conversation and was unreachable to anyone
     * trying to start a second session with it.
     *
     * Asserting on PEER IDS is what makes this test able to fail: both receivers sign with the same
     * K_local, so a pubkey assertion stays green on the first receiver's auth alone.
     */
    const relay = await startAuthRecordingRelay();
    const { logger } = makeLogger();
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
      const db = manager.getDb();
      const ids = await seedAgents(db, ["alice"]);
      const now = Date.now();
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
         VALUES (?, ?, ?, 'sealed', ?, ?, 0, ?, ?)`,
      ).run(randomUUID().replaceAll("-", ""), ids.get("alice")!, "cc".repeat(32), now, now, relay.peerId, JSON.stringify([relay.addr]));

      await manager.ensureStandingReceiverForAgent("alice");
      await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      const firstPeerId = manager.getStandingReceiverInfo("alice")?.peerId;
      expect(firstPeerId, "precondition: a first receiver exists").toBeTruthy();
      await waitUntil(() => relay.authenticatedPeerIds.includes(firstPeerId!), 10_000);

      // Consume the standing receiver into a session, exactly as a real session start does. That
      // promotion is what triggers the REPLACEMENT receiver being built behind it.
      const counterpartyNode = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
      await counterpartyNode.start();
      const created = await manager.createSessionNode(
        randomUUID().replaceAll("-", ""), "alice", "dd".repeat(32),
        counterpartyNode.getPeerId(), randomUUID(), true,
      );
      expect(created.ok, "precondition: the session must consume the standing receiver").toBe(true);

      // A DIFFERENT receiver must now exist, and it must have proven itself independently.
      const rebuilt = await waitUntil(() => {
        const id = manager.getStandingReceiverInfo("alice")?.peerId;
        return id !== undefined && id !== firstPeerId;
      }, 15_000);
      expect(rebuilt, "precondition: a replacement receiver must be built after the promotion").toBe(true);
      const secondPeerId = manager.getStandingReceiverInfo("alice")!.peerId;

      const secondProven = await waitUntil(() => relay.authenticatedPeerIds.includes(secondPeerId), 15_000);
      expect(
        secondProven,
        "the REPLACEMENT receiver must prove possession from its OWN transport identity. If this " +
          "fails, the relay revokes its reservation and the agent is unreachable to anyone starting " +
          "a new session while the existing one is open.",
      ).toBe(true);

      await counterpartyNode.stop();
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 45_000);

  it("★★★ the assignment also reaches the RESERVATION relay when it differs from the witness relay", async () => {
    /**
     * Review HIGH-2. Two relays serve one session, chosen by unrelated rules:
     *   - the WITNESS relay is `assignment.relay_endpoint`, picked by the directory, and it is the
     *     only relay either party presented the assignment to;
     *   - the RESERVATION relay is whichever one this node's circuit address is held on.
     *
     * The counterparty dials our CIRCUIT address, so it is the RESERVATION relay whose gater decides
     * whether to allow it — and with no assignment recorded there it refused a legitimate dial. Two
     * relays run in production and falling through to the second candidate is frequent, so this is
     * the ordinary case: the session opened, but every message dropped to the slow park path with
     * the only trace on a relay nobody tails.
     */
    const witnessRelay = await startAuthRecordingRelay();
    const reservationRelay = await startAuthRecordingRelay();
    const { logger } = makeLogger();
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
    manager.setDetachedRelayClientBuilder((agentName, relayPeerId, relayAddrs, stores) =>
      new AgentRelayClient({
        relayPeerId, relayAddrs, keyProvider: agentKp, senderPubkey: agentPubkey, logger,
        receiptStore: stores.receiptStore, sealLeafStore: stores.sealLeafStore,
      }),
    );

    try {
      // The standing receiver reserves on the RESERVATION relay (it is the only endpoint seeded).
      const db = manager.getDb();
      const ids = await seedAgents(db, ["alice"]);
      const now = Date.now();
      db.prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
         VALUES (?, ?, ?, 'sealed', ?, ?, 0, ?, ?)`,
      ).run(randomUUID().replaceAll("-", ""), ids.get("alice")!, "cc".repeat(32), now, now, reservationRelay.peerId, JSON.stringify([reservationRelay.addr]));

      await manager.ensureStandingReceiverForAgent("alice");
      const reserved = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(reserved, "precondition: the receiver holds a reservation on the RESERVATION relay").toBe(true);

      // The session's assignment names the WITNESS relay — a different one, as the directory picks.
      const counterpartyNode = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
      await counterpartyNode.start();
      const sessionIdHex = randomUUID().replaceAll("-", "");
      const counterpartyPub = await generateKeypair().getPublicKey();
      const created = await manager.createSessionNode(
        sessionIdHex, "alice", Buffer.from(counterpartyPub).toString("hex"),
        counterpartyNode.getPeerId(), randomUUID(), true,
        {
          relayPeerId: witnessRelay.peerId,
          relayAddrs: [witnessRelay.addr],
          keyProvider: agentKp,
          senderPubkey: agentPubkey,
          sessionIdBytes: new Uint8Array(Buffer.from(sessionIdHex, "hex")),
          assignment: {
            participantA: agentPubkey,
            participantB: counterpartyPub,
            sessionTimestamp: Date.now(),
            initiatorSessionPeerId: manager.getStandingReceiverInfo("alice")?.peerId ?? "",
            counterpartySessionPeerId: counterpartyNode.getPeerId(),
            // A real directory signature is not needed: these test relays record what they are
            // HANDED. Whether the relay would VERIFY it is the relay's own concern and is covered
            // relay-side. What is under test here is WHICH relays the client presents it to.
            assignmentSignature: new Uint8Array(64).fill(9),
          },
        },
      );
      expect(created.ok, "precondition: the session must be created").toBe(true);

      // The witness relay obviously gets it — that was never the bug.
      const witnessGot = await waitUntil(() => witnessRelay.recordedSessionIds.includes(sessionIdHex), 15_000);
      expect(witnessGot, "precondition: the witness relay receives the assignment as it always did").toBe(true);

      // THE ASSERTION: the relay that will gate inbound circuit dials to this node also holds it.
      const reservationGot = await waitUntil(() => reservationRelay.recordedSessionIds.includes(sessionIdHex), 15_000);
      expect(
        reservationGot,
        "the RESERVATION relay must also hold the assignment. Without it, its dial-through gate finds " +
          "no binding and refuses the counterparty's legitimate dial — the session still opens, but " +
          "every message silently falls to the slow store-and-forward path.",
      ).toBe(true);

      await counterpartyNode.stop();
    } finally {
      await manager.gracefulShutdown();
      await witnessRelay.node.stop();
      await reservationRelay.node.stop();
    }
  }, 45_000);
});
