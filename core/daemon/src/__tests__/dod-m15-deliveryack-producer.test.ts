/**
 * DOD-M15-DELIVERYACK-1 unit 1 — THE PRODUCER HALF, IN THE GATE.
 *
 * ⚠️ WHY THIS FILE EXISTS. Unit 1's producer side — a mailbox-recovered message being acknowledged
 * at all, and an acknowledgement with no live stream going to the mailbox instead of being
 * abandoned — was covered ONLY by `j-deliveryack.spine.test.ts`, which the root gate excludes. So
 * `pnpm run test` proved the encoding, the slot derivation and the acceptance leaf, and proved
 * nothing whatever about the two behaviours the unit is named for: deleting either one left the
 * whole suite green.
 *
 * The live journey still runs both end to end and is the stronger evidence. This is the part that
 * fails on a laptop, before anyone starts a relay.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { InMemoryKeyProvider, verifyDeliveryAck, signDeliveryAck } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgentKeys, wireAgentKeyProviders } from "./helpers/seed-agents.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";
import {
  decodeParkedDeliveryAck, parkedDeliveryAckMailboxHash, encodeParkEnvelope, encodeParkedDeliveryAck,
} from "../park-envelope.js";
import { buildParkContentTbs } from "@cello-protocol/protocol-types";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

const SID = "ef".repeat(16);

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (level: string) => (event: string, context?: Record<string, unknown>) => {
    events.push({ level, event, context: context ?? {} });
  };
  return { logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") }, events };
}

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

/** A node that exists but can open no stream — the far side is gone, which is the whole case. */
class DeadPeerNode implements Partial<CelloNode> {
  readonly #peerId = `dead-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { throw new Error("connection_lost: peer is gone"); }
  async handle(): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(): void {}
  onPeerDisconnect(): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(): () => void { return () => {}; }
  async hangUp(): Promise<void> {}
  async newStream(): Promise<Stream> { throw new Error("connection_lost: peer is gone"); }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/** Everything the relay would have been handed, captured instead of deposited. */
interface Deposit {
  recipientPubkeyHex: string;
  contentHashHex: string;
  content: Uint8Array;
  relayPeerId: string;
}

describe("DELIVERYACK/producer: an acknowledgement with nowhere to go goes to the mailbox", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-ack-producer-")); });
  afterEach(async () => {
    while (managers.length) { try { await managers.pop()!.gracefulShutdown(); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  /**
   * An agent that has RECEIVED a message from bob and has no live way to answer him. The park hook
   * is captured rather than performed, so the assertion is on what would have reached the relay.
   */
  async function receivingAgent(dbName: string, opts: { withRelay?: boolean } = {}): Promise<{
    mgr: SessionNodeManager;
    events: LogEvent[];
    bobPubHex: string;
    alicePubHex: string;
    alicePub: Uint8Array;
    deposits: Deposit[];
    contentHash: Uint8Array;
    deliverFromMailbox: () => Promise<unknown>;
    parkedAckFromCounterparty: () => Promise<{ envelope: Uint8Array; slot: Uint8Array }>;
  }> {
    const { logger, events } = makeLogger();
    const mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ControlledFactory(new DeadPeerNode() as unknown as CelloNode),
      logger,
      dbPath: join(tempDir, dbName),
    });
    await mgr.initialize();
    managers.push(mgr);
    await seedAgentKeys(mgr.getDb(), ["alice"]);
    await wireAgentKeyProviders(mgr, mgr.getDb());
    mgr.setSessionGenesisForTest("alice", SID, TEST_SESSION_GENESIS);
    const bob = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const bobPubHex = Buffer.from(await bob.getPublicKey()).toString("hex");

    const deposits: Deposit[] = [];
    mgr.setContentParkHook(async (args) => {
      deposits.push({
        recipientPubkeyHex: args.recipientPubkeyHex,
        contentHashHex: args.contentHashHex,
        content: args.content,
        relayPeerId: args.relayPeerId,
      });
      return { ok: true };
    });

    // A session row with a recorded counterparty and (optionally) a relay — and NO live node, which
    // is the state a daemon is in when the far side is down.
    const agentId = mgr.resolveAgentId("alice");
    mgr.getDb().prepare(
      `INSERT INTO sessions (agent_id, session_id, counterparty_pubkey, status, created_at, updated_at, relay_peer_id, relay_addrs)
       VALUES (?, ?, ?, 'open', ?, ?, ?, ?)`,
    ).run(
      agentId, SID, bobPubHex, Date.now(), Date.now(),
      opts.withRelay === false ? null : "12D3KooWTestRelayPeerId",
      opts.withRelay === false ? null : JSON.stringify(["/ip4/127.0.0.1/tcp/4001"]),
    );

    /**
     * A message from bob, in the shape the MAILBOX delivers it: a signed park envelope. Driving
     * `recoverParkedEntry` rather than a test seam is deliberate — it exercises the real chain the
     * unit changed (envelope gate → ingest → acknowledge → no live node → mailbox) through public
     * API only, so nothing here can pass against a daemon that has stopped acknowledging.
     */
    const body = new TextEncoder().encode("a message bob sent us");
    const contentHash = msgLeafHash(body);
    const alicePubHex = (mgr.getDb().prepare(
      "SELECT k_local_pubkey FROM agents WHERE agent_name = 'alice'",
    ).get() as { k_local_pubkey: string }).k_local_pubkey;
    const alicePub = new Uint8Array(Buffer.from(alicePubHex, "hex"));
    const envelope = encodeParkEnvelope({
      content: body,
      senderPubkey: new Uint8Array(Buffer.from(bobPubHex, "hex")),
      parkSig: await bob.sign(buildParkContentTbs(SID, alicePub, contentHash)),
    });
    const deliverFromMailbox = (): Promise<unknown> =>
      mgr.recoverParkedEntry("alice", SID, alicePub, envelope, contentHash, "corr");

    /**
     * The same mailbox shape, carrying an ACKNOWLEDGEMENT from bob rather than a message — used to
     * prove the recovery path recognises one and does not answer it.
     */
    const parkedAckFromCounterparty = async (): Promise<{ envelope: Uint8Array; slot: Uint8Array }> => {
      const slot = parkedDeliveryAckMailboxHash(SID, contentHash);
      const payload = encodeParkedDeliveryAck({
        sessionIdHex: SID,
        contentHash,
        ackSig: await signDeliveryAck(bob, Buffer.from(SID, "hex"), contentHash),
      });
      return {
        envelope: encodeParkEnvelope({
          content: payload,
          senderPubkey: new Uint8Array(Buffer.from(bobPubHex, "hex")),
          parkSig: await bob.sign(buildParkContentTbs(SID, alicePub, slot)),
        }),
        slot,
      };
    };

    return { mgr, events, bobPubHex, alicePubHex, alicePub, deposits, contentHash, deliverFromMailbox, parkedAckFromCounterparty };
  }

  it("★★★ with NO live session node, the acknowledgement is deposited — not abandoned", async () => {
    /**
     * THE BRANCH THIS UNIT TURNS ON. It used to be a bare early return logged `session_node_gone`,
     * which is the ordinary state whenever the sender is down — so the acknowledgement for every
     * message that had to be parked and recovered was thrown away at exactly this line.
     */
    const a = await receivingAgent("no-node.db");
    await a.deliverFromMailbox();
    await new Promise((r) => setTimeout(r, 50));

    expect(a.deposits.length, `nothing was deposited. events: ${JSON.stringify(a.events.map((e) => e.event))}`).toBe(1);
    const d = a.deposits[0]!;
    expect(d.recipientPubkeyHex, "the acknowledgement must be addressed to the SENDER").toBe(a.bobPubHex);
    expect(d.contentHashHex, "it must be filed in the DERIVED slot, never the message's own").toBe(
      Buffer.from(parkedDeliveryAckMailboxHash(SID, a.contentHash)).toString("hex"),
    );
    expect(a.events.some((e) => e.event === "content.delivery.ack.parked")).toBe(true);
  });

  it("★★★ what lands in the mailbox is a real, verifiable acknowledgement — not a shaped blank", async () => {
    /**
     * "Something was deposited" is a shadow. This names the value: the deposited bytes decode as an
     * acknowledgement, and the signature inside VERIFIES against this agent's own published key over
     * this session and this message.
     */
    const a = await receivingAgent("payload.db");
    await a.deliverFromMailbox();
    await new Promise((r) => setTimeout(r, 50));
    /**
     * Decoded DIRECTLY, not through `decodeParkEnvelope`. The park hook is what wraps and seals —
     * so what reaches it is the bare acknowledgement payload, and running it through the envelope
     * decoder would take that function's unknown-shape fallback (`{version: 1, content: input}`) and
     * pass while asserting nothing about either layer.
     */
    const parked = decodeParkedDeliveryAck(a.deposits[0]!.content);
    expect(parked, "the deposited payload does not decode as an acknowledgement").not.toBeNull();
    expect(parked!.sessionIdHex).toBe(SID);
    expect(Buffer.from(parked!.contentHash).toString("hex")).toBe(Buffer.from(a.contentHash).toString("hex"));

    const ownPub = Buffer.from(a.alicePubHex, "hex");
    expect(
      verifyDeliveryAck({
        participantIdentityPublics: [new Uint8Array(ownPub)],
        sessionId: new Uint8Array(Buffer.from(SID, "hex")),
        contentHash: a.contentHash,
        signature: parked!.ackSig,
      }).ok,
      "the acknowledgement in the mailbox does not verify against this agent's own key",
    ).toBe(true);
  });

  it("★★ it goes through the SAME park hook content does — so it is signed and sealed by the same code", async () => {
    /**
     * ⚠️ THIS TEST ASSERTED THE DEPOSIT WAS CIPHERTEXT AND THAT WAS THE WRONG LAYER. The park hook
     * is what signs the envelope and seals it to the recipient (`sealParkEnvelope`); what reaches
     * the hook is plaintext, by design, for content exactly as for an acknowledgement. Asserting
     * ciphertext here would have been asserting a property of the test's own stub.
     *
     * What IS checkable here is the thing that makes the sealing true for acknowledgements too:
     * they take the hook, rather than some private deposit path of their own. The live journey
     * proves the far end can open it, which is the only real proof the sealing happened.
     */
    const a = await receivingAgent("sealed.db");
    await a.deliverFromMailbox();
    await new Promise((r) => setTimeout(r, 50));
    expect(a.deposits.length).toBe(1);
    expect(a.deposits[0]!.relayPeerId, "it must use the session's recorded relay").toBe("12D3KooWTestRelayPeerId");
    expect(decodeParkedDeliveryAck(a.deposits[0]!.content)).not.toBeNull();
  });

  it("★★★ AN ACKNOWLEDGEMENT IS NEVER ITSELF ACKNOWLEDGED — it terminates", async () => {
    /**
     * The order's own words: *"An ack is never itself acked. It terminates."* Two daemons that
     * acknowledged each other's acknowledgements would talk forever without either operator sending
     * anything, and every one of those would be a deposit in somebody's mailbox.
     *
     * It holds today because the acknowledgement branch returns before ingest, and therefore before
     * the acknowledge-on-recovery call added by this unit. That is an ORDERING, which is exactly the
     * kind of property a later refactor breaks silently — so it is pinned here rather than left to
     * be re-derived by whoever moves that branch.
     */
    const a = await receivingAgent("no-ack-of-ack.db");
    // First, prove the fixture WOULD deposit for a message — otherwise this test passes on nothing.
    await a.deliverFromMailbox();
    await new Promise((r) => setTimeout(r, 50));
    expect(a.deposits.length, "the control case must deposit, or the assertion below is vacuous").toBe(1);
    a.deposits.length = 0;
    a.events.length = 0; // ...and the event log too, or the assertion below reads the control case.

    // Now deliver an ACKNOWLEDGEMENT through the very same mailbox path.
    const parkedAck = await a.parkedAckFromCounterparty();
    const res = await a.mgr.recoverParkedEntry("alice", SID, a.alicePub, parkedAck.envelope, parkedAck.slot, "corr");
    await new Promise((r) => setTimeout(r, 50));
    expect(res, "an acknowledgement must be recognised as one, not ingested as a message").toHaveProperty("deliveryAck");
    expect(a.deposits.length, "an acknowledgement was acknowledged — the loop this rule exists to stop").toBe(0);
    expect(a.events.some((e) => e.event === "content.delivery.ack.parked")).toBe(false);
  });

  it("★★★ with no relay recorded for the session, it is LOUD and says what the sender loses", async () => {
    /**
     * No acknowledgement is this unit's own symptom, so the one case where we knowingly cannot
     * produce one has to be visible — otherwise it is indistinguishable from the defect. And the
     * wording must not blame the counterparty: this is a local absence, and their message arrived.
     */
    const a = await receivingAgent("no-relay.db", { withRelay: false });
    await a.deliverFromMailbox();
    await new Promise((r) => setTimeout(r, 50));
    expect(a.deposits.length).toBe(0);
    const failed = a.events.find((e) => e.event === "content.delivery.ack.park.failed");
    expect(failed, "declining to acknowledge must never be silent").toBeTruthy();
    expect(failed!.context.reason).toBe("no_relay_for_session");
    expect(String(failed!.context.impact)).toContain("WAS received");
    for (const word of ["evasi", "ignored", "unresponsive"]) {
      expect(JSON.stringify(failed), `must not characterise the counterparty: "${word}"`).not.toContain(word);
    }
  });
});
