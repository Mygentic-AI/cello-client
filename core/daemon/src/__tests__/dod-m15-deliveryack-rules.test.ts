/**
 * DOD-M15-DELIVERYACK-1 — the five out-of-band rules, on the real inbound path.
 *
 * ─── Why these five and not a shape check ──────────────────────────────────────────────────────
 *
 * The client is open source and runs on the counterparty's machine, so every inbound
 * acknowledgement is attacker-controlled input. The five properties below are the same five the
 * presence notice is held to, and each one is a separate way to turn an acknowledgement into a
 * lever:
 *
 *   1. VERIFIED against the session's recorded counterparty key — never a key in the frame.
 *   2. BOUND — it names a hash this side actually sent in this session.
 *   3. INERT — it records evidence and resolves the sender's own fallback timer. Nothing else.
 *   4. IDEMPOTENT AND BOUNDED — one per (session, hash); duplicates do nothing; the number that can
 *      ever be recorded is the number of messages this side sent.
 *   5. MALFORMED FAILS EXACTLY AS MISSING DOES.
 *
 * ⚠️ WHAT "THE SAME OBSERVABLE OUTCOME" MEANS IN RULE 5, because this is the clause most likely to
 * be quietly skipped and the easiest to fake. It means the PROTOCOL STATE is identical: the
 * awaiting entry survives, `content.delivery.acked` does not fire, no row is written, and the
 * message goes on to park exactly as it would have with nothing arriving at all. It does NOT mean
 * the logs are identical — they must differ, because the log is the forensic record and a refusal
 * that leaves no trace is its own defect. So the assertions below compare the state, and separately
 * assert that each case is heard.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import * as lp from "it-length-prefixed";
import { Encoder } from "cbor-x";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { InMemoryKeyProvider, signDeliveryAck } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { LEAF_KIND_MSG } from "../session-relay-client.js";
import { readDeliveryFacts } from "../session-delivery-acks.js";
import { seedAgentKeys, wireAgentKeyProviders } from "./helpers/seed-agents.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
const SID = "ef".repeat(32);

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

/** A node whose outbound sends go nowhere, so only the frames a test injects ever arrive. */
class LoneNode implements Partial<CelloNode> {
  #handler: ((stream: Stream, remotePeerId?: string) => void) | null = null;
  readonly #peerId = `lone-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, h: (stream: Stream, remotePeerId?: string) => void): Promise<void> { this.#handler = h; }
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async hangUp(_p: string): Promise<void> {}
  invokeHandler(data: unknown, fromPeerId: string): void {
    const h = this.#handler;
    if (!h) return;
    const chunks = [data];
    const inbound = {
      [Symbol.asyncIterator]() {
        let i = 0;
        return { next(): Promise<IteratorResult<unknown>> {
          return i < chunks.length
            ? Promise.resolve({ value: chunks[i++], done: false })
            : Promise.resolve({ value: undefined, done: true });
        } };
      },
    } as unknown as Stream;
    h(inbound, fromPeerId);
  }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

const COUNTERPARTY_PEER = "bob-peer";

async function settle(): Promise<void> { await new Promise((r) => setTimeout(r, 40)); }

describe("DELIVERYACK: the five rules, on the inbound path", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-deliveryack-")); });
  afterEach(async () => {
    while (managers.length) { try { await managers.pop()!.gracefulShutdown(); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  /** One agent with one live session and one message sent and awaiting acknowledgement. */
  async function sendingAgent(dbName: string): Promise<{
    mgr: SessionNodeManager;
    node: LoneNode;
    events: LogEvent[];
    bob: InMemoryKeyProvider;
    bobPubHex: string;
    hash: Uint8Array;
    ack: (over: { sig?: Uint8Array | undefined; hash?: Uint8Array; level?: string }) => unknown;
  }> {
    const node = new LoneNode();
    const { logger, events } = makeLogger();
    const mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ControlledFactory(node as unknown as CelloNode),
      logger,
      dbPath: join(tempDir, dbName),
      contentTtfMs: 60_000,
    });
    await mgr.initialize();
    managers.push(mgr);
    await seedAgentKeys(mgr.getDb(), ["alice"]);
    await wireAgentKeyProviders(mgr, mgr.getDb());
    mgr.setSessionGenesisForTest("alice", SID, TEST_SESSION_GENESIS);
    const bob = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const bobPubHex = Buffer.from(await bob.getPublicKey()).toString("hex");
    await mgr.createSessionNode(SID, "alice", bobPubHex, COUNTERPARTY_PEER, "corr");
    mgr.setSessionContentKeyForTest("alice", SID, new Uint8Array(32).fill(0x7e));

    const content = new TextEncoder().encode("a message worth acknowledging");
    const hash = msgLeafHash(content);
    const res = await mgr.sendContent("alice", SID, content, hash, "corr", LEAF_KIND_MSG);
    expect(res.ok).toBe(true);

    const ack = (over: { sig?: Uint8Array | undefined; hash?: Uint8Array; level?: string }): unknown =>
      lp.encode.single(
        CBOR_ENC.encode({
          type: "content_delivery_ack",
          session_id: SID,
          content_hash: over.hash ?? hash,
          level: over.level ?? "persisted",
          ...(over.sig === undefined ? {} : { ack_sig: over.sig }),
        }),
      );
    return { mgr, node, events, bob, bobPubHex, hash, ack };
  }

  /** The protocol state rule 5 is about: still awaiting, nothing fired, nothing kept. */
  function stateAfter(a: { mgr: SessionNodeManager; events: LogEvent[] }): {
    acked: boolean;
    heldAcks: number;
  } {
    return {
      acked: a.events.some((e) => e.event === "content.delivery.acked"),
      heldAcks: readDeliveryFacts(a.mgr.getDb(), a.mgr.resolveAgentId("alice"), SID).filter((f) => f.acknowledged !== null).length,
    };
  }

  it("★ RULE 1: an acknowledgement signed by the session's counterparty is accepted and KEPT", async () => {
    const a = await sendingAgent("rule1-ok.db");
    a.node.invokeHandler(a.ack({ sig: await signDeliveryAck(a.bob, Buffer.from(SID, "hex"), a.hash) }), COUNTERPARTY_PEER);
    await settle();
    expect(stateAfter(a)).toEqual({ acked: true, heldAcks: 1 });
    const kept = readDeliveryFacts(a.mgr.getDb(), a.mgr.resolveAgentId("alice"), SID)[0]!;
    expect(kept.acknowledged?.signer_pubkey).toBe(a.bobPubHex);
    expect(kept.acknowledged?.asserted_by).toBe("recipient");
  });

  it("★★★ RULE 1: an acknowledgement signed by a STRANGER is discarded — a valid signature is not a relevant one", async () => {
    /**
     * The stranger's signature is cryptographically perfect and arrives on the counterparty's own
     * peer connection, so the frame gate above lets it through. What stops it is checking against
     * the key the SESSION recorded rather than anything the frame offered.
     */
    const a = await sendingAgent("rule1-stranger.db");
    const stranger = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    a.node.invokeHandler(a.ack({ sig: await signDeliveryAck(stranger, Buffer.from(SID, "hex"), a.hash) }), COUNTERPARTY_PEER);
    await settle();
    expect(stateAfter(a)).toEqual({ acked: false, heldAcks: 0 });
    const heard = a.events.find((e) => e.event === "content.delivery.ack.discarded");
    expect(heard?.context.reason).toBe("delivery_ack_signature_mismatch");
  });

  it("★★★ RULE 2: an acknowledgement naming a hash we never sent is discarded", async () => {
    const a = await sendingAgent("rule2.db");
    const neverSent = msgLeafHash(new TextEncoder().encode("a message that was never sent"));
    a.node.invokeHandler(
      a.ack({ hash: neverSent, sig: await signDeliveryAck(a.bob, Buffer.from(SID, "hex"), neverSent) }),
      COUNTERPARTY_PEER,
    );
    await settle();
    expect(stateAfter(a)).toEqual({ acked: false, heldAcks: 0 });
    expect(a.events.find((e) => e.event === "content.delivery.ack.discarded")?.context.reason).toBe("not_awaiting");
  });

  it("★★★ RULE 5: a MISSING signature and a MALFORMED one leave the protocol in exactly the state an ABSENT acknowledgement does", async () => {
    /**
     * Three runs, three identical states. The absent case runs the same sequence and injects
     * nothing, which is the only baseline worth comparing against — comparing the two refusals to
     * each other would pass even if both quietly accepted.
     */
    const absent = await sendingAgent("rule5-absent.db");
    await settle();

    const missing = await sendingAgent("rule5-missing.db");
    missing.node.invokeHandler(missing.ack({ sig: undefined }), COUNTERPARTY_PEER);
    await settle();

    const malformed = await sendingAgent("rule5-malformed.db");
    malformed.node.invokeHandler(malformed.ack({ sig: new Uint8Array(63) }), COUNTERPARTY_PEER);
    await settle();

    const baseline = stateAfter(absent);
    expect(baseline).toEqual({ acked: false, heldAcks: 0 });
    expect(stateAfter(missing)).toEqual(baseline);
    expect(stateAfter(malformed)).toEqual(baseline);

    // ...and each refusal is HEARD, with its own reason. A silent discard would satisfy the
    // assertions above and still be a defect.
    expect(missing.events.find((e) => e.event === "content.delivery.ack.discarded")?.context.reason)
      .toBe("delivery_ack_signature_missing");
    expect(malformed.events.find((e) => e.event === "content.delivery.ack.discarded")?.context.reason)
      .toBe("delivery_ack_malformed");
  });

  it("★★ RULE 5: a wrong-TYPED signature field takes the MISSING path, not a tolerance branch of its own", async () => {
    const a = await sendingAgent("rule5-typed.db");
    a.node.invokeHandler(
      lp.encode.single(CBOR_ENC.encode({
        type: "content_delivery_ack", session_id: SID, content_hash: a.hash, level: "persisted",
        ack_sig: "not bytes at all",
      })),
      COUNTERPARTY_PEER,
    );
    await settle();
    expect(stateAfter(a)).toEqual({ acked: false, heldAcks: 0 });
    expect(a.events.find((e) => e.event === "content.delivery.ack.discarded")?.context.reason)
      .toBe("delivery_ack_signature_missing");
  });

  it("★★★ RULE 4: a REPLAYED acknowledgement is dropped and changes nothing", async () => {
    const a = await sendingAgent("rule4.db");
    const sig = await signDeliveryAck(a.bob, Buffer.from(SID, "hex"), a.hash);
    a.node.invokeHandler(a.ack({ sig }), COUNTERPARTY_PEER);
    await settle();
    const first = readDeliveryFacts(a.mgr.getDb(), a.mgr.resolveAgentId("alice"), SID);
    const ackedCount = () => a.events.filter((e) => e.event === "content.delivery.acked").length;
    expect(ackedCount()).toBe(1);

    for (let i = 0; i < 20; i++) a.node.invokeHandler(a.ack({ sig }), COUNTERPARTY_PEER);
    await settle();
    // Twenty replays: one row, one acked event, and the stored signature unchanged.
    expect(readDeliveryFacts(a.mgr.getDb(), a.mgr.resolveAgentId("alice"), SID)).toEqual(first);
    expect(ackedCount()).toBe(1);
    expect(a.events.filter((e) => e.event === "content.delivery.ack.recorded").length).toBe(1);
  });

  it("★★★ RULE 4: a flood of BAD acknowledgements cannot make this machine shout — one loud line per message", async () => {
    /**
     * The awaiting entry must SURVIVE a refusal (rule 5 depends on it), which is exactly what makes
     * the log spendable: the counterparty can resend the same bad acknowledgement forever. The
     * budget is keyed on a message THIS side sent, so they cannot create one — and the refusal is
     * still recorded, at debug, so nothing is lost from the forensic record.
     */
    const a = await sendingAgent("rule4-flood.db");
    for (let i = 0; i < 50; i++) a.node.invokeHandler(a.ack({ sig: new Uint8Array(63) }), COUNTERPARTY_PEER);
    await settle();
    const discards = a.events.filter((e) => e.event === "content.delivery.ack.discarded");
    expect(discards.filter((e) => e.level === "warn").length).toBe(1);
    expect(discards.length).toBe(50);
    // And the flood changed nothing: still awaiting, nothing kept.
    expect(stateAfter(a)).toEqual({ acked: false, heldAcks: 0 });
  });

  it("★★★ RULE 3: an acknowledgement is INERT — no leaf, no transcript row, no seal, no session change", async () => {
    /**
     * Machine traffic never enters the tamper-evident record. Measured as a BEFORE/AFTER on the
     * artifacts a leaf would move, not as an absence of one log line: an acknowledgement in the
     * chain would double the length of every conversation and make the daemon a participant in it.
     */
    const a = await sendingAgent("rule3.db");
    const rootBefore = a.mgr.getSessionTree("alice", SID).rootHex();
    const leavesBefore = a.mgr.getSessionTree("alice", SID).leaves().length;
    const transcriptBefore = a.mgr.readTranscript("alice", SID).messages.length;
    const statusBefore = a.mgr.getSessionRecord("alice", SID)?.status;

    a.node.invokeHandler(a.ack({ sig: await signDeliveryAck(a.bob, Buffer.from(SID, "hex"), a.hash) }), COUNTERPARTY_PEER);
    await settle();

    expect(a.mgr.getSessionTree("alice", SID).leaves().length).toBe(leavesBefore);
    expect(a.mgr.getSessionTree("alice", SID).rootHex()).toBe(rootBefore);
    expect(a.mgr.readTranscript("alice", SID).messages.length).toBe(transcriptBefore);
    expect(a.mgr.getSessionRecord("alice", SID)?.status).toBe(statusBefore);
    // The evidence landed — otherwise the four assertions above are satisfied by nothing happening.
    expect(stateAfter(a).heldAcks).toBe(1);
  });

  it("★★ the receipt surface reports the three facts separately and derives nothing from an absence", async () => {
    const a = await sendingAgent("facts.db");
    a.node.invokeHandler(a.ack({ sig: await signDeliveryAck(a.bob, Buffer.from(SID, "hex"), a.hash) }), COUNTERPARTY_PEER);
    await settle();
    const [fact] = readDeliveryFacts(a.mgr.getDb(), a.mgr.resolveAgentId("alice"), SID);
    expect(fact).toBeTruthy();
    // Three independent slots. Acknowledged is present; the two relay-asserted facts are not held
    // by this side and read null — reported as missing, with nothing inferred from it.
    expect(Object.keys(fact!).sort()).toEqual(
      ["acknowledged", "content_hash", "delivered", "ordered", "seq"],
    );
    expect(fact!.ordered).toBeNull();
    expect(fact!.delivered).toBeNull();
    expect(fact!.acknowledged).not.toBeNull();
    // No derived verdict anywhere in the payload: nothing that reads as a status or a score.
    const rendered = JSON.stringify(fact);
    for (const word of ["unresponsive", "ignored", "status", "score", "verdict", "fault"]) {
      expect(rendered).not.toContain(word);
    }
  });
});
