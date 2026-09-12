/**
 * DOD-M15-DELIVERYACK-1 unit 1 — the acknowledgement rides the relay's mailbox when the sender is
 * offline.
 *
 * ─── The gap this closes ───────────────────────────────────────────────────────────────────────
 *
 * The acknowledgement was sent on the direct session stream only. If the sender's daemon was down
 * when their counterparty read the message, the acknowledgement went nowhere and the sender ended up
 * holding no proof for that one message — the message that was HARDEST to deliver being the one with
 * no evidence, which is the opposite of the point of the unit.
 *
 * The order says it: *"It rides back to the sender through the relay's existing per-recipient
 * delivery path… If the sender is offline, the relay queues it."*
 *
 * ─── Why it needed a discriminator, and where the discriminator lives ──────────────────────────
 *
 * The relay's mailbox holds opaque ciphertext with no notion of what is inside it, so a parked
 * acknowledgement would arrive at the recipient's content-recovery path and be read as a MESSAGE.
 * The discriminator therefore lives INSIDE the seal, where the relay cannot see it, read it, strip
 * it or forge it — the relay stays a blind custodian and needs no change at all.
 *
 * Two independent checks then run on a recovered acknowledgement, against two different recorded
 * keys, and both must pass:
 *   1. the park envelope's own SEC-1 gate — the depositor is this session's counterparty;
 *   2. the delivery-ack signature itself — over this session and this content hash.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory } from "../session-node-manager.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import { acceptParkedDeliveryAck, readDeliveryFacts } from "../session-delivery-acks.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { InMemoryKeyProvider, signDeliveryAck } from "@cello-protocol/crypto";
import {
  encodeParkedDeliveryAck,
  decodeParkedDeliveryAck,
  parkedDeliveryAckMailboxHash,
  PARKED_DELIVERY_ACK_TAG,
  type ParkedDeliveryAck,
} from "../park-envelope.js";

let tempDir: string;
const managers: SessionNodeManager[] = [];
beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-parked-ack-")); });
afterEach(async () => {
  while (managers.length) { try { await managers.pop()!.gracefulShutdown(); } catch { /* ignore */ } }
  await rm(tempDir, { recursive: true, force: true });
});

const SID = "ef".repeat(16);
const HASH = new Uint8Array(createHash("sha256").update("a message").digest());

describe("DELIVERYACK/parked: the payload says what it is, and only to the recipient", () => {
  it("★ a parked acknowledgement round-trips through its own encoding", async () => {
    const bob = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const sig = await signDeliveryAck(bob, Buffer.from(SID, "hex"), HASH);
    const bytes = encodeParkedDeliveryAck({
      sessionIdHex: SID,
      contentHash: HASH,
      ackSig: sig,
      signerPubkey: await bob.getPublicKey(),
    });
    const back = decodeParkedDeliveryAck(bytes);
    expect(back).not.toBeNull();
    expect(Buffer.from(back!.contentHash).toString("hex")).toBe(Buffer.from(HASH).toString("hex"));
    expect(Buffer.from(back!.ackSig).toString("hex")).toBe(Buffer.from(sig).toString("hex"));
    expect(back!.sessionIdHex).toBe(SID);
  });

  it("★★★ ORDINARY MESSAGE CONTENT NEVER DECODES AS AN ACKNOWLEDGEMENT", async () => {
    /**
     * The whole safety of the discriminator. If a message's own bytes could be read as an
     * acknowledgement, a counterparty could send a message that the far side files as proof of
     * delivery instead of delivering it — content vanishing into the evidence store.
     *
     * The exemplars are chosen from the shapes that could actually collide, not from a random
     * string: plain text, a CBOR array of the right length with the wrong tag, and a CBOR array
     * whose tag slot holds the right STRING in the wrong position.
     */
    for (const candidate of [
      new TextEncoder().encode("hello, this is an ordinary message"),
      new Uint8Array(0),
      new Uint8Array([0x00, 0x01, 0x02]),
      // A CBOR array of the right arity with a different tag.
      (await import("@cello-protocol/protocol-types")).encodeCbor([
        "cello/park/something-else/v1", SID, HASH, new Uint8Array(64), new Uint8Array(32),
      ]) as Uint8Array,
      // The right tag in the WRONG slot.
      (await import("@cello-protocol/protocol-types")).encodeCbor([
        SID, PARKED_DELIVERY_ACK_TAG, HASH, new Uint8Array(64), new Uint8Array(32),
      ]) as Uint8Array,
    ]) {
      expect(
        decodeParkedDeliveryAck(candidate),
        `these bytes decoded as an acknowledgement and must not: ${Buffer.from(candidate).toString("hex").slice(0, 40)}`,
      ).toBeNull();
    }
  });

  it("★★★ a malformed acknowledgement payload decodes to NULL, exactly as absent content does", async () => {
    const bob = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const good = {
      sessionIdHex: SID,
      contentHash: HASH,
      ackSig: await signDeliveryAck(bob, Buffer.from(SID, "hex"), HASH),
      signerPubkey: await bob.getPublicKey(),
    };
    const { encodeCbor } = await import("@cello-protocol/protocol-types");
    // Right tag, wrong widths — each field in turn. None may be waved through.
    const wrong = [
      [PARKED_DELIVERY_ACK_TAG, SID, new Uint8Array(31), good.ackSig, good.signerPubkey],
      [PARKED_DELIVERY_ACK_TAG, SID, good.contentHash, new Uint8Array(63), good.signerPubkey],
      [PARKED_DELIVERY_ACK_TAG, SID, good.contentHash, good.ackSig, new Uint8Array(31)],
      [PARKED_DELIVERY_ACK_TAG, "not hex", good.contentHash, good.ackSig, good.signerPubkey],
      [PARKED_DELIVERY_ACK_TAG, SID, good.contentHash, good.ackSig],
    ];
    for (const w of wrong) {
      expect(decodeParkedDeliveryAck(encodeCbor(w) as Uint8Array)).toBeNull();
    }
    // ...and the well-formed one still decodes, so the loop above is not vacuously null.
    expect(decodeParkedDeliveryAck(encodeParkedDeliveryAck(good))).not.toBeNull();
  });
});

describe("DELIVERYACK/parked: the mailbox key cannot collide with a message", () => {
  it("★★★ the mailbox hash is DOMAIN-SEPARATED from a content hash over the same bytes", () => {
    /**
     * The relay files entries by (recipient, content_hash). If an acknowledgement were filed under
     * the hash it acknowledges, it would sit in the same slot a parked copy of that message would —
     * and one would evict or be mistaken for the other. The derived key puts it somewhere no
     * message can ever be.
     */
    const mailbox = parkedDeliveryAckMailboxHash(SID, HASH);
    expect(Buffer.from(mailbox).toString("hex")).not.toBe(Buffer.from(HASH).toString("hex"));
    // Not merely different — derived through a labelled domain, so no message's content hash can
    // land on it by accident or by construction.
    const naive = new Uint8Array(createHash("sha256").update(Buffer.from(SID, "hex")).update(HASH).digest());
    expect(Buffer.from(mailbox).toString("hex")).not.toBe(Buffer.from(naive).toString("hex"));
    expect(mailbox.length).toBe(32);
  });

  it("★★ it is DETERMINISTIC, so a re-park lands on the same slot and the relay dedups it", () => {
    expect(Buffer.from(parkedDeliveryAckMailboxHash(SID, HASH)).toString("hex"))
      .toBe(Buffer.from(parkedDeliveryAckMailboxHash(SID, HASH)).toString("hex"));
  });

  it("★★ a different session or a different message gets a different slot", () => {
    const other = parkedDeliveryAckMailboxHash("ab".repeat(16), HASH);
    const otherMsg = parkedDeliveryAckMailboxHash(SID, new Uint8Array(32).fill(9));
    const base = Buffer.from(parkedDeliveryAckMailboxHash(SID, HASH)).toString("hex");
    expect(Buffer.from(other).toString("hex")).not.toBe(base);
    expect(Buffer.from(otherMsg).toString("hex")).not.toBe(base);
  });
});

// ─── The acceptance path: the same five rules, arriving by the other road ──────────────────────

describe("DELIVERYACK/parked: an acknowledgement out of the mailbox is held to the same five rules", () => {
  /**
   * The parked route reaches `acceptParkedDeliveryAck` with the park envelope's SEC-1 gate ALREADY
   * passed — the depositor has been proved to be this session's counterparty. These tests are about
   * the second, independent check, which is the one that catches a counterparty who rewrote their
   * own daemon: the envelope gate is passed by construction for them, and only the acknowledgement's
   * own signature says whether they actually signed for this message.
   */
  const SESSION = "ef".repeat(16);

  async function fixture(dbName: string): Promise<{
    db: DaemonDatabase;
    logger: Logger;
    events: Array<{ level: string; event: string; context: Record<string, unknown> }>;
    agentId: string;
    bob: InMemoryKeyProvider;
    bobPubHex: string;
    sentHash: Uint8Array;
    /** `counterparty` is NOT defaulted — see the no-key test for why that matters. */
    accept: (ack: ParkedDeliveryAck, counterparty: string | undefined) => { ok: boolean; reason?: string };
    held: () => number;
  }> {
    const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
    const push = (level: string) => (event: string, context?: Record<string, unknown>) => {
      events.push({ level, event, context: context ?? {} });
    };
    const logger: Logger = { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") };
    const mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: { async createNode() { throw new Error("no node needed"); } } as unknown as ISessionNodeFactory,
      logger,
      dbPath: join(tempDir, dbName),
    });
    await mgr.initialize();
    managers.push(mgr);
    await seedAgentKeys(mgr.getDb(), ["alice"]);
    const db = mgr.getDb();
    const agentId = mgr.resolveAgentId("alice");
    const bob = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const bobPubHex = Buffer.from(await bob.getPublicKey()).toString("hex");

    // A message this side DURABLY sent in this session — the bind rule 2 reads.
    const sentHash = new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update("a sent message").digest());
    const sentHex = Buffer.from(sentHash).toString("hex");
    db.prepare(
      "INSERT INTO session_tree_leaves (agent_id, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(agentId, SESSION, 0, "msg", sentHex, Date.now());
    db.prepare(
      "INSERT INTO transcript (agent_id, session_id, sequence, direction, blob, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(agentId, SESSION, 0, "sent", Buffer.from("a sent message"), Date.now());

    return {
      db, logger, events, agentId, bob, bobPubHex, sentHash,
      accept: (ack, counterparty) =>
        acceptParkedDeliveryAck({
          db, logger, agentId, agentName: "alice", sessionId: SESSION,
          counterpartyPubkeyHex: counterparty, ack, correlationId: "corr",
        }),
      held: () => readDeliveryFacts(db, logger, agentId, SESSION).filter((f) => f.acknowledged !== null).length,
    };
  }

  async function ackFor(signer: InMemoryKeyProvider, hash: Uint8Array, session = SESSION): Promise<ParkedDeliveryAck> {
    return {
      sessionIdHex: session,
      contentHash: hash,
      ackSig: await signDeliveryAck(signer, Buffer.from(session, "hex"), hash),
      signerPubkey: await signer.getPublicKey(),
    };
  }

  it("★ an acknowledgement from the counterparty, for a message we durably sent, is kept", async () => {
    const f = await fixture("parked-ok.db");
    expect(f.accept(await ackFor(f.bob, f.sentHash), f.bobPubHex)).toEqual({ ok: true });
    expect(f.held()).toBe(1);
    expect(f.events.some((e) => e.event === "content.delivery.ack.parked.recovered")).toBe(true);
  });

  it("★★★ RULE 1: signed by a STRANGER — discarded, even though the envelope gate already passed", async () => {
    /**
     * The case the second check exists for. The depositor IS the counterparty (the envelope gate
     * said so), and the acknowledgement inside is signed by somebody else. A rewritten daemon can
     * do exactly this.
     */
    const f = await fixture("parked-stranger.db");
    const stranger = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const verdict = f.accept(await ackFor(stranger, f.sentHash), f.bobPubHex);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe("delivery_ack_signature_mismatch");
    expect(f.held()).toBe(0);
  });

  it("★★★ RULE 1: the signerPubkey INSIDE the payload is never what it is checked against", async () => {
    /**
     * The self-certifying case. The payload names its own signer, and that field is decoration: a
     * stranger who signs correctly AND names themselves must still be refused, because the only key
     * that counts is the one the SESSION recorded.
     */
    const f = await fixture("parked-selfnamed.db");
    const stranger = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const ack = await ackFor(stranger, f.sentHash); // signerPubkey IS the stranger's — consistent, and irrelevant
    expect(f.accept(ack, f.bobPubHex).ok).toBe(false);
    expect(f.held()).toBe(0);
  });

  it("★★★ RULE 2: an acknowledgement for a message we never sent is discarded", async () => {
    const f = await fixture("parked-unsent.db");
    const never = new Uint8Array(createHash("sha256").update("never sent").digest());
    const verdict = f.accept(await ackFor(f.bob, never), f.bobPubHex);
    expect(verdict).toEqual({ ok: false, reason: "not_sent_here" });
    expect(f.held()).toBe(0);
  });

  it("★★★ RULE 1: a session with NO usable recorded key has nothing to check against — discarded", async () => {
    /**
     * ⚠️ THE HELPER'S `counterparty` USED TO BE DEFAULTED, AND THIS TEST PASSED VACUOUSLY BECAUSE OF
     * IT. Passing `undefined` for a parameter with a default means "use the default" — so the case
     * named "no recorded key" was run WITH the real key and quietly succeeded. The value was chosen
     * from what I meant rather than from what the parameter does. The default is gone; both
     * exemplars now reach the branch they are named for.
     */
    const f = await fixture("parked-nokey.db");
    expect(f.accept(await ackFor(f.bob, f.sentHash), "bobpk").reason).toBe("delivery_ack_no_participant_keys");
    expect(f.accept(await ackFor(f.bob, f.sentHash), undefined).reason).toBe("delivery_ack_no_participant_keys");
    expect(f.accept(await ackFor(f.bob, f.sentHash), "").reason).toBe("delivery_ack_no_participant_keys");
    expect(f.held()).toBe(0);
  });

  it("★★★ RULE 4: the same acknowledgement arriving twice — or by BOTH roads — is stored once", async () => {
    /**
     * The two routes write the same key, which is what makes them idempotent with respect to each
     * other: a counterparty that both sent it directly and parked it does not produce two proofs,
     * and a mailbox that is drained twice does not either.
     */
    const f = await fixture("parked-dupe.db");
    const ack = await ackFor(f.bob, f.sentHash);
    expect(f.accept(ack, f.bobPubHex)).toEqual({ ok: true });
    for (let i = 0; i < 10; i++) expect(f.accept(ack, f.bobPubHex)).toEqual({ ok: true });
    expect(f.held()).toBe(1);
    expect(f.events.filter((e) => e.event === "content.delivery.ack.recorded").length).toBe(1);
  });

  it("★★★ RULE 3: accepting one is INERT — no leaf, no transcript row, no sequence", async () => {
    const f = await fixture("parked-inert.db");
    const leavesBefore = (f.db.prepare("SELECT COUNT(*) AS n FROM session_tree_leaves").get() as { n: number }).n;
    const transcriptBefore = (f.db.prepare("SELECT COUNT(*) AS n FROM transcript").get() as { n: number }).n;
    expect(f.accept(await ackFor(f.bob, f.sentHash), f.bobPubHex)).toEqual({ ok: true });
    expect((f.db.prepare("SELECT COUNT(*) AS n FROM session_tree_leaves").get() as { n: number }).n).toBe(leavesBefore);
    expect((f.db.prepare("SELECT COUNT(*) AS n FROM transcript").get() as { n: number }).n).toBe(transcriptBefore);
    expect(f.held()).toBe(1); // ...and the evidence DID land, so the two assertions above are not vacuous.
  });

  it("★★ a refusal says nothing about the counterparty, and is not a security event", async () => {
    const f = await fixture("parked-neutral.db");
    const stranger = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    f.accept(await ackFor(stranger, f.sentHash), f.bobPubHex);
    const line = f.events.find((e) => e.event === "content.delivery.ack.parked.discarded");
    expect(line).toBeTruthy();
    const rendered = JSON.stringify(line);
    for (const word of ["evasi", "ignored", "unresponsive", "attack", "malicious"]) {
      expect(rendered, `a discard must not characterise the counterparty: found "${word}"`).not.toContain(word);
    }
    // And nothing froze: a discard leaves the session exactly as it was.
    expect(f.events.some((e) => e.event.includes("freeze") || e.event.includes("refused.session"))).toBe(false);
  });
});
