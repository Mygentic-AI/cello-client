/**
 * DOD-M15-EPHEMERAL-AUTH-1 — the exchange, the signature and the encryption, END TO END.
 *
 * ─── Why this file uses REAL identities and a REAL connection ──────────────────────────────────
 *
 * Every other content test in this repo seeds the agreed key, because its counterparty is a fake
 * node that cannot take part in a handshake. That is legitimate — the state it produces is the
 * production state — but it means NOTHING in those tests exercises the exchange itself.
 *
 * So this file is the one that does: two managers over real libp2p, real Ed25519 identities on both
 * sides, each manager wired to its own key provider exactly as the daemon wires it. The keys are
 * agreed by the code that will agree them in production, and a message crosses under them.
 *
 * ─── The attack these tests are actually about ─────────────────────────────────────────────────
 *
 * Unsigned, an arriving throwaway key carries no evidence of who sent it: the relay keeps yours,
 * forwards its own to your counterparty, does the same in reverse, and holds one secret with each of
 * you. It reads everything, and both ends see a conversation that decrypts perfectly. We run the
 * relays, so without the signature the guarantee is "trust us".
 *
 * That is why a bad signature STOPS THE SESSION rather than degrading it. There is no unencrypted
 * mode to fall back to — a fallback is a thing an attacker steers you into by stripping one field.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createNode } from "@cello-protocol/transport";
import {
  generateKeypair, msgLeafHash, signSessionEphemeral, sealSessionContent,
  type KeyProvider,
} from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { agreeSessionGenesis } from "./helpers/session-genesis.js";
import { LEAF_KIND_MSG, LEAF_KIND_DOC } from "../session-relay-client.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";

/** The lp-framed CBOR a content stream actually carries. */
function framed(frame: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor(frame) as Uint8Array).subarray();
}

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function pollFor<T>(fn: () => T | null | undefined | false, tries = 200, stepMs = 25): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    const v = fn();
    if (v) return v as T;
    await wait(stepMs);
  }
  return null;
}

const SID = "6a".repeat(16);

describe("DOD-M15-EPHEMERAL-AUTH-1: the real exchange, over a real connection", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-ephauth-"));
    managers.length = 0;
  });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* already down */ } }
    managers.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeManager(agent: string, kp: KeyProvider): { manager: SessionNodeManager; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `snm-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(), factory: new RealNodeFactory(), logger, dbPath,
    });
    // Exactly as `daemon.ts` wires it — the manager signs each session's throwaway key with the
    // agent's identity, so it needs the same provider the daemon holds.
    manager.setKeyProviderResolver((name: string) => (name === agent ? kp : undefined));
    managers.push(manager);
    return { manager, events };
  }

  /** Two managers, real identities, real connection — and NO seeded key anywhere. */
  async function liveSession() {
    const aliceKp = generateKeypair();
    const bobKp = generateKeypair();
    const alicePub = Buffer.from(await aliceKp.getPublicKey()).toString("hex");
    const bobPub = Buffer.from(await bobKp.getPublicKey()).toString("hex");

    const A = makeManager("alice", aliceKp);
    const B = makeManager("bob", bobKp);
    await A.manager.initialize();
    await B.manager.initialize();
    await seedAgents(A.manager.getDb(), ["alice"]);
    await seedAgents(B.manager.getDb(), ["bob"]);
    await B.manager.ensureStandingReceiverForAgent("bob");
    const bInfo = B.manager.getStandingReceiverInfo("bob");
    expect(bInfo).not.toBeNull();

    // Both sides agree the session's starting point before either builds its node — see
    // `helpers/session-genesis.ts` for why the order and the sharing are both load-bearing.
    agreeSessionGenesis(SID, [
      { mgr: A.manager, agentName: "alice" },
      { mgr: B.manager, agentName: "bob" },
    ]);
    const created = await A.manager.createSessionNode(SID, "alice", bobPub, bInfo!.peerId, "corr-A");
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("createSessionNode failed");
    expect((await A.manager.connectToCounterparty("alice", SID, bInfo!.addrs)).ok).toBe(true);
    expect((await B.manager.acceptSession(SID, "bob", alicePub, created.peerId, "corr-B")).ok).toBe(true);
    return { A, B, alicePub, bobPub, aliceKp, bobKp };
  }

  it("★★ BOTH sides agree a key through the real signed exchange, and a message crosses under it", async () => {
    /**
     * THE CLAUSE THAT MAKES THE FEATURE REAL. Two managers, real Ed25519 identities on both sides, a
     * real connection, and NOTHING seeded: each signs its throwaway public with its agent identity,
     * each verifies the other's against the counterparty identity the session was opened with, both
     * derive, and a message goes across encrypted under the result.
     *
     * Every other content test in this repo seeds the agreed key, because its counterparty is a fake
     * node that cannot handshake. This is the one that does not.
     */
    const { A, B } = await liveSession();
    await wait(600);

    expect(
      A.events.find((e) => e.event === "session.key.agreed"),
      "A never agreed a key — the exchange did not complete in its direction",
    ).toBeDefined();
    expect(B.events.find((e) => e.event === "session.key.agreed"), "B never agreed a key").toBeDefined();
    expect(
      A.events.find((e) => e.event === "session.key.refused") ?? B.events.find((e) => e.event === "session.key.refused"),
      "a side refused the other's key even though both are genuine",
    ).toBeUndefined();

    const text = "the price is 40,000 and we close on Friday";
    const content = new TextEncoder().encode(text);
    const sent = await A.manager.sendContent("alice", SID, content, msgLeafHash(content), "corr-send", LEAF_KIND_MSG) as { ok: boolean; delivered?: boolean };
    expect(sent.ok, "the send failed even though both sides agreed a key").toBe(true);
    expect(
      sent.delivered,
      "the send PARKED instead of going direct — `ok` alone covers parked, so asserting it would pass for a message that never crossed the connection",
    ).toBe(true);

    const received = await pollFor(() => B.manager.takeReceivedContent("bob", SID));
    expect(received, "the message never arrived at B").not.toBeNull();
    // The buffer holds the PLAINTEXT as hex — decrypted on the way in, exactly as every reader
    // downstream expects it. Comparing the hex proves the bytes, not just a length.
    expect(
      Buffer.from((received as { contentHex: string }).contentHex, "hex").toString("utf8"),
      "B decrypted to something other than what A sent",
    ).toBe(text);
    expect(
      (received as { contentHex: string }).contentHex,
      "and it is the plaintext that was buffered, not the sealed form",
    ).toBe(Buffer.from(content).toString("hex"));
  }, 60_000);

  it("★★ the BYTES ON THE WIRE are ciphertext — asserted on the FRAME B actually received", async () => {
    /**
     * ⚠️ REPLACES A TEST THAT PROVED NOTHING (review F4). It called `sendContent`, then ignored what
     * was sent and asserted on a freshly built `sealSessionContent(...)` — a test of the crypto
     * primitive, which its own suite already covers twice. Reverting `content_bytes: wireBody` back
     * to `content_bytes: content` left it green, so the clause that makes this feature real was
     * unproven by one character of revert.
     *
     * This captures the frame on B's inbound content stream and asserts against THOSE bytes.
     */
    const { A, B } = await liveSession();
    await wait(600);

    const seen: Array<Record<string, unknown>> = [];
    B.manager.observeInboundContentFramesForTest((f) => { seen.push(f); });

    const text = "a sentence a relay must not be able to read";
    const content = new TextEncoder().encode(text);
    await A.manager.sendContent("alice", SID, content, msgLeafHash(content), "corr-wire", LEAF_KIND_MSG);
    await pollFor(() => B.manager.takeReceivedContent("bob", SID));

    const frame = seen.find((f) => f["type"] === "content_frame");
    expect(frame, "B never saw a content frame — nothing to assert about the wire").toBeDefined();

    const onWire = frame!["content_bytes"] as Uint8Array;
    expect(
      Buffer.from(onWire).toString("hex").includes(Buffer.from(content).toString("hex")),
      "THE PLAINTEXT IS IN THE FRAME — a relay carrying this reads the message",
    ).toBe(false);
    expect(
      frame!["content_encryption"],
      "and the frame must name the scheme, so a receiver never infers it from a length",
    ).toBe(SESSION_CONTENT_ENCRYPTION_V1);
    expect(
      onWire.length,
      "the sealed form must carry the version, IV and tag on top of the body",
    ).toBe(content.length + 1 + 12 + 16);
  }, 60_000);

  it("★★ ONE SIDE RESTARTS and the OTHER adopts the new key — DoD 9, review F1", async () => {
    /**
     * ⚠️ THE CLAUSE HAD NO TEST AND THE CODE FAILED IT. The idempotence guard keyed on "a key
     * exists", so only the side that restarted re-keyed. The other one is never torn down — nothing
     * else clears the key — so it saw the peer's NEW ephemeral, found a key already there, and kept
     * the old one.
     *
     * A relay roll is enough: only the side whose witness stream closes interrupts. From then on
     * every message fails GCM and the RECEIVER tells its operator the content may have been MODIFIED
     * IN FLIGHT and to confirm out of band. Nothing was modified — it is a local key skew, and two
     * people end up having a security conversation about it.
     *
     * B restarts for real (interrupt, revive, fresh ephemeral). B's new half then reaches A through
     * A's REAL inbound handler — signature verified against bob's identity, then derived. The
     * transport hop is stood in for because a revived node in this harness has no route back to A,
     * and the defect was never in the transport: it was A declining to adopt a half it already held
     * a key for.
     */
    const { A, B, bobKp } = await liveSession();
    await wait(600);
    expect(B.events.find((e) => e.event === "session.key.agreed"), "PRECONDITION: agreed once").toBeDefined();
    const beforeHalf = B.manager.sessionEphemeralPublicForTest("bob", SID);

    await B.manager.markInterruptedWithDetails("bob", SID, 0, "stream_close");
    await B.manager.reviveSessionNode("bob", SID);
    const afterHalf = B.manager.sessionEphemeralPublicForTest("bob", SID);
    expect(afterHalf, "PRECONDITION: the revived side minted a keypair").not.toBeNull();
    expect(
      Buffer.from(afterHalf!).toString("hex"),
      "PRECONDITION: the restart produced a DIFFERENT half, or there is no re-key to adopt",
    ).not.toBe(Buffer.from(beforeHalf!).toString("hex"));

    const sig = await signSessionEphemeral(bobKp, Buffer.from(SID, "hex"), afterHalf!);
    await A.manager.handleEphemeralFrameForTest("alice", SID, { ephemeralPublic: afterHalf!, signature: sig });

    expect(
      A.events.filter((e) => e.event === "session.key.agreed" && e.context["rekey"] === true).length,
      "A kept its old key after B re-keyed — every message from here fails to decrypt, and B's " +
        "operator is told the content may have been tampered with for what is a local key skew",
    ).toBe(1);
  }, 60_000);

  it("★ the SAME half re-announced does NOT churn the key — idempotence is preserved", async () => {
    /**
     * The other half of F1's fix. A peer re-announces on every connect, so the same signed ephemeral
     * arrives repeatedly in an ordinary session, and re-deriving would move a value both sides depend
     * on underneath them. Keying the guard on the peer's BYTES has to keep this true while letting a
     * genuinely different half through.
     */
    const { A, B, bobKp } = await liveSession();
    await wait(600);
    const half = B.manager.sessionEphemeralPublicForTest("bob", SID)!;
    const sig = await signSessionEphemeral(bobKp, Buffer.from(SID, "hex"), half);

    const before = A.events.filter((e) => e.event === "session.key.agreed").length;
    await A.manager.handleEphemeralFrameForTest("alice", SID, { ephemeralPublic: half, signature: sig });
    await A.manager.handleEphemeralFrameForTest("alice", SID, { ephemeralPublic: half, signature: sig });
    expect(
      A.events.filter((e) => e.event === "session.key.agreed").length,
      "the same half re-announced churned the key — both sides depend on it not moving mid-session",
    ).toBe(before);
  }, 60_000);

  it("★★ NO KEY means NO DIRECT SEND — the body never goes out in the open", async () => {
    /**
     * ⚠️ THIS RULE HAD NO TEST, AND A MUTATION PROVED IT. Replacing the gate with a fallback to an
     * all-zero key left every test green — so the one line standing between "encrypted or not sent"
     * and a session quietly encrypting under a constant was unguarded.
     *
     * The rule is absolute on purpose: a plaintext (or fixed-key) fallback is what an attacker
     * steers a session into by stripping the key frame. With no key the send must NOT go direct; it
     * parks instead, sealed to the counterparty's long-term identity key, so the message still
     * arrives and nothing crosses the wire unprotected.
     */
    const { A, B } = await liveSession();
    await wait(600);
    expect(A.events.find((e) => e.event === "session.key.agreed"), "PRECONDITION: a key was agreed").toBeDefined();

    // Take the key away, exactly as a teardown does, while the session and connection stay up.
    A.manager.forgetSessionContentKeyForTest("alice", SID);

    const seen: Array<Record<string, unknown>> = [];
    B.manager.observeInboundContentFramesForTest((f) => { seen.push(f); });

    const text = "this must not travel in the clear";
    const content = new TextEncoder().encode(text);
    const sent = await A.manager.sendContent("alice", SID, content, msgLeafHash(content), "corr-nokey", LEAF_KIND_MSG) as { ok: boolean; delivered?: boolean };

    expect(
      sent.delivered,
      "the send went DIRECT with no agreed key — whatever it put on the wire was not encrypted by us",
    ).not.toBe(true);
    await wait(300);
    const leaked = seen.find((f) =>
      f["type"] === "content_frame" &&
      Buffer.from(f["content_bytes"] as Uint8Array).toString("hex").includes(Buffer.from(content).toString("hex")));
    expect(leaked, "the plaintext reached the wire").toBeUndefined();
  }, 60_000);

  it("★★ a DOCUMENT update crosses the same encrypted path — DoD 5, tested not assumed", async () => {
    /**
     * Documents ride the SAME `content_frame` as messages, so the encryption covers them for free.
     * "For free" is exactly the reasoning that produces an untested claim, and the clause says
     * tested rather than assumed — the document hook is handed the body AFTER decryption, and if it
     * ever received the sealed form instead, collaboration would break with no message-path symptom
     * to notice it by.
     */
    const { A, B } = await liveSession();
    await wait(600);

    const routed: Uint8Array[] = [];
    B.manager.setOnDocumentFrame((_agent, _sid, content) => { routed.push(content); return { consumed: true }; });

    // A document update is a content send with the DOC leaf kind.
    const update = new TextEncoder().encode("yjs-update-bytes-stand-in");
    const sent = await A.manager.sendContent("alice", SID, update, msgLeafHash(update), "corr-doc", LEAF_KIND_DOC) as { ok: boolean; delivered?: boolean };
    expect(sent.delivered, "the document update did not go direct").toBe(true);

    await pollFor(() => (routed.length > 0 ? routed : null));
    expect(routed.length, "the document layer never saw the update").toBeGreaterThan(0);
    expect(
      Buffer.from(routed[0]!).toString("hex"),
      "the document layer was handed the SEALED bytes — collaboration would break with nothing on " +
        "the message path to notice it by",
    ).toBe(Buffer.from(update).toString("hex"));
  }, 60_000);

  it("★★ an UNSIGNED ephemeral STOPS the session — it does not carry on unencrypted", async () => {
    /**
     * The loophole this whole unit is built around: an attacker evading a mismatch check does not
     * forge a signature, it sends none. If "we could not tell" were treated more gently than "we
     * proved it wrong", stripping one field would be the whole attack.
     */
    const { B } = await liveSession();
    const stranger = generateKeypair();
    const strangerEph = new Uint8Array(32).fill(0x44);

    await B.manager.handleEphemeralFrameForTest("bob", SID, {
      ephemeralPublic: strangerEph,
      // No signature at all.
    });

    const refused = B.events.find((e) => e.event === "session.key.refused");
    expect(refused, "an unsigned key was accepted").toBeDefined();
    expect(refused!.context["reason"]).toBe("ephemeral_signature_missing");
    expect(
      B.events.find((e) => e.event === "session.key.session_stopped"),
      "the session carried on after a key that could not be tied to the counterparty",
    ).toBeDefined();
    void stranger;
  }, 60_000);

  it("★★ a key signed by SOMEONE ELSE stops the session — this is the relay substituting its own", async () => {
    /**
     * The signature here is perfectly VALID. It is simply not the counterparty's, which is exactly
     * what a relay holding its own identity key produces.
     */
    const { B } = await liveSession();
    const relayKp = generateKeypair();
    const relayEph = new Uint8Array(32).fill(0x55);
    const relaySig = await signSessionEphemeral(relayKp, Buffer.from(SID, "hex"), relayEph);

    await B.manager.handleEphemeralFrameForTest("bob", SID, {
      ephemeralPublic: relayEph, signature: relaySig,
    });

    const refused = B.events.find((e) => e.event === "session.key.refused");
    expect(refused, "a key signed by anyone at all was accepted — the substitution succeeds").toBeDefined();
    expect(refused!.context["reason"]).toBe("ephemeral_signature_mismatch");
    expect(
      String(refused!.context["guidance"]),
      "and the operator must be sent OUT OF BAND — not back over the channel that may be compromised",
    ).toMatch(/out of band/i);
  }, 60_000);

  it("★★ a body with NO encryption marker is refused UNREAD — absence is not plaintext", async () => {
    /**
     * The downgrade, on the receive side. There is no unencrypted sender to be compatible with, so a
     * frame that does not say what scheme it is under is not "an old peer" — it is a frame something
     * rewrote. Reading it raw is precisely what the attacker asked for.
     */
    const { A, B } = await liveSession();
    await pollFor(() => B.events.find((e) => e.event === "session.key.agreed") ? true : null);

    const content = new TextEncoder().encode("delivered in the clear, if you let me");
    await B.manager.handleContentFrameForTest("bob", SID, framed({
      type: "content_frame", session_id: SID,
      content_bytes: content, content_hash: msgLeafHash(content),
    }), A.manager.getSessionNodePeerId("alice", SID) ?? undefined);

    const refused = await pollFor(() =>
      B.events.find((e) => e.event === "session.content.refused") ?? null);
    expect(refused, "a frame with no encryption marker was read as plaintext").not.toBeNull();
    expect(refused!.context["reason"]).toBe("content_encryption_absent_or_unknown");
    const delivered = B.manager.takeReceivedContent("bob", SID);
    expect(
      delivered === null || delivered.length === 0,
      "a refused frame must deliver nothing",
    ).toBe(true);
  }, 60_000);

  it("★★ a body encrypted under a DIFFERENT key is refused unread", async () => {
    const { A, B } = await liveSession();
    await pollFor(() => B.events.find((e) => e.event === "session.key.agreed") ? true : null);

    const content = new TextEncoder().encode("sealed to a key this session never agreed");
    await B.manager.handleContentFrameForTest("bob", SID, framed({
      type: "content_frame", session_id: SID,
      content_bytes: sealSessionContent(new Uint8Array(32).fill(0x99), content),
      content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
      content_hash: msgLeafHash(content),
    }), A.manager.getSessionNodePeerId("alice", SID) ?? undefined);

    const refused = await pollFor(() =>
      B.events.find((e) => e.event === "session.content.refused" && e.context["reason"] === "decrypt_failed") ?? null);
    expect(refused, "a body under the wrong key was accepted").not.toBeNull();
    const got = B.manager.takeReceivedContent("bob", SID);
    expect(got === null || got.length === 0, "a refused frame must deliver nothing").toBe(true);
  }, 60_000);
});
