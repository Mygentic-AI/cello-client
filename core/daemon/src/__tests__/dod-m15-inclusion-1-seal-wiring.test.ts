/**
 * DOD-M15-INCLUSION-1 — the seam that fills the certified leaf set, driven by a real seal frame.
 *
 * ─── WHY THIS FILE EXISTS SEPARATELY, WHICH IS THE WHOLE POINT ────────────────────────────────
 *
 * Review finding F1, and it is the kind of gap that ships a feature working perfectly in vitest and
 * returning `certified_leaves_not_carried` on every real session. The unit's other test file calls
 * `recordCertifiedLeafSet` / `getCertifiedLeafSet` DIRECTLY. Nothing drove a seal frame through
 * `keepCertifiedLeafSet`, so **all three call sites in `seal-coordinator.ts` could be deleted and
 * the entire suite stayed green** — while the chain that actually populates the table in production
 * (`frame["frontier_leaves"]` → `parseFrontierLeaves` → `certifiedLeafSetFrom` → the table) was
 * unproven end to end. A wrong field name, a wrong `toU8` coercion for the shape cbor-x decodes, or
 * a hook inside the wrong `if` would all have shipped.
 *
 * So this drives the real listener: `createSealCoordinator` → `registerSealListeners` → a
 * `session_sealed` frame → the real `SessionNodeManager` → the real table.
 *
 * ─── TWO FIXTURE DECISIONS, BOTH LOAD-BEARING ─────────────────────────────────────────────────
 *
 * **The leaves are really signed.** They have to be: the bilateral path runs `reDeriveFrontiers`
 * over this exact array and RETURNS on a bad signature, so filler signatures would abort before
 * `keepCertifiedLeafSet` and the test would pass for the wrong reason — proving only that a frame
 * with unusable leaves stores nothing. Real Ed25519 over the real Structure 1 bytes is what makes
 * the frame reach the code under test.
 *
 * **`signature_type` is deliberately absent.** The FROST branch verifies a consortium signature this
 * fixture has no way to produce, and that branch has its own tests (`dod-m15-sealwire-1-*`). Omitting
 * it takes the directory's single-key path, which is a real production shape and the one that
 * exercises the leaf-set wiring without re-testing signature verification.
 *
 * Crypto refs: RFC 8032 (Ed25519), RFC 6962 §2.1 (Merkle hash trees).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes, createHash } from "node:crypto";
import { buildMerkleTree, merkleRoot, InMemoryKeyProvider, type LeafInput } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { SignalingManager } from "@cello-protocol/transport";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory } from "../session-node-manager.js";
import { createSealCoordinator } from "../seal-coordinator.js";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { contentHashFor, CONTENT_HASH_ALGS } from "../wire-content-hash.js";
import type { Logger } from "../types.js";
import { seedAgents } from "./helpers/seed-agents.js";

const AGENT = "alice";
const AGENT_PUB = "aa".repeat(32);
/**
 * 16 BYTES, and the hex is the WHOLE of it — not a prefix.
 *
 * The listener derives the session id it works with from the frame (`frameValueToHex`), so a
 * constant that is not exactly the hex of the bytes on the frame means every lookup below runs
 * against a session the daemon has never heard of. The first run of this file failed on precisely
 * that, and it failed silently in the useful sense: the frame was processed, just for another id.
 */
const SESSION_ID = "7c".repeat(16);
const SESSION_ID_BYTES = new Uint8Array(Buffer.from(SESSION_ID, "hex"));

const NO_FACTORY = { create: () => { throw new Error("no session node in this fixture"); } } as unknown as ISessionNodeFactory;

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(e, c) { events.push({ level: "debug", event: e, context: c }); },
    info(e, c) { events.push({ level: "info", event: e, context: c }); },
    warn(e, c) { events.push({ level: "warn", event: e, context: c }); },
    error(e, c) { events.push({ level: "error", event: e, context: c }); },
  };
  return { logger, events };
}

/** Records the inbound handlers a coordinator registers, and can fire a frame at all of them. */
function fakeSignaling() {
  const handlers: Array<(frame: Record<string, unknown>) => void> = [];
  return {
    registerInboundHandler: vi.fn((h: (frame: Record<string, unknown>) => void) => {
      handlers.push(h);
      return () => { /* unregister */ };
    }),
    sendRaw: vi.fn(async () => { /* directory send */ }),
    deliver(frame: Record<string, unknown>) { for (const h of handlers) h(frame); },
  };
}

/** The root rule, stated with the shared primitives rather than with the module under test. */
function rootOver(hashesHex: readonly string[]): string {
  const inputs: LeafInput[] = hashesHex.map((h) => ({ kind: "hash" as const, data: new Uint8Array(Buffer.from(h, "hex")) }));
  return Buffer.from(merkleRoot(buildMerkleTree(inputs))).toString("hex");
}

describe("DOD-M15-INCLUSION-1: a real session_sealed frame fills the certified leaf set", () => {
  let tempDir: string;
  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-inc-wiring-")); });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  it("the bilateral seal path stores the leaf set the certificate is signed over", async () => {
    const { logger, events } = makeLogger();
    const mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: NO_FACTORY,
      logger,
      dbPath: join(tempDir, "s.db"),
    });
    await mgr.initialize();
    await seedAgents(mgr.getDb(), [AGENT]);
    const agentId = (mgr.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(AGENT) as { agent_id: string }).agent_id;
    const now = Date.now();
    mgr.getDb()
      .prepare("INSERT OR IGNORE INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(SESSION_ID, agentId, "bb".repeat(32), "active", now, now);

    // The salt the session hashes under, and the two messages it carries.
    const salt = new Uint8Array(randomBytes(32));
    mgr.getDb().prepare("UPDATE sessions SET content_salt = ? WHERE session_id = ?").run(Buffer.from(salt), SESSION_ID);
    const messages = ["Shipment leaves Rotterdam on the 3rd.", "Confirmed for the 3rd."];
    const contentHashes = messages.map((m) =>
      Buffer.from(contentHashFor(new TextEncoder().encode(m), { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt })).toString("hex"),
    );
    for (const h of contentHashes) mgr.appendSessionLeaf(AGENT, SESSION_ID, "msg", h);

    // The SEAL ctrl leaf: in the certified set, never in the local tree.
    const ctrlHash = createHash("sha256").update(new Uint8Array([0x02])).update(new Uint8Array(randomBytes(40))).digest("hex");
    const certifiedLeaves = [...contentHashes, ctrlHash];
    const sealedRoot = rootOver(certifiedLeaves);

    // REALLY SIGNED — see the header. `reDeriveFrontiers` returns on a bad signature, so filler
    // would abort before the code under test and the test would pass for the wrong reason.
    const signer = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const senderPubkey = await signer.getPublicKey();
    const frontierLeaves = await Promise.all(
      certifiedLeaves.map(async (h, i) => {
        const s1 = encodeStructure1({
          contentHash: new Uint8Array(Buffer.from(h, "hex")),
          senderPubkey,
          sessionId: SESSION_ID_BYTES,
          lastSeenSeq: i,
          timestamp: 1_700_000_000_000 + i,
          lastSeenHash: new Uint8Array(32).fill(0xa7),
          prevOwnHash: new Uint8Array(32).fill(0xb4),
        });
        return { structure1_cbor: s1, sender_pubkey: senderPubkey, sender_signature: await signer.sign(s1) };
      }),
    );

    const coordinator = createSealCoordinator({
      logger,
      sessionNodeManager: mgr,
      getPersistence: vi.fn() as never,
      getKeyProvider: vi.fn(() => undefined),
      recoverContent: vi.fn(async () => { /* nothing parked */ }),
      recordSealFailure: vi.fn(),
    });
    const signaling = fakeSignaling();
    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, AGENT_PUB);

    expect(mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toBeNull();

    signaling.deliver({
      type: "session_sealed",
      session_id: SESSION_ID_BYTES,
      sealed_root: new Uint8Array(Buffer.from(sealedRoot, "hex")),
      leaf_count: certifiedLeaves.length,
      // THE REAL SHAPE `normalizeLegibility` ACCEPTS. Without `attests: "receipt"` and a non-empty
      // `disclaimer` it returns undefined, the whole legibility block is skipped, and the frame is
      // processed to completion having stored nothing and logged nothing about it — which is exactly
      // how the first run of this test failed, and is worth the comment.
      legibility: {
        attests: "receipt",
        disclaimer: "This signature attests receipt, never assent.",
        participants: [{
          pubkey: Buffer.from(senderPubkey).toString("hex"),
          content_frontier_seq: 1,
          last_authored_seq: 2,
          attestation_mode: "live",
        }],
        final_message: { sender_pubkey: Buffer.from(senderPubkey).toString("hex"), seq: 2, answered: true },
      },
      frontier_leaves: frontierLeaves,
    });

    await vi.waitFor(() => expect(mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).not.toBeNull());

    // THE ASSERTION THAT MATTERS: what landed is the set, in order, and it reproduces the root the
    // certificate is signed over. Not "some rows were written".
    const stored = mgr.getCertifiedLeafSet(AGENT, SESSION_ID);
    expect(stored).toEqual(certifiedLeaves);
    expect(rootOver(stored!)).toBe(sealedRoot);
    expect(mgr.getCertifiedLeafSetState(AGENT, SESSION_ID)?.state).toBe("stored");
    expect(events.some((e) => e.event === "seal.certified_leaves.recorded")).toBe(true);

    // And it covers the seal's control leaf, which the local tree does not hold — the asymmetry the
    // whole unit exists for, observed here on the real path rather than assembled by a fixture.
    expect(stored).toHaveLength(mgr.getSessionTree(AGENT, SESSION_ID).size() + 1);
    expect(mgr.getSessionTreeRootHex(AGENT, SESSION_ID)).not.toBe(sealedRoot);

    await mgr.gracefulShutdown();
  });

  it("a seal frame carrying NO signed leaves records why, so the refusal can name it", async () => {
    const { logger } = makeLogger();
    const mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: NO_FACTORY,
      logger,
      dbPath: join(tempDir, "n.db"),
    });
    await mgr.initialize();
    await seedAgents(mgr.getDb(), [AGENT]);
    const agentId = (mgr.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(AGENT) as { agent_id: string }).agent_id;
    const now = Date.now();
    mgr.getDb()
      .prepare("INSERT OR IGNORE INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(SESSION_ID, agentId, "bb".repeat(32), "active", now, now);

    const coordinator = createSealCoordinator({
      logger,
      sessionNodeManager: mgr,
      getPersistence: vi.fn() as never,
      getKeyProvider: vi.fn(() => undefined),
      recoverContent: vi.fn(async () => { /* nothing parked */ }),
      recordSealFailure: vi.fn(),
    });
    const signaling = fakeSignaling();
    coordinator.registerSealListeners(signaling as unknown as SignalingManager, AGENT, AGENT_PUB);

    signaling.deliver({
      type: "session_sealed",
      session_id: SESSION_ID_BYTES,
      sealed_root: new Uint8Array(Buffer.from("dd".repeat(32), "hex")),
      leaf_count: 3,
      // No frontier_leaves, and no participant claiming to have received anything — otherwise the
      // fail-closed guard above rejects the whole certificate and this path is never reached.
      legibility: {
        attests: "receipt",
        disclaimer: "This signature attests receipt, never assent.",
        participants: [],
        final_message: { sender_pubkey: null, seq: null, answered: false },
      },
    });

    await vi.waitFor(() => expect(mgr.getCertifiedLeafSetState(AGENT, SESSION_ID)).not.toBeNull());
    // PRESENT party, because this is the bilateral frame — so the operator must NOT be sent to a
    // counterparty who holds even less.
    expect(mgr.getCertifiedLeafSetState(AGENT, SESSION_ID)?.state).toBe("not_carried_present_party");
    expect(mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toBeNull();

    await mgr.gracefulShutdown();
  });
});
