/**
 * DOD-M15-INCLUSION-1 — proving that ONE message sits under the root the directory notarized.
 *
 * Specification (SPARC Phase S), one `it` per Definition-of-Done line:
 *
 *  1. A message in a sealed session yields a proof, and the verify path accepts it.
 *  2. The proof verifies against the CERTIFIED root — taken from the certificate, NOT the local
 *     tree. Asserted with teeth: the certified root and the local tree root are DIFFERENT values in
 *     a real sealed session (the certified root covers the seal's ctrl leaf and the local tree does
 *     not), so a proof built from `SessionTree` would fail this and nothing else would notice.
 *  3. A message that is NOT in the session is refused, by name.
 *  4. A session that is not yet sealed is refused, by a DIFFERENT name.
 *  5. A local tree that disagrees with the certified root refuses rather than emitting a proof.
 *  6. A tampered message fails verification — one byte.
 *  7. A tampered proof path fails verification.
 *  8. A salted session proves and names its algorithm and salt; an UNSALTED session is refused by
 *     name (no compatibility branch — the alpha-cost ruling in the work order).
 *  9. Verification runs from proof + message + certificate alone, with the daemon's database CLOSED
 *     AND DELETED — so "no DB access" is a fact about the run, not a claim about the imports.
 *
 * ─── WHY THE FIXTURE HASHES FOR REAL AND SIGNS WITH FILLER ────────────────────────────────────
 *
 * Every content hash here is produced by the daemon's own `contentHashFor`, and every root by
 * `buildMerkleTree`/`merkleRoot` from `@cello-protocol/crypto` — no crypto is mocked, because the
 * whole subject is whether two independently-derived hashes agree.
 *
 * The Ed25519 signatures on the fixture's `SealFrontierLeaf`s ARE filler, and deliberately so:
 * `recordCertifiedLeafSet` does not check them and must not, because by the time it runs
 * `reDeriveFrontiers` has already verified that exact array (seal-coordinator.ts). Signing here
 * would test a check that lives somewhere else and hide the one that lives here — the ROOT
 * comparison, which is what makes the stored set the consortium's rather than the directory's word.
 *
 * Crypto refs: RFC 6962 §2.1.1 (Merkle audit paths), RFC 2104 (HMAC), FIPS 180-4 (SHA-256).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes, createHash } from "node:crypto";
import { buildMerkleTree, merkleRoot, type LeafInput } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory } from "../session-node-manager.js";
import { encodeStructure1 } from "../session-relay-client.js";
import type { SealFrontierLeaf } from "../seal-frontier-verify.js";
import { registerInclusionProofHandlers } from "../inclusion-proof-handlers.js";
import { verifyInclusionProof, INCLUSION_VERIFY_REASONS, type InclusionProof } from "../inclusion-proof.js";
import { CONTENT_HASH_ALGS, contentHashFor } from "../wire-content-hash.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";
import { seedAgents } from "./helpers/seed-agents.js";

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

/** The manager never opens a session node in this file — only its persisted state is exercised. */
const NO_FACTORY = { create: () => { throw new Error("no session node in this fixture"); } } as unknown as ISessionNodeFactory;

const AGENT = "alice";
const SESSION_ID = "9f".repeat(32);
const SESSION_ID_BYTES = new Uint8Array(Buffer.from(SESSION_ID.slice(0, 32), "hex"));

/** The root rule, stated with the shared primitives rather than with the module under test. */
function rootOver(leafHashesHex: readonly string[]): string {
  const inputs: LeafInput[] = leafHashesHex.map((h) => ({ kind: "hash" as const, data: new Uint8Array(Buffer.from(h, "hex")) }));
  return Buffer.from(merkleRoot(buildMerkleTree(inputs))).toString("hex");
}

/** A SEAL control leaf's content hash: SHA-256(0x02 ‖ payload) — the client's own derivation. */
function ctrlLeafHashHex(payload: Uint8Array): string {
  return createHash("sha256").update(new Uint8Array([0x02])).update(payload).digest("hex");
}

function signedLeavesFor(hashesHex: readonly string[]): SealFrontierLeaf[] {
  return hashesHex.map((h, i) => ({
    structure1_cbor: encodeStructure1(
      new Uint8Array(Buffer.from(h, "hex")),
      new Uint8Array(32),
      SESSION_ID_BYTES,
      i,
      1_700_000_000_000 + i,
    ),
    sender_pubkey: new Uint8Array(32),
    sender_signature: new Uint8Array(64),
  }));
}

interface Fixture {
  mgr: SessionNodeManager;
  handlers: Map<string, IpcHandler>;
  messages: string[];
  salt: Uint8Array | null;
  contentHashes: string[];
  certifiedLeaves: string[];
  sealedRoot: string;
  localTreeRoot: string;
  events: LogEvent[];
  getProof(overrides?: Record<string, unknown>): Promise<Record<string, unknown>>;
}

/**
 * A session in the state a completed seal leaves: content leaves in the local tree, a certificate,
 * and the certified leaf set — which includes the SEAL ctrl leaf the local tree never holds.
 *
 * `opts.salted: false` produces the unsalted session DoD 8 requires be REFUSED. `opts.seal: false`
 * stops before the certificate for DoD 4.
 */
async function makeFixture(
  dbPath: string,
  opts: { salted?: boolean; seal?: boolean; messages?: string[] } = {},
): Promise<Fixture> {
  const salted = opts.salted !== false;
  const seal = opts.seal !== false;
  const messages = opts.messages ?? [
    "The invoice total is 41,500 EUR, payable on the 14th.",
    "Agreed — 41,500 EUR on the 14th.",
  ];

  const { logger, events } = makeLogger();
  const mgr = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory: NO_FACTORY,
    logger,
    dbPath,
  });
  await mgr.initialize();
  await seedAgents(mgr.getDb(), [AGENT]);

  // The sessions row, keyed on the STABLE agent_id exactly as production keys it.
  const agentId = (mgr.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(AGENT) as { agent_id: string }).agent_id;
  const now = Date.now();
  mgr.getDb()
    .prepare("INSERT OR IGNORE INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(SESSION_ID, agentId, "bb".repeat(32), "active", now, now);

  const salt = salted ? new Uint8Array(randomBytes(32)) : null;
  if (salt) {
    mgr.getDb()
      .prepare("UPDATE sessions SET content_salt = ? WHERE session_id = ?")
      .run(Buffer.from(salt), SESSION_ID);
  }

  // Content leaves, hashed the way the session hashes them.
  const alg = salt ? CONTENT_HASH_ALGS.HMAC_SALT_V1 : CONTENT_HASH_ALGS.SHA256;
  const contentHashes = messages.map((m) =>
    Buffer.from(contentHashFor(new TextEncoder().encode(m), { alg, salt })).toString("hex"),
  );
  for (const h of contentHashes) mgr.appendSessionLeaf(AGENT, SESSION_ID, "msg", h);

  // The SEAL ctrl leaf: in the certified set, NEVER in the local tree. This asymmetry is the reason
  // this unit exists, so the fixture reproduces it rather than papering over it.
  const ctrlHash = ctrlLeafHashHex(new Uint8Array(randomBytes(48)));
  const certifiedLeaves = [...contentHashes, ctrlHash];
  const sealedRoot = rootOver(certifiedLeaves);
  const localTreeRoot = mgr.getSessionTreeRootHex(AGENT, SESSION_ID);

  if (seal) {
    mgr.recordSealCertificate(AGENT, SESSION_ID, sealedRoot, JSON.stringify({ participants: [], final_message: { answered: true } }));
    mgr.recordCertifiedLeafSet(AGENT, SESSION_ID, signedLeavesFor(certifiedLeaves), sealedRoot);
  }

  const handlers = new Map<string, IpcHandler>();
  registerInclusionProofHandlers({
    handlers,
    logger,
    sessionNodeManager: mgr,
    getConnState: () => ({ currentAgent: AGENT }) as never,
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
  });

  const getProof = async (overrides: Record<string, unknown> = {}) =>
    (await handlers.get("cello_get_inclusion_proof")!(
      { session_id: SESSION_ID, message: messages[0], ...overrides },
      "conn-1",
    )) as Record<string, unknown>;

  return { mgr, handlers, messages, salt, contentHashes, certifiedLeaves, sealedRoot, localTreeRoot, events, getProof };
}

describe("DOD-M15-INCLUSION-1: prove one message sits under the sealed root", () => {
  let tempDir: string;

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-inclusion-")); });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  const dbPath = (): string => join(tempDir, "s.db");

  it("DoD 1: a message in a sealed session yields a proof and the verify path accepts it", async () => {
    const f = await makeFixture(dbPath());
    const res = await f.getProof();

    expect(res["ok"]).toBe(true);
    const proof = res["proof"] as InclusionProof;
    expect(proof.version).toBe(1);
    expect(proof.leaf_index).toBe(0);
    expect(proof.leaf_count).toBe(3);

    const verdict = await f.handlers.get("cello_verify_inclusion_proof")!(
      { proof, message: f.messages[0], certified_root: f.sealedRoot },
      "conn-1",
    ) as Record<string, unknown>;
    expect(verdict["ok"]).toBe(true);
    expect(verdict["verified"]).toBe(true);
    expect(verdict["leaf_index"]).toBe(0);
  });

  /**
   * DoD 2 — AND THE ASSERTION THAT GIVES IT TEETH.
   *
   * `expect(proof.certified_root).toBe(sealedRoot)` alone would stay green if the handler used the
   * local tree AND the two roots happened to be equal. In a real sealed session they are NOT equal —
   * the certified root covers the seal's ctrl leaf — so asserting the INEQUALITY first is what makes
   * the following equality mean "it used the certificate" rather than "the values coincided".
   */
  it("DoD 2: the proof lands on the CERTIFIED root, which is not the local tree's root", async () => {
    const f = await makeFixture(dbPath());

    expect(f.localTreeRoot).not.toBe(f.sealedRoot);

    const proof = (await f.getProof())["proof"] as InclusionProof;
    expect(proof.certified_root).toBe(f.sealedRoot);
    expect(proof.certified_root).not.toBe(f.localTreeRoot);

    // And it verifies against the root taken from the CERTIFICATE, read back the way an operator
    // reads it — not against the value the proof carries.
    const fromCertificate = f.mgr.getSealCertificate(AGENT, SESSION_ID)!.sealed_root;
    expect(verifyInclusionProof(proof, new TextEncoder().encode(f.messages[0]), fromCertificate).ok).toBe(true);

    // The same proof checked against the LOCAL tree's root is refused, which is the property that
    // makes "certified" load-bearing rather than decorative.
    const againstLocal = verifyInclusionProof(proof, new TextEncoder().encode(f.messages[0]), f.localTreeRoot);
    expect(againstLocal.ok).toBe(false);
    expect(againstLocal.ok === false && againstLocal.reason).toBe(INCLUSION_VERIFY_REASONS.ROOT_NOT_FROM_CERTIFICATE);
  });

  it("DoD 3: a message that is not in the session is refused by name", async () => {
    const f = await makeFixture(dbPath());
    const res = await f.getProof({ message: "I never said this." });

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("message_not_in_session");
    expect(String(res["guidance"])).toContain("cello_transcript");
  });

  it("DoD 4: a session that is not sealed yet is refused by a DIFFERENT name", async () => {
    const f = await makeFixture(dbPath(), { seal: false });
    const res = await f.getProof();

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("not_sealed_yet");
    // The two situations must never share a reason string — DoD 4 is about the DIFFERENCE.
    expect(res["reason"]).not.toBe("message_not_in_session");
    expect(String(res["guidance"])).toContain("cello_close_session");
  });

  it("DoD 5: a local tree that disagrees with the certified root refuses rather than proving", async () => {
    const f = await makeFixture(dbPath());

    // Rewrite one leaf of THIS SIDE's record, leaving the certified set intact — the shape a
    // divergence takes: the operator's transcript is no longer the notarized conversation.
    f.mgr.getDb()
      .prepare("UPDATE session_tree_leaves SET leaf_hash_hex = ? WHERE session_id = ? AND leaf_index = 0")
      .run("cc".repeat(32), SESSION_ID);
    // Force a reload from disk so the in-memory tree reflects the edited row.
    const reopened = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: NO_FACTORY,
      logger: makeLogger().logger,
      dbPath: dbPath(),
    });
    await reopened.initialize();
    const handlers = new Map<string, IpcHandler>();
    const { logger, events } = makeLogger();
    registerInclusionProofHandlers({
      handlers,
      logger,
      sessionNodeManager: reopened,
      getConnState: () => ({ currentAgent: AGENT }) as never,
      resolveCurrentAgent: () => AGENT,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    });

    const res = (await handlers.get("cello_get_inclusion_proof")!(
      { session_id: SESSION_ID, message: f.messages[1] },
      "conn-1",
    )) as Record<string, unknown>;

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("local_tree_diverged");
    expect(res["proof"]).toBeUndefined();
    // Loud as well as blocking — the log is the durable half, the response is the control.
    expect(events.some((e) => e.level === "error" && e.event === "inclusion.local_tree.diverged")).toBe(true);
  });

  it("DoD 6: a message altered by ONE byte fails verification", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;

    // One character: the amount is the thing a dispute would be about.
    const tampered = f.messages[0].replace("41,500", "41,600");
    expect(tampered).not.toBe(f.messages[0]);
    expect(tampered.length).toBe(f.messages[0].length);

    const verdict = verifyInclusionProof(proof, new TextEncoder().encode(tampered), f.sealedRoot);
    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe(INCLUSION_VERIFY_REASONS.MESSAGE_DOES_NOT_MATCH_LEAF);
    // The untouched message still passes, so the failure is about the edit and not about the fixture.
    expect(verifyInclusionProof(proof, new TextEncoder().encode(f.messages[0]), f.sealedRoot).ok).toBe(true);
  });

  it("DoD 7: a tampered proof path fails verification", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;
    expect(proof.proof_path.length).toBeGreaterThan(0);

    const tampered: InclusionProof = {
      ...proof,
      proof_path: [ "11".repeat(32), ...proof.proof_path.slice(1) ],
    };
    const verdict = verifyInclusionProof(tampered, new TextEncoder().encode(f.messages[0]), f.sealedRoot);
    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe(INCLUSION_VERIFY_REASONS.PROOF_PATH_INVALID);
  });

  it("DoD 8a: a salted session proves, and names its algorithm and salt", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;

    expect(proof.content_hash_alg).toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
    expect(proof.content_salt).toBe(Buffer.from(f.salt!).toString("hex"));

    // The salt is what makes the proof about a sentence: recomputing the leaf WITHOUT it produces a
    // different value, so a verifier handed the proof and no salt could not check anything.
    const unsalted = Buffer.from(
      contentHashFor(new TextEncoder().encode(f.messages[0]), { alg: CONTENT_HASH_ALGS.SHA256, salt: null }),
    ).toString("hex");
    expect(unsalted).not.toBe(proof.leaf_hash);
  });

  it("DoD 8b: an UNSALTED session is refused by name — there is no compatibility branch", async () => {
    const f = await makeFixture(dbPath(), { salted: false });
    const res = await f.getProof();

    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("session_unsalted");
    expect(res["proof"]).toBeUndefined();
    expect(String(res["guidance"])).toContain("UNSALTED");
  });

  /**
   * A CORRUPT SALT IS NOT AN UNSALTED SESSION — fallback-finder finding 2.
   *
   * `getSessionContentSalt` answers null for both, and the two need opposite sentences. A session
   * whose salt row is the wrong width DID hash its leaves under a salt; telling its operator the
   * session is unsalted and to start a new one with their counterparty sends them to the other party
   * over damage to their own disk. `wrong_width` is `#getSessionSalt`'s own case, used verbatim
   * rather than a representative — the clause names it.
   */
  it("a session whose salt row is CORRUPT is refused as unreadable, not reported as unsalted", async () => {
    const f = await makeFixture(dbPath());
    f.mgr.getDb()
      .prepare("UPDATE sessions SET content_salt = ? WHERE session_id = ?")
      .run(Buffer.from(new Uint8Array(7)), SESSION_ID); // wrong width — a salt is SESSION_SALT_BYTES

    // A fresh manager, because the salt this process already read is cached in memory.
    const reopened = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: NO_FACTORY,
      logger: makeLogger().logger,
      dbPath: dbPath(),
    });
    await reopened.initialize();
    const handlers = new Map<string, IpcHandler>();
    const { logger, events } = makeLogger();
    registerInclusionProofHandlers({
      handlers, logger, sessionNodeManager: reopened,
      getConnState: () => ({ currentAgent: AGENT }) as never,
      resolveCurrentAgent: () => AGENT,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    });

    const res = (await handlers.get("cello_get_inclusion_proof")!(
      { session_id: SESSION_ID, message: f.messages[0] },
      "conn-1",
    )) as Record<string, unknown>;

    expect(res["reason"]).toBe("session_salt_unreadable");
    expect(res["reason"]).not.toBe("session_unsalted");
    // The remedy must point at THIS machine, and must not send the operator to the counterparty.
    expect(String(res["guidance"])).toContain("THIS MACHINE'S DATABASE");
    expect(String(res["guidance"])).toContain("session.salt.read.failed");
    // The remedy must not be "start a new session" — but the text legitimately contains that phrase
    // in order to FORBID it, so the assertion is on the instruction, not on the substring. A bare
    // `.not.toContain("start a new session")` fails the corrected text and passes the broken one.
    expect(String(res["guidance"])).toMatch(/do not[^.]{0,60}start a new session/i);
    expect(String(res["guidance"])).not.toMatch(/^(?!.*do not).*start a new session/is);
    expect(events.some((e) => e.level === "error" && e.event === "inclusion.salt.unreadable")).toBe(true);
  });

  it("DoD 8c: the verifier refuses an unsalted PROOF rather than checking it", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;

    const downgraded = { ...proof, content_hash_alg: CONTENT_HASH_ALGS.SHA256, content_salt: null };
    const verdict = verifyInclusionProof(downgraded, new TextEncoder().encode(f.messages[0]), f.sealedRoot);
    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe(INCLUSION_VERIFY_REASONS.UNSALTED_PROOF);
    // "Not checked" is not "found false" — the guidance must not let a reader conclude the second.
    expect(verdict.ok === false && verdict.guidance).toContain("has NOT been shown to be false");
  });

  /**
   * DoD 9 — and the database is CLOSED AND DELETED before the verifier runs.
   *
   * Asserting that the verify function "takes only three arguments" would be a claim about the
   * signature. CLOSING the database and then deleting it is a fact about the run: a handle that has
   * been through `gracefulShutdown` cannot be read, so if any part of this path touched the daemon's
   * store the call below would throw rather than return a verdict.
   */
  it("DoD 9: verification runs from proof + message + certificate with the daemon's DB deleted", async () => {
    const f = await makeFixture(dbPath());
    const issued = await f.getProof();
    const certifiedRoot = f.mgr.getSealCertificate(AGENT, SESSION_ID)!.sealed_root;

    // What a third party actually receives: JSON, pasted, re-parsed. Not the live object.
    const overTheWire = JSON.parse(JSON.stringify(issued["proof"])) as unknown;
    const message = f.messages[1];
    const proofForSecond = JSON.parse(
      JSON.stringify((await f.getProof({ message }))["proof"]),
    ) as unknown;

    // ⚠️ `rm` ALONE DOES NOT PROVE THIS — review F7. On POSIX an unlinked SQLite file stays fully
    // readable through an open handle, so a verifier that DID reach the manager would still have
    // passed. Closing the handle first is what makes the deletion mean something.
    await f.mgr.gracefulShutdown();
    await rm(tempDir, { recursive: true, force: true });

    expect(verifyInclusionProof(overTheWire, new TextEncoder().encode(f.messages[0]), certifiedRoot).ok).toBe(true);
    expect(verifyInclusionProof(proofForSecond, new TextEncoder().encode(message), certifiedRoot).ok).toBe(true);

    // Re-created for afterEach's rm, which must not fail on a directory this test removed.
    tempDir = await mkdtemp(join(tmpdir(), "cello-inclusion-"));
  });

  /**
   * THE STORED SET IS RE-PROVED AGAINST THE CERTIFICATE ON EVERY READ.
   *
   * Not a DoD line of its own; it is what DoD 2 rests on. The seal-time check ran against the seal
   * FRAME. This one runs against a SQLCipher file on the operator's own disk, which is the thing a
   * sceptic is entitled to doubt, and without it an edited row would silently produce proofs
   * against a root nobody signed.
   */
  it("a certified leaf set edited on disk stops producing proofs", async () => {
    const f = await makeFixture(dbPath());
    f.mgr.getDb()
      .prepare("UPDATE session_certified_leaves SET content_hash_hex = ? WHERE session_id = ? AND leaf_index = 0")
      .run("ab".repeat(32), SESSION_ID);

    const res = await f.getProof();
    expect(res["ok"]).toBe(false);
    expect(res["reason"]).toBe("certified_leaves_root_mismatch");
  });

  /**
   * A LEAF SET THAT DOES NOT REPRODUCE THE SIGNED ROOT IS NEVER STORED.
   *
   * This is what separates "the leaves the directory sent" from "the leaves the consortium signed".
   * A directory that adds, drops, reorders or alters one leaf produces a different root, and the set
   * is refused rather than becoming the basis of every later proof.
   */
  it("recordCertifiedLeafSet refuses a leaf set that does not hash to the certified root", async () => {
    const f = await makeFixture(dbPath(), { seal: false });
    const tamperedSet = [...f.certifiedLeaves];
    tamperedSet[1] = "ee".repeat(32);

    const stored = f.mgr.recordCertifiedLeafSet(AGENT, SESSION_ID, signedLeavesFor(tamperedSet), f.sealedRoot);
    expect(stored).toBe(false);
    expect(f.mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toBeNull();
    expect(
      f.events.some((e) => e.level === "error" && e.event === "seal.certified_leaves.refused" && e.context["reason"] === "sealed_leaves_root_disagrees"),
    ).toBe(true);

    // The honest set for the same root IS stored — so the refusal above is about the tampering and
    // not about the method rejecting everything.
    expect(f.mgr.recordCertifiedLeafSet(AGENT, SESSION_ID, signedLeavesFor(f.certifiedLeaves), f.sealedRoot)).toBe(true);
    expect(f.mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toEqual(f.certifiedLeaves);
  });

  /**
   * THE SAME TEXT TWICE IS TWO MESSAGES.
   *
   * `DOD-FRONTIER-STRAND-1` already paid for treating byte-identical content as one thing: a session
   * stranded because a genuine second send was dropped as a redelivery. So a repeat is refused with
   * its positions rather than silently resolved to the first.
   */
  it("a message sent twice is refused as ambiguous, and leaf_index picks the occurrence", async () => {
    const repeated = "Confirmed.";
    const f = await makeFixture(dbPath(), { messages: [repeated, "Noted.", repeated] });

    const ambiguous = await f.getProof({ message: repeated });
    expect(ambiguous["ok"]).toBe(false);
    expect(ambiguous["reason"]).toBe("message_ambiguous");
    expect(ambiguous["candidate_leaf_indices"]).toEqual([0, 2]);

    const second = await f.getProof({ message: repeated, leaf_index: 2 });
    expect(second["ok"]).toBe(true);
    expect((second["proof"] as InclusionProof).leaf_index).toBe(2);

    // And the two proofs are genuinely different audit paths, not the same one relabelled.
    const first = await f.getProof({ message: repeated, leaf_index: 0 });
    expect((first["proof"] as InclusionProof).proof_path).not.toEqual((second["proof"] as InclusionProof).proof_path);
    expect(verifyInclusionProof(second["proof"], new TextEncoder().encode(repeated), f.sealedRoot).ok).toBe(true);
  });

  /**
   * WHY THERE IS NO LEAF SET — four causes, four sentences. Fallback-finder finding 1.
   *
   * These used to be ONE reason whose guidance asserted the most benign of them: *"the normal state
   * for the party that was ABSENT at seal time … ask your counterparty."* So an operator who was
   * present throughout, whose directory had just shipped a leaf set contradicting its own FROST
   * signature, was told they had been absent and sent to a counterparty with nothing to give.
   *
   * The exemplars are the recorded state values verbatim, not representatives — the branch is a
   * switch on those strings, and picking a plausible-looking substitute would take the `default`.
   */
  it("the ABSENT party is told so by name, and pointed at the side that CAN prove it", async () => {
    const f = await makeFixture(dbPath(), { seal: false });
    f.mgr.recordSealCertificate(AGENT, SESSION_ID, f.sealedRoot, JSON.stringify({ participants: [] }));
    f.mgr.noteCertifiedLeafSetUnavailable(AGENT, SESSION_ID, "not_carried_absent_party", "no frontier_leaves on the unilateral_notification seal frame");

    const res = await f.getProof();
    expect(res["reason"]).toBe("certified_leaves_unavailable");
    expect(res["sealed_root"]).toBe(f.sealedRoot);
    expect(String(res["guidance"])).toContain("Ask your counterparty");
  });

  it("the PRESENT party is NOT sent to a counterparty who holds even less", async () => {
    const f = await makeFixture(dbPath(), { seal: false });
    f.mgr.recordSealCertificate(AGENT, SESSION_ID, f.sealedRoot, JSON.stringify({ participants: [] }));
    f.mgr.noteCertifiedLeafSetUnavailable(AGENT, SESSION_ID, "not_carried_present_party", "no frontier_leaves on the unilateral seal frame");

    const res = await f.getProof();
    expect(res["reason"]).toBe("certified_leaves_not_carried");
    expect(res["reason"]).not.toBe("certified_leaves_unavailable");
    // The remedy that was wrong: on this path the counterparty was the absent one.
    expect(String(res["guidance"])).toContain("Do not ask them");
    expect(String(res["guidance"])).toContain("NEITHER side");
  });

  it("a directory that contradicts its own signature is named as that, not as an absent party", async () => {
    const f = await makeFixture(dbPath(), { seal: false });
    f.mgr.recordSealCertificate(AGENT, SESSION_ID, f.sealedRoot, JSON.stringify({ participants: [] }));

    // The real path: a set that does not reproduce the signed root is refused AND the cause recorded.
    const tampered = [...f.certifiedLeaves];
    tampered[1] = "ee".repeat(32);
    expect(f.mgr.recordCertifiedLeafSet(AGENT, SESSION_ID, signedLeavesFor(tampered), f.sealedRoot)).toBe(false);
    expect(f.mgr.getCertifiedLeafSetState(AGENT, SESSION_ID)?.state).toBe("sealed_leaves_root_disagrees");

    const handlers = new Map<string, IpcHandler>();
    const { logger, events } = makeLogger();
    registerInclusionProofHandlers({
      handlers, logger, sessionNodeManager: f.mgr,
      getConnState: () => ({ currentAgent: AGENT }) as never,
      resolveCurrentAgent: () => AGENT,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    });
    const res = (await handlers.get("cello_get_inclusion_proof")!(
      { session_id: SESSION_ID, message: f.messages[0] },
      "conn-1",
    )) as Record<string, unknown>;

    expect(res["reason"]).toBe("certified_leaves_root_disagrees");
    expect(String(res["guidance"])).toContain("NOT THE ORDINARY");
    expect(String(res["guidance"])).not.toContain("ABSENT at seal time");
    // Loud as well as named — this is the strongest misbehaviour signal this client can produce.
    expect(events.some((e) => e.level === "error" && e.event === "inclusion.certified_leaves.directory_disagreed")).toBe(true);
  });

  it("a re-delivered SHORTER leaf set replaces the old one instead of leaving stale rows", async () => {
    const f = await makeFixture(dbPath());
    expect(f.mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toEqual(f.certifiedLeaves);

    // A two-leaf set with its own root — the shape that used to leave leaf 2 behind and make the
    // stored set hash to nothing anybody signed.
    const shorter = f.certifiedLeaves.slice(0, 2);
    const shorterRoot = rootOver(shorter);
    expect(f.mgr.recordCertifiedLeafSet(AGENT, SESSION_ID, signedLeavesFor(shorter), shorterRoot)).toBe(true);
    expect(f.mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toEqual(shorter);
    expect(f.mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toHaveLength(2);
  });

  it("a garbled certified_root is named as garbled, not as 'a different root'", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;

    const truncated = f.sealedRoot.slice(0, 40); // the copy/paste failure, not a different session
    const verdict = verifyInclusionProof(proof, new TextEncoder().encode(f.messages[0]), truncated);
    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe(INCLUSION_VERIFY_REASONS.CERTIFIED_ROOT_MALFORMED);
    expect(verdict.ok === false && verdict.guidance).toContain("NOTHING about the proof has been established");
  });

  it("a verified proof does NOT claim its session id was checked", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;
    const relabelled = { ...proof, session_id: "not-the-session-this-was-issued-for" };

    // It still verifies — the anchor is the ROOT, and the root is unchanged. That is correct, and it
    // is exactly why the session id must not be presented as a finding.
    const verdict = verifyInclusionProof(relabelled, new TextEncoder().encode(f.messages[0]), f.sealedRoot);
    expect(verdict.ok).toBe(true);
    expect(verdict.ok === true && verdict.session_id_verified).toBe(false);

    const viaTool = (await f.handlers.get("cello_verify_inclusion_proof")!(
      { proof: relabelled, message: f.messages[0], certified_root: f.sealedRoot },
      "conn-1",
    )) as Record<string, unknown>;
    expect(viaTool["session_id_verified"]).toBe(false);
    expect(String(viaTool["means"])).toContain("was NOT checked");
  });

  it("an EMPTY leaf set is refused by the function that claims it, not by its caller", async () => {
    const f = await makeFixture(dbPath(), { seal: false });
    // sha256("") is the RFC 6962 empty-tree root. Nothing may 'verify' against zero leaves.
    const emptyRoot = rootOver([]);
    expect(f.mgr.recordCertifiedLeafSet(AGENT, SESSION_ID, [], emptyRoot)).toBe(false);
    expect(f.mgr.getCertifiedLeafSet(AGENT, SESSION_ID)).toBeNull();
    expect(f.mgr.getCertifiedLeafSetState(AGENT, SESSION_ID)?.state).toBe("sealed_leaves_malformed");
  });

  it("verification requires the certified root — it is never defaulted from the proof", async () => {
    const f = await makeFixture(dbPath());
    const proof = (await f.getProof())["proof"] as InclusionProof;

    const missing = (await f.handlers.get("cello_verify_inclusion_proof")!(
      { proof, message: f.messages[0] },
      "conn-1",
    )) as Record<string, unknown>;
    expect(missing["ok"]).toBe(false);
    expect(missing["reason"]).toBe("missing_certified_root");
    expect(String(missing["guidance"])).toContain("never from the proof");
  });
});
