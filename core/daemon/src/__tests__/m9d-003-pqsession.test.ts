/**
 * M9D 003-PQSESSION — the daemon's hybrid key agreement, tests 9–15.
 *
 * Tests 9–13 run TWO real `SessionEphemerals` in one process with real crypto: each side's announce
 * is captured off its (fake) stream as the length-prefixed CBOR a real stream would carry, decoded
 * by the production reader, and handed to the other side. Nothing about the keys is seeded.
 *
 * Tests 14–15 drive a real `SessionNodeManager` through the ingest's own `lp.decode` path.
 */
import { describe, it, expect, afterEach } from "vitest";
import { decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import {
  InMemoryKeyProvider, generateKeypair, mlDsaGenerateSeed, mlDsaProviderFromSeed, mlKemEncapsulate,
  deriveSessionSecrets, generateSessionEphemeral, signSessionEphemeral, decodeSessionKeyAgreementFrame,
  sealSessionContent, ML_KEM_CIPHERTEXT_BYTES,
  type MlDsaKeyProvider, type KeyProvider, type SessionEphemeral,
} from "@cello-protocol/crypto";
import { encodeCbor, encodeStructure1 } from "@cello-protocol/protocol-types";
import { randomBytes } from "node:crypto";
import { SessionEphemerals } from "../session-ephemerals.js";
import type { Logger } from "../types.js";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";
import { wireContentHash } from "../wire-content-hash.js";
import { LEAF_KIND_MSG } from "../session-relay-client.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";

const SID = "3c".repeat(16);
const SID_BYTES = new Uint8Array(Buffer.from(SID, "hex"));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function lexLess(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return (a[i] as number) < (b[i] as number);
  return a.length < b.length;
}

interface Ev { level: string; event: string; ctx: Record<string, unknown> }
function capture(): { logger: Logger; events: Ev[] } {
  const events: Ev[] = [];
  const push = (level: string) => (event: string, ctx?: Record<string, unknown>) => { events.push({ level, event, ctx: ctx ?? {} }); };
  return { logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") } as Logger, events };
}

/** Decode one lp-framed CBOR frame exactly as a content stream would carry it. */
async function unframe(bytes: Uint8Array): Promise<Record<string, unknown>> {
  for await (const chunk of lp.decode([bytes])) return decode(chunk.subarray()) as Record<string, unknown>;
  throw new Error("no frame");
}

interface Side {
  name: string;
  eph: SessionEphemerals;
  kLocal: KeyProvider;
  mlDsa: MlDsaKeyProvider;
  pub: Uint8Array;
  pqPub: Uint8Array;
  outbox: Uint8Array[];
  events: Ev[];
  frozen: string[];
}

/** One side: a real SessionEphemerals over a fake stream, wired to its peer's verified keys. */
async function makeSide(name: string, peer: () => Side): Promise<Side> {
  const kLocal = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
  const mlDsa = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
  const { logger, events } = capture();
  const outbox: Uint8Array[] = [];
  const frozen: string[] = [];
  const side = { name, kLocal, mlDsa, pub: await kLocal.getPublicKey(), pqPub: await mlDsa.getPublicKey(), outbox, events, frozen } as Side;
  side.eph = new SessionEphemerals({
    logger,
    sessionKey: (a, sid) => `${a}:${sid}`,
    activeEntry: () => ({
      counterpartyPubkey: hex(peer().pub),
      counterpartySessionPeerId: `${name}-peer`,
      node: {
        newStream: async () => ({
          send: (b: Uint8Array) => { outbox.push(Uint8Array.from(b)); return true; },
          close: async () => {},
          abort: () => {},
        }),
      },
    }) as never,
    keyProvider: () => kLocal,
    mlDsaProvider: () => mlDsa,
    counterpartyPqKeys: () => ({ mlDsa: peer().pqPub, mlKem: new Uint8Array(1184) }),
    freezeSessionForKeyRefusal: async (_a, _sid, reason) => { frozen.push(reason); },
  });
  return side;
}

async function pair(): Promise<{ A: Side; B: Side }> {
  let A!: Side; let B!: Side;
  A = await makeSide("alice", () => B);
  B = await makeSide("bob", () => A);
  return { A, B };
}

/** Deliver every queued frame in both directions until both outboxes are empty. */
async function pump(A: Side, B: Side): Promise<void> {
  for (let round = 0; round < 10 && (A.outbox.length > 0 || B.outbox.length > 0); round++) {
    for (const [from, to] of [[A, B], [B, A]] as const) {
      const queued = from.outbox.splice(0);
      for (const bytes of queued) {
        await to.eph.handleEphemeralFrame(to.name, SID, decodeSessionKeyAgreementFrame(await unframe(bytes)), "test");
      }
    }
  }
}

const keyOf = (s: Side): Uint8Array | null => s.eph.contentEncryptionState(s.name, SID).key;

async function agreedPair(wantALower: boolean): Promise<{ A: Side; B: Side }> {
  for (let attempt = 0; attempt < 40; attempt++) {
    const { A, B } = await pair();
    await A.eph.mintSessionEphemeral(A.name, SID);
    await B.eph.mintSessionEphemeral(B.name, SID);
    const aPub = A.eph.sessionEphemeralPublicsForTest(A.name, SID)!.x25519;
    const bPub = B.eph.sessionEphemeralPublicsForTest(B.name, SID)!.x25519;
    if (lexLess(aPub, bPub) !== wantALower) continue;
    return { A, B };
  }
  throw new Error("could not draw the wanted X25519 order");
}

describe("003 test 9 — both sides agree across roles", () => {
  for (const aLower of [true, false]) {
    it(`agreement when ${aLower ? "A" : "B"} holds the lower X25519 key (and so encapsulates)`, async () => {
      const { A, B } = await agreedPair(aLower);
      await A.eph.sendEphemeralFrame(A.name, SID);
      await B.eph.sendEphemeralFrame(B.name, SID);
      await pump(A, B);
      const ka = keyOf(A); const kb = keyOf(B);
      expect(ka, `A derived no key: ${JSON.stringify(A.events.filter((e) => e.level === "error"))}`).not.toBeNull();
      expect(kb, `B derived no key: ${JSON.stringify(B.events.filter((e) => e.level === "error"))}`).not.toBeNull();
      expect(hex(ka!)).toBe(hex(kb!));
      // The lower side encapsulated: its announce carried the ciphertext, the other's never did.
      const encapsulator = aLower ? A : B;
      expect(encapsulator.events.some((e) => e.event === "session.key.agreed" && e.ctx["role"] === "encapsulator")).toBe(true);
    });
  }
});

describe("003 test 10 (D10) — a re-announce with a new ct under an unchanged X25519 key is processed", () => {
  it("the decapsulator records the first announce, then derives from the second", async () => {
    const { A, B } = await agreedPair(true); // A encapsulates, B decapsulates
    await A.eph.sendEphemeralFrame(A.name, SID); // A's FIRST announce: A does not yet hold B's ML-KEM key → no ct
    const first = await unframe(A.outbox.shift()!);
    expect(first["mlkem_ciphertext"], "A's first announce must not carry a ciphertext").toBeUndefined();
    await B.eph.handleEphemeralFrame(B.name, SID, decodeSessionKeyAgreementFrame(first), "t");
    expect(keyOf(B), "B must wait for the ciphertext, not derive").toBeNull();

    await B.eph.sendEphemeralFrame(B.name, SID);
    await pump(A, B); // A receives B → encapsulates → re-announces WITH ct under the same X25519 key
    expect(keyOf(B), "the second announce (same X25519, new ct) was dropped as a duplicate").not.toBeNull();
    expect(hex(keyOf(B)!)).toBe(hex(keyOf(A)!));
  });
});

describe("003 test 11 — a ciphertext from the decapsulator is a role violation", () => {
  it("refused as ephemeral_pq_role_violation and the session is frozen", async () => {
    const { A, B } = await agreedPair(true); // B is the decapsulator
    const b = B.eph.sessionEphemeralPublicsForTest(B.name, SID)!;
    const { sig, pqSig } = await signSessionEphemeral(B.kLocal, B.mlDsa, SID_BYTES, b.x25519, b.mlKem, new Uint8Array(ML_KEM_CIPHERTEXT_BYTES).fill(9));
    await A.eph.handleEphemeralFrame(A.name, SID, {
      ephemeralPublic: b.x25519, mlkemPublic: b.mlKem, mlkemCiphertext: new Uint8Array(ML_KEM_CIPHERTEXT_BYTES).fill(9),
      signature: sig, pqSignature: pqSig,
    }, "t");
    expect(A.frozen).toContain("ephemeral_pq_role_violation");
    expect(A.events.some((e) => e.event === "session.key.refused" && e.ctx["reason"] === "ephemeral_pq_role_violation")).toBe(true);
    expect(keyOf(A)).toBeNull();
  });
});

describe("003 test 12 — re-key on either side", () => {
  async function rekey(side: Side, other: Side, stayLower: boolean): Promise<void> {
    for (let attempt = 0; attempt < 40; attempt++) {
      side.eph.destroySessionEphemeralFor(side.name, SID);
      await side.eph.mintSessionEphemeral(side.name, SID);
      const mine = side.eph.sessionEphemeralPublicsForTest(side.name, SID)!.x25519;
      const theirs = other.eph.sessionEphemeralPublicsForTest(other.name, SID)!.x25519;
      if (lexLess(mine, theirs) === stayLower) return;
    }
    throw new Error("could not draw the wanted order on re-key");
  }

  it("the ENCAPSULATOR re-keys: the survivor decapsulates the new ct with its unchanged ML-KEM seed", async () => {
    const { A, B } = await agreedPair(true);
    await A.eph.sendEphemeralFrame(A.name, SID); await B.eph.sendEphemeralFrame(B.name, SID); await pump(A, B);
    const before = hex(keyOf(B)!);
    const bSeedBefore = B.eph.sessionEphemeralPublicsForTest(B.name, SID)!.mlKem;
    await rekey(A, B, true);
    await A.eph.sendEphemeralFrame(A.name, SID); await B.eph.sendEphemeralFrame(B.name, SID); await pump(A, B);
    expect(hex(B.eph.sessionEphemeralPublicsForTest(B.name, SID)!.mlKem), "B's ML-KEM key must be unchanged").toBe(hex(bSeedBefore));
    expect(keyOf(A)).not.toBeNull();
    expect(hex(keyOf(B)!)).toBe(hex(keyOf(A)!));
    expect(hex(keyOf(B)!)).not.toBe(before);
  });

  it("the DECAPSULATOR re-keys: both agree again", async () => {
    const { A, B } = await agreedPair(true);
    await A.eph.sendEphemeralFrame(A.name, SID); await B.eph.sendEphemeralFrame(B.name, SID); await pump(A, B);
    const before = hex(keyOf(A)!);
    await rekey(B, A, false);
    await B.eph.sendEphemeralFrame(B.name, SID); await A.eph.sendEphemeralFrame(A.name, SID); await pump(A, B);
    expect(keyOf(B)).not.toBeNull();
    expect(hex(keyOf(A)!)).toBe(hex(keyOf(B)!));
    expect(hex(keyOf(A)!)).not.toBe(before);
  });
});

describe("003 test 13 (D12) — the ML-KEM seed and ssPq are zeroed", () => {
  it("destroySessionEphemeralFor zeroes the held ML-KEM seed", async () => {
    const { A } = await pair();
    const e: SessionEphemeral = await generateSessionEphemeral();
    const seedRef = e.mlKemSeed;
    A.eph.setSessionEphemeralForTest(A.name, SID, e);
    A.eph.destroySessionEphemeralFor(A.name, SID);
    expect(seedRef.every((b) => b === 0), "the ML-KEM seed survived destroySessionEphemeralFor").toBe(true);
  });

  it("destroyAll zeroes every held ML-KEM seed", async () => {
    const { A } = await pair();
    const e: SessionEphemeral = await generateSessionEphemeral();
    const seedRef = e.mlKemSeed;
    A.eph.setSessionEphemeralForTest(A.name, SID, e);
    A.eph.destroyAll();
    expect(seedRef.every((b) => b === 0), "the ML-KEM seed survived destroyAll").toBe(true);
  });

  it("every ssPq buffer is zero once its derivation is done", async () => {
    const { A, B } = await agreedPair(true);
    const seen: Uint8Array[] = [];
    A.eph.observeSsPqForTest((b) => seen.push(b));
    B.eph.observeSsPqForTest((b) => seen.push(b));
    await A.eph.sendEphemeralFrame(A.name, SID); await B.eph.sendEphemeralFrame(B.name, SID); await pump(A, B);
    expect(seen.length, "one ssPq on each side").toBe(2);
    for (const b of seen) expect(b.every((x) => x === 0), "an ssPq outlived its derivation").toBe(true);
  });
});

// ─── 14–15: through the real ingest ─────────────────────────────────────────────────────────────

const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";

describe("003 tests 14–15 — held content and the largest announce, through the ingest", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /**
   * A session on alice whose counterparty ("them") holds the LOWER X25519 key — so them encapsulates
   * and alice waits for its ciphertext. Returns them's two announces and the key them derives.
   */
  async function setup() {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-pqsession-" });
    const themK = generateKeypair();
    const themPq = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
    const themPub = await themK.getPublicKey();
    await fx.createSession(SID, "alice", hex(themPub), PEER);
    fx.snm.forgetSessionContentKeyForTest("alice", SID);
    fx.snm.recordCounterpartyKeys("alice", SID, {
      primaryHex: "ab".repeat(32), mlDsaHex: hex(await themPq.getPublicKey()), mlKemHex: "cd".repeat(1184),
    });
    const alice = fx.snm.sessionEphemeralPublicsForTest("alice", SID)!;
    let themEph = await generateSessionEphemeral();
    while (!lexLess(themEph.publicKey, alice.x25519)) themEph = await generateSessionEphemeral();

    const { ciphertext, sharedSecret } = await mlKemEncapsulate(alice.mlKem);
    const key = deriveSessionSecrets({
      ownEphemeralSecret: themEph.secretKey, peerEphemeralPublic: alice.x25519, sessionId: SID_BYTES,
      extraSharedSecret: sharedSecret, pqTranscript: Buffer.concat([ciphertext, alice.mlKem]),
    }).contentKey;
    const announce = async (ct?: Uint8Array) => {
      const { sig, pqSig } = await signSessionEphemeral(themK, themPq, SID_BYTES, themEph.publicKey, themEph.mlKemPublic, ct);
      return lp.encode.single(encodeCbor({
        type: "session_key_agreement", session_id: SID,
        ephemeral_public: themEph.publicKey, mlkem_public: themEph.mlKemPublic,
        ...(ct ? { mlkem_ciphertext: ct } : {}),
        ephemeral_sig: sig, ephemeral_pq_sig: pqSig,
      }) as Uint8Array).subarray();
    };
    const contentFrame = async (body: string) => {
      const content = new TextEncoder().encode(body);
      const contentHash = wireContentHash(content);
      const structure1 = encodeStructure1({
        contentHash, senderPubkey: themPub, sessionId: SID_BYTES, lastSeenSeq: 0, timestamp: 1_750_000_000_000,
        lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: TEST_SESSION_GENESIS,
      });
      return lp.encode.single(encodeCbor({
        type: "content_frame", content_hash_alg: "sha256", session_id: SID,
        content_hash: contentHash, content_bytes: sealSessionContent(key, content),
        content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
        structure1_cbor: structure1, sender_signature: await themK.sign(structure1), leaf_kind: LEAF_KIND_MSG,
      }) as Uint8Array).subarray();
    };
    return { announce, contentFrame, ciphertext, key };
  }

  const refusalReasons = (): unknown[] => fx!.eventsNamed("session.content.refused").map((e) => e.ctx["reason"]);

  it("★ test 15 (D15): the largest announce — with ct — passes the ingest's real lp.decode path intact", async () => {
    const s = await setup();
    const withCt = await s.announce(s.ciphertext);
    expect(withCt.length, "the largest announce is ~4.8 KB").toBeGreaterThan(4700);
    await fx!.snm.handleContentFrameForTest("alice", SID, await s.announce(), PEER);
    await fx!.snm.handleContentFrameForTest("alice", SID, withCt, PEER);
    const key = fx!.snm.contentEncryptionStateForTest("alice", SID).key;
    expect(key, `alice derived nothing from the largest announce: ${JSON.stringify(fx!.eventsNamed("session.key.refused"))}`).not.toBeNull();
    expect(hex(key!)).toBe(hex(s.key));
  });

  it("★ test 14: content before the ct is HELD, then delivered — no decrypt_failed, no no_session_key", async () => {
    const s = await setup();
    await fx!.snm.handleContentFrameForTest("alice", SID, await s.announce(), PEER); // no ct → alice waits
    await fx!.snm.handleContentFrameForTest("alice", SID, await s.contentFrame("sent before the key"), PEER);
    await wait(50);
    expect(fx!.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received")).toHaveLength(0);

    await fx!.snm.handleContentFrameForTest("alice", SID, await s.announce(s.ciphertext), PEER);
    await wait(200);
    const received = fx!.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received");
    expect(received.map((m) => m.text)).toEqual(["sent before the key"]);
    expect(refusalReasons()).not.toContain("decrypt_failed");
    expect(refusalReasons()).not.toContain("no_session_key");
  });

  it("★ test 14b: no ct ever arrives → the held frame is refused as pq_ciphertext_not_received", async () => {
    const s = await setup();
    fx!.snm.setPqCiphertextHoldForTest({ ms: 150 });
    await fx!.snm.handleContentFrameForTest("alice", SID, await s.announce(), PEER);
    await fx!.snm.handleContentFrameForTest("alice", SID, await s.contentFrame("never opened"), PEER);
    await wait(400);
    expect(refusalReasons()).toContain("pq_ciphertext_not_received");
    expect(refusalReasons()).not.toContain("decrypt_failed");
    expect(refusalReasons()).not.toContain("no_session_key");
    expect(fx!.eventsNamed("session.key.pq_ciphertext_timeout")).toHaveLength(1);
  });
});
