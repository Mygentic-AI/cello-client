/**
 * A side that restarted mid-session co-signs from the request's own signed evidence — and from nothing
 * weaker.
 *
 * ─── The live failure ──────────────────────────────────────────────────────────────────────────
 *
 * 2026-09-16, session `9bcfc168…`. A daemon restarted mid-conversation and lost its session identity,
 * so the relay refused it `not_a_participant` for the rest of the session. It could still send its
 * SEAL leaf; it could never receive the counterparty's. Asked to co-sign, it held 1 of 2 SEAL leaves,
 * refused, and no certificate was ever stored on any of the three directory nodes.
 *
 * The missing leaf was in the request it refused: `seal_verified` carries `frontier_leaves`.
 *
 * ─── What these tests are really about ─────────────────────────────────────────────────────────
 *
 * ONE test here is the fix. Every other one is a way the fix could be turned into a hole — a
 * directory that fills a gap with a leaf nobody signed, signed for another conversation, REPLAYED
 * from earlier in this one, or reordered; or that quietly overrides a leaf this side witnessed.
 * Signing puts this agent's key on a durable claim, so each of those must refuse.
 *
 * Every fixture here builds a REAL chain: each sender's first leaf names the session anchor, each
 * later one names that sender's previous leaf — exactly the links the relay enforced on submission.
 * A fixture with filler links would make every honest case fail the chain walk, and every forged case
 * fail for the wrong reason.
 *
 * Real Ed25519 keys and real Merkle roots throughout: this is the crypto boundary, and a stubbed
 * signature would pass the one test that matters most against an implementation that never checks it.
 */
import { describe, it, expect, afterEach } from "vitest";
import { generateKeypair, buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { verifyCertifiedRootFromEvidence } from "../seal-evidence-root-check.js";
import type { SealCarryLeaf } from "../session-seal-leaf-store.js";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";

const SESSION_HEX = "9b".repeat(16);
const OTHER_SESSION_HEX = "7a".repeat(16);
const GENESIS = TEST_SESSION_GENESIS;

type Kp = ReturnType<typeof generateKeypair>;
type Party = { kp: Kp; pub: Uint8Array; hex: string };
type Leaf = { wire: { structure1_cbor: Uint8Array; sender_pubkey: Uint8Array; sender_signature: Uint8Array }; hash: Uint8Array };

async function party(): Promise<Party> {
  const kp = generateKeypair();
  const pub = await kp.getPublicKey();
  return { kp, pub, hex: Buffer.from(pub).toString("hex") };
}

/** A real, signed evidence leaf, exactly as `seal_verified` ships one, linked to `prev`. */
async function signedLeaf(who: Party, fill: number, prev: Uint8Array, sessionHex = SESSION_HEX): Promise<Leaf> {
  const hash = new Uint8Array(32).fill(fill);
  const structure1_cbor = encodeStructure1({
    contentHash: hash,
    senderPubkey: who.pub,
    sessionId: Uint8Array.from(Buffer.from(sessionHex, "hex")),
    lastSeenSeq: 0,
    timestamp: 1,
    lastSeenHash: new Uint8Array(32).fill(0x11),
    prevOwnHash: prev,
  });
  return { wire: { structure1_cbor, sender_pubkey: who.pub, sender_signature: await who.kp.sign(structure1_cbor) }, hash };
}

/** What this side actually holds for a leaf — the carry the evidence may never contradict. */
function held(seq: number, leaf: Leaf, senderHex: string, kind = 0x00): SealCarryLeaf {
  return { sequenceNumber: seq, leafKind: kind, senderPubkeyHex: senderHex, structure2Cbor: new Uint8Array(), structure1Cbor: leaf.wire.structure1_cbor };
}

function rootOf(hashes: Uint8Array[]): Uint8Array {
  return merkleRoot(buildMerkleTree(hashes.map((data) => ({ kind: "hash" as const, data }))));
}

/**
 * The live shape: the Mac's message, Hermes's two replies, Hermes's SEAL leaf (sent, so held), and the
 * Mac's SEAL leaf (the one that never arrived). Hermes holds positions 1–4, never 5.
 */
async function liveShape() {
  const mac = await party();
  const hermes = await party();
  const m1 = await signedLeaf(mac, 0x01, GENESIS);
  const h2 = await signedLeaf(hermes, 0x02, GENESIS);
  const h3 = await signedLeaf(hermes, 0x03, h2.hash);
  const h4 = await signedLeaf(hermes, 0x04, h3.hash); // Hermes's SEAL leaf
  const m5 = await signedLeaf(mac, 0x05, m1.hash); // the Mac's SEAL leaf — never received
  const leaves = [m1, h2, h3, h4, m5];
  const ownCarry = [held(1, m1, mac.hex), held(2, h2, hermes.hex), held(3, h3, hermes.hex), held(4, h4, hermes.hex, 0x02)];
  return { mac, hermes, leaves, ownCarry, root: rootOf(leaves.map((l) => l.hash)) };
}

function check(over: Partial<Parameters<typeof verifyCertifiedRootFromEvidence>[0]> & { leaves: Leaf[]; ownCarry: SealCarryLeaf[]; mac: Party; hermes: Party }) {
  const { leaves, ownCarry, mac, hermes, ...rest } = over;
  return verifyCertifiedRootFromEvidence({
    ownCarry, evidence: leaves.map((l) => l.wire), sessionIdHex: SESSION_HEX, participantsHex: [hermes.hex, mac.hex],
    genesis: GENESIS, certifiedRoot: rootOf(leaves.map((l) => l.hash)), certifiedLeafCount: leaves.length, ...rest,
  });
}

describe("a restarted side co-signs from the request's signed evidence", () => {
  it("★★★ THE FIX: 1 of 2 SEAL leaves held, the evidence supplies the other, and the root matches", async () => {
    const s = await liveShape();
    expect(check(s), "the missing leaf was in the request all along — refusing here is what stranded the receipt").toEqual({ verdict: "match", filled: 1 });
  });

  /**
   * Review HIGH. Each leaf alone was valid wherever it sat, and the root is built from content hashes
   * only — so positions this side never saw could hold COPIES of a participant's earlier signed
   * leaves: their "I withdraw the offer" and their closing leaf replaced by replays of their greeting.
   */
  it("★★★ a gap filled with a REPLAY of a participant's earlier signed leaf is refused", async () => {
    const s = await liveShape();
    const replayed = [s.leaves[0]!, s.leaves[1]!, s.leaves[2]!, s.leaves[3]!, s.leaves[0]!];
    const v = check({ ...s, leaves: replayed });
    expect(v.verdict, "a genuine signature is valid anywhere; its position is what the chain fixes").toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_leaf_repeated: position 5");
  });

  it("★★★ a sender's leaves REORDERED within the gap break that sender's chain", async () => {
    const mac = await party();
    const hermes = await party();
    const m1 = await signedLeaf(mac, 0x01, GENESIS);
    const m2 = await signedLeaf(mac, 0x02, m1.hash);
    const m3 = await signedLeaf(mac, 0x03, m2.hash);
    const h4 = await signedLeaf(hermes, 0x04, GENESIS);
    // Hermes holds only its own leaf; the Mac's three are all gap, and the directory swaps two of them.
    const v = check({ mac, hermes, leaves: [m1, m3, m2, h4], ownCarry: [held(4, h4, hermes.hex, 0x02)] });
    expect(v.verdict).toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_self_chain_broken: position 2");
  });

  it("★★★ a message DROPPED from the middle of a sender's run breaks the chain", async () => {
    const mac = await party();
    const hermes = await party();
    const m1 = await signedLeaf(mac, 0x01, GENESIS);
    const m2 = await signedLeaf(mac, 0x02, m1.hash); // e.g. "I withdraw the offer"
    const m3 = await signedLeaf(mac, 0x03, m2.hash);
    const h4 = await signedLeaf(hermes, 0x04, GENESIS);
    const v = check({ mac, hermes, leaves: [m1, m3, h4], ownCarry: [held(3, h4, hermes.hex, 0x02)] });
    expect(v.verdict, "a withdrawal the directory leaves out must not vanish from what this agent signs").toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_self_chain_broken");
  });

  it("★★★ evidence that CONTRADICTS a leaf this side holds is an accusation, never a fill", async () => {
    const s = await liveShape();
    // A chain-valid alternative for Hermes — so it is the contradiction that refuses, not the chain.
    const x2 = await signedLeaf(s.hermes, 0x92, GENESIS);
    const x3 = await signedLeaf(s.hermes, 0x93, x2.hash);
    const x4 = await signedLeaf(s.hermes, 0x94, x3.hash);
    const v = check({ ...s, leaves: [s.leaves[0]!, x2, x3, x4, s.leaves[4]!] });
    expect(v.verdict, "the evidence may fill gaps; it may never rewrite what this side witnessed").toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_contradicts_own_leaf: sequence 2");
  });

  it("★★★ a gap filled by someone who is NOT a participant is refused", async () => {
    const s = await liveShape();
    const stranger = await party();
    const forged = [...s.leaves];
    forged[4] = await signedLeaf(stranger, 0x05, GENESIS);
    const v = check({ ...s, leaves: forged });
    expect(v.verdict, "a directory must not be able to author the counterparty's closing leaf").toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_sender_not_a_participant");
  });

  it("★★★ a gap filled with a BROKEN signature is refused", async () => {
    const s = await liveShape();
    const wires = s.leaves.map((l) => ({ ...l.wire }));
    const sig = new Uint8Array(wires[4]!.sender_signature);
    sig[0] ^= 0xff;
    wires[4] = { ...wires[4]!, sender_signature: sig };
    const v = verifyCertifiedRootFromEvidence({
      ownCarry: s.ownCarry, evidence: wires, sessionIdHex: SESSION_HEX, participantsHex: [s.hermes.hex, s.mac.hex],
      genesis: GENESIS, certifiedRoot: s.root, certifiedLeafCount: 5,
    });
    expect(v.verdict, "a participant's key named on a leaf they did not sign authorises nothing").toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_signature_invalid");
  });

  it("★★ a real participant's leaf from ANOTHER conversation cannot fill this one", async () => {
    const s = await liveShape();
    const forged = [...s.leaves];
    forged[4] = await signedLeaf(s.mac, 0x05, s.leaves[0]!.hash, OTHER_SESSION_HEX);
    const v = check({ ...s, leaves: forged });
    expect(v.verdict).toBe("mismatch");
    expect((v as { detail: string }).detail).toContain("evidence_leaf_is_for_another_session");
  });

  it("★★ evidence that does not hash to the certified root is refused", async () => {
    const s = await liveShape();
    expect(check({ ...s, certifiedRoot: new Uint8Array(32).fill(0xee) }).verdict).toBe("mismatch");
  });

  it("★★ evidence whose size is not the certified count is refused", async () => {
    const s = await liveShape();
    expect(check({ ...s, certifiedLeafCount: 6 }).verdict).toBe("mismatch");
  });

  it("★★ with no record of the participants, it cannot judge — and so does not sign", async () => {
    const s = await liveShape();
    expect(check({ ...s, participantsHex: [] }), "the participants must come from this side's record").toEqual({ verdict: "cannot_judge", reason: "participants_unknown" });
  });

  it("★★ with no session anchor, the chains cannot be walked — so it does not sign", async () => {
    const s = await liveShape();
    expect(check({ ...s, genesis: undefined }), "an unwalked gap is exactly what a replay needs").toEqual({ verdict: "cannot_judge", reason: "genesis_unknown" });
  });
});

/**
 * THE WIRING, because the pure function above passes against a daemon that never calls it — or that
 * calls it and ignores what it says.
 *
 * Run on a real manager and a real database, so the participants and the anchor are read from the
 * session row the way production reads them.
 */
describe("the daemon consults the evidence when its own carry cannot judge", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  async function sessionWith(counterparty: Party): Promise<string> {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-evidence-seam-" });
    await fx.createSession(SESSION_HEX, "alice", counterparty.hex, "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn");
    return (fx.snm.getDb().prepare("SELECT k_local_pubkey AS pub FROM agents WHERE agent_name = ?").get("alice") as { pub: string }).pub;
  }

  async function counterpartyRun(cp: Party): Promise<Leaf[]> {
    const c1 = await signedLeaf(cp, 0x01, GENESIS);
    const c2 = await signedLeaf(cp, 0x02, c1.hash);
    const c3 = await signedLeaf(cp, 0x03, c2.hash);
    return [c1, c2, c3];
  }

  it("★★★ a short carry plus signed evidence verifies; the SAME call without evidence does not", async () => {
    const cp = await party();
    const alice = await sessionWith(cp);
    const leaves = await counterpartyRun(cp);
    const root = rootOf(leaves.map((l) => l.hash));
    expect(fx!.snm.verifyCertifiedRoot(alice, SESSION_HEX, root, 3, undefined).verdict, "control: exactly the live failure").toBe("cannot_judge");
    expect(fx!.snm.verifyCertifiedRoot(alice, SESSION_HEX, root, 3, leaves.map((l) => l.wire))).toEqual({ verdict: "match" });
  });

  /**
   * Review MEDIUM. The case above passes against a daemon that returns `match` whenever evidence is
   * present, without checking it. Through the same real manager, a forged set must be REFUSED.
   */
  it("★★★ the daemon USES the verdict — a replayed set through the real manager is refused", async () => {
    const cp = await party();
    const alice = await sessionWith(cp);
    const [c1, c2] = await counterpartyRun(cp);
    const replayed = [c1!, c2!, c1!];
    const v = fx!.snm.verifyCertifiedRoot(alice, SESSION_HEX, rootOf(replayed.map((l) => l.hash)), 3, replayed.map((l) => l.wire));
    expect(v.verdict, "evidence is a thing to check, never a thing whose presence suffices").toBe("mismatch");
  });

  it("★★★ the co-signing ceremony passes the request's evidence into the root check", async () => {
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    // Comments stripped first, so a commented-out call cannot satisfy this (review, LOW).
    const src = readFileSync(join(import.meta.dirname, "..", "session-ceremony.ts"), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
    expect(
      /verifyCertifiedRoot\([^)]*sealEvidenceLeaves\)/.test(src),
      "without this argument the restarted side is back to refusing a seal whose missing leaf is in its own hands",
    ).toBe(true);
  });
});
