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
 * directory that fills a gap with a leaf nobody signed, or signed for another conversation, or that
 * quietly overrides a leaf this side witnessed. Signing puts this agent's key on a durable claim, so
 * each of those must refuse.
 *
 * Real Ed25519 keys and real Merkle roots throughout: this is the crypto boundary, and a stubbed
 * signature would pass the one test that matters most against an implementation that never checks it.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { generateKeypair, buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { verifyCertifiedRootFromEvidence } from "../seal-evidence-root-check.js";
import type { SealCarryLeaf } from "../session-seal-leaf-store.js";

const SESSION_HEX = "9b".repeat(16);
const OTHER_SESSION_HEX = "7a".repeat(16);

type Kp = ReturnType<typeof generateKeypair>;

async function party(): Promise<{ kp: Kp; pub: Uint8Array; hex: string }> {
  const kp = generateKeypair();
  const pub = await kp.getPublicKey();
  return { kp, pub, hex: Buffer.from(pub).toString("hex") };
}

/** A real, signed evidence leaf, exactly as `seal_verified` ships one. */
async function signedLeaf(
  who: { kp: Kp; pub: Uint8Array },
  fill: number,
  sessionHex = SESSION_HEX,
): Promise<{ wire: { structure1_cbor: Uint8Array; sender_pubkey: Uint8Array; sender_signature: Uint8Array }; hash: Uint8Array }> {
  const hash = new Uint8Array(32).fill(fill);
  const structure1_cbor = encodeStructure1({
    contentHash: hash,
    senderPubkey: who.pub,
    sessionId: Uint8Array.from(Buffer.from(sessionHex, "hex")),
    lastSeenSeq: 0,
    timestamp: 1,
    lastSeenHash: new Uint8Array(32).fill(0x11),
    prevOwnHash: new Uint8Array(32).fill(0x22),
  });
  return { wire: { structure1_cbor, sender_pubkey: who.pub, sender_signature: await who.kp.sign(structure1_cbor) }, hash };
}

/** What this side actually holds for a leaf — the carry the evidence may never contradict. */
function held(seq: number, leaf: { wire: { structure1_cbor: Uint8Array }; }, senderHex: string, kind = 0x00): SealCarryLeaf {
  return { sequenceNumber: seq, leafKind: kind, senderPubkeyHex: senderHex, structure2Cbor: new Uint8Array(), structure1Cbor: leaf.wire.structure1_cbor };
}

function rootOf(hashes: Uint8Array[]): Uint8Array {
  return merkleRoot(buildMerkleTree(hashes.map((data) => ({ kind: "hash" as const, data }))));
}

/**
 * The live shape: messages 1–3, then Hermes's SEAL leaf (which it holds, having sent it) and the Mac's
 * SEAL leaf (which it never received). Hermes holds 1, 2, 3 and 4 — never 5.
 */
async function liveShape() {
  const mac = await party();
  const hermes = await party();
  const leaves = [
    await signedLeaf(mac, 0x01),
    await signedLeaf(hermes, 0x02),
    await signedLeaf(hermes, 0x03),
    await signedLeaf(hermes, 0x04), // Hermes's SEAL leaf — sent, so held
    await signedLeaf(mac, 0x05), // the Mac's SEAL leaf — the one that never arrived
  ];
  const ownCarry = [
    held(1, leaves[0]!, mac.hex),
    held(2, leaves[1]!, hermes.hex),
    held(3, leaves[2]!, hermes.hex),
    held(4, leaves[3]!, hermes.hex, 0x02),
  ];
  return { mac, hermes, leaves, ownCarry, root: rootOf(leaves.map((l) => l.hash)) };
}

describe("a restarted side co-signs from the request's signed evidence", () => {
  it("★★★ THE FIX: 1 of 2 SEAL leaves held, the evidence supplies the other, and the root matches", async () => {
    const { mac, hermes, leaves, ownCarry, root } = await liveShape();
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: leaves.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: root, certifiedLeafCount: 5,
    });
    expect(verdict, "the missing leaf was in the request all along — refusing here is what stranded the receipt").toEqual({ verdict: "match", filled: 1 });
  });

  it("★★★ evidence that CONTRADICTS a leaf this side holds is an accusation, never a fill", async () => {
    const { mac, hermes, leaves, ownCarry } = await liveShape();
    const forged = [...leaves];
    forged[1] = await signedLeaf(hermes, 0x99); // a real signature, over a message this side never saw
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: forged.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: rootOf(forged.map((l) => l.hash)), certifiedLeafCount: 5,
    });
    expect(verdict.verdict, "the evidence may fill gaps; it may never rewrite what this side witnessed").toBe("mismatch");
    expect((verdict as { detail: string }).detail).toContain("evidence_contradicts_own_leaf: sequence 2");
  });

  it("★★★ a gap filled by someone who is NOT a participant is refused", async () => {
    const { mac, hermes, leaves, ownCarry } = await liveShape();
    const stranger = await party();
    const forged = [...leaves];
    forged[4] = await signedLeaf(stranger, 0x05); // same content, validly signed — by the wrong key
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: forged.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: rootOf(forged.map((l) => l.hash)), certifiedLeafCount: 5,
    });
    expect(verdict.verdict, "a directory must not be able to author the counterparty's closing leaf").toBe("mismatch");
    expect((verdict as { detail: string }).detail).toContain("evidence_sender_not_a_participant");
  });

  it("★★★ a gap filled with a BROKEN signature is refused", async () => {
    const { mac, hermes, leaves, ownCarry, root } = await liveShape();
    const tampered = leaves.map((l) => ({ ...l.wire }));
    const sig = new Uint8Array(tampered[4]!.sender_signature);
    sig[0] ^= 0xff;
    tampered[4] = { ...tampered[4]!, sender_signature: sig };
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: tampered, sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: root, certifiedLeafCount: 5,
    });
    expect(verdict.verdict, "a participant's key named on a leaf they did not sign authorises nothing").toBe("mismatch");
    expect((verdict as { detail: string }).detail).toContain("evidence_signature_invalid");
  });

  it("★★ a real participant's leaf from ANOTHER conversation cannot fill this one", async () => {
    const { mac, hermes, leaves, ownCarry } = await liveShape();
    const forged = [...leaves];
    forged[4] = await signedLeaf(mac, 0x05, OTHER_SESSION_HEX);
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: forged.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: rootOf(forged.map((l) => l.hash)), certifiedLeafCount: 5,
    });
    expect(verdict.verdict).toBe("mismatch");
    expect((verdict as { detail: string }).detail).toContain("evidence_leaf_is_for_another_session");
  });

  it("★★ evidence that does not hash to the certified root is refused", async () => {
    const { mac, hermes, leaves, ownCarry } = await liveShape();
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: leaves.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: new Uint8Array(32).fill(0xee), certifiedLeafCount: 5,
    });
    expect(verdict.verdict, "consistent evidence the certificate does not describe is still not what is being signed").toBe("mismatch");
  });

  it("★★ evidence whose size is not the certified count is refused", async () => {
    const { mac, hermes, leaves, ownCarry, root } = await liveShape();
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: leaves.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [hermes.hex, mac.hex], certifiedRoot: root, certifiedLeafCount: 6,
    });
    expect(verdict.verdict).toBe("mismatch");
  });

  it("★★ with no record of who the participants are, it cannot judge — and so does not sign", async () => {
    const { leaves, ownCarry, root } = await liveShape();
    const verdict = verifyCertifiedRootFromEvidence({
      ownCarry, evidence: leaves.map((l) => l.wire), sessionIdHex: SESSION_HEX,
      participantsHex: [], certifiedRoot: root, certifiedLeafCount: 5,
    });
    expect(verdict, "the participants must come from this side's record; the frame is what is being checked").toEqual({ verdict: "cannot_judge", reason: "participants_unknown" });
  });
});

/**
 * THE WIRING, because the pure function above passes against a daemon that never calls it.
 *
 * Run on a real manager and a real database, so the participants are read from the session row the
 * way production reads them — the one thing the frame must never be allowed to supply.
 */
describe("the daemon consults the evidence when its own carry cannot judge", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★★★ a short carry plus signed evidence verifies; the SAME call without evidence does not", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-evidence-seam-" });
    const counterparty = await party();
    await fx.createSession(SESSION_HEX, "alice", counterparty.hex, "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn");
    const alice = fx.snm.getDb().prepare("SELECT k_local_pubkey AS pub FROM agents WHERE agent_name = ?").get("alice") as { pub: string };

    const leaves = [await signedLeaf(counterparty, 0x01), await signedLeaf(counterparty, 0x02), await signedLeaf(counterparty, 0x03)];
    const root = rootOf(leaves.map((l) => l.hash));

    expect(
      fx.snm.verifyCertifiedRoot(alice.pub, SESSION_HEX, root, 3).verdict,
      "control: with no evidence this side holds nothing to judge by, and refuses — exactly the live failure",
    ).toBe("cannot_judge");
    expect(
      fx.snm.verifyCertifiedRoot(alice.pub, SESSION_HEX, root, 3, leaves.map((l) => l.wire)),
      "with the request's own signed evidence, the participants read from THIS side's session row, it verifies",
    ).toEqual({ verdict: "match" });
  });

  it("★★★ the co-signing ceremony passes the request's evidence into the root check", async () => {
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const src = readFileSync(join(import.meta.dirname, "..", "session-ceremony.ts"), "utf8");
    expect(
      /verifyCertifiedRoot\([^)]*sealEvidenceLeaves\)/.test(src),
      "without this argument the restarted side is back to refusing a seal whose missing leaf is in its own hands",
    ).toBe(true);
  });
});
