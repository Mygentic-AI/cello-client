/**
 * 038-KEYBIND — the responder's half: a group key it can PLACE, or a refusal.
 *
 * ─── What was broken, in the shape a test can hold ─────────────────────────────────────────────
 *
 * On first contact `verifyInboundAssignment` had no pin, so it did
 * `verifyAgainst = assignment.signer_pubkey` — a field of the very document under verification. A
 * directory minting its own FROST-ish key, signing the establishment TBS with it, and naming it in
 * `signer_pubkey` produced an assignment that verified perfectly. That key was then PINNED as the
 * counterparty's identity forever, so every later session with them agreed with the substitution.
 *
 * The FORGED-KEY test below is the one with teeth: it builds exactly that assignment — internally
 * consistent, correctly signed, everything a pre-038 responder checked — and asserts it is refused.
 * It passed against the old code. It fails against the old code now only because the binding is
 * missing from it, which is the point: a directory that does not hold participant_a's K_local
 * cannot produce one.
 *
 * REAL CRYPTO ONLY. The unit IS a signature check.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair, buildKeyBindingTbs, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import { verifyInboundAssignment } from "../assignment-verify.js";
import { parseSessionAssignment } from "../session-assignment-parser.js";

const SESSION_ID = new Uint8Array(16).fill(9);
const TS = 1_700_000_000_000;
const RESPONDER_PUB = new Uint8Array(32).fill(0xb0);

/**
 * Build the frame a directory would send: the initiator's identity, the group key it claims, the
 * establishment signature under that group key, and the binding.
 *
 * `groupSigner` is what SIGNS the assignment, and `claimBindingWith` is who signs the binding.
 * Splitting the two is what lets a test model a directory that holds a key the initiator does not.
 */
async function frameFor(opts: {
  initiator: KeyProvider;
  groupSigner: KeyProvider;
  /** Sign the binding with this instead of `initiator` — models a directory vouching for itself. */
  claimBindingWith?: KeyProvider;
  omitBinding?: boolean;
  /** Truncate the binding to 32 bytes — MALFORMED, which must land where ABSENT lands. */
  malformedBinding?: boolean;
  /** Change a signed field after signing. */
  tamperAfterSigning?: boolean;
}): Promise<Record<string, unknown>> {
  const initiatorPub = await opts.initiator.getPublicKey();
  const groupPub = await opts.groupSigner.getPublicKey();
  const counterpartyPeerId = opts.tamperAfterSigning ? "12D3KooWHonest" : "12D3KooWResponder";

  const genesis = computeGenesisPrevRoot(initiatorPub, RESPONDER_PUB, SESSION_ID, TS);
  const tbs = buildSessionEstablishmentTbs(
    SESSION_ID, initiatorPub, RESPONDER_PUB, genesis, TS,
    "12D3KooWInitiator", ["/ip4/127.0.0.1/tcp/3"],
    counterpartyPeerId, ["/ip4/127.0.0.1/tcp/4"],
    "relay", false, "",
  );
  const ctx = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
  const framed = new Uint8Array(ctx.length + 1 + tbs.length);
  framed.set(ctx, 0); framed[ctx.length] = 0x00; framed.set(tbs, ctx.length + 1);

  const bindingSigner = opts.claimBindingWith ?? opts.initiator;
  const fullBinding = await bindingSigner.sign(buildKeyBindingTbs(initiatorPub, groupPub));
  const binding = opts.malformedBinding ? fullBinding.subarray(0, 32) : fullBinding;

  return {
    session_id: SESSION_ID,
    participant_a: { pubkey: initiatorPub, peer_id: "12D3KooWA", multiaddrs: [] },
    participant_b: { pubkey: RESPONDER_PUB, peer_id: "12D3KooWB", multiaddrs: [] },
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
    session_timestamp: TS,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    directory_signature: await opts.groupSigner.sign(framed),
    signature_type: "frost",
    signer_pubkey: groupPub,
    initiator_session_peer_id: "12D3KooWInitiator",
    initiator_session_addrs: ["/ip4/127.0.0.1/tcp/3"],
    // The tamper: the frame says one dialer, the signature covers another.
    counterparty_session_peer_id: opts.tamperAfterSigning ? "12D3KooWImpostor" : counterpartyPeerId,
    counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/4"],
    transport_mode: "relay",
    high_stakes: false,
    prior_relay_id: "",
    ...(opts.omitBinding ? {} : { participant_a_key_binding: binding }),
  };
}

function parsed(raw: Record<string, unknown>): SessionAssignment {
  const a = parseSessionAssignment(raw);
  if (!a) throw new Error("fixture did not parse — the test would be measuring the parser, not the verifier");
  return a;
}

describe("038-KEYBIND: a responder places the caller's group key before verifying anything under it", () => {
  it("ACCEPTS a first contact whose group key the caller's own identity key vouched for", async () => {
    const initiator = generateKeypair();
    const group = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: group });

    const v = verifyInboundAssignment(parsed(raw), null);
    expect(v.ok, "a legitimate first contact must still connect — a gate that breaks sessions is worse than the hole").toBe(true);
    // `bound`, not `internal`: the verdict names a property the code now holds.
    expect(v.ok && v.mode).toBe("bound");
  });

  it("★ REFUSES a FORGED group key — the exact assignment that passed before 038-KEYBIND", async () => {
    /**
     * The attack, built end to end. `directory` is a compromised node: it mints its own key, signs
     * the establishment TBS with it, and names it as the initiator's group key. Everything is
     * internally consistent — the signature verifies over the frame's own recomputed contents under
     * the key the frame names — which is precisely why the old code accepted it and pinned it.
     *
     * What it cannot do is sign the binding: that takes the INITIATOR's K_local, which it does not
     * have. So it either omits the binding (the next test) or vouches for itself (this one).
     */
    const initiator = generateKeypair();
    const directory = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: directory, claimBindingWith: directory });

    const v = verifyInboundAssignment(parsed(raw), null);
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("inbound_assignment_key_binding_invalid");
    expect(!v.ok && v.detail).toContain("identity key");
  });

  it("REFUSES a MISSING binding, by its own name — a withheld proof cannot be cheaper than a wrong one", async () => {
    const initiator = generateKeypair();
    const directory = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: directory, omitBinding: true });

    const v = verifyInboundAssignment(parsed(raw), null);
    expect(v.ok).toBe(false);
    // A DIFFERENT reason from the failed case: absent means the caller's side is behind, failed
    // means a key was substituted, and the two remedies are not the same.
    expect(!v.ok && v.reason).toBe("inbound_assignment_no_key_binding");
  });

  it("sends a MALFORMED binding down the ABSENT path — missing and malformed never diverge", async () => {
    const initiator = generateKeypair();
    const group = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: group, malformedBinding: true });

    const v = verifyInboundAssignment(parsed(raw), null);
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("inbound_assignment_no_key_binding");
  });

  it("REFUSES a binding lifted from ANOTHER agent — the group key alone is not what is signed", async () => {
    // A real, valid binding exists: `other` genuinely vouches for `group`. The directory replays it
    // while naming `initiator` as participant_a. If the binding covered only the group key, this
    // would verify.
    const initiator = generateKeypair();
    const other = generateKeypair();
    const group = generateKeypair();
    const otherPub = await other.getPublicKey();
    const groupPub = await group.getPublicKey();
    const liftable = await other.sign(buildKeyBindingTbs(otherPub, groupPub));

    const raw = await frameFor({ initiator, groupSigner: group });
    raw["participant_a_key_binding"] = liftable;

    const v = verifyInboundAssignment(parsed(raw), null);
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("inbound_assignment_key_binding_invalid");
  });

  it("still catches a TAMPERED frame — the binding is an addition, not a replacement", async () => {
    const initiator = generateKeypair();
    const group = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: group, tamperAfterSigning: true });

    const v = verifyInboundAssignment(parsed(raw), null);
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("inbound_assignment_signature_invalid");
  });

  it("REFUSES a valid binding whose group key is NOT the pinned one — the pin still outranks it", async () => {
    // Both proofs are real: the caller genuinely vouches for this group key. It is simply not the
    // key this daemon recorded for them, which is either a re-registration or a substitution.
    const initiator = generateKeypair();
    const group = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: group });
    const pinned = Buffer.from(await generateKeypair().getPublicKey()).toString("hex");

    const v = verifyInboundAssignment(parsed(raw), pinned);
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("inbound_assignment_signer_not_pinned");
  });

  it("ACCEPTS in PINNED mode when the binding holds and the pin agrees", async () => {
    const initiator = generateKeypair();
    const group = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: group });
    const pinned = Buffer.from(await group.getPublicKey()).toString("hex");

    const v = verifyInboundAssignment(parsed(raw), pinned);
    expect(v.ok).toBe(true);
    expect(v.ok && v.mode).toBe("pinned");
  });

  it("REFUSES a missing binding even WITH a matching pin — the binding is not optional once trusted", async () => {
    // The pin would have carried this session before 038-KEYBIND. It must not now: a path where a
    // known counterparty is exempt from the proof is a path an attacker steers every session onto.
    const initiator = generateKeypair();
    const group = generateKeypair();
    const raw = await frameFor({ initiator, groupSigner: group, omitBinding: true });
    const pinned = Buffer.from(await group.getPublicKey()).toString("hex");

    const v = verifyInboundAssignment(parsed(raw), pinned);
    expect(v.ok).toBe(false);
    expect(!v.ok && v.reason).toBe("inbound_assignment_no_key_binding");
  });
});
