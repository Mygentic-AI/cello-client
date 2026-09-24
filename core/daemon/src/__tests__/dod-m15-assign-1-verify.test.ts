/**
 * DOD-M15-ASSIGN-1 — the session assignment's signature is verified, and a bad one refuses.
 *
 * WHAT THIS PROTECTS, because a test that does not say it invites someone to weaken it later: the
 * assignment is the permission slip that tells this daemon which peer id and addresses to dial for
 * a counterparty. Nothing verified it. Whichever directory node the daemon happened to be talking
 * to could name ANY peer — one compromised node could put an operator into a session with an
 * impostor, and everything downstream would look normal, because the impostor is a real agent
 * signing with its own real key.
 *
 * REAL CRYPTO THROUGHOUT — no mocks (project rule, and the rule earns itself here: the whole unit
 * IS the signature check, so a faked verify would test nothing). A plain Ed25519 signature verifies
 * under `verifyFrostSignature`, which is what lets these tests mint real signatures with a real
 * keypair rather than stubbing the primitive.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair, buildKeyBindingTbs, CONTEXT_SESSION_ESTABLISHMENT, signMlDsa } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import type { ParsedSessionAssignment as SessionAssignment } from "../session-assignment-parser.js";
import { fixturePqKeys } from "./helpers/signed-assignment.js";
import { verifyAssignmentSignature } from "../assignment-verify.js";
import type { DbRegistrationPersistence } from "../db-identity-store.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

function events(): { logger: Logger; seen: string[] } {
  const seen: string[] = [];
  return {
    seen,
    logger: {
      debug(e) { seen.push(e); }, info(e) { seen.push(e); },
      warn(e) { seen.push(e); }, error(e) { seen.push(e); },
    },
  };
}

/** A persistence double that answers only what the verifier asks of it. */
function persistenceWith(primaryPubkey: string | null): DbRegistrationPersistence {
  return {
    async loadRegistrationState() {
      return primaryPubkey === null
        ? null
        : { agentId: "agent-1", primaryPubkey, mlDsaPubkey: "", registeredAt: 0, status: "registered" };
    },
  } as unknown as DbRegistrationPersistence;
}

const SESSION_ID = new Uint8Array(16).fill(7);
const PUB_A = new Uint8Array(32).fill(0xaa);
/**
 * 038-KEYBIND — participant_b is a REAL keypair now, and the group key it vouches for is separate.
 *
 * The initiator refuses an assignment unless the counterparty's own identity key has signed for the
 * threshold key the frame names as theirs. A made-up `0xbb` pubkey has no private half, so it could
 * never produce that signature — which is the property, not an inconvenience.
 */
const RESPONDER = generateKeypair();
const PUB_B_GROUP = new Uint8Array(32).fill(0x5b);
const TS = 1_700_000_000_000;

/** Build an assignment and sign its TBS with `signWith`, announcing `announceKey` as the signer. */
async function makeAssignment(opts: {
  signWith: ReturnType<typeof generateKeypair>;
  /** 038-KEYBIND: send NO counterparty group key / binding. */
  omitCounterpartyBinding?: boolean;
  /** 038-KEYBIND: have someone OTHER than participant_b vouch for participant_b's group key. */
  forgeCounterpartyBinding?: boolean;
  /** M9D 002-PQKEYS: participant_b's ML-DSA half signed by a THIRD agent's genuine ML-DSA key. */
  forgeCounterpartyBindingPq?: boolean;
  announceKey?: Uint8Array;
  counterpartyPeerId?: string;
  tamperAfterSigning?: boolean;
  /** 017-TBS: default false / "" — a fresh, ordinary session. */
  highStakes?: boolean;
  priorRelayId?: string;
}): Promise<SessionAssignment> {
  const signerPub = opts.announceKey ?? (await opts.signWith.getPublicKey());
  const PUB_B = await RESPONDER.getPublicKey();
  const counterpartyPeerId = opts.counterpartyPeerId ?? "12D3KooWCounterparty";
  const highStakes = opts.highStakes ?? false;
  const priorRelayId = opts.priorRelayId ?? "";
  const base = {
    session_id: SESSION_ID,
    participant_a: { pubkey: PUB_A },
    participant_b: { pubkey: PUB_B },
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
    session_timestamp: TS,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    initiator_session_peer_id: "12D3KooWInit",
    initiator_session_addrs: ["/ip4/127.0.0.1/tcp/3"],
    counterparty_session_peer_id: counterpartyPeerId,
    counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/4"],
    transport_mode: "relay" as const,
    high_stakes: highStakes,
    prior_relay_id: priorRelayId,
    relay_id: "",
  };
  const genesis = computeGenesisPrevRoot(PUB_A, PUB_B, SESSION_ID, TS);
  const tbs = buildSessionEstablishmentTbs(
    SESSION_ID, PUB_A, PUB_B, genesis, TS,
    base.initiator_session_peer_id, base.initiator_session_addrs,
    base.counterparty_session_peer_id, base.counterparty_session_addrs, base.transport_mode,
    highStakes, priorRelayId, "",
  );
  // The FROST context framing the directory signs under.
  const enc = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
  const framed = new Uint8Array(enc.length + 1 + tbs.length);
  framed.set(enc, 0); framed[enc.length] = 0x00; framed.set(tbs, enc.length + 1);
  const sig = await opts.signWith.sign(framed);

  // M9D 002-PQKEYS: participant_b's v2 binding — all four of their keys, both signatures.
  const bPq = await fixturePqKeys(Buffer.from(PUB_B).toString("hex"));
  const bTbs = buildKeyBindingTbs({ kLocal: PUB_B, group: PUB_B_GROUP, mlDsa: bPq.mlDsaPubkey, mlKem: bPq.mlKemPubkey });

  return {
    ...base,
    signer_pubkey: signerPub,
    directory_signature: sig,
    // 038-KEYBIND: participant_b vouches for its own group key, so the initiator can record it.
    ...(opts.omitCounterpartyBinding
      ? {}
      : {
          participant_b_primary_pubkey: PUB_B_GROUP,
          participant_b_ml_dsa_pubkey: bPq.mlDsaPubkey,
          participant_b_ml_kem_pubkey: bPq.mlKemPubkey,
          participant_b_key_binding: await (opts.forgeCounterpartyBinding ? generateKeypair() : RESPONDER).sign(bTbs),
          participant_b_key_binding_pq: await signMlDsa(
            opts.forgeCounterpartyBindingPq ? (await fixturePqKeys("third-party")).mlDsaProvider : bPq.mlDsaProvider,
            "cello-mldsa-key-binding-v1",
            bTbs,
          ),
        }),
    // TAMPERED AFTER SIGNING: the address set the daemon would dial is changed, the signature is
    // not. This is the shape a compromised directory produces.
    ...(opts.tamperAfterSigning ? { counterparty_session_peer_id: "12D3KooWImpostor" } : {}),
  } as unknown as SessionAssignment;
}

describe("DOD-M15-ASSIGN-1: a session assignment is verified before anything dials what it names", () => {
  it("ACCEPTS an assignment signed by this agent's own threshold key", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok, "a legitimate assignment must not be refused — a gate that breaks sessions is worse than the hole").toBe(true);
  });

  /**
   * 017-TBS — `high_stakes` and `prior_relay_id` at the verifier's call sites. The fixture SIGNS
   * them, so a verifier that drops or alters either cannot produce a matching signature.
   */
  it("ACCEPTS an assignment — a FRESH session, where both new values are the falsy ones", async () => {
    // The common case and the one most likely to break: false and "" are the values a truthiness
    // bug anywhere in the chain turns into "absent".
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, highStakes: false, priorRelayId: "" });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok, "a fresh assignment is the normal path — refusing it breaks every session").toBe(true);
  });

  it("ACCEPTS an assignment on a RESUME, naming the prior relay", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, highStakes: true, priorRelayId: "a".repeat(64) });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok).toBe(true);
  });

  it("REFUSES an assignment whose prior relay was swapped after signing", async () => {
    // The binding that matters. prior_relay_id decides which relay's receipts the NEW relay will
    // trust, so if it were outside the signature a tampering party could redirect that trust to a
    // relay the directory never named. Tampered after signing, which is the shape a compromised
    // directory or a man-in-the-middle produces.
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, highStakes: false, priorRelayId: "a".repeat(64) });
    (asg as unknown as { prior_relay_id: string }).prior_relay_id = "b".repeat(64);

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok, "prior_relay_id is inside the signed bytes — swapping it must not verify").toBe(false);
  });

  it("REFUSES an assignment whose high_stakes was flipped after signing", async () => {
    // Same binding, the other field: flipping the tier off would put the counterparty back on the
    // short delivery floor the initiator did not ask for.
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, highStakes: true, priorRelayId: "" });
    (asg as unknown as { high_stakes: boolean }).high_stakes = false;

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok).toBe(false);
  });

  it("REFUSES an assignment announcing a signer that is not this agent's key", async () => {
    /**
     * THE ANTI-CIRCULARITY CASE, and the one that makes the whole check worth anything.
     * `signer_pubkey` rides in the frame, so an attacker supplies BOTH the key and the signature —
     * a self-consistent forgery. Verifying the signature against the announced key alone would pass
     * it. The only thing that catches it is comparing that key against what this daemon persisted
     * at registration, which the frame cannot influence.
     */
    const attacker = generateKeypair();
    const ours = generateKeypair();
    const asg = await makeAssignment({ signWith: attacker }); // internally consistent, wrong key
    const oursHex = Buffer.from(await ours.getPublicKey()).toString("hex");

    const ev = events();
    const r = await verifyAssignmentSignature(asg, persistenceWith(oursHex), ev.logger, "alice", "corr");
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toBe("assignment_signer_not_this_agent");
    expect(ev.seen).toContain("session.assignment.signer_mismatch");
    // Invariant 2: loud in the log AND answered to the caller, and worded as an observation.
    expect(r.ok === false && r.guidance).toMatch(/cause undetermined/i);
    expect(r.ok === false && r.guidance, "must say nothing was established").toMatch(/nothing was established/i);
  });

  it("REFUSES when the signed contents were altered after signing — the dialled peer is covered", async () => {
    // A directory that signs honestly and then swaps the counterparty's peer id. The signature is
    // real, the key is right, and the bytes no longer match what was signed.
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, tamperAfterSigning: true });

    const ev = events();
    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), ev.logger, "alice", "corr");
    expect(r.ok, "the peer id the daemon would dial is inside the signed bytes").toBe(false);
    expect(r.ok === false && r.reason).toBe("assignment_signature_invalid");
    expect(ev.seen).toContain("session.assignment.signature_invalid");
  });

  it("FAILS CLOSED when this agent has no registration — unverifiable is not valid", async () => {
    // Without our own registration there is no key to compare the announced signer against, so the
    // assignment cannot be checked. That is not the same as checking out.
    const kp = generateKeypair();
    const asg = await makeAssignment({ signWith: kp });

    const r = await verifyAssignmentSignature(asg, persistenceWith(null), silent, "alice", "corr");
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toBe("assignment_unverifiable_no_registration");
    // Invariant 4: the refusal names a real, dispatchable next step.
    expect(r.ok === false && r.guidance).toMatch(/cello register-agent/);
  });
});

describe("038-KEYBIND: the initiator learns the responder's group key, or refuses", () => {
  it("RETURNS the counterparty's group key when their own identity key vouched for it", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok).toBe(true);
    // THE VALUE, not "it did not refuse". The whole point of the field is what gets PINNED as the
    // seal trust anchor, so asserting only `ok` would stay green if the function returned nothing.
    expect(r.ok && r.counterpartyPrimaryHex).toBe(Buffer.from(PUB_B_GROUP).toString("hex"));
  });

  it("REFUSES when the counterparty's key binding is ABSENT — a withheld proof costs what a wrong one costs", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const { logger, seen } = events();
    const asg = await makeAssignment({ signWith: kp, omitCounterpartyBinding: true });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), logger, "alice", "corr");
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toBe("key_binding_missing");
    expect(!r.ok && r.guidance.length).toBeGreaterThan(0);
    expect(seen).toContain("session.assignment.counterparty_binding_refused");
  });

  it("REFUSES — with a DIFFERENT reason — when someone other than the counterparty vouched for their group key", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const { logger, seen } = events();
    const asg = await makeAssignment({ signWith: kp, forgeCounterpartyBinding: true });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), logger, "alice", "corr");
    expect(r.ok).toBe(false);
    // Distinct from the absent case: one says the directory is behind, the other says a key was
    // substituted. Collapsing them would send the operator to the wrong remedy.
    expect(!r.ok && r.reason).toBe("key_binding_signature_mismatch");
    expect(seen).toContain("session.assignment.counterparty_binding_refused");
  });

  it("002-PQKEYS test 12: genuine Ed25519 beside a THIRD agent's genuine ML-DSA → key_binding_pq_signature_mismatch, no keys returned", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, forgeCounterpartyBindingPq: true });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toBe("key_binding_pq_signature_mismatch");
    // Nothing reaches `recordCounterpartyKeys` without the verified result, and there is none.
    expect("counterpartyMlKemHex" in r).toBe(false);
  });

  it("002-PQKEYS test 14 (initiator half): returns exactly the responder's two PQ keys", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp });
    const bPq = await fixturePqKeys(Buffer.from(await RESPONDER.getPublicKey()).toString("hex"));

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok).toBe(true);
    expect(r.ok && r.counterpartyMlDsaHex).toBe(Buffer.from(bPq.mlDsaPubkey).toString("hex"));
    expect(r.ok && r.counterpartyMlKemHex).toBe(Buffer.from(bPq.mlKemPubkey).toString("hex"));
  });
});
