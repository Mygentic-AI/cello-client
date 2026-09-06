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
import { generateKeypair, buildKeyBindingTbs, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
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
  announceKey?: Uint8Array;
  counterpartyPeerId?: string;
  tamperAfterSigning?: boolean;
  /** 017-TBS: supply BOTH for the 12-field layout; omit both for the 10-field one. */
  highStakes?: boolean;
  priorRelayId?: string;
}): Promise<SessionAssignment> {
  const signerPub = opts.announceKey ?? (await opts.signWith.getPublicKey());
  const PUB_B = await RESPONDER.getPublicKey();
  const counterpartyPeerId = opts.counterpartyPeerId ?? "12D3KooWCounterparty";
  // 017-TBS: present ONLY when the caller asks, so every existing fixture keeps signing 10 fields.
  const twelve = opts.highStakes !== undefined && opts.priorRelayId !== undefined;
  const base = {
    session_id: SESSION_ID,
    participant_a: { pubkey: PUB_A, peer_id: "12D3KooWA", multiaddrs: [] as string[] },
    participant_b: { pubkey: PUB_B, peer_id: "12D3KooWB", multiaddrs: [] as string[] },
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
    session_timestamp: TS,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    initiator_session_peer_id: "12D3KooWInit",
    initiator_session_addrs: ["/ip4/127.0.0.1/tcp/3"],
    counterparty_session_peer_id: counterpartyPeerId,
    counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/4"],
    transport_mode: "relay" as const,
    ...(twelve ? { high_stakes: opts.highStakes, prior_relay_id: opts.priorRelayId } : {}),
  };
  const genesis = computeGenesisPrevRoot(PUB_A, PUB_B, SESSION_ID, TS);
  const tbs = buildSessionEstablishmentTbs(
    SESSION_ID, PUB_A, PUB_B, genesis, TS,
    base.initiator_session_peer_id, base.initiator_session_addrs,
    base.counterparty_session_peer_id, base.counterparty_session_addrs, base.transport_mode,
    // Forwarded as-is including undefined — the builder chooses its layout on arity.
    opts.highStakes, opts.priorRelayId,
  );
  // The FROST context framing the directory signs under.
  const enc = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
  const framed = new Uint8Array(enc.length + 1 + tbs.length);
  framed.set(enc, 0); framed[enc.length] = 0x00; framed.set(tbs, enc.length + 1);
  const sig = await opts.signWith.sign(framed);

  return {
    ...base,
    signature_type: "frost",
    signer_pubkey: signerPub,
    directory_signature: sig,
    // 038-KEYBIND: participant_b vouches for its own group key, so the initiator can record it.
    ...(opts.omitCounterpartyBinding
      ? {}
      : {
          participant_b_primary_pubkey: PUB_B_GROUP,
          participant_b_key_binding: await (
            opts.forgeCounterpartyBinding ? generateKeypair() : RESPONDER
          ).sign(buildKeyBindingTbs(PUB_B, PUB_B_GROUP)),
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
   * 017-TBS — the verifier's half of the 12-field layout.
   *
   * These are the only tests that exercise the two new arguments at the verifier's call sites.
   * Without them the sign and verify halves both stayed on 10 fields, agreed with each other, and
   * proved nothing: dropping the arguments from `verifyAssignmentSignature` left every existing
   * test green. The signature is what makes this real — the fixture SIGNS 12 fields, so a verifier
   * that rebuilds 10 cannot produce a matching signature no matter what else is right.
   */
  it("ACCEPTS a 12-field assignment — a FRESH session, where both new values are the falsy ones", async () => {
    // The common case and the one most likely to break: false and "" are the values a truthiness
    // bug anywhere in the chain turns into "absent", which silently selects the 10-field layout.
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, highStakes: false, priorRelayId: "" });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok, "a fresh 12-field assignment is the normal path — refusing it breaks every session").toBe(true);
  });

  it("ACCEPTS a 12-field assignment on a RESUME, naming the prior relay", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const asg = await makeAssignment({ signWith: kp, highStakes: true, priorRelayId: "a".repeat(64) });

    const r = await verifyAssignmentSignature(asg, persistenceWith(hex), silent, "alice", "corr");
    expect(r.ok).toBe(true);
  });

  it("REFUSES a 12-field assignment whose prior relay was swapped after signing", async () => {
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

  it("REFUSES a 12-field assignment whose high_stakes was flipped after signing", async () => {
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

/**
 * ─── Review F1: the one-field downgrade that disabled every check above ──────────────────────────
 *
 * `signature_type` rides in the frame and no signature covers it. The parser reads anything that is
 * not the literal "frost" — an absent field included — as "single", and the verifier used to route
 * that to a branch which checked `directory_signature` against the `directory_pubkey` sitting
 * beside it in the same unsigned frame. A key verified against itself proves nothing.
 *
 * So a hostile directory disabled the whole unit by omitting one field: mint a fresh keypair, name
 * an impostor as the counterparty, sign, drop `signature_type`, and the daemon dialled the impostor
 * having "verified" the assignment.
 */
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
    expect(!r.ok && r.reason).toBe("assignment_counterparty_binding_absent");
    expect(!r.ok && r.guidance.length).toBeGreaterThan(0);
    expect(seen).toContain("session.assignment.counterparty_binding_absent");
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
    expect(!r.ok && r.reason).toBe("assignment_counterparty_binding_invalid");
    expect(seen).toContain("session.assignment.counterparty_binding_invalid");
  });
});

describe("DOD-M15-ASSIGN-1: a weaker signature type cannot be claimed to skip the check", () => {
  it("REFUSES an assignment whose signature_type is not frost, even when its own signature verifies", async () => {
    const attacker = generateKeypair();
    const ours = generateKeypair();
    const { logger, seen } = events();

    // The attacker's assignment is INTERNALLY VALID: they signed it with their own key and named
    // that key. Under the old code the single-key branch verified it and returned ok.
    const forged = await makeAssignment({ signWith: attacker, counterpartyPeerId: "12D3KooWImpostor" });
    (forged as unknown as Record<string, unknown>)["signature_type"] = "single";
    (forged as unknown as Record<string, unknown>)["directory_pubkey"] = await attacker.getPublicKey();

    const verdict = await verifyAssignmentSignature(
      forged,
      persistenceWith(Buffer.from(await ours.getPublicKey()).toString("hex")),
      logger,
      "agent-1",
      "corr-1",
    );

    expect(verdict.ok, "a non-frost assignment must not be accepted for a threshold-registered agent").toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe("assignment_signature_type_downgraded");
    // Named as its own cause, not collapsed into the generic invalid-signature reason: the
    // signature here is perfectly valid, and saying otherwise would send the reader hunting a
    // crypto fault instead of a downgrade.
    expect(seen).toContain("session.assignment.signature_type_downgraded");
  });

  it("REFUSES an assignment with signature_type absent entirely (the parser reads it as single)", async () => {
    const attacker = generateKeypair();
    const ours = generateKeypair();
    const { logger } = events();

    const forged = await makeAssignment({ signWith: attacker });
    delete (forged as unknown as Record<string, unknown>)["signature_type"];

    const verdict = await verifyAssignmentSignature(
      forged,
      persistenceWith(Buffer.from(await ours.getPublicKey()).toString("hex")),
      logger,
      "agent-1",
      "corr-1",
    );

    expect(verdict.ok).toBe(false);
    expect(verdict.ok === false && verdict.reason).toBe("assignment_signature_type_downgraded");
  });
});
