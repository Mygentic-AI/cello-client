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
import { generateKeypair, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
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
const PUB_B = new Uint8Array(32).fill(0xbb);
const TS = 1_700_000_000_000;

/** Build an assignment and sign its TBS with `signWith`, announcing `announceKey` as the signer. */
async function makeAssignment(opts: {
  signWith: ReturnType<typeof generateKeypair>;
  announceKey?: Uint8Array;
  counterpartyPeerId?: string;
  tamperAfterSigning?: boolean;
}): Promise<SessionAssignment> {
  const signerPub = opts.announceKey ?? (await opts.signWith.getPublicKey());
  const counterpartyPeerId = opts.counterpartyPeerId ?? "12D3KooWCounterparty";
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
  };
  const genesis = computeGenesisPrevRoot(PUB_A, PUB_B, SESSION_ID, TS);
  const tbs = buildSessionEstablishmentTbs(
    SESSION_ID, PUB_A, PUB_B, genesis, TS,
    base.initiator_session_peer_id, base.initiator_session_addrs,
    base.counterparty_session_peer_id, base.counterparty_session_addrs, base.transport_mode,
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
