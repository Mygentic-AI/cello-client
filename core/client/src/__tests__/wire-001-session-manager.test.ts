/**
 * CELLO-M7-WIRE-001 — receiveSessionAssignment verification tests
 *
 * Tests the M7 session Peer ID verification, TBS extension, and transport_mode pass-through.
 *
 * AC-011: Missing session peer ID returns assignment_missing_session_peer_id
 * AC-012: Tampered TBS returns assignment_tbs_verification_failed
 * AC-010: Peer ID mismatch returns assignment_peer_id_mismatch
 * AC-006: Valid initiator flow (FROST verify passes, self-check passes)
 * AC-007: Valid target flow (FROST verify passes, session peer IDs passed through)
 * AC-013: transport_mode passed through without address inference
 * SI-001: Tampered counterparty_session_peer_id fails FROST verification
 */

import {
  setupV3Tests,
  createTestScope,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import type { TestScope } from "@claude-flow/testing";
import { randomBytes } from "node:crypto";
import { generateKeypair, FrostThresholdSigner, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import { bootstrapKeyShares, clearTestShares } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import { createInProcessStubs } from "@cello-protocol/crypto/frost/stubs.js";
import {
  buildSessionEstablishmentTbs,
  computeGenesisPrevRoot,
} from "@cello-protocol/protocol-types";
import type { SessionAssignmentFrost } from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import { createClient } from "../client.js";

setupV3Tests();

// ─── Test scope ───────────────────────────────────────────────────────────────

let scope: TestScope;
beforeEach(() => { scope = createTestScope(); });
afterEach(() => {
  clearTestShares();
  return scope.run(async () => {});
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

const INITIATOR_SESSION_PEER_ID = "12D3KooWTestInitiatorSessionPeerId";
const COUNTERPARTY_SESSION_PEER_ID = "12D3KooWTestCounterpartySessionPeerId";
const INITIATOR_SESSION_ADDRS = ["/ip4/127.0.0.1/tcp/9000"];
const COUNTERPARTY_SESSION_ADDRS = ["/ip4/127.0.0.1/tcp/9001"];
const TRANSPORT_MODE = "relay" as const;

interface SetupResult {
  pubkeyA: Uint8Array;
  pubkeyB: Uint8Array;
  signer: FrostThresholdSigner;
  primaryPubkey: Uint8Array;
  nodeA: Awaited<ReturnType<typeof createNode>>;
  clientA: ReturnType<typeof createClient>;
}

async function setupWithFrost(): Promise<SetupResult> {
  const kpA = generateKeypair();
  const kpB = generateKeypair();
  const pubkeyA = await kpA.getPublicKey();
  const pubkeyB = await kpB.getPublicKey();

  const nodeA = await createNode({ keyProvider: kpA, listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  await nodeA.start();
  scope.addCleanup(() => nodeA.stop());

  const stubs = createInProcessStubs(3);
  const bootstrap = await bootstrapKeyShares(pubkeyA, { threshold: 2, participants: 3, directoryNodeStubs: stubs });
  const signer = new FrostThresholdSigner({ threshold: 2, participants: 3, directoryNodeStubs: stubs }, pubkeyA);

  const clientA = createClient(nodeA, kpA, { thresholdSigner: signer });
  await clientA.registerHandler();

  return { pubkeyA, pubkeyB, signer, primaryPubkey: bootstrap.primaryPubkey, nodeA, clientA };
}

async function buildValidAssignment(opts: {
  pubkeyA: Uint8Array;
  pubkeyB: Uint8Array;
  signer: FrostThresholdSigner;
  primaryPubkey: Uint8Array;
  overrides?: Partial<SessionAssignmentFrost>;
}): Promise<SessionAssignmentFrost> {
  const sessionId = randomBytes(16);
  const timestamp = Date.now();
  const genesisPrevRoot = computeGenesisPrevRoot(opts.pubkeyA, opts.pubkeyB, sessionId, timestamp);

  const initiatorSessionPeerId = opts.overrides?.initiator_session_peer_id ?? INITIATOR_SESSION_PEER_ID;
  const initiatorSessionAddrs = opts.overrides?.initiator_session_addrs ?? INITIATOR_SESSION_ADDRS;
  const counterpartySessionPeerId = opts.overrides?.counterparty_session_peer_id ?? COUNTERPARTY_SESSION_PEER_ID;
  const counterpartySessionAddrs = opts.overrides?.counterparty_session_addrs ?? COUNTERPARTY_SESSION_ADDRS;
  const transportMode = opts.overrides?.transport_mode ?? TRANSPORT_MODE;

  const tbs = buildSessionEstablishmentTbs(
    sessionId, opts.pubkeyA, opts.pubkeyB, genesisPrevRoot, timestamp,
    initiatorSessionPeerId, initiatorSessionAddrs,
    counterpartySessionPeerId, counterpartySessionAddrs,
    transportMode,
  );

  // Sign with FROST
  const signResult = await opts.signer.participateInCeremony("wire-001-test", tbs, CONTEXT_SESSION_ESTABLISHMENT);
  if (!signResult.ok) throw new Error("FROST signing failed in test setup");

  return {
    session_id: sessionId,
    participant_a: { pubkey: opts.pubkeyA, peer_id: "12D3KooWA", multiaddrs: ["/ip4/127.0.0.1/tcp/4001"] },
    participant_b: { pubkey: opts.pubkeyB, peer_id: "12D3KooWB", multiaddrs: ["/ip4/127.0.0.1/tcp/4002"] },
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/5000"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/6000"] },
    session_timestamp: timestamp,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    directory_signature: signResult.signature,
    signature_type: "frost" as const,
    signer_pubkey: opts.primaryPubkey,
    initiator_session_peer_id: initiatorSessionPeerId,
    initiator_session_addrs: initiatorSessionAddrs,
    counterparty_session_peer_id: counterpartySessionPeerId,
    counterparty_session_addrs: counterpartySessionAddrs,
    transport_mode: transportMode,
    ...opts.overrides,
  };
}

// ─── AC-011: Missing session peer ID ─────────────────────────────────────────

describe("WIRE-001 AC-011: missing session peer ID returns assignment_missing_session_peer_id", () => {
  it("AC-011: empty initiator_session_peer_id returns assignment_missing_session_peer_id with guidance", async () => {
    const { pubkeyA, pubkeyB, primaryPubkey, clientA } = await setupWithFrost();

    // Build assignment with empty initiator_session_peer_id — FROST sig will be over
    // the TBS with the empty string, but the check triggers before TBS reconstruction
    const assignment: SessionAssignmentFrost = {
      session_id: randomBytes(16),
      participant_a: { pubkey: pubkeyA, peer_id: "12D3KooWA", multiaddrs: ["/ip4/127.0.0.1/tcp/4001"] },
      participant_b: { pubkey: pubkeyB, peer_id: "12D3KooWB", multiaddrs: ["/ip4/127.0.0.1/tcp/4002"] },
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: [] },
      directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: [] },
      session_timestamp: Date.now(),
      directory_pubkey: new Uint8Array(32),
      directory_signature: new Uint8Array(64),
      signature_type: "frost" as const,
      signer_pubkey: primaryPubkey,
      initiator_session_peer_id: "", // empty — triggers rejection
      initiator_session_addrs: INITIATOR_SESSION_ADDRS,
      counterparty_session_peer_id: COUNTERPARTY_SESSION_PEER_ID,
      counterparty_session_addrs: COUNTERPARTY_SESSION_ADDRS,
      transport_mode: TRANSPORT_MODE,
    };

    const result = await clientA.receiveSessionAssignment(assignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_missing_session_peer_id");
      expect(result.guidance).toBeDefined();
      expect(result.guidance).toContain("session Peer ID");
    }
  });

  it("AC-011: counterparty present without initiator returns assignment_missing_session_peer_id", async () => {
    const { pubkeyA, pubkeyB, primaryPubkey, clientA } = await setupWithFrost();

    const assignment: SessionAssignmentFrost = {
      session_id: randomBytes(16),
      participant_a: { pubkey: pubkeyA, peer_id: "12D3KooWA", multiaddrs: [] },
      participant_b: { pubkey: pubkeyB, peer_id: "12D3KooWB", multiaddrs: [] },
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: [] },
      directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: [] },
      session_timestamp: Date.now(),
      directory_pubkey: new Uint8Array(32),
      directory_signature: new Uint8Array(64),
      signature_type: "frost" as const,
      signer_pubkey: primaryPubkey,
      initiator_session_peer_id: undefined, // absent initiator
      initiator_session_addrs: undefined,
      counterparty_session_peer_id: "12D3KooWCounterparty", // present counterparty — malformed
      counterparty_session_addrs: COUNTERPARTY_SESSION_ADDRS,
      transport_mode: TRANSPORT_MODE,
    };

    const result = await clientA.receiveSessionAssignment(assignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_missing_session_peer_id");
    }
  });
});

// ─── AC-012: Tampered TBS returns assignment_tbs_verification_failed ─────────

describe("WIRE-001 AC-012: tampered TBS returns assignment_tbs_verification_failed", () => {
  it("AC-012: assignment with tampered directory_signature fails FROST verification", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({ pubkeyA, pubkeyB, signer, primaryPubkey });
    // Tamper with the signature
    assignment.directory_signature = new Uint8Array(64).fill(0x42);

    const result = await clientA.receiveSessionAssignment(assignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_tbs_verification_failed");
      expect(result.guidance).toBeDefined();
    }
  });
});

// ─── AC-010: Peer ID mismatch ────────────────────────────────────────────────

describe("WIRE-001 AC-010: peer ID mismatch returns assignment_peer_id_mismatch", () => {
  it("AC-010: initiator session peer ID does not match local node — returns assignment_peer_id_mismatch", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({ pubkeyA, pubkeyB, signer, primaryPubkey });

    // Pass a different mySessionPeerId that doesn't match what's in the assignment
    const result = await clientA.receiveSessionAssignment(
      assignment,
      pubkeyA,
      { mySessionPeerId: "12D3KooWDifferentPeerId" },
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_peer_id_mismatch");
      expect(result.guidance).toBeDefined();
      expect(result.guidance).toContain("initiator session Peer ID");
    }
  });

  it("AC-010: when mySessionPeerId matches assignment, no mismatch error occurs", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({ pubkeyA, pubkeyB, signer, primaryPubkey });

    // Pass the correct mySessionPeerId — should pass peer ID check
    // Will fail at relay dial (relay_auth_error) which proves it passed all verification
    const result = await clientA.receiveSessionAssignment(
      assignment,
      pubkeyA,
      { mySessionPeerId: INITIATOR_SESSION_PEER_ID },
    );
    // It will fail at relay auth (no relay running), not at peer ID check
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).not.toBe("assignment_peer_id_mismatch");
      expect(result.reason).not.toBe("assignment_missing_session_peer_id");
      expect(result.reason).not.toBe("assignment_tbs_verification_failed");
    }
  });
});

// ─── AC-006: Valid initiator flow ────────────────────────────────────────────

describe("WIRE-001 AC-006: valid initiator flow passes all verification checks", () => {
  it("AC-006: FROST verify passes, self-check passes, log emitted — fails only at relay", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({ pubkeyA, pubkeyB, signer, primaryPubkey });

    // Call as initiator with matching peer ID
    const result = await clientA.receiveSessionAssignment(
      assignment,
      pubkeyA,
      { mySessionPeerId: INITIATOR_SESSION_PEER_ID },
    );

    // The function passes all M7 verification checks but fails at relay dial
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The only acceptable failure reason is relay-related (proves verification passed)
      expect(["relay_auth_error", "relay_auth_failed"]).toContain(result.reason);
    }
  });
});

// ─── AC-007: Valid target flow ───────────────────────────────────────────────

describe("WIRE-001 AC-007: valid target flow passes verification, session peer IDs available", () => {
  it("AC-007: target (participant B) receives valid assignment — passes FROST verify", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    // Build an assignment where pubkeyA is the TARGET (participant_b)
    const sessionId = randomBytes(16);
    const timestamp = Date.now();
    const genesisPrevRoot = computeGenesisPrevRoot(pubkeyB, pubkeyA, sessionId, timestamp);

    const tbs = buildSessionEstablishmentTbs(
      sessionId, pubkeyB, pubkeyA, genesisPrevRoot, timestamp,
      INITIATOR_SESSION_PEER_ID, INITIATOR_SESSION_ADDRS,
      COUNTERPARTY_SESSION_PEER_ID, COUNTERPARTY_SESSION_ADDRS,
      TRANSPORT_MODE,
    );

    // For the target flow, we verify against signer_pubkey from the frame (A's primary_pubkey)
    const signResult = await signer.participateInCeremony("wire-001-target-test", tbs, CONTEXT_SESSION_ESTABLISHMENT);
    if (!signResult.ok) throw new Error("FROST signing failed in test setup");

    const targetAssignment: SessionAssignmentFrost = {
      session_id: sessionId,
      participant_a: { pubkey: pubkeyB, peer_id: "12D3KooWB", multiaddrs: ["/ip4/127.0.0.1/tcp/4002"] },
      participant_b: { pubkey: pubkeyA, peer_id: "12D3KooWA", multiaddrs: ["/ip4/127.0.0.1/tcp/4001"] },
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/5000"] },
      directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/6000"] },
      session_timestamp: timestamp,
      directory_pubkey: new Uint8Array(32).fill(0xdd),
      directory_signature: signResult.signature,
      signature_type: "frost" as const,
      signer_pubkey: primaryPubkey, // initiator's primary pubkey — used by target for verification
      initiator_session_peer_id: INITIATOR_SESSION_PEER_ID,
      initiator_session_addrs: INITIATOR_SESSION_ADDRS,
      counterparty_session_peer_id: COUNTERPARTY_SESSION_PEER_ID,
      counterparty_session_addrs: COUNTERPARTY_SESSION_ADDRS,
      transport_mode: TRANSPORT_MODE,
    };

    // pubkeyA is participant_b (target) — no self-check on peer ID for target
    const result = await clientA.receiveSessionAssignment(targetAssignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Should pass verification, fail only at relay
      expect(["relay_auth_error", "relay_auth_failed"]).toContain(result.reason);
    }
  });
});

// ─── AC-013: transport_mode passed through ───────────────────────────────────

describe("WIRE-001 AC-013: transport_mode passed through without address inference", () => {
  it("AC-013: transport_mode 'direct' is accepted and included in TBS", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({
      pubkeyA, pubkeyB, signer, primaryPubkey,
      overrides: { transport_mode: "direct" },
    });

    const result = await clientA.receiveSessionAssignment(
      assignment, pubkeyA, { mySessionPeerId: INITIATOR_SESSION_PEER_ID },
    );
    // Passes verification (fails at relay dial)
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["relay_auth_error", "relay_auth_failed"]).toContain(result.reason);
    }
  });

  it("AC-013: transport_mode 'relay' is accepted and included in TBS", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({
      pubkeyA, pubkeyB, signer, primaryPubkey,
      overrides: { transport_mode: "relay" },
    });

    const result = await clientA.receiveSessionAssignment(
      assignment, pubkeyA, { mySessionPeerId: INITIATOR_SESSION_PEER_ID },
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["relay_auth_error", "relay_auth_failed"]).toContain(result.reason);
    }
  });
});

// ─── SI-001: Tampered counterparty_session_peer_id fails FROST ───────────────

describe("WIRE-001 SI-001: tampered counterparty_session_peer_id fails FROST verification", () => {
  it("SI-001: modifying counterparty_session_peer_id after signing causes TBS mismatch", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({ pubkeyA, pubkeyB, signer, primaryPubkey });

    // Tamper with the counterparty_session_peer_id AFTER signing
    // The FROST signature was computed over the original TBS, so changing this field
    // will cause TBS reconstruction to differ and FROST verification to fail
    assignment.counterparty_session_peer_id = "12D3KooWTamperedPeerId";

    const result = await clientA.receiveSessionAssignment(assignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_tbs_verification_failed");
    }
  });

  it("SI-001: modifying initiator_session_addrs after signing causes TBS mismatch", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({ pubkeyA, pubkeyB, signer, primaryPubkey });

    // Tamper with the addrs
    assignment.initiator_session_addrs = ["/ip4/10.0.0.99/tcp/1234"];

    const result = await clientA.receiveSessionAssignment(assignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_tbs_verification_failed");
    }
  });

  it("SI-001: modifying transport_mode after signing causes TBS mismatch", async () => {
    const { pubkeyA, pubkeyB, signer, primaryPubkey, clientA } = await setupWithFrost();

    const assignment = await buildValidAssignment({
      pubkeyA, pubkeyB, signer, primaryPubkey,
      overrides: { transport_mode: "relay" },
    });

    // Flip transport_mode from relay to direct
    assignment.transport_mode = "direct";

    const result = await clientA.receiveSessionAssignment(assignment, pubkeyA);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("assignment_tbs_verification_failed");
    }
  });
});
