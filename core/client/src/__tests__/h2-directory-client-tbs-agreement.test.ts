/**
 * CELLO-M7 H-2 — Directory producer ⇄ client verifier byte-for-byte agreement.
 *
 * This test proves, under REAL FROST crypto (no mocks, no structural-prefix
 * checks), that:
 *   1. The 10-field session-establishment TBS the DIRECTORY builds by hand
 *      (canonical CBOR array) is byte-for-byte identical to the shared
 *      buildSessionEstablishmentTbs() the client uses on its verify path.
 *   2. A real FrostThresholdSigner signature over that TBS, with the
 *      CONTEXT_SESSION_ESTABLISHMENT domain, verifies through the client's real
 *      verifyFrostSignature() path against the group public key.
 *
 * If the directory's encoding ever drifts from the client's, signature
 * verification fails silently in production — this test is the guard.
 *
 * Per RFC 9591 (FROST), RFC 8949 (canonical CBOR).
 */

import {
  setupV3Tests,
  describe,
  it,
  expect,
  afterEach,
} from "@claude-flow/testing";
import { randomBytes } from "node:crypto";
import { Encoder } from "cbor-x";
import {
  generateKeypair,
  FrostThresholdSigner,
  CONTEXT_SESSION_ESTABLISHMENT,
  verifyFrostSignature,
} from "@cello-protocol/crypto";
import {
  bootstrapKeyShares,
  clearTestShares,
} from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import { createInProcessStubs } from "@cello-protocol/crypto/frost/stubs.js";
import {
  buildSessionEstablishmentTbs,
  computeGenesisPrevRoot,
} from "@cello-protocol/protocol-types";

setupV3Tests();

afterEach(() => {
  clearTestShares();
});

// The directory uses cbor-x with tagUint8Array:false (CONTEXT.md / session.ts).
const CBOR_ENC = new Encoder({ tagUint8Array: false });

/**
 * How the DIRECTORY builds the 10-field TBS by hand — the canonical CBOR array
 * exactly as specified, independent of the shared protocol-types helper.
 */
function directoryBuildsTbs(args: {
  sessionId: Uint8Array;
  pubA: Uint8Array;
  pubB: Uint8Array;
  genesisPrevRoot: Uint8Array;
  timestamp: number;
  initiatorSessionPeerId: string;
  initiatorSessionAddrs: string[];
  counterpartySessionPeerId: string;
  counterpartySessionAddrs: string[];
  transportMode: "direct" | "relay";
}): Uint8Array {
  // Canonical timestamp width rule (session.ts): values above uint32 max are
  // encoded as CBOR bigints. Date.now() is always above this, so this matters.
  const tsEncoded =
    args.timestamp > 0xffffffff ? BigInt(args.timestamp) : args.timestamp;
  return CBOR_ENC.encode([
    args.sessionId,
    args.pubA,
    args.pubB,
    args.genesisPrevRoot,
    tsEncoded,
    args.initiatorSessionPeerId,
    JSON.stringify(args.initiatorSessionAddrs.slice().sort()),
    args.counterpartySessionPeerId,
    JSON.stringify(args.counterpartySessionAddrs.slice().sort()),
    args.transportMode,
  ]) as Uint8Array;
}

describe("H-2: directory TBS producer and client verifier agree under real FROST", () => {
  it("byte-for-byte TBS match + a real FROST signature verifies on the client path", async () => {
    const kpA = generateKeypair();
    const kpB = generateKeypair();
    const pubA = await kpA.getPublicKey();
    const pubB = await kpB.getPublicKey();

    const sessionId = randomBytes(16);
    const timestamp = Date.now();
    const genesisPrevRoot = computeGenesisPrevRoot(pubA, pubB, sessionId, timestamp);

    const initiatorSessionPeerId = "12D3KooWInitiatorSessionPeerId";
    // Deliberately unsorted to prove canonical address ordering is applied identically.
    const initiatorSessionAddrs = ["/ip4/127.0.0.1/tcp/9100", "/ip4/127.0.0.1/tcp/9000"];
    const counterpartySessionPeerId = "12D3KooWCounterpartySessionPeerId";
    const counterpartySessionAddrs = ["/ip4/127.0.0.1/tcp/9001"];
    const transportMode = "relay" as const;

    // Producer side (directory) — hand-built canonical CBOR array.
    const directoryTbs = directoryBuildsTbs({
      sessionId, pubA, pubB, genesisPrevRoot, timestamp,
      initiatorSessionPeerId, initiatorSessionAddrs,
      counterpartySessionPeerId, counterpartySessionAddrs, transportMode,
    });

    // Shared builder used on the client's verify path.
    const clientTbs = buildSessionEstablishmentTbs(
      sessionId, pubA, pubB, genesisPrevRoot, timestamp,
      initiatorSessionPeerId, initiatorSessionAddrs,
      counterpartySessionPeerId, counterpartySessionAddrs, transportMode,
    );

    // 1) Byte-for-byte agreement.
    expect(Buffer.from(directoryTbs).equals(Buffer.from(clientTbs))).toBe(true);

    // 2) Sign the directory-built TBS with a REAL FROST threshold signer.
    const stubs = createInProcessStubs(3);
    const bootstrap = await bootstrapKeyShares(pubA, { threshold: 2, participants: 3, directoryNodeStubs: stubs });
    const signer = new FrostThresholdSigner({ threshold: 2, participants: 3, directoryNodeStubs: stubs }, pubA);

    const signResult = await signer.participateInCeremony("h2-test", directoryTbs, CONTEXT_SESSION_ESTABLISHMENT);
    expect(signResult.ok).toBe(true);
    if (!signResult.ok) throw new Error("FROST signing failed");

    // 3) Verify through the client's real verify path against the group public key.
    const verified = verifyFrostSignature(
      signResult.signature,
      clientTbs,
      CONTEXT_SESSION_ESTABLISHMENT,
      bootstrap.primaryPubkey,
    );
    expect(verified).toBe(true);

    // Negative control: a one-byte mutation of the TBS must fail verification.
    const mutated = Uint8Array.from(clientTbs);
    mutated[mutated.length - 1] ^= 0xff;
    const mutatedVerify = verifyFrostSignature(
      signResult.signature,
      mutated,
      CONTEXT_SESSION_ESTABLISHMENT,
      bootstrap.primaryPubkey,
    );
    expect(mutatedVerify).toBe(false);
  });
});
