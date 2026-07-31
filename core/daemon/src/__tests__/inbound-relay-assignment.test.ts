/**
 * DOD-FIRSTMSG-WITNESS-1 — the responder must be able to record its OWN relay session.
 *
 * Second producer gap behind the missing first-message witness. Only ONE thing creates the
 * relay's session state: a client presenting `client_record_assignment` (#doRecord). The
 * initiator can do that — `buildRelayConnectParams` (daemon.ts) builds a `RelayAssignmentCarry`
 * from the directory's `relay_directory_signature`. The responder cannot: the inbound wire
 * parser DROPPED that signature, so `inbound-sessions.ts` built its `relayParams` with no
 * `assignment` field at all.
 *
 * The consequence is not cosmetic. `#doRecord` returns TRUE ("nothing to present") when there is
 * no assignment, `#doSubmit` submits anyway, and the relay answers `session_not_found` — so a
 * responder's first message depends entirely on the INITIATOR having already recorded the
 * session, a race the responder does not know it is in. Same-machine loses that race (local
 * delivery is instant; the initiator's record is a round trip), which is exactly why the live
 * defect is same-machine only — the solo multi-agent wedge.
 *
 * These pin the wire boundary: the signature survives parsing, and its absence is reported as
 * absent rather than as an empty-but-present assignment.
 */
import { describe, it, expect } from "vitest";
import { extractInboundSessionAssignment } from "../inbound-sessions.js";

const A_PUB = new Uint8Array(32).fill(0xa1);
const B_PUB = new Uint8Array(32).fill(0xb2);
const SID = new Uint8Array(16).fill(0x5d);
const REL_SIG = new Uint8Array(64).fill(0xc3);

function frame(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    assignment: {
      session_id: SID,
      participant_a: { pubkey: A_PUB },
      participant_b: { pubkey: B_PUB },
      session_timestamp: 1_750_000_000_000,
      initiator_session_peer_id: "12D3KooWInitiator",
      counterparty_session_peer_id: "12D3KooWResponder",
      relay_endpoint: {
        peer_id: "12D3KooWRelay",
        multiaddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      },
      ...extra,
    },
  };
}

describe("inbound assignment: relay_directory_signature survives the wire boundary", () => {
  it("carries the directory signature so the RESPONDER can record its own relay session", () => {
    const parsed = extractInboundSessionAssignment(frame({ relay_directory_signature: REL_SIG }));

    expect(parsed).not.toBeNull();
    // Without this the responder can never present client_record_assignment and is permanently
    // dependent on the initiator winning a race — the live same-machine failure.
    expect(parsed!.relayDirectorySignature).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(parsed!.relayDirectorySignature!).equals(Buffer.from(REL_SIG))).toBe(true);
    expect(parsed!.relayDirectorySignature!.length).toBe(64);
  });

  it("reports the signature as ABSENT (undefined) when the directory did not issue one", () => {
    // Direct/legacy/pre-Option-B assignments carry no relay_directory_signature. That must read as
    // absent — never as a present-but-empty signature, which would make #doRecord present a frame
    // the relay rejects as forged.
    const parsed = extractInboundSessionAssignment(frame());

    expect(parsed).not.toBeNull();
    expect(parsed!.relayDirectorySignature).toBeUndefined();
  });

  it("still parses the fields the carry is built from (participants, timestamp, peer ids)", () => {
    // The carry is assembled from these; a regression here silently produces an unverifiable
    // assignment rather than a missing one.
    const parsed = extractInboundSessionAssignment(frame({ relay_directory_signature: REL_SIG }));

    expect(parsed!.participantAPubkeyHex).toBe(Buffer.from(A_PUB).toString("hex"));
    expect(parsed!.participantBPubkeyHex).toBe(Buffer.from(B_PUB).toString("hex"));
    expect(parsed!.sessionTimestamp).toBe(1_750_000_000_000);
    expect(parsed!.initiatorPeerId).toBe("12D3KooWInitiator");
    expect(parsed!.counterpartySessionPeerId).toBe("12D3KooWResponder");
  });
});
