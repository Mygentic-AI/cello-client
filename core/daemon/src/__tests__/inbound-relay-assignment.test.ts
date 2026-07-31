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
import { extractInboundSessionAssignment, buildResponderRelayAssignment, buildResponderRelayParams } from "../inbound-sessions.js";

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

  it("reports a MALFORMED signature as absent, and distinguishably so", () => {
    // A wrong-length value is a wire/version bug, not a legacy session. It must read as absent
    // (presenting it would be rejected as forged, which sets recordRejected TERMINALLY and leaves
    // the session permanently unwitnessed — worse than the defect being fixed), but the daemon
    // must still be able to say WHY it degraded.
    const parsed = extractInboundSessionAssignment(
      frame({ relay_directory_signature: new Uint8Array(63).fill(0xc3) }),
    );

    expect(parsed!.relayDirectorySignature).toBeUndefined();
    expect(parsed!.relayDirectorySignatureMalformed).toBe(true);
    // The legitimately-absent case must NOT be flagged malformed.
    expect(extractInboundSessionAssignment(frame())!.relayDirectorySignatureMalformed).toBe(false);
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

describe("responder relay assignment: the carry actually handed to the relay client", () => {
  // The parser is only half the fix. These pin the CONSUMER: without them the whole
  // `assignment:` wiring could be deleted from acceptInboundAssignment and every parser test
  // would still pass, leaving the responder exactly as broken as before.
  const parsed = (over: Partial<Parameters<typeof buildResponderRelayAssignment>[0]> = {}) => ({
    participantAPubkeyHex: Buffer.from(A_PUB).toString("hex"),
    participantBPubkeyHex: Buffer.from(B_PUB).toString("hex"),
    sessionTimestamp: 1_750_000_000_000,
    initiatorPeerId: "12D3KooWInitiator",
    counterpartySessionPeerId: "12D3KooWResponder" as string | null,
    relayDirectorySignature: REL_SIG as Uint8Array | undefined,
    ...over,
  });

  it("maps every field the relay rebuilds the signed TBS from", () => {
    // A swapped participant or a dropped peer id yields an assignment the relay rejects as FORGED,
    // which marks the session recordRejected TERMINALLY — permanently unwitnessed.
    const carry = buildResponderRelayAssignment(parsed());

    expect(carry).toBeDefined();
    expect(Buffer.from(carry!.participantA).equals(Buffer.from(A_PUB))).toBe(true);
    expect(Buffer.from(carry!.participantB).equals(Buffer.from(B_PUB))).toBe(true);
    expect(carry!.sessionTimestamp).toBe(1_750_000_000_000);
    expect(carry!.initiatorSessionPeerId).toBe("12D3KooWInitiator");
    expect(carry!.counterpartySessionPeerId).toBe("12D3KooWResponder");
    expect(Buffer.from(carry!.assignmentSignature).equals(Buffer.from(REL_SIG))).toBe(true);
  });

  it("is undefined when the directory issued no signature — direct/legacy sessions unchanged", () => {
    expect(buildResponderRelayAssignment(parsed({ relayDirectorySignature: undefined }))).toBeUndefined();
  });

  it("normalises absent peer ids to undefined rather than empty string / null", () => {
    // The relay covers these in the TBS only when present; an empty string is not the same value
    // as absent and would change the reconstructed bytes.
    const carry = buildResponderRelayAssignment(parsed({ initiatorPeerId: "", counterpartySessionPeerId: null }));

    expect(carry!.initiatorSessionPeerId).toBeUndefined();
    expect(carry!.counterpartySessionPeerId).toBeUndefined();
  });
});

describe("responder relay params: the whole object handed to acceptSession", () => {
  const PUB = new Uint8Array(32).fill(0xee);
  const kp = { getPublicKey: async () => PUB } as unknown as Parameters<typeof buildResponderRelayParams>[1];
  const caplog = () => {
    const warns: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger = {
      debug() {}, info() {}, error() {},
      warn(event: string, ctx: Record<string, unknown>) { warns.push({ event, ctx }); },
    } as unknown as Parameters<typeof buildResponderRelayParams>[2];
    return { logger, warns };
  };

  it("includes the assignment — the field whose absence IS the defect", async () => {
    const { logger, warns } = caplog();
    const parsed = extractInboundSessionAssignment(frame({ relay_directory_signature: REL_SIG }))!;

    const params = await buildResponderRelayParams(parsed, kp, logger, "agentB");

    expect(params).toBeDefined();
    expect(params!.assignment).toBeDefined();
    expect(Buffer.from(params!.assignment!.assignmentSignature).equals(Buffer.from(REL_SIG))).toBe(true);
    expect(params!.relayPeerId).toBe("12D3KooWRelay");
    expect(Buffer.from(params!.sessionIdBytes).equals(Buffer.from(SID))).toBe(true);
    expect(Buffer.from(params!.senderPubkey).equals(Buffer.from(PUB))).toBe(true);
    // The healthy case is silent — the warning is reserved for a real degradation.
    expect(warns.filter((w) => w.event === "session.relay.assignment.signature.missing")).toHaveLength(0);
  });

  it("WARNS when a relay-endpoint assignment carries no signature — degraded, but never invisible", async () => {
    const { logger, warns } = caplog();
    const parsed = extractInboundSessionAssignment(frame())!;

    const params = await buildResponderRelayParams(parsed, kp, logger, "agentB");

    expect(params!.assignment).toBeUndefined();
    const w = warns.find((x) => x.event === "session.relay.assignment.signature.missing");
    expect(w).toBeDefined();
    expect(w!.ctx["reason"]).toBe("relay_mode_assignment_without_directory_signature");
  });

  it("distinguishes a MALFORMED signature from an absent one in the warning", async () => {
    const { logger, warns } = caplog();
    const parsed = extractInboundSessionAssignment(frame({ relay_directory_signature: new Uint8Array(63) }))!;

    await buildResponderRelayParams(parsed, kp, logger, "agentB");

    const w = warns.find((x) => x.event === "session.relay.assignment.signature.missing");
    expect(w!.ctx["reason"]).toBe("relay_directory_signature_malformed");
  });

  it("returns undefined (no relay witness) when the assignment carries no relay endpoint", async () => {
    const { logger } = caplog();
    const parsed = extractInboundSessionAssignment({
      assignment: {
        session_id: SID,
        participant_a: { pubkey: A_PUB },
        participant_b: { pubkey: B_PUB },
        session_timestamp: 1_750_000_000_000,
      },
    })!;

    expect(await buildResponderRelayParams(parsed, kp, logger, "agentB")).toBeUndefined();
  });
});
