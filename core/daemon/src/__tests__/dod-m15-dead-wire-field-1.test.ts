/**
 * DOD-M15-DEAD-WIRE-FIELD-1 (client half) — a field nobody reads cannot kill a session.
 *
 * ─── The checked-then-ignored ──────────────────────────────────────────────────────────────────
 *
 * `participant_a/b.multiaddrs` has been permanently `[]` on every session assignment since the
 * directory-facing node stopped listening. The directory stores it and **signs nothing over it** —
 * neither the session nor the relay TBS includes it. The client parses it and drops it: the only
 * read of a parsed assignment's participants takes `.pubkey`.
 *
 * And the parser REJECTED THE WHOLE ASSIGNMENT if that array was malformed. So a value with no
 * consumers, covered by no signature, could refuse a session outright — a directory bug, a CBOR
 * quirk or a future field-type change would end a conversation over something nothing acts on.
 *
 * ─── What this half does, and what it deliberately leaves ──────────────────────────────────────
 *
 * Removing the field from the wire is BILATERAL and belongs with the other pending wire changes
 * (`DOD-M15-SUBMIT-ID-1`'s 7-element Structure 1, `DOD-M15-TERMINAL-REASON-1`'s reasons) so the two
 * repos move once. That is carried.
 *
 * Making the client stop REFUSING over it is unilateral, backward-compatible, and closes the
 * checked-then-ignored today.
 *
 * ─── The distinction that matters, and the reason for the second test ──────────────────────────
 *
 * `parseEndpointInfo` reads the same-named field for the RELAY and DIRECTORY endpoints — and those
 * multiaddrs ARE dialed. Loosening both would be the easy mistake: identical field name, adjacent
 * functions, one dead and one load-bearing. The relay endpoint must stay strict, and the second test
 * is what holds that line.
 */

import { describe, it, expect } from "vitest";
import { parseSessionAssignment } from "../session-assignment-parser.js";

/** A well-formed assignment, with the pieces a test wants to corrupt exposed. */
function assignment(overrides: {
  participantMultiaddrs?: unknown;
  relayMultiaddrs?: unknown;
} = {}): Record<string, unknown> {
  const participant = (pub: number) => ({
    pubkey: new Uint8Array(32).fill(pub),
    peer_id: `12D3KooWParticipant${pub}`,
    multiaddrs: "participantMultiaddrs" in overrides ? overrides.participantMultiaddrs : [],
  });
  return {
    session_id: new Uint8Array(16).fill(1),
    participant_a: participant(0xaa),
    participant_b: participant(0xbb),
    relay_endpoint: {
      peer_id: "12D3KooWRelay",
      multiaddrs: "relayMultiaddrs" in overrides ? overrides.relayMultiaddrs : ["/ip4/127.0.0.1/tcp/1"],
    },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
    session_timestamp: 1_700_000_000_000,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    directory_signature: new Uint8Array(64).fill(0xee),
    signature_type: "frost",
    signer_pubkey: new Uint8Array(32).fill(0xcc),
    initiator_session_peer_id: "12D3KooWInitiator",
    initiator_session_addrs: ["/ip4/127.0.0.1/tcp/3"],
    counterparty_session_peer_id: "12D3KooWReceiver",
    counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/4"],
    transport_mode: "relay",
  };
}

describe("DOD-M15-DEAD-WIRE-FIELD-1: a field with no consumers cannot refuse a session", () => {
  it("the well-formed case still parses — the control", () => {
    expect(parseSessionAssignment(assignment())).not.toBeNull();
  });

  it("★ a MALFORMED participant multiaddrs no longer refuses the whole assignment", () => {
    /**
     * Nothing reads it and no signature covers it, so refusing over it ends a conversation for a
     * value that cannot affect anything. Numbers in place of strings is the shape a field-type
     * change or a CBOR quirk actually produces.
     */
    const parsed = parseSessionAssignment(assignment({ participantMultiaddrs: [1, 2, 3] }));
    expect(
      parsed,
      "A session was refused over `participant.multiaddrs` — a field that is permanently empty, " +
        "covered by no signature, and read by nothing (the only read of a parsed participant takes " +
        "`.pubkey`).",
    ).not.toBeNull();
    // THE OUTCOME, not its shadow (hollow-test Q4). `not.toBeNull()` alone passed a mutation that
    // returned the malformed value verbatim AND one that FABRICATED an address — both measured
    // green by review. `[]` is what the comment promises, so `[]` is what gets asserted.
    expect(parsed!.participant_a.multiaddrs).toEqual([]);
  });

  it("an ABSENT participant multiaddrs parses too", () => {
    // The shape the bilateral half will produce once the field leaves the wire. Accepting it now
    // means the client is already compatible when the directory stops sending it.
    const a = assignment();
    delete (a["participant_a"] as Record<string, unknown>)["multiaddrs"];
    const parsed = parseSessionAssignment(a);
    expect(parsed).not.toBeNull();
    expect(parsed!.participant_a.multiaddrs).toEqual([]);
  });

  it("the RELAY endpoint's multiaddrs stays STRICT — those are dialed", () => {
    /**
     * The line this must not cross. `parseEndpointInfo` reads an identically-named field on the
     * relay and directory endpoints, and those addresses ARE dialed — a malformed one is a session
     * that cannot connect, which is worth refusing loudly at the boundary rather than discovering
     * at dial time.
     *
     * Same field name, adjacent function, one dead and one load-bearing: loosening both is the easy
     * mistake, and this is what stops it.
     */
    expect(
      parseSessionAssignment(assignment({ relayMultiaddrs: [1, 2, 3] })),
      "a malformed RELAY multiaddr must still refuse — it is dialed, unlike the participant field",
    ).toBeNull();
  });

  it("a participant is still rejected for the things that ARE read", () => {
    // Tolerance is scoped to the dead field. `pubkey` is the one value a parsed participant is read
    // for, so it stays strict — otherwise this change would trade a harmless refusal for a real one.
    const a = assignment();
    (a["participant_a"] as Record<string, unknown>)["pubkey"] = new Uint8Array(8);
    expect(parseSessionAssignment(a), "a short pubkey must still refuse").toBeNull();
  });
});
