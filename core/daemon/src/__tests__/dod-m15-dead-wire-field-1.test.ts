/**
 * DOD-M15-DEAD-WIRE-FIELD-1 — a participant is its pubkey, and nothing else can refuse a session.
 *
 * The directory used to put `peer_id` and `multiaddrs` on each participant. Nothing read them and no
 * signature covered them, yet a malformed or empty one refused the whole assignment — so an agent
 * whose peer-info announce was late could not be talked to at all. They are no longer part of
 * `ParticipantInfo`; any that still arrive are ignored.
 *
 * `parseEndpointInfo` reads identically-named fields on the RELAY and DIRECTORY endpoints, and those
 * ARE dialed, so they stay strict. Same field name, adjacent function, one dead and one
 * load-bearing: the relay tests below hold that line.
 */

import { describe, it, expect } from "vitest";
import { parseSessionAssignment } from "../session-assignment-parser.js";

function assignment(participantExtras: Record<string, unknown> = {}): Record<string, unknown> {
  const participant = (pub: number) => ({ pubkey: new Uint8Array(32).fill(pub), ...participantExtras });
  return {
    session_id: new Uint8Array(16).fill(1),
    participant_a: participant(0xaa),
    participant_b: participant(0xbb),
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
    session_timestamp: 1_700_000_000_000,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    directory_signature: new Uint8Array(64).fill(0xee),
    signer_pubkey: new Uint8Array(32).fill(0xcc),
    initiator_session_peer_id: "12D3KooWInitiator",
    initiator_session_addrs: ["/ip4/127.0.0.1/tcp/3"],
    counterparty_session_peer_id: "12D3KooWReceiver",
    counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/4"],
    transport_mode: "relay",
    high_stakes: false,
    prior_relay_id: "",
    relay_id: "",
  };
}

describe("DOD-M15-DEAD-WIRE-FIELD-1: a participant is its pubkey", () => {
  it("a participant carrying only its pubkey parses — the control", () => {
    const parsed = parseSessionAssignment(assignment());
    expect(parsed).not.toBeNull();
    expect(Object.keys(parsed!.participant_a)).toEqual(["pubkey"]);
  });

  it("★ junk in the old participant fields cannot refuse the assignment, and is not carried", () => {
    const parsed = parseSessionAssignment(assignment({ peer_id: "", multiaddrs: [1, 2, 3] }));
    expect(parsed, "fields nothing reads must not be able to end a conversation").not.toBeNull();
    expect(Object.keys(parsed!.participant_a)).toEqual(["pubkey"]);
  });

  it("a participant is still rejected for its pubkey — the one value that IS read", () => {
    const a = assignment();
    (a["participant_a"] as Record<string, unknown>)["pubkey"] = new Uint8Array(8);
    expect(parseSessionAssignment(a), "a short pubkey must still refuse").toBeNull();
  });

  it("the RELAY endpoint's peer_id stays STRICT — it is dialed", () => {
    const a = assignment();
    (a["relay_endpoint"] as Record<string, unknown>)["peer_id"] = "";
    expect(parseSessionAssignment(a), "an empty RELAY peer_id must still refuse").toBeNull();
  });

  it("the RELAY endpoint's multiaddrs stays STRICT — those are dialed", () => {
    const a = assignment();
    (a["relay_endpoint"] as Record<string, unknown>)["multiaddrs"] = [1, 2, 3];
    expect(parseSessionAssignment(a), "a malformed RELAY multiaddr must still refuse").toBeNull();
  });
});
