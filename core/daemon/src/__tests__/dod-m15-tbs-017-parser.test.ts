/**
 * 017-TBS (client half) — `high_stakes: false`, `prior_relay_id: ""` and `relay_id: ""` are ANSWERS,
 * not absences.
 *
 * The verifier rebuilds the directory-signed 13-field TBS from the parsed assignment. These are the
 * fields whose "empty" values are the common case — most sessions are not high-stakes, not a relay
 * handover, and a direct session has no relay. Read with a truthiness test rather than a type test,
 * any of them turns into an absence, and every ordinary session is refused.
 */

import { describe, it, expect } from "vitest";
import { parseSessionAssignment } from "../session-assignment-parser.js";

/** A well-formed assignment, with every field exposed for overriding. */
function assignment(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const participant = (pub: number) => ({
    pubkey: new Uint8Array(32).fill(pub),
    peer_id: `12D3KooWParticipant${pub}`,
    multiaddrs: [],
  });
  return {
    session_id: new Uint8Array(16).fill(1),
    participant_a: participant(0xaa),
    participant_b: participant(0xbb),
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
    session_timestamp: 1_700_000_000_000,
    directory_pubkey: new Uint8Array(32).fill(0xdd),
    directory_signature: new Uint8Array(64).fill(0xee),
    signature_type: "frost",
    signer_pubkey: new Uint8Array(32).fill(0xcc),
    initiator_session_peer_id: "12D3KooWInitiator",
    initiator_session_addrs: ["/ip4/127.0.0.1/tcp/3"],
    counterparty_session_peer_id: "12D3KooWCounterparty",
    counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/4"],
    transport_mode: "relay",
    high_stakes: false,
    prior_relay_id: "",
    relay_id: "",
    ...overrides,
  };
}

describe("017-TBS parser: falsy values survive as values", () => {
  it("keeps high_stakes false — NOT undefined", () => {
    const parsed = parseSessionAssignment(assignment());
    expect(parsed).not.toBeNull();
    // Name the value. `toBeFalsy()` would pass on `undefined`, which is the exact bug.
    expect(parsed!.high_stakes).toBe(false);
  });

  it("keeps prior_relay_id \"\" — NOT undefined", () => {
    const parsed = parseSessionAssignment(assignment());
    expect(parsed!.prior_relay_id).toBe("");
  });

  it("carries a real prior relay id through unchanged", () => {
    const priorRelayId = "a".repeat(64);
    const parsed = parseSessionAssignment(assignment({ prior_relay_id: priorRelayId }));
    expect(parsed!.prior_relay_id).toBe(priorRelayId);
  });

  it("keeps high_stakes true", () => {
    const parsed = parseSessionAssignment(assignment({ high_stakes: true }));
    expect(parsed!.high_stakes).toBe(true);
  });

  it("refuses an assignment MISSING any of them — there is no shorter statement to verify", () => {
    for (const field of ["high_stakes", "prior_relay_id", "relay_id"]) {
      const raw = assignment();
      delete raw[field];
      expect(parseSessionAssignment(raw), `${field} absent`).toBeNull();
    }
  });

  it("refuses a wrong-typed value rather than reading it as a real one", () => {
    // A non-boolean high_stakes is not "truthy therefore true" — it is not an answer at all.
    expect(parseSessionAssignment(assignment({ high_stakes: "yes" }))).toBeNull();
    expect(parseSessionAssignment(assignment({ prior_relay_id: 7 }))).toBeNull();
  });
});
