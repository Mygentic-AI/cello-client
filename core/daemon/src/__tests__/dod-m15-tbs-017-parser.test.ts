/**
 * 017-TBS (client half) — `high_stakes: false` and `prior_relay_id: ""` are ANSWERS, not absences.
 *
 * ─── Why this file exists ──────────────────────────────────────────────────────────────────────
 *
 * The verifier rebuilds the directory-signed TBS by handing the parsed assignment's fields back to
 * `buildSessionEstablishmentTbs`, which chooses its layout on ARITY: an argument that is
 * `undefined` is treated as not supplied, and the shorter layout is emitted.
 *
 * The parser directly above these fields does the opposite thing on purpose. An empty session peer
 * id means "the directory never learned this endpoint", so it is deliberately mapped to
 * `undefined` and both sides drop to the short layout. Two fields sitting in the same block are
 * NOT like that — and they are exactly the two whose "empty" values are the common case:
 *
 *   - `high_stakes: false` — most sessions
 *   - `prior_relay_id: ""`  — every session that is not a relay handover
 *
 * Read either with a truthiness test rather than a type test and it becomes `undefined`, the
 * verifier rebuilds the 10-field TBS, the directory signed the 12-field one, and **every ordinary
 * session fails signature verification**. The failure is total and it looks like a crypto bug.
 *
 * The neighbouring `""`-means-absent lines are the reason this is easy to get wrong: copying the
 * adjacent pattern is the natural move and it is the broken one.
 */

import { describe, it, expect } from "vitest";
import { parseSessionAssignment } from "../session-assignment-parser.js";

/** A well-formed 12-field assignment, with the two new fields exposed for overriding. */
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

  it("reports a GENUINELY absent field as undefined — an older directory", () => {
    // The one case that must yield undefined, so the verifier drops to the 10-field layout that
    // such a directory actually signed. Distinguishing this from `false`/`""` is the whole point.
    const raw = assignment();
    delete raw["high_stakes"];
    delete raw["prior_relay_id"];
    const parsed = parseSessionAssignment(raw);
    expect(parsed!.high_stakes).toBeUndefined();
    expect(parsed!.prior_relay_id).toBeUndefined();
  });

  it("refuses to read a wrong-typed value as a real one", () => {
    // A non-boolean high_stakes is not "truthy therefore true" — it is not an answer at all.
    const parsed = parseSessionAssignment(assignment({ high_stakes: "yes", prior_relay_id: 7 }));
    expect(parsed!.high_stakes).toBeUndefined();
    expect(parsed!.prior_relay_id).toBeUndefined();
  });
});
