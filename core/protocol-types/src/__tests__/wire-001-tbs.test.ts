/**
 * CELLO-M7-WIRE-001 — buildSessionEstablishmentTbs tests
 *
 * AC-004: Extended TBS with 10 fields; canonical address ordering; different
 *         counterparty_session_peer_id produces different TBS.
 * AC-001: Type completeness — SessionAssignment values constructed with all fields.
 *
 * Per RFC 9591 (FROST), RFC 8949 (CBOR canonical).
 */

import {
  setupV3Tests,
  describe,
  it,
  expect,
} from "@claude-flow/testing";
import {
  buildSessionEstablishmentTbs,
} from "../session.js";
import type { SessionAssignment, SessionAssignmentFrost } from "../session.js";

setupV3Tests();

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeSessionId(): Uint8Array {
  return new Uint8Array(16).fill(0x11);
}

function makePubA(): Uint8Array {
  return new Uint8Array(32).fill(0xaa);
}

function makePubB(): Uint8Array {
  return new Uint8Array(32).fill(0xbb);
}

function makeGenesisPrevRoot(): Uint8Array {
  return new Uint8Array(32).fill(0xcc);
}

const TIMESTAMP = 1700000000000;

// ─── AC-004: buildSessionEstablishmentTbs with 10 fields ─────────────────────

describe("WIRE-001 AC-004: buildSessionEstablishmentTbs — M7 extended TBS", () => {
  it("AC-004: 10-field TBS includes session peer IDs, addrs, and transport mode", () => {
    const result = buildSessionEstablishmentTbs(
      makeSessionId(),
      makePubA(),
      makePubB(),
      makeGenesisPrevRoot(),
      TIMESTAMP,
      "12D3KooWInitiatorPeerId",
      ["/ip4/127.0.0.1/tcp/9000"],
      "12D3KooWCounterpartyPeerId",
      ["/ip4/127.0.0.1/tcp/9001"],
      "relay",
    );
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("AC-004: different counterparty_session_peer_id produces different TBS", () => {
    const common = [
      makeSessionId(),
      makePubA(),
      makePubB(),
      makeGenesisPrevRoot(),
      TIMESTAMP,
      "12D3KooWInitiatorPeerId",
      ["/ip4/127.0.0.1/tcp/9000"],
    ] as const;

    const tbs1 = buildSessionEstablishmentTbs(
      ...common,
      "12D3KooWCounterpartyA",
      ["/ip4/127.0.0.1/tcp/9001"],
      "relay",
    );
    const tbs2 = buildSessionEstablishmentTbs(
      ...common,
      "12D3KooWCounterpartyB",
      ["/ip4/127.0.0.1/tcp/9001"],
      "relay",
    );

    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("AC-004: canonical address ordering — different addr order produces same TBS", () => {
    const addrsA = ["/ip4/10.0.0.1/tcp/9000", "/ip4/192.168.1.1/tcp/9000"];
    const addrsB = ["/ip4/192.168.1.1/tcp/9000", "/ip4/10.0.0.1/tcp/9000"]; // reversed

    const tbs1 = buildSessionEstablishmentTbs(
      makeSessionId(),
      makePubA(),
      makePubB(),
      makeGenesisPrevRoot(),
      TIMESTAMP,
      "12D3KooWInitiator",
      addrsA,
      "12D3KooWCounterparty",
      ["/ip4/127.0.0.1/tcp/9001"],
      "direct",
    );
    const tbs2 = buildSessionEstablishmentTbs(
      makeSessionId(),
      makePubA(),
      makePubB(),
      makeGenesisPrevRoot(),
      TIMESTAMP,
      "12D3KooWInitiator",
      addrsB, // reversed order
      "12D3KooWCounterparty",
      ["/ip4/127.0.0.1/tcp/9001"],
      "direct",
    );

    expect(Buffer.from(tbs1).toString("hex")).toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("AC-004: canonical ordering applies to counterparty addrs as well", () => {
    const counterpartyAddrsA = ["/ip4/10.0.0.2/tcp/8000", "/dns4/relay.cello.org/tcp/443"];
    const counterpartyAddrsB = ["/dns4/relay.cello.org/tcp/443", "/ip4/10.0.0.2/tcp/8000"];

    const tbs1 = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      "12D3KooWInit", ["/ip4/127.0.0.1/tcp/9000"],
      "12D3KooWCounterparty", counterpartyAddrsA,
      "relay",
    );
    const tbs2 = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      "12D3KooWInit", ["/ip4/127.0.0.1/tcp/9000"],
      "12D3KooWCounterparty", counterpartyAddrsB,
      "relay",
    );

    expect(Buffer.from(tbs1).toString("hex")).toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("AC-004: transport_mode 'direct' vs 'relay' produces different TBS", () => {
    const tbs1 = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      "12D3KooWInit", ["/ip4/127.0.0.1/tcp/9000"],
      "12D3KooWCounterparty", ["/ip4/127.0.0.1/tcp/9001"],
      "direct",
    );
    const tbs2 = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      "12D3KooWInit", ["/ip4/127.0.0.1/tcp/9000"],
      "12D3KooWCounterparty", ["/ip4/127.0.0.1/tcp/9001"],
      "relay",
    );

    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("backward compat: omitting new params produces legacy 5-field TBS", () => {
    const tbsLegacy = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
    );
    const tbs10 = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      "12D3KooWInit", ["/ip4/127.0.0.1/tcp/9000"],
      "12D3KooWCounterparty", ["/ip4/127.0.0.1/tcp/9001"],
      "relay",
    );

    // The 10-field TBS must differ from the 5-field TBS
    expect(Buffer.from(tbsLegacy).toString("hex")).not.toBe(Buffer.from(tbs10).toString("hex"));
    expect(tbsLegacy.length).toBeGreaterThan(0);
    expect(tbs10.length).toBeGreaterThan(tbsLegacy.length);
  });

  it("empty addrs array is canonically sorted (no crash)", () => {
    const result = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      "12D3KooWInit", [],
      "12D3KooWCounterparty", [],
      "direct",
    );
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });
});

// ─── AC-001: Type completeness ───────────────────────────────────────────────

describe("WIRE-001 AC-001: SessionAssignment type completeness", () => {
  it("AC-001: SessionAssignmentFrost can be constructed with all M7 fields (compile-time check)", () => {
    const assignment: SessionAssignmentFrost = {
      session_id: makeSessionId(),
      participant_a: { pubkey: makePubA(), peer_id: "12D3KooWA", multiaddrs: ["/ip4/127.0.0.1/tcp/4001"] },
      participant_b: { pubkey: makePubB(), peer_id: "12D3KooWB", multiaddrs: ["/ip4/127.0.0.1/tcp/4002"] },
      relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/5000"] },
      directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/6000"] },
      session_timestamp: TIMESTAMP,
      directory_pubkey: new Uint8Array(32).fill(0xdd),
      directory_signature: new Uint8Array(64).fill(0xee),
      signature_type: "frost",
      signer_pubkey: new Uint8Array(32).fill(0xff),
      initiator_session_peer_id: "12D3KooWInitSession",
      initiator_session_addrs: ["/ip4/127.0.0.1/tcp/9000"],
      counterparty_session_peer_id: "12D3KooWCounterSession",
      counterparty_session_addrs: ["/ip4/127.0.0.1/tcp/9001"],
      transport_mode: "relay",
    };

    expect(assignment.initiator_session_peer_id).toBe("12D3KooWInitSession");
    expect(assignment.counterparty_session_peer_id).toBe("12D3KooWCounterSession");
    expect(assignment.initiator_session_addrs).toEqual(["/ip4/127.0.0.1/tcp/9000"]);
    expect(assignment.counterparty_session_addrs).toEqual(["/ip4/127.0.0.1/tcp/9001"]);
    expect(assignment.transport_mode).toBe("relay");
  });

  it("AC-001: SessionAssignment union type works with discriminated union", () => {
    const assignment: SessionAssignment = {
      session_id: makeSessionId(),
      participant_a: { pubkey: makePubA(), peer_id: "12D3KooWA", multiaddrs: [] },
      participant_b: { pubkey: makePubB(), peer_id: "12D3KooWB", multiaddrs: [] },
      relay_endpoint: { peer_id: "r1", multiaddrs: [] },
      directory_endpoint: { peer_id: "d1", multiaddrs: [] },
      session_timestamp: TIMESTAMP,
      directory_pubkey: new Uint8Array(32),
      directory_signature: new Uint8Array(64),
      signature_type: "frost",
      signer_pubkey: new Uint8Array(32),
      initiator_session_peer_id: "12D3KooWInit",
      initiator_session_addrs: [],
      counterparty_session_peer_id: "12D3KooWTarget",
      counterparty_session_addrs: [],
      transport_mode: "direct",
    };

    if (assignment.signature_type === "frost") {
      expect(assignment.signer_pubkey).toBeInstanceOf(Uint8Array);
    }
    expect(assignment.transport_mode).toBe("direct");
  });
});

// ─── 017-TBS: the 12-field layout ────────────────────────────────────────────

/**
 * Two fields join the signed bytes, batched because a TBS change is bilateral and the cost is
 * paid once: `high_stakes`, which the target is currently held to without being told, and
 * `prior_relay_id`, which names the relay that witnessed a conversation up to a handover. The new
 * relay verifies the old one's receipts, and the directory's signature is the only trustworthy
 * source for who the old one was — a relay knows no other relay's identity.
 */
describe("017-TBS: 12-field layout", () => {
  const M7: [string, string[], string, string[], "direct" | "relay"] = [
    "12D3KooWInit", ["/ip4/127.0.0.1/tcp/9000"],
    "12D3KooWCounterparty", ["/ip4/127.0.0.1/tcp/9001"],
    "relay",
  ];

  it("emits 12 fields whenever the M7 fields are present, on a FRESH session", () => {
    // high_stakes false and prior_relay_id "" are VALUES, not absences. A fresh session is the
    // normal path and must still reach the long layout — anything else hands the next reader two
    // possible layouts for one session shape.
    const twelve = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, false, "",
    );
    const ten = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7,
    );
    expect(twelve.length).toBeGreaterThan(ten.length);
    expect(Buffer.from(twelve).equals(Buffer.from(ten))).toBe(false);
  });

  it("high_stakes changes the signed bytes", () => {
    // The defect this closes: the flag rides the initiator's request and was never forwarded, so
    // the counterparty was held to a longer floor and a mandatory-evidence bar it never saw.
    const off = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, false, "",
    );
    const on = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, true, "",
    );
    expect(Buffer.from(off).equals(Buffer.from(on))).toBe(false);
  });

  it("prior_relay_id changes the signed bytes", () => {
    const fresh = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, false, "",
    );
    const resume = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, false, "a".repeat(64),
    );
    expect(Buffer.from(fresh).equals(Buffer.from(resume))).toBe(false);
  });

  it("a DIFFERENT prior relay produces different bytes — the field is bound, not decorative", () => {
    // Without this, a signature over one prior relay would carry over to another and the new relay
    // would accept receipts from a relay the directory never named.
    const one = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, false, "a".repeat(64),
    );
    const two = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, false, "b".repeat(64),
    );
    expect(Buffer.from(one).equals(Buffer.from(two))).toBe(false);
  });

  it("is deterministic — same inputs, same bytes", () => {
    const a = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, true, "a".repeat(64),
    );
    const b = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7, true, "a".repeat(64),
    );
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("the two legacy layouts are untouched", () => {
    // Byte-pinned, not merely "still shorter": a change to either legacy path breaks every
    // assignment already signed under it, and length alone would not notice a reordering.
    const five = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
    );
    expect(Buffer.from(five).toString("hex")).toBe(
      "8550111111111111111111111111111111115820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      + "5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      + "5820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc1b0000018bcfe56800",
    );

    const ten = buildSessionEstablishmentTbs(
      makeSessionId(), makePubA(), makePubB(), makeGenesisPrevRoot(), TIMESTAMP,
      ...M7,
    );
    expect(Buffer.from(ten).toString("hex")).toBe(
      "8a50111111111111111111111111111111115820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      + "5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      + "5820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc1b0000018bcfe56800"
      + "6c313244334b6f6f57496e6974781b5b222f6970342f3132372e302e302e312f7463702f39303030225d"
      + "74313244334b6f6f57436f756e7465727061727479781b5b222f6970342f3132372e302e302e312f7463702f39303031225d"
      + "6572656c6179",
    );
  });
});
