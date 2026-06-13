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
