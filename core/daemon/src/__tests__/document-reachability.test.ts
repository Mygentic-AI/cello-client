/**
 * DOD-DOC-DELIVERY-2 — the discovery_lookup → reachability mapping.
 *
 * The delivery worker's whole retry behaviour turns on this answer being about the PEER. Five
 * discovery outcomes, one of which is an answer about the peer; the other four are facts about us
 * or about the directory, and collapsing any of them into "offline" sends the operator to ask the
 * wrong person why nothing is syncing.
 */

import { describe, it, expect } from "vitest";
import {
  reachabilityFromDiscovery,
  DiscoveryUnavailableError,
} from "../document-reachability.js";
import type { DiscoveryOutcome } from "../cross-node-negotiation.js";

describe("reachabilityFromDiscovery — a directory RESULT is an answer about the peer", () => {
  it("online is reachable", () => {
    expect(
      reachabilityFromDiscovery({ kind: "result", state: "online", owningNodeIds: ["n1"] }),
    ).toEqual({ reachable: true, unknownAgent: false });
  });

  it("offline is not reachable, and is not an unknown agent", () => {
    expect(
      reachabilityFromDiscovery({ kind: "result", state: "offline", owningNodeIds: [] }),
    ).toEqual({ reachable: false, unknownAgent: false });
  });

  it("unknown_agent is not reachable, and says so distinctly", () => {
    // It IS an answer from the directory about the peer — the address does not resolve — so the
    // consequence matches offline (do not dial, retry later). It is a bad address rather than a
    // transient absence, which the caller surfaces differently.
    expect(
      reachabilityFromDiscovery({ kind: "result", state: "unknown_agent", owningNodeIds: [] }),
    ).toEqual({ reachable: false, unknownAgent: true });
  });
});

describe("reachabilityFromDiscovery — everything else THROWS, because we learned nothing", () => {
  const cases: Array<[string, DiscoveryOutcome, string]> = [
    ["a directory DB fault", { kind: "error", reason: "db_timeout" }, "directory_error"],
    ["a reply that did not parse", { kind: "malformed" }, "malformed_reply"],
    ["no reply at all", { kind: "timeout" }, "timeout"],
    [
      "our OWN signaling stream being down",
      { kind: "send_failed", reason: "signaling_unavailable" },
      "signaling_unavailable",
    ],
  ];

  for (const [label, outcome, kind] of cases) {
    it(`refuses to call ${label} an offline peer`, () => {
      // Returning false here would record a directory outage — or our own transport fault — as the
      // operator's collaborator being absent. The worker already logs a throw as lookup_failed and
      // keeps that distinction; this is what feeds it.
      expect(() => reachabilityFromDiscovery(outcome)).toThrow(DiscoveryUnavailableError);
      try {
        reachabilityFromDiscovery(outcome);
      } catch (e) {
        expect((e as DiscoveryUnavailableError).kind).toBe(kind);
      }
    });
  }

  it("carries the upstream reason verbatim rather than replacing it", () => {
    try {
      reachabilityFromDiscovery({ kind: "error", reason: "discovery_lookup_error_db" });
    } catch (e) {
      // The reason the directory gave is the diagnosis; a generic message would be a label on the
      // exit point.
      expect((e as Error).message).toContain("discovery_lookup_error_db");
    }
  });

  it("refuses an UNRECOGNIZED outcome rather than defaulting it either way", () => {
    // A silent default would have to invent one of the two answers — "reachable" burns dials at a
    // peer we know nothing about, "offline" stalls delivery indefinitely. Neither is a measurement.
    expect(() =>
      reachabilityFromDiscovery({ kind: "something_new" } as unknown as DiscoveryOutcome),
    ).toThrow(/unrecognized_outcome/);
  });
});
