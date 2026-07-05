// Cross-node topology (Story B, item 1 client mirror) — parse the directory's discovery replies.
// Pure-unit: mirrors parseSessionAssignment / sessionRequestErrorReason discipline in
// session-assignment-parser.ts. Distinct cause → distinct value; malformed → null; unknown → safe.

import { describe, it, expect } from "vitest";
import { parseDiscoveryLookupResult, discoveryLookupErrorReason } from "../session-assignment-parser.js";

describe("parseDiscoveryLookupResult", () => {
  it("parses an online result with an owning node", () => {
    const r = parseDiscoveryLookupResult({ type: "discovery_lookup_result", state: "online", owning_node_ids: ["aws-eu-central-1"] });
    expect(r).toEqual({ state: "online", owningNodeIds: ["aws-eu-central-1"] });
  });

  it("parses an offline result (empty owning node list)", () => {
    const r = parseDiscoveryLookupResult({ type: "discovery_lookup_result", state: "offline", owning_node_ids: [] });
    expect(r).toEqual({ state: "offline", owningNodeIds: [] });
  });

  it("parses unknown_agent", () => {
    const r = parseDiscoveryLookupResult({ type: "discovery_lookup_result", state: "unknown_agent", owning_node_ids: [] });
    expect(r).toEqual({ state: "unknown_agent", owningNodeIds: [] });
  });

  it("tolerates a missing owning_node_ids (defaults to empty)", () => {
    const r = parseDiscoveryLookupResult({ type: "discovery_lookup_result", state: "offline" });
    expect(r).toEqual({ state: "offline", owningNodeIds: [] });
  });

  it("rejects an unknown state (returns null, never a fabricated state)", () => {
    expect(parseDiscoveryLookupResult({ type: "discovery_lookup_result", state: "maybe" })).toBeNull();
  });

  it("rejects a non-string entry in owning_node_ids", () => {
    expect(parseDiscoveryLookupResult({ type: "discovery_lookup_result", state: "online", owning_node_ids: [123] })).toEqual(
      { state: "online", owningNodeIds: [] },
    );
  });
});

describe("discoveryLookupErrorReason", () => {
  it("passes through the known lookup_failed reason", () => {
    expect(discoveryLookupErrorReason({ type: "discovery_lookup_error", reason: "lookup_failed" })).toBe("lookup_failed");
  });

  it("maps an unknown reason to lookup_failed (retryable, never a fabricated authoritative state)", () => {
    expect(discoveryLookupErrorReason({ type: "discovery_lookup_error", reason: "weird" })).toBe("lookup_failed");
  });
});
