// Cross-node negotiation — the pure per-attempt decision (Story B, item 2). Exhaustive branch +
// error-code mapping, no daemon harness. The async retry loop / I/O is covered live by Story C.

import { describe, it, expect } from "vitest";
import { classifyDiscoveryOutcome } from "../cross-node-negotiation.js";

const HOME = "aws-us-east-1";

describe("classifyDiscoveryOutcome", () => {
  it("old directory (unsupported) ⇒ fallback to today's home path", () => {
    expect(classifyDiscoveryOutcome({ kind: "unsupported" }, HOME)).toEqual({ kind: "fallback" });
  });

  it("directory DB error ⇒ retry (never an authoritative offline/unknown)", () => {
    expect(classifyDiscoveryOutcome({ kind: "error" }, HOME)).toEqual({ kind: "retry" });
  });

  it("state unknown_agent ⇒ unknown_agent (distinct, no retry)", () => {
    expect(classifyDiscoveryOutcome({ kind: "result", state: "unknown_agent", owningNodeIds: [] }, HOME)).toEqual({ kind: "unknown_agent" });
  });

  it("state offline ⇒ offline (no retry storm)", () => {
    expect(classifyDiscoveryOutcome({ kind: "result", state: "offline", owningNodeIds: [] }, HOME)).toEqual({ kind: "offline" });
  });

  it("online on the SAME node ⇒ same_node (home path, zero visiting connections)", () => {
    expect(classifyDiscoveryOutcome({ kind: "result", state: "online", owningNodeIds: [HOME] }, HOME)).toEqual({ kind: "same_node" });
  });

  it("online on a DIFFERENT node ⇒ cross_node with that owning node", () => {
    expect(classifyDiscoveryOutcome({ kind: "result", state: "online", owningNodeIds: ["aws-eu-central-1"] }, HOME)).toEqual({
      kind: "cross_node",
      owningNodeId: "aws-eu-central-1",
    });
  });

  it("online but no owning node named ⇒ retry (never dials a fabricated node)", () => {
    expect(classifyDiscoveryOutcome({ kind: "result", state: "online", owningNodeIds: [] }, HOME)).toEqual({ kind: "retry" });
  });

  it("online but home node id unknown (no step-6) ⇒ cross_node (validate via manifest before dialing)", () => {
    // Can't prove co-location without our own node id, so take the manifest-validated cross-node path
    // even when the owning node happens to equal what would be home.
    expect(classifyDiscoveryOutcome({ kind: "result", state: "online", owningNodeIds: [HOME] }, null)).toEqual({
      kind: "cross_node",
      owningNodeId: HOME,
    });
  });
});
