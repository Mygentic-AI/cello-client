// Cross-node negotiation — the pure online-result classifier (Story B, item 2). Exhaustive branch +
// error-code mapping, no daemon harness. Transport / directory-fault / timeout handling and the async
// retry loop are exercised live by Story C.

import { describe, it, expect } from "vitest";
import { classifyOnlineResult } from "../cross-node-negotiation.js";

const HOME = "aws-us-east-1";

describe("classifyOnlineResult", () => {
  it("state unknown_agent ⇒ unknown_agent (distinct, no retry)", () => {
    expect(classifyOnlineResult("unknown_agent", [], HOME)).toEqual({ kind: "unknown_agent" });
  });

  it("state offline ⇒ offline (no retry storm)", () => {
    expect(classifyOnlineResult("offline", [], HOME)).toEqual({ kind: "offline" });
  });

  it("online on the SAME node ⇒ same_node (home path, zero visiting connections)", () => {
    expect(classifyOnlineResult("online", [HOME], HOME)).toEqual({ kind: "same_node" });
  });

  it("online on a DIFFERENT node ⇒ cross_node with that owning node", () => {
    expect(classifyOnlineResult("online", ["aws-eu-central-1"], HOME)).toEqual({
      kind: "cross_node",
      owningNodeId: "aws-eu-central-1",
    });
  });

  it("online but no owning node named ⇒ retry (never dials a fabricated node)", () => {
    expect(classifyOnlineResult("online", [], HOME)).toEqual({ kind: "retry" });
  });

  it("online but home node id unknown (no step-6) ⇒ cross_node (validate via manifest before dialing)", () => {
    // Can't prove co-location without our own node id, so take the manifest-validated cross-node path
    // even when the owning node happens to equal what would be home.
    expect(classifyOnlineResult("online", [HOME], null)).toEqual({ kind: "cross_node", owningNodeId: HOME });
  });
});
