/**
 * M12 `DOD-INV-NODEID` (client half) — a DKG whose participants share a FROST identifier is refused,
 * and the refusal names the cause.
 *
 * ─── Why this exists at all, given round 2 already throws ───────────────────────────────────────
 * `@noble/curves` `DKG.round2` rejects colliding identifiers, so this is not the detector — it is the
 * DIAGNOSIS. That throw arrives from inside a crypto library and then has to survive every catch
 * between there and the operator; until recently one of those was a bare `catch {}` that discarded it
 * entirely, so a duplicate `NODE_ID` across two directory boxes reached the operator as the bare word
 * `dkg_failed`, with guidance telling them to check their pre-auth token.
 *
 * The collision is also invisible upstream: every other check in the consortium compares manifest
 * nodeId STRINGS, while a node's identifier is derived from its OWN deployed `NODE_ID`. Two entries
 * with distinct nodeIds, deployed on boxes sharing one `NODE_ID`, pass all of them.
 *
 * ─── What this file does and does not prove ─────────────────────────────────────────────────────
 * It proves the LOGIC. It does not prove the PLACEMENT — that the check runs before round 2 and before
 * the share-routing map keyed by target identifier, which would otherwise deliver one node's share to
 * another. Reaching that call site needs a live multi-node DKG (J-TOFN-DKG), so placement is a review
 * property, stated here rather than left implied.
 */

import { describe, it, expect } from "vitest";
import { assertDistinctFrostIdentifiers } from "../network-directory-node.js";

/** Index 0 is the client; 1..n are directory nodes — the same convention the call site uses. */
const describeParticipant = (i: number): string => (i === 0 ? "the client" : `directory node n${i}`);

describe("DOD-INV-NODEID: a DKG needs DISTINCT FROST identifiers", () => {
  it("accepts a well-formed participant set", () => {
    expect(() =>
      assertDistinctFrostIdentifiers(["aa".repeat(16), "bb".repeat(16), "cc".repeat(16)], describeParticipant),
    ).not.toThrow();
  });

  it("refuses two DIRECTORY nodes sharing an identifier, and names both", () => {
    // The deployment error this is built for: two boxes, distinct manifest entries, one NODE_ID.
    const dupe = "dd".repeat(16);
    let msg = "";
    try {
      assertDistinctFrostIdentifiers([`aa`.repeat(16), dupe, dupe], describeParticipant);
    } catch (e) {
      msg = (e as Error).message;
    }
    // Both participants named — "a duplicate exists" is not actionable; "n1 and n2" is.
    expect(msg).toContain("directory node n1");
    expect(msg).toContain("directory node n2");
    // And the likely cause, because the operator's next question is always "so what do I change?".
    expect(msg).toMatch(/same NODE_ID/);
    // The identifier is truncated, not dumped whole.
    expect(msg).toContain(dupe.slice(0, 24));
  });

  it("refuses a CLIENT↔node collision and says 'the client', not a node id", () => {
    // The other reachable shape: the agent's own identifier colliding with a directory's. Naming a
    // directory node here would send the operator to the wrong machine entirely.
    const dupe = "ee".repeat(16);
    let msg = "";
    try {
      assertDistinctFrostIdentifiers([dupe, dupe], describeParticipant);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain("the client");
    expect(msg).toContain("directory node n1");
  });

  it("reports the FIRST collision when several exist", () => {
    // Deterministic output beats a complete one: the operator fixes one deployment at a time, and a
    // message listing every pair is harder to act on than the earliest offender.
    const a = "11".repeat(16);
    const b = "22".repeat(16);
    let msg = "";
    try {
      assertDistinctFrostIdentifiers([a, b, a, b], describeParticipant);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain("the client"); // index 0 vs index 2 — before the b/b pair
    expect(msg).toContain("directory node n2");
  });

  it("does not false-positive on identifiers sharing a prefix", () => {
    // They are compared whole, not by the truncated form used in the message — otherwise two distinct
    // participants whose identifiers agree in the first 24 chars would be refused, taking down a
    // healthy consortium. That failure would be far worse than the one this guard prevents.
    const base = "ab".repeat(16);
    const near = `${base.slice(0, 24)}${"f".repeat(base.length - 24)}`;
    expect(near.slice(0, 24)).toBe(base.slice(0, 24));
    expect(near).not.toBe(base);
    expect(() => assertDistinctFrostIdentifiers([base, near], describeParticipant)).not.toThrow();
  });

  it("accepts an empty or single-participant set", () => {
    expect(() => assertDistinctFrostIdentifiers([], describeParticipant)).not.toThrow();
    expect(() => assertDistinctFrostIdentifiers(["aa".repeat(16)], describeParticipant)).not.toThrow();
  });
});
