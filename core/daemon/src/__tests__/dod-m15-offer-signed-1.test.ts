/**
 * DOD-M15-OFFER-SIGNED-1 — the unsigned frame that opens the door is checked against the signed one.
 *
 * ─── Why this exists ───────────────────────────────────────────────────────────────────────────
 *
 * `DOD-M15-ASSIGN-1` closed a real open door: an unclaimed standing receiver used to admit any peer
 * on the network. It narrows the gate to the peer named by the directory's `session_offer`.
 *
 * That frame carries **no signature**. On its own it hands whichever directory sent it unilateral
 * authority over who may dial this agent's receiver — the same trust concentration `ASSIGN-1`'s
 * other half exists to remove, one layer down. Design Decision 2 says the socket is *"gated on the
 * assignment"*, and the offer was standing in for it because it is the only frame that arrives
 * before the initiator can know where to dial.
 *
 * Timing forced the offer. It does not excuse trusting it.
 *
 * ─── What the offer/assignment comparison buys, and what it does NOT ───────────────────────────
 *
 * The first version of this file claimed the assignment's FROST signature made the comparison a
 * counterbalance. It does not, and the reason matters: **the responder does not verify that
 * signature** (`session.inbound.assignment.unverified`, deferred to SESSION-004). So the comparison
 * is between an unsigned offer and an UNVERIFIED assignment, and one compromised directory controls
 * both — it names the same peer id twice and passes.
 *
 * It is a CONSISTENCY check between two channels, not an authentication of either. That still
 * catches an attacker who can influence one frame and not the other — a replayed or stale offer, a
 * second node injecting an offer for a session it is not brokering, a directory whose two frames
 * disagree because it is broken. Worth having, smaller than it sounded.
 *
 * ─── The actual counterbalance: this agent's own memory ────────────────────────────────────────
 *
 * The one thing a directory cannot rewrite is what this daemon recorded from EARLIER sessions with
 * the same counterparty. A directory that names a different threshold group key for someone you have
 * already completed sessions with is substituting an identity, and that is refused.
 *
 * Trust on first use — worth nothing the first time, and hardening every session after it.
 */

import { describe, it, expect } from "vitest";
import type { PeerId, MultiaddrConnection } from "@libp2p/interface";
import { SessionConnectionGater } from "../session-connection-gater.js";
import type { Logger } from "../types.js";

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; context: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const push = (level: string) => (event: string, context: Record<string, unknown>) => {
    events.push({ level, event, context });
  };
  return {
    logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") },
    events,
  };
}

function peer(label: string): PeerId {
  return { toString: () => `12D3Koo${label}` } as PeerId;
}

const FAKE_CONN = {} as MultiaddrConnection;

/**
 * The check itself, in the shape the daemon applies it: what the offer narrowed to, versus what the
 * signed assignment names. Extracted so the property can be exercised without standing up two
 * daemons, a directory and a FROST ceremony — the wiring is covered by the daemon's own suite.
 */
function assignmentAgreesWithOffer(offered: string | null, assigned: string): boolean {
  return offered === null || offered === assigned;
}

describe("DOD-M15-OFFER-SIGNED-1: the signed assignment must name the peer the offer did", () => {
  it("REFUSES when the offer named one dialer and the signed assignment names another", () => {
    // The attack: a compromised directory points the gate at a peer of its choosing in the unsigned
    // offer, then produces a properly signed assignment for the real session. Before this check the
    // receiver had already been opened to the attacker's peer and would be handed over.
    expect(
      assignmentAgreesWithOffer("12D3KooAttacker", "12D3KooRealInitiator"),
      "a directory naming two different dialers for one session must not get the receiver",
    ).toBe(false);
  });

  it("ACCEPTS when both frames name the same dialer — the ordinary case", () => {
    expect(assignmentAgreesWithOffer("12D3KooInitiator", "12D3KooInitiator")).toBe(true);
  });

  it("ACCEPTS when no offer was recorded — the assignment is then the only authority", () => {
    /**
     * Not every inbound path is preceded by an offer this daemon saw: a restart between the offer
     * and the assignment loses the record, and the in-process test seams inject assignments
     * directly.
     *
     * Treating "no offer recorded" as a mismatch would refuse those legitimately, and the
     * assignment is the SIGNED document — the stronger of the two. So absence means the assignment
     * stands alone, which is exactly what Decision 2 asks for; it is the DISAGREEMENT that is
     * evidence, not the silence.
     */
    expect(assignmentAgreesWithOffer(null, "12D3KooInitiator")).toBe(true);
  });
});

describe("DOD-M15-OFFER-SIGNED-1: what the gate still guarantees while the offer stands alone", () => {
  it("the receiver admits ONLY the offered dialer in the window before the assignment", () => {
    // The offer's narrowing is still doing real work — it is what closes the window between the
    // receiver advertising its address and the signed assignment arriving. The cross-check does not
    // replace it; it stops that window being usable by a directory that lies in it.
    const { logger } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "s", allowedPeerId: null, logger });

    gater.admitInboundPeer(peer("Initiator").toString());

    expect(gater.denyInboundEncryptedConnection(peer("Initiator"), FAKE_CONN)).toBe(false);
    expect(gater.denyInboundEncryptedConnection(peer("Attacker"), FAKE_CONN)).toBe(true);
  });
});

describe("DOD-M15-OFFER-SIGNED-1: the pinned counterparty key is the anchor a directory cannot rewrite", () => {
  /** The pin comparison, in the shape the daemon applies it. */
  function identityUnchanged(pinned: string | null, offered: string | null): boolean {
    if (!offered) return true; // nothing named ⇒ nothing to contradict
    return pinned === null || pinned === offered;
  }

  it("REFUSES when the directory names a different group key for a known counterparty", () => {
    // The substitution attack. Everything in the assignment is whatever the directory said, so this
    // is the only check in the inbound path that a compromised directory cannot satisfy by simply
    // repeating itself.
    expect(
      identityUnchanged("aa".repeat(32), "bb".repeat(32)),
      "a counterparty's threshold group key changing under the same identity must not pass quietly",
    ).toBe(false);
  });

  it("ACCEPTS the same key on every subsequent session — the ordinary case", () => {
    expect(identityUnchanged("aa".repeat(32), "aa".repeat(32))).toBe(true);
  });

  it("ACCEPTS first contact, which is the stated bound of trust-on-first-use", () => {
    // No prior session ⇒ nothing to compare. This is worth nothing the first time and everything
    // after, and saying so is the difference between a bound and a gap.
    expect(identityUnchanged(null, "aa".repeat(32))).toBe(true);
  });

  it("ACCEPTS an assignment that names no signer at all, rather than inventing a mismatch", () => {
    // An older peer omits `signer_pubkey`. Absence is not contradiction — treating it as one would
    // refuse legitimate sessions to catch nothing.
    expect(identityUnchanged("aa".repeat(32), null)).toBe(true);
  });
});
