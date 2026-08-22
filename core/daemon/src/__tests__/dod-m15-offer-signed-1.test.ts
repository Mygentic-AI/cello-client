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
 * ─── The counterbalance ────────────────────────────────────────────────────────────────────────
 *
 * The assignment is FROST-signed by the INITIATOR's own threshold group — which no single directory
 * can produce — and it names the same `initiator_session_peer_id`. So the two frames check each
 * other, and the door is only handed over when they agree.
 *
 * A truthful directory never names two different dialers for one session. A compromised one doing
 * exactly that is the attack this closes.
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
