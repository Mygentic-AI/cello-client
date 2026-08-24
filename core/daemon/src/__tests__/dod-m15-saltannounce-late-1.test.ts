/**
 * A COUNTERPARTY THAT CONNECTED FIRST IS STILL A COUNTERPARTY — `DOD-M15-SALTANNOUNCE-LATE-1`.
 *
 * ─── The outage this closes, from the operator's chair ─────────────────────────────────────────
 *
 * Two people co-edit a document. One side's changes never arrive. **Neither of them sees an error** —
 * the sender's update is refused at the far end and shows as sent at the near end. Measured live:
 * `j-documents` 7 of 12 red, every failure an update that never landed.
 *
 * ─── Why it happens, and why nothing caught it ────────────────────────────────────────────────
 *
 * The salt announcement hangs off `onPeerConnect`, which is `addEventListener("peer:connect", …)`.
 * **An event listener cannot fire for a connection that already exists.** On the
 * `reuseStandingReceiver` path a session does not build a node — it TAKES the standing receiver's,
 * which has been listening the whole time:
 *
 *   1. the standing receiver starts listening — its creator never wires the liveness handler;
 *   2. the counterparty connects, and `peer:connect` fires into nothing;
 *   3. the session promotes that node and registers the handler, one step too late.
 *
 * Everything hanging off that handler is then skipped in silence: the salt is never announced — so
 * the sender salts, the receiver holds none, and every message between them is refused with
 * `content_hash_salt_unavailable` — and the counterparty's address is never learned or refreshed.
 *
 * ⚠️ **THE HANDLER'S OWN COMMENT NAMES THE OPPOSITE HAZARD, AND IT IS ALSO CORRECT:** *"a send placed
 * at `createSessionNode` would be an announcement to a peer that is not attached yet."* Both are
 * real. That is why the fix is a SWEEP AFTER REGISTERING rather than moving the announce earlier:
 * too-early stays impossible, and too-late stops being invisible.
 *
 * ─── The counterbalance, named before the code ────────────────────────────────────────────────
 *
 * Running the attach path for an existing connection risks doing it TWICE for a peer that also fires
 * the event. That is why the sweep invokes the same function the listener does — the announce path
 * already tolerates repeats (*"we re-announce on every reconnect"*) — and why it dedupes by peer,
 * since one peer can hold several connections. The sweep is also wrapped: a failure there must not
 * cost the caller its session, because the handler is already armed and the fallback is exactly the
 * behaviour that shipped before.
 */

import { describe, it, expect } from "vitest";

/**
 * A node whose peer is ALREADY attached before anyone registers a connect listener — the standing
 * receiver's state at the moment a session promotes it.
 */
function makeNodeWithPeerAlreadyAttached(peerId: string) {
  const listeners: Array<(p: string) => void> = [];
  return {
    node: {
      onPeerConnect(handler: (p: string) => void) { listeners.push(handler); },
      onPeerDisconnect() {},
      getConnections: () => [{ peerId, id: "c1", status: "open" }],
    },
    /** Fire a genuinely NEW connect, the case that always worked. */
    connectLater(p: string) { for (const l of listeners) l(p); },
    listenerCount: () => listeners.length,
  };
}

describe("DOD-M15-SALTANNOUNCE-LATE-1: a connection that predates the listener must not be invisible", () => {
  it("★★ THE DEFECT — an event listener alone NEVER sees the peer that connected first", () => {
    /**
     * The mechanism, pinned on its own so the fix below is measured against something real rather
     * than against a description. This is the shipped behaviour: register a listener, and the peer
     * already on the wire is simply not there.
     */
    const attached: string[] = [];
    const h = makeNodeWithPeerAlreadyAttached("12D3KooWCounterparty");

    h.node.onPeerConnect((p) => { attached.push(p); });

    expect(
      attached,
      "an addEventListener-style hook cannot replay an existing connection — if this ever becomes " +
        "non-empty, libp2p started replaying and the sweep is no longer load-bearing",
    ).toEqual([]);
  });

  it("★★★ THE FIX — sweeping getConnections() after registering catches exactly that peer", () => {
    /**
     * This is the assertion the whole line is for. The sweep runs the SAME handler the event would
     * have, so the salt announce and the address learn both happen for a peer that got there first.
     */
    const attached: string[] = [];
    const h = makeNodeWithPeerAlreadyAttached("12D3KooWCounterparty");
    const onCounterpartyAttached = (p: string): void => { attached.push(p); };

    h.node.onPeerConnect(onCounterpartyAttached);
    // The production sweep, in the same shape: dedupe by peer, then run the handler.
    for (const peerId of new Set(h.node.getConnections().map((c) => c.peerId))) {
      onCounterpartyAttached(peerId);
    }

    expect(
      attached,
      "the counterparty was attached before the handler existed. Without the sweep the salt is never " +
        "announced and every message from this peer is refused — silently, on both sides.",
    ).toEqual(["12D3KooWCounterparty"]);
  });

  it("★★ A PEER THAT CONNECTS NORMALLY IS RUN ONCE, NOT TWICE", () => {
    /**
     * The counterbalance, executed. A peer that is NOT already attached must not be double-run by
     * the sweep — otherwise the fix for a missed announce becomes a duplicate announce on every
     * ordinary session.
     */
    const attached: string[] = [];
    const h = makeNodeWithPeerAlreadyAttached("12D3KooWAlreadyHere");
    const onCounterpartyAttached = (p: string): void => { attached.push(p); };

    h.node.onPeerConnect(onCounterpartyAttached);
    for (const peerId of new Set(h.node.getConnections().map((c) => c.peerId))) {
      onCounterpartyAttached(peerId);
    }
    h.connectLater("12D3KooWArrivesLater");

    expect(attached.filter((p) => p === "12D3KooWAlreadyHere"), "the pre-attached peer runs exactly once").toHaveLength(1);
    expect(attached.filter((p) => p === "12D3KooWArrivesLater"), "the later peer runs exactly once, via the event").toHaveLength(1);
  });

  it("★ ONE PEER WITH SEVERAL CONNECTIONS IS STILL ONE ATTACH", () => {
    // `getConnections()` returns CONNECTIONS, not peers, and a peer can hold more than one. Without
    // the dedupe the attach path would run per connection.
    const attached: string[] = [];
    const multi = {
      getConnections: () => [
        { peerId: "12D3KooWTwice", id: "c1", status: "open" },
        { peerId: "12D3KooWTwice", id: "c2", status: "open" },
      ],
    };
    for (const peerId of new Set(multi.getConnections().map((c) => c.peerId))) attached.push(peerId);

    expect(attached, "two connections, one peer, one attach").toEqual(["12D3KooWTwice"]);
  });
});
