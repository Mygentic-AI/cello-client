/**
 * The mailbox pull dialled a relay at an address the fleet closed days earlier.
 *
 * Live 2026-09-15: three messages parked for Mac_Coder_1 at the us-east1 relay were never collected.
 * Every pull dialled `/ip4/34.139.119.165/tcp/4001/ws` — the relay's pre-TLS address, saved on a
 * session row from before the cutover — while the directory had just handed this daemon the current
 * `/dns4/relay-use1…/tcp/443/tls/ws` address for the same relay peer. 1,904 failed opens since
 * 2026-09-11. The pull only ever worked when a live relay connection already existed to reuse,
 * which after a laptop sleep it never does.
 *
 * The reservation path already put the directory's pool first. The mailbox pull read the saved
 * rows alone. Both now go through one merge, so they cannot disagree about where a relay is.
 */
import { describe, it, expect } from "vitest";
import { mergeRelayEndpoints } from "../relay-endpoints.js";

const RELAY = "12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const OTHER = "12D3KooWFpvG5ksTBoiMCfyy3n126AtpFNYGXB14R2335DAf1BYt";
const DEAD = `/ip4/34.139.119.165/tcp/4001/ws/p2p/${RELAY}`;
const CURRENT = `/dns4/relay-use1.cello.mygentic.ai/tcp/443/tls/ws/p2p/${RELAY}`;

describe("relay endpoints: the directory's current pool wins over saved session rows", () => {
  it("★★★ a relay the directory lists is dialled at the directory's address, never a saved one", () => {
    const merged = mergeRelayEndpoints(
      [{ relayPeerId: RELAY, relayAddrs: [CURRENT] }],
      [{ relayPeerId: RELAY, relayAddrs: [DEAD] }],
    );
    expect(
      merged,
      "the saved row is from before the TLS cutover; dialling it is how three parked messages sat " +
        "uncollected after a laptop sleep",
    ).toEqual([{ relayPeerId: RELAY, relayAddrs: [CURRENT] }]);
  });

  it("a relay only past sessions know about is still offered, so a directory that sent no pool strands nothing", () => {
    const merged = mergeRelayEndpoints(
      [{ relayPeerId: RELAY, relayAddrs: [CURRENT] }],
      [{ relayPeerId: OTHER, relayAddrs: ["/dns4/relay-euw1.cello.mygentic.ai/tcp/443/tls/ws"] }],
    );
    expect(merged.map((e) => e.relayPeerId)).toEqual([RELAY, OTHER]);
  });

  it("with no directory pool at all, the saved rows are used as they are", () => {
    expect(mergeRelayEndpoints(undefined, [{ relayPeerId: RELAY, relayAddrs: [DEAD] }])).toEqual([
      { relayPeerId: RELAY, relayAddrs: [DEAD] },
    ]);
  });
});
