/**
 * DOD-M15-BOOTSTRAP-AUTH-1 — a POISONED bootstrap coordinate does not strand the client.
 *
 * ─── The claim this file exists to settle ──────────────────────────────────────────────────────
 *
 * `/bootstrap` is a **plaintext HTTP endpoint on port 9090**, so anyone on-path can answer it with a
 * coordinate of their choosing. The DoD line scoped that and concluded it is **not launch-blocking**,
 * on a chain of four points — the roster cannot be changed, a rogue cannot be impersonated, replay is
 * bounded to ±5 minutes, and the only residual is denial of ONE node because the signed manifest
 * names N of them to fall back to.
 *
 * **Point four was an argument, not a measurement, and the whole "not blocking" call rests on it.**
 * The scoping said so in as many words: *"what I could NOT prove: that a client meeting a poisoned
 * coordinate actually FAILS OVER to another roster node rather than stalling on the refusal."*
 *
 * ─── What the answer turned out to be, and it is stronger than expected ────────────────────────
 *
 * **The client never dials the rogue at all.** `createRosterAwareEndpointResolver` checks the
 * primary's peer id against DECLARED manifest membership *before* returning it, so a coordinate
 * carrying an attacker's peer id is refused at RESOLUTION time — one step earlier than step-6
 * identity auth, which is where the scoping assumed the defence lived.
 *
 * That guard is not new and it is not hypothetical: the code's own comment records the incident that
 * produced it — *"the compiled-in default URL after a consortium move resolved forever while every
 * connection died at step-6 identity auth with `key_not_in_manifest`. Reachability was never the
 * right test."*
 *
 * ─── ⚠️ WHAT THIS FILE ADDS, CORRECTED AFTER REVIEW ───────────────────────────────────────────
 *
 * **I first wrote that this guard "HAD NO TEST". That was false, and the way I got it wrong is the
 * point.** I grepped the EVENT NAME (`not_in_consortium`), found nothing, and concluded the guard
 * was uncovered. `directory-bootstrap.test.ts:313` has had four tests on it since M12 — including
 * one that is this file's test 1 minus the log assertion, and one that is this file's test 3. **An
 * empty grep is a hypothesis, not proof of absence**, and I applied the deadness-by-grep shape to
 * tests instead of to code.
 *
 * **What is genuinely new here:** test 2 (the all-poisoned → `null` case, which has no analogue),
 * test 4 (the address residual, asserted as a bound), and one assertion each in tests 1 and 3 — that
 * the swap is REPORTED, and that the healthy path reports nothing.
 *
 * ─── ⚠️ THE PRECONDITION, WHICH IS NOT UNIVERSAL ──────────────────────────────────────────────
 *
 * All of this holds on the **bundled-manifest posture**: `CELLO_DIRECTORY_URL` unset, or byte-equal
 * to a bundled endpoint. On any other URL `buildManifestDeps` returns `{}` — no manifest provider,
 * so `getManifestPeerIds` is absent, **the membership check is skipped AND step-6 identity auth is
 * off**, and a poisoned coordinate is completely unmitigated. The daemon says so at warn
 * (`daemon.manifest.bundled.skipped`). A DNS name pointing at the same machine is enough to land
 * there, which is `DOD-M15-STEP6-REPLAY-1`'s byte-match bullet.
 */

import { describe, it, expect } from "vitest";
import {
  createRosterAwareEndpointResolver,
  type ConsortiumEndpoint,
} from "../directory-bootstrap.js";
import type { DirectoryEndpoint } from "../signaling-connect.js";
import type { Logger } from "../types.js";

/** A real consortium node, named in the signed manifest. */
const HONEST_A = "12D3KooWHonestNodeAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HONEST_B = "12D3KooWHonestNodeBBBBBBBBBBBBBBBBBBBBBBBBBBB";
/** The attacker's node. Its peer id is NOT in the manifest, because the manifest is signed. */
const ROGUE = "12D3KooWRogueNodeXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

const addr = (p: string) => `/dns4/node.example/tcp/443/wss/p2p/${p}`;

function captureLogger(events: Array<{ level: string; event: string }>): Logger {
  const rec = (level: string) => (event: string) => { events.push({ level, event }); };
  return { debug: rec("debug"), info: rec("info"), warn: rec("warn"), error: rec("error") };
}

/**
 * ⚠️ Declared as real `ConsortiumEndpoint`s with no cast — review F4. `pubkey` is REQUIRED, and the
 * first version cast past that with `as ConsortiumEndpoint`. This file is in the typecheck allowlist
 * precisely so "the mutants are typecheck failures now" is true, and the roster is the one object
 * the resolver actually reads — casting it was the single place that claim did not hold.
 */
const ROSTER: ConsortiumEndpoint[] = [
  { nodeId: "gcp-use1", pubkey: "a".repeat(64), peerId: HONEST_A, multiaddr: addr(HONEST_A) },
  { nodeId: "gcp-euw1", pubkey: "b".repeat(64), peerId: HONEST_B, multiaddr: addr(HONEST_B) },
];

/** Members as the SIGNED manifest declares them. The rogue is absent by construction. */
const MANIFEST_MEMBERS = new Set([HONEST_A, HONEST_B]);

describe("DOD-M15-BOOTSTRAP-AUTH-1 — a poisoned /bootstrap coordinate", () => {
  it("★★★ is REFUSED AT RESOLUTION and the client fails over — it never dials the rogue", async () => {
    /**
     * ⚠️ THE ASSERTION THE LAUNCH CALL RESTS ON. An on-path attacker answers the plaintext
     * `/bootstrap` with their own coordinate. If the resolver handed it back, the client would dial
     * an attacker-chosen machine and depend entirely on step-6 identity auth to refuse it — and on
     * step 6 being configured at all.
     *
     * It does not get that far: the peer id is compared against DECLARED manifest membership, which
     * is LOCAL and signed, so the rogue is discarded and a real consortium node is returned instead.
     *
     * **Revert test:** delete the `members.has(primary.peerId)` block in
     * `createRosterAwareEndpointResolver` and this goes red — the rogue is returned as the endpoint
     * to dial.
     */
    const events: Array<{ level: string; event: string }> = [];
    const resolver = createRosterAwareEndpointResolver({
      // The poisoned answer: resolves perfectly, and is not who it claims to be.
      primaryResolver: async (): Promise<DirectoryEndpoint | null> =>
        ({ peerId: ROGUE, multiaddr: addr(ROGUE) }),
      getConsortiumRoster: async () => ROSTER,
      getManifestPeerIds: () => MANIFEST_MEMBERS,
      logger: captureLogger(events),
      shuffle: (xs) => xs, // deterministic: take the first survivor
    });

    const chosen = await resolver();

    expect(chosen, "the resolver must return SOMETHING — refusing to resolve at all would be the stall").not.toBeNull();
    expect(
      chosen?.peerId,
      "a coordinate whose peer id is not in the SIGNED manifest must never be handed back as the " +
        "node to dial — that is the whole poisoned-bootstrap case, and it is caught before any dial",
    ).not.toBe(ROGUE);
    expect(
      MANIFEST_MEMBERS.has(chosen!.peerId),
      "and what IS returned must be a declared consortium member, not merely 'not the rogue'",
    ).toBe(true);
    expect(
      events.map((e) => e.event),
      "the swap must be visible — an operator whose bootstrap is being poisoned should be able to " +
        "see it named rather than infer it from a directory that keeps changing",
    ).toContain("directory.bootstrap.primary.not_in_consortium");
  });

  it("★★★ with the whole consortium poisoned it returns NULL rather than a directory it knows will reject it", async () => {
    /**
     * The all-nodes-poisoned case. Returning the rogue "because there is nothing else" would be the
     * silent-fallback shape this milestone exists to remove: a caller handed an endpoint it will
     * dial and be refused by, with nothing saying why. Null makes the caller retry, which is the
     * honest answer — and the code says so at the site: *"return null so the caller retries rather
     * than hand back a directory we KNOW will reject us."*
     */
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver: async () => ({ peerId: ROGUE, multiaddr: addr(ROGUE) }),
      getConsortiumRoster: async () => [], // nothing honest answered either
      getManifestPeerIds: () => MANIFEST_MEMBERS,
      logger: captureLogger([]),
    });

    expect(
      await resolver(),
      "with no reachable member, hand back NOTHING rather than a node we already know will refuse us",
    ).toBeNull();
  });

  it("★★ an HONEST primary is returned untouched — the guard must not cost the normal case", async () => {
    /**
     * The regression half, and it is the one that would hurt: this guard sits on every signaling
     * connect. If it were wrong in this direction it would fail over constantly, spreading every
     * client off its home node for no reason and turning a healthy fleet into a reconnect storm.
     */
    const events: Array<{ level: string; event: string }> = [];
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver: async () => ({ peerId: HONEST_A, multiaddr: addr(HONEST_A) }),
      getConsortiumRoster: async () => { throw new Error("the healthy path must not probe the roster"); },
      getManifestPeerIds: () => MANIFEST_MEMBERS,
      logger: captureLogger(events),
    });

    expect((await resolver())?.peerId, "a member primary is returned as-is").toBe(HONEST_A);
    expect(
      events.map((e) => e.event),
      "and nothing is reported — a warning on the healthy path is how a real one gets ignored",
    ).not.toContain("directory.bootstrap.primary.not_in_consortium");
  });

  it("★★★ THE RESIDUAL, ASSERTED SO IT IS A KNOWN BOUND: a rogue ADDRESS under a real peer id passes", async () => {
    /**
     * ⚠️ THIS TEST ASSERTS A LIMITATION, NOT A PROTECTION — deliberately, because the alternative is
     * that someone later reads the three tests above and concludes the poisoned-bootstrap case is
     * fully closed.
     *
     * The guard checks the peer ID against manifest membership. It does **not** check the ADDRESS.
     * So an attacker who answers `/bootstrap` with a REAL node's peer id and their OWN multiaddr
     * gets past it, and the client dials the attacker's machine.
     *
     * **What stops it there:** libp2p's Noise handshake authenticates the remote peer id, and the
     * attacker does not hold that node's private key, so the connection cannot be established. The
     * cost is DENIAL, not impersonation.
     *
     * ⚠️ **AND REVIEW MEASURED THE DENIAL WIDER THAN I FIRST WROTE IT.** I called it "denial of that
     * node". It is denial of **this daemon's directory connection, with no failover path**: branch 2
     * returns the primary every call, never sets `stuckToFallback`, and never probes the roster — and
     * `maxReconnectAttempts` is `MAX_SAFE_INTEGER`, so the manager reconnect-loops forever rather
     * than ever reporting `lost`. A restart re-picks a bundled endpoint whose plaintext `/bootstrap`
     * the same on-path attacker answers again. **That is a STALL, which is the outcome this line
     * pre-registered as "failover does NOT hold" — see `DOD-M15-BOOTSTRAP-ADDR-1`.**
     *
     * **And the resolver cannot learn better on its own.** Its own doc says so: *"stickiness here is
     * by ROSTER REACHABILITY, not by observed connect success — the resolver is not told whether a
     * dial/auth against the returned endpoint actually succeeded."* Closing it means feeding connect
     * outcomes back into selection, which is a different unit.
     */
    const resolver = createRosterAwareEndpointResolver({
      // Real peer id, attacker's address.
      primaryResolver: async () => ({ peerId: HONEST_A, multiaddr: "/dns4/attacker.example/tcp/443/wss/p2p/" + HONEST_A }),
      getConsortiumRoster: async () => ROSTER,
      getManifestPeerIds: () => MANIFEST_MEMBERS,
      logger: captureLogger([]),
    });

    const chosen = await resolver();
    expect(
      chosen?.multiaddr,
      "RECORDED AS A LIMIT: membership is checked on the peer id, never on the address, so a rogue " +
        "address under a real peer id is returned. Noise refuses the connection, so this is denial " +
        "of that node rather than impersonation — but the resolver will keep choosing it.",
    ).toContain("attacker.example");
  });
});
