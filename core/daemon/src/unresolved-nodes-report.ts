/**
 * The directory-reachability block a status read carries — and the rule for when it says nothing.
 *
 * Silence is reserved for ONE state: a reading taken recently enough to speak for the present, which
 * found nothing wrong. Every other combination emits, including an EMPTY node list, because an empty
 * list is not proof of health — it also means nothing has looked, or looked too long ago to say. So
 * the presence of this block does not mean nodes are failing; `measurement` is the field to read
 * first, and only then the list.
 *
 * Two consumers, which is why it is a module rather than a closure: the MCP `cello_status` handler
 * and the daemon-wide `getStatus()` the CLI renders. That second one is the surface that was silent
 * on 2026-07-31 while every session failed.
 */
import { classifyRosterReading, describeRosterFreshness } from "./roster-freshness.js";
import type { RosterFreshness } from "./roster-freshness.js";
import type { NodeResolveFailure } from "./directory-bootstrap.js";

export interface UnresolvedNodesDeps {
  getUnresolvedNodes: () => NodeResolveFailure[];
  getUnresolvedSweptAt: () => string | null;
  lastRosterSweepError: () => RosterFreshness["last_sweep_error"] | undefined;
  manifestConfigured: boolean;
}

export function createUnresolvedNodesReport(deps: UnresolvedNodesDeps) {
  const { getUnresolvedNodes, getUnresolvedSweptAt, lastRosterSweepError, manifestConfigured } = deps;

  // ─── MCP-001: cello_status (per-connection perspective) ───
  /**
   * The directory-reachability block for `cello_status`.
   *
   * `undefined` — i.e. silence — is reserved for ONE state: a reading taken recently enough to
   * speak for the present, which found nothing wrong. Every other combination emits, including an
   * EMPTY node list, because an empty list is not proof of health: it also means nothing has
   * looked, or looked too long ago to say. `DOD-M15-STALEROSTER-1`.
   *
   * So presence of this block does NOT mean nodes are failing. Read `measurement` first —
   * `current` | `stale` | `never` | `not_configured` — and only then the node list.
   */
  function unresolvedNodesForStatus(): { directory_endpoints_unresolved: unknown } | undefined {
    const failures = getUnresolvedNodes();
    /**
     * DOD-M15-STALEROSTER-1 — the block is now gated on the AGE of the reading, not just on whether
     * it found anything.
     *
     * `if (failures.length === 0) return undefined` made two different states render identically:
     * "all three nodes answered a moment ago" and "nothing has ever looked". The second is
     * reachable — `verifyStartupManifest` returns without sweeping when the consortium manifest is
     * missing, not yet valid, EXPIRED, or rolled back — so a daemon with an expired manifest
     * reported no directory trouble at all.
     *
     * Silence is therefore reserved for the one case that has earned it: a RECENT reading that
     * found nothing wrong. Every other case says why it cannot make that claim.
     */
    const freshness = describeRosterFreshness(classifyRosterReading(getUnresolvedSweptAt(), Date.now()), {
      // REVIEW F2: "no manifest configured" is DESIGNED (local dev, the e2e harness, or a
      // CELLO_DIRECTORY_URL that is not byte-equal to a bundled endpoint) and must not be dressed
      // as an alarm — it would fire on every local run. It still EMITS, because the line forbids
      // hiding the field; what differs is what the operator is told.
      manifestConfigured,
      ...(lastRosterSweepError() ? { lastSweepError: lastRosterSweepError() } : {}),
    });
    if (failures.length === 0 && freshness.measurement === "current") return undefined;
    return {
      directory_endpoints_unresolved: {
        // WHEN this was measured, and whether that is recent enough to mean anything. Without it the
        // block asserts the PRESENT, and a transient blip reads as an ongoing outage: on 2026-08-09
        // all three endpoints failed with ENETUNREACH for under a minute — a network transition on
        // the operator's machine — and the block went on reporting them unreachable long after they
        // answered again. True when taken, false when read.
        ...freshness,
        // DOD-M15-BOOTSTRAP-1: `attempts` distinguishes a node that answered definitively (one
        // probe — a 404, a bad payload, its configuration) from one that never answered at all
        // (every probe spent — the path to it). Those call for opposite responses, and without the
        // count they rendered identically here.
        nodes: failures.map((f) => ({ node: f.nodeId, endpoint: f.endpoint, reason: f.reason, detail: f.detail, attempts: f.attempts })),
        guidance: failures.length === 0
          // The block is present with an EMPTY node list, which before DOD-M15-STALEROSTER-1 could
          // not happen. Saying "could not resolve these endpoints" here would be a flat lie — there
          // are no endpoints listed and the point is that nothing was measured. The empty list is
          // the ABSENCE of a reading, not a clean bill of health, and freshness_guidance above says
          // which of the two it is.
          ? "This block is present with NO nodes listed, which does not mean the nodes are healthy — " +
            "it means this reading cannot support that claim. See freshness_guidance above for " +
            "whether the daemon has never measured, or measured too long ago to speak for the " +
            "present. Directory reachability is what threshold ceremonies depend on, so an " +
            "unmeasured roster is an unknown, not an all-clear."
          : "AS OF checked_at (this is a point-in-time reading, not necessarily now), this daemon could not "
          + "resolve these directory endpoints, so the consortium roster was short and " +
          "threshold ceremonies will fail — sessions surface that as home_node_reports_no_receiver, " +
          "home_node_not_in_reachable_roster, directory_named_no_home, directory_below_threshold or " +
          "ceremony_exhausted, none of which name the real cause on their own (DOD-M15-ERRSTRING-1 " +
          "renamed the first three; they now append this shortfall to their own guidance). " +
          "Agents can still show 'online': signaling dials multiaddrs and does not need DNS. " +
          "If reason is dns_error after a directory restart or wake, the resolver is holding a cached " +
          "negative answer — flush it (macOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder). " +
          "Verify with node -e 'require(\"dns\").lookup(host,console.log)', NOT dig: dig bypasses the " +
          "cache this daemon is stuck behind, so it reports success while the daemon still fails. "
          + "attempts:1 means the node ANSWERED and the answer was unusable — look at that node. "
          + "attempts:2+ means it never answered — look at the path to it.",
      },
    };
  }

  return { unresolvedNodesForStatus };
}
