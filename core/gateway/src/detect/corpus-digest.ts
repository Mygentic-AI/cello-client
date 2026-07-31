import { createHash } from "node:crypto";
import { injectionPatternIds } from "./injection-patterns.js";
import { secretRuleIds } from "./secrets.js";

/**
 * M10B / DOD-END-SCAN-1 (`M10B-D15`) — a stable digest of the ACTIVE detector corpus.
 *
 * The intake scanner's `scanner_version` is DERIVED from this, never hand-maintained. A hand-bumped
 * constant goes stale the first time someone edits a regex and forgets — and because the directory
 * cannot re-run the scan, that stale value is notarized as evidence of a scan that did not happen,
 * which is the stated reason `DOD-DIR-WRITE-1` made the field signed in the first place.
 *
 * Returns null when either corpus is uncompiled. A digest over "no rules" would be a perfectly
 * stable, perfectly meaningless value that a fail-closed caller could not distinguish from a real
 * one — so the absence is reported as absence (§5a), and the caller refuses.
 *
 * SORTED before hashing, because corpus ORDER is not a property anyone should depend on: reordering
 * the source array changes nothing about which text is caught, and a digest that moved on a reorder
 * would force a spurious `scanner_version` change and read as a rule change to anyone auditing it.
 * What the digest MUST track is the SET of active rules.
 */
export function detectorCorpusDigest(): string | null {
  const patterns = injectionPatternIds();
  const secrets = secretRuleIds();
  if (patterns === null || secrets === null) return null;
  const canonical = JSON.stringify({
    injection: [...patterns].sort(),
    secrets: [...secrets].sort(),
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}
