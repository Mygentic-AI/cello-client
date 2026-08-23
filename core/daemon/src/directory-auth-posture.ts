/**
 * DOD-M15-DIRAUTH-1 — directory authentication cannot be silently skipped.
 *
 * ─── The map, grepped rather than assumed ──────────────────────────────────────────────────────
 *
 *   DECIDED   `manifest-deps.ts` builds a challenge verifier ONLY when the resolved directory URL
 *             byte-matches a bundled endpoint; otherwise it returns `{}` and logs
 *             `daemon.manifest.bundled.skipped` once at startup.
 *   ENFORCED  `signaling-connect.ts` step 6 — `if (verifier) { … }`. With a verifier it fails CLOSED
 *             correctly: missing proof throws, bad signature throws.
 *   SKIPPED   the same `if (verifier)`. Without one the block is stepped over on every connect and
 *             every reconnect, and nothing is logged at that site at all.
 *
 * NOT the live path, despite a comment claiming it is: `signaling-manager.ts`'s `processStep5Frame`
 * has no production caller. Its `no_challenge_verifier` branch returns silently and nothing reaches
 * it. Mistaking that for the enforcement point is the error this header exists to prevent.
 *
 * ─── Why the skip exists, and why it is still a hole ───────────────────────────────────────────
 *
 * The bundled manifest is the trust anchor for the PRODUCTION consortium only. Local dev and the
 * e2e harness run their own directory on 127.0.0.1, which the bundle cannot describe, so enforcing
 * there would reject every connection. The skip is correct for them.
 *
 * The hole is the test itself. It compares against the bundled roster after NORMALISATION — trimmed,
 * trailing slash dropped, lowercased (`manifest-deps.ts`) — so case and a trailing slash are
 * forgiven. **A DNS name pointing at the very same machine is not**, so an operator doing the most
 * natural thing available — putting a hostname in `CELLO_DIRECTORY_URL` — silently loses directory
 * identity authentication.
 *
 * (Review F7: this said "byte-equality" three times, including in operator-facing text. An operator
 * told that would hunt a trailing slash or a capital letter — both of which are tolerated — and not
 * find it.)
 * The DoD line is explicit that this is a workaround rather than a fix: *"That is why the production
 * directory URL is a raw IP."*
 *
 * Step 6 is what stops a `/bootstrap` MITM redirecting failover to a rogue directory — precisely, it
 * CONVERTS the redirect into a refused connection: the rogue host cannot produce a signature over
 * `nodeId ‖ our agent pubkey ‖ nonce ‖ timestamp` without a manifest node's private key, so the
 * connect throws and the failover resolver moves on. The attacker keeps denial-of-service; they do
 * not get impersonation. Without step 6 the client authenticates to whatever answers.
 *
 * ─── Scope ─────────────────────────────────────────────────────────────────────────────────────
 *
 * This does not remove the skip. It makes it impossible to MISS (the posture is stated in the agent
 * response, both directions) and makes it REFUSABLE (`CELLO_REQUIRE_DIRECTORY_AUTH`). Resolving the
 * bootstrap coordinate over an authenticated channel is the line's second bullet, and is carried.
 */

/** Private/loopback ranges — a directory here is local dev or the e2e harness, by design. */
const LOCAL_URL = /^https?:\/\/(localhost|127\.|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

/**
 * Should a missing challenge verifier be a REFUSAL rather than a skip?
 *
 * Default OFF, and that is not timidity: enforcing unconditionally would reject every local-dev and
 * e2e connection, since those directories cannot be described by the bundled manifest at all.
 *
 * The parsing is deliberately lopsided — anything set that is not an explicit negative counts as ON.
 * A security opt-in that silently fails to apply is worse than not offering one: an operator who
 * writes `CELLO_REQUIRE_DIRECTORY_AUTH=yes` believes they have demanded authentication, and a
 * parser that recognised only `1`/`true` would hand them the permissive default while they believed
 * the opposite. Getting it wrong in the safe direction costs a startup error the operator can read.
 */
export function directoryAuthRequired(env: Record<string, string | undefined>): boolean {
  const raw = env["CELLO_REQUIRE_DIRECTORY_AUTH"];
  if (raw === undefined) return false;
  const v = raw.trim().toLowerCase();
  if (v === "" || v === "0" || v === "false" || v === "no" || v === "off") return false;
  return true;
}

/**
 * The posture, for `cello_status`.
 *
 * NOTE the inversion from the rest of this milestone: here the healthy case DOES contribute a field.
 * Everywhere else a field on the good path is furniture that teaches the reader to skip the block
 * that matters — but the whole defect being fixed is that ON and OFF are distinguished only by the
 * absence of a log line nobody reads. "I checked, and it is on" has to be an answer an operator can
 * actually obtain. Only the GUIDANCE is conditional.
 */
export function describeDirectoryAuth(opts: {
  verifierPresent: boolean;
  directoryUrl: string;
}): Record<string, unknown> {
  if (opts.verifierPresent) {
    return { directory_authentication: "enforced" };
  }

  const expected = LOCAL_URL.test(opts.directoryUrl);
  return {
    directory_authentication: "disabled",
    /**
     * Two very different situations, which must not read the same.
     *
     * A loopback or private address is local dev or the e2e harness pointing at its own directory —
     * designed, and an alarm there would fire on every local run. Anything else is a client talking
     * to a PUBLIC directory with identity authentication off, which is weaker than its operator
     * believes, and the only previous signal was the absence of a log line.
     */
    directory_authentication_expected: expected,
    directory_authentication_directory_url: opts.directoryUrl,
    directory_authentication_guidance: expected
      ? `Directory identity authentication (step 6) is OFF because ${opts.directoryUrl} is a local ` +
        "address, which the bundled consortium manifest cannot describe. This is the designed " +
        "configuration for local development and the e2e harness — enforcing here would reject " +
        "every connection. To turn it on, supply a matching manifest with CELLO_CONSORTIUM_MANIFEST " +
        "AND CELLO_CONSORTIUM_ROOT_KEYS AND CELLO_CONSORTIUM_THRESHOLD — all three are required " +
        "together, and setting only the first makes the daemon refuse to start with a different error."
      : `Directory identity authentication (step 6) is OFF, because ${opts.directoryUrl} is not ` +
        "in the bundled consortium manifest after normalisation (trimmed, trailing slash dropped, " +
        "lowercased — so case and a trailing slash are forgiven). This client is weaker than " +
        "it looks: step 6 is what stops a MITM on the plaintext /bootstrap endpoint redirecting " +
        "failover to a ROGUE DIRECTORY, and without it this daemon will authenticate to whatever " +
        "answers. The usual cause is a HOSTNAME — normalisation forgives case and slashes but not " +
        "DNS, so a name pointing at exactly the right machine still does not match, which is why the " +
        "production " +
        "directory URL is a raw address. Either use a bundled endpoint address, or supply a matching " +
        "manifest with CELLO_CONSORTIUM_MANIFEST AND CELLO_CONSORTIUM_ROOT_KEYS AND " +
        "CELLO_CONSORTIUM_THRESHOLD — all three are required together, and setting only the first " +
        "makes the daemon refuse to start with a different error. Set CELLO_REQUIRE_DIRECTORY_AUTH=1 " +
        "to refuse to start rather than run without step 6; to turn that demand back off set it to " +
        "0, false, no or off (an unrecognised value counts as ON, deliberately).",
  };
}
