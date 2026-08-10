/**
 * WHICH TRUST SIGNALS AN OPERATOR MAY REVOKE — and why the answer is not "all of them".
 *
 * ── THIS FILE IS UX, NOT ENFORCEMENT. SAY IT OUT LOUD. ─────────────────────────────────────────
 * A client-side check is a courtesy to an honest operator: it refuses early, names the category,
 * and says what to do instead. It stops nobody, because the operator owns this process and can edit
 * it. The party with the motive to destroy a bad track record IS the subject, so the client is
 * exactly the wrong place to trust.
 *
 * The real enforcement lives where the operator cannot reach:
 *   • MANDATORY — the PORTAL refuses to mint a revocation. It is server-side, and it is the only
 *     party that knows a signal is a track record rather than a GitHub link (see ZERO-BUMP below).
 *   • ATTESTATIONS — the DIRECTORY already enforces exact-issuer authority in
 *     `signal_records_effective`: a tombstone whose revoker is not the issuer is written but INERT.
 *     So nobody can destroy an endorsement somebody else wrote, whatever their client does.
 *
 * ── WHY THE DIRECTORY CANNOT HOLD THIS LIST (DOD-INV-ZERO-BUMP) ────────────────────────────────
 * `signal_records.type` is deliberately an OPAQUE STRING — no enum, no CHECK constraint, no index
 * on a type value. A new signal type must cost a portal change and NOTHING else; a type list at the
 * directory would silently defeat that, and the day the portal invented a type the directory would
 * reject it three hops from where the mistake was made. So "mandatory" is not a concept the
 * directory can hold. It knows `issuer_kind`, not `track_record`.
 *
 * ── THE THREE CATEGORIES ───────────────────────────────────────────────────────────────────────
 */

/** What an operator may do with a signal, and the reason, resolved from its type. */
export type Revocability =
  | { revocable: true }
  | { revocable: false; category: "mandatory" | "security_derived"; guidance: string };

/**
 * MANDATORY — behavioural history and the verified baseline. Never revocable.
 *
 * `track_record` exists specifically so an agent cannot hide poor conduct; if the subject can delete
 * it, it means nothing for anybody. `email` and `phone` assert only THAT a channel was verified —
 * never the address or the number — so there is no privacy argument for removing them, and they are
 * the baseline the same-operator check leans on. The governing principle is older than this file:
 * if a signal could reveal undesirable behaviour, its subject does not get to suppress it.
 */
const MANDATORY = new Set(["track_record", "email", "phone"]);

/**
 * SECURITY-DERIVED — a mirror of a portal security setting, not a credential you hold.
 *
 * `webauthn` and `totp` exist BECAUSE the factor is enabled, and enrolling is the only thing that
 * mints them. That makes direct revocation a one-way trap, and it is the reason this category
 * exists rather than being folded into "discretionary":
 *
 *   Revoke the signal while the factor is still on → the factor is enabled, the signal is gone, and
 *   it can NEVER be regenerated, because the trigger that creates it is an enrolment that has
 *   already happened. The operator is stuck with no way back.
 *
 * So the way to remove one is to turn the factor off in the portal, which revokes the signal as a
 * consequence (`revokeSecurityDerivedSignal` there). Both halves of that are now wired — the
 * WebAuthn half was not, until 2026-08-10, which left a live signal claiming a passkey the account
 * no longer had.
 */
const SECURITY_DERIVED = new Set(["webauthn", "totp"]);

/**
 * DISCRETIONARY is everything else, and it is the DEFAULT — deliberately.
 *
 * A new signal type must not need a client release to become revocable. Defaulting to "revocable"
 * means the client stays out of the way of the zero-bump invariant: the portal is the enforcer, and
 * an unknown type reaching this function is a type this build has never heard of, which is the
 * normal case rather than an error. Defaulting the other way would make every new type silently
 * unrevocable until every operator upgraded.
 */
export function revocabilityOf(type: string): Revocability {
  if (MANDATORY.has(type)) {
    return {
      revocable: false,
      category: "mandatory",
      guidance:
        `'${type}' cannot be revoked. It is part of the behavioural record counterparties rely on — ` +
        `a track record you could delete would be worth nothing to anyone, and the verified email and ` +
        `phone signals assert only THAT a channel was verified, never the address or number, so there ` +
        `is nothing private to remove. If you want it shown less, that is a different question: ` +
        `presentation is controlled per-signal, and mandatory signals are deliberately not hideable ` +
        `either.`,
    };
  }
  if (SECURITY_DERIVED.has(type)) {
    return {
      revocable: false,
      category: "security_derived",
      guidance:
        `'${type}' is not revoked from here — it mirrors a security factor on your portal account, ` +
        `and enabling that factor is the only thing that creates it. Turn the factor off in the ` +
        `portal and the signal is revoked with it. Revoking it directly would leave the factor ` +
        `enabled with no signal, and you could never get the signal back, because the only way to ` +
        `mint one is to enrol a factor you have already enrolled.`,
    };
  }
  return { revocable: true };
}

/** The categorised types, exported so tests and surfaces read the SAME sets rather than a copy. */
export const REVOCABILITY_SETS = {
  mandatory: MANDATORY as ReadonlySet<string>,
  securityDerived: SECURITY_DERIVED as ReadonlySet<string>,
} as const;
