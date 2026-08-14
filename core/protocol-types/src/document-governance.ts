/**
 * DOD-MP-GOVERN-1 — the signature-requirement policy. Rulings D2/D3 (2026-08-11), as code.
 *
 * The policy VALIDATES the collection's claimed required set; it does not mint one. "Any single
 * admin may act" has no single answer to mint — {a} and {b} are both acceptable claims — so the
 * seam is a verdict on what the collection claims, and the multisig layer then demands every
 * claimed signature actually verify.
 *
 * The rules:
 * - **Single-admin kinds** — `add_holder`, `promote_admin`, `remove_holder` (of a non-admin),
 *   `change_property`: the claim is EXACTLY ONE current admin. A wider claim is refused, not
 *   welcomed as extra-safe: every claimed signer must sign for the collection to complete, so an
 *   inflated claim lets one absent co-signer veto an action the rule gives to any single admin —
 *   a governance change smuggled through the claim.
 * - **Voluntary leave** — `remove_holder` claimed by exactly the subject themselves is always
 *   acceptable, admin or not. Leaving is theirs (D3).
 * - **`remove_admin`** — the claim is exactly ALL OTHER admins; the subject neither required nor
 *   counted. With exactly two admins NEITHER CAN REMOVE THE OTHER — by design, and the refusal
 *   names the recourse (D3: stop working in it, duplicate it, start fresh without them).
 * - **The holder door is not a bypass** — `remove_holder` of a CURRENT ADMIN (other than
 *   voluntary leave) is refused: holder removal drops admin status too, so allowing it under the
 *   single-admin rule would expel an admin on one signature, evading `remove_admin` and the
 *   deadlock in one move. Demote first, under remove_admin's rule.
 *
 * Kind/subject semantics (does the subject hold? is it already an admin? last-admin protection)
 * are the causal fold's job (`deriveDocumentState`) and run BEFORE this policy is consulted — it may assume a
 * semantically coherent amendment.
 */

import type { AmendmentKind } from "./document-amendment.js";

export type GovernanceVerdict = { ok: true } | { ok: false; reason: string };

function canonical(ids: readonly string[]): string[] {
  return [...new Set(ids)].sort();
}

/** A duplicated claim is a builder bug, refused — deduping here would hand the multisig layer a
 * collection it THROWS on (`multisig_duplicate_signer`), escaping the derivation's never-throw
 * contract. The two layers agree: duplicates refuse, loudly, at the first gate they reach. */
function hasDuplicates(ids: readonly string[]): boolean {
  return new Set(ids).size !== ids.length;
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((id, i) => id === b[i]);
}

export function documentGovernancePolicy(
  kind: AmendmentKind,
  subjectAgentId: string | null,
  state: { participants: ReadonlySet<string>; admins: ReadonlySet<string> },
  claimedRequiredSet: readonly string[],
): GovernanceVerdict {
  if (hasDuplicates(claimedRequiredSet)) {
    return {
      ok: false,
      reason: "governance_claim_shape: the claimed required set names a signer more than once",
    };
  }
  const claimed = canonical(claimedRequiredSet);
  if (claimed.length === 0) {
    return {
      ok: false,
      reason: "governance_claim_shape: a collection nobody is required to sign authorizes nothing",
    };
  }

  if (kind === "remove_admin") {
    // The fold already refused a non-admin subject and the last-admin case.
    if (state.admins.size === 2) {
      return {
        ok: false,
        reason:
          "governance_two_admin_deadlock: with exactly two admins neither can remove the other " +
          "(D3, by design) — the recourse is to stop working in this document, duplicate it, and " +
          "start fresh without them",
      };
    }
    const others = canonical([...state.admins].filter((id) => id !== subjectAgentId));
    if (!sameSet(claimed, others)) {
      return {
        ok: false,
        reason:
          `governance_remove_admin_set: removing an admin takes the signatures of ALL other ` +
          `admins [${others.join(", ")}] exactly — the subject neither required nor counted — ` +
          `and the collection claims [${claimed.join(", ")}]`,
      };
    }
    return { ok: true };
  }

  // Voluntary leave: the subject signing their own removal, admin or not. Checked before the
  // admin-door rule below so a leaving admin is not told to demote themselves first.
  if (
    kind === "remove_holder" &&
    subjectAgentId !== null &&
    claimed.length === 1 &&
    claimed[0] === subjectAgentId
  ) {
    return { ok: true };
  }

  if (kind === "remove_holder" && subjectAgentId !== null && state.admins.has(subjectAgentId)) {
    return {
      ok: false,
      reason:
        "governance_remove_admin_first: removing an admin from the document takes the " +
        "remove_admin rule (all other admins) — a single admin cannot expel a fellow admin " +
        "through the holder door, and holder removal drops admin status too",
    };
  }

  // The single-admin kinds: add_holder, promote_admin, remove_holder (non-admin), change_property.
  if (claimed.length !== 1) {
    return {
      ok: false,
      reason:
        `governance_claim_shape: ${kind} is a single-admin action and the collection claims ` +
        `${claimed.length} required signers — a wider claim lets an absent co-signer veto what ` +
        `the rule gives to any one admin`,
    };
  }
  if (!state.admins.has(claimed[0]!)) {
    return {
      ok: false,
      reason:
        `governance_not_admin: ${claimed[0]} holds no admin power over this document — ` +
        `${kind} takes a current admin's signature`,
    };
  }
  return { ok: true };
}
