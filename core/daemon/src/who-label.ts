/**
 * MONIKER-4 AC1 — whoLabel: the one display-name resolution (M8C-MONIKER-SPEC §2).
 *
 *   who = localMoniker ?? offeredMoniker ?? fingerprint(pubkey)
 *
 * PURE and TOTAL: never throws, never returns an empty label. Both name inputs
 * are re-validated with the shared wire rule — the boundaries (MONIKER-2/3)
 * make invalid values unreachable here, but totality means this function is
 * safe even if misused. `whoKnown` is true ONLY when the label came from the
 * local address book (a deliberate operator act — CC-1); an offered name is an
 * unverified hint and a fingerprint is derived identity, both unknown.
 *
 * The name-vs-fingerprint discriminator is unforgeable by construction:
 * MONIKER_RE excludes spaces, and a fingerprint always contains one.
 */

import { validateMoniker } from "@cello-protocol/protocol-types";

export type WhoSource = "local" | "offered" | "fingerprint";

/** `agent 178d420b…` — first 8 hex chars. Total: garbage still yields a non-empty label. */
export function fingerprint(pubkeyHex: unknown): string {
  const hex = typeof pubkeyHex === "string" && pubkeyHex.length >= 8 ? pubkeyHex.slice(0, 8) : null;
  return hex !== null ? `agent ${hex}…` : "agent unknown…";
}

export function whoLabel(input: {
  localMoniker?: string | null;
  offeredMoniker?: string | null;
  pubkeyHex: string;
}): { who: string; whoKnown: boolean; source: WhoSource } {
  const local = input.localMoniker != null ? validateMoniker(input.localMoniker) : null;
  if (local !== null) return { who: local, whoKnown: true, source: "local" };
  const offered = input.offeredMoniker != null ? validateMoniker(input.offeredMoniker) : null;
  if (offered !== null) return { who: offered, whoKnown: false, source: "offered" };
  return { who: fingerprint(input.pubkeyHex), whoKnown: false, source: "fingerprint" };
}
