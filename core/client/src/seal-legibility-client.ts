/**
 * CELLO-M7-SESSION-004 — Client-side seal certificate legibility parsing & verification
 *
 * The directory builds the legibility certificate and pushes it on the SessionSealed
 * wire frame; the client persists it and exposes it intact on read. The client also
 * independently re-derives each party's content_frontier_seq from its own local
 * session state and rejects a certificate whose published frontier EXCEEDS the locally
 * re-derived signed maximum (SI-002 client guard) with `certificate_frontier_unverifiable`.
 *
 * CBOR canonical RFC 8949 §4.2.1.
 */

import type { SealLegibility, SealLegibilityParticipant, AttestationMode } from "@cello-protocol/protocol-types";

/** Distinct client-side rejection code for a certificate whose published frontier
 *  exceeds the maximum the client can re-derive (SI-002). Never collides with the
 *  directory seal-rejection codes (merkle_root_mismatch, leaf_signature_invalid,
 *  prev_root_chain_broken, causal_chain_violated, seal_leaves_invalid). */
export const CERTIFICATE_FRONTIER_UNVERIFIABLE = "certificate_frontier_unverifiable" as const;

function toUint8Array(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

function toNum(v: unknown): number | null {
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return null;
}

/**
 * Parse a CBOR-decoded (or in-memory) legibility object into a typed SealLegibility.
 * Returns null on a structurally invalid object so a malformed certificate is never
 * silently accepted. Pubkeys are normalised to Uint8Array.
 */
export function parseLegibility(raw: unknown): SealLegibility | null {
  if (raw === null || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (o["attests"] !== "receipt") return null;
  if (o["implies_assent"] !== false) return null;
  const disclaimer = o["disclaimer"];
  if (typeof disclaimer !== "string" || disclaimer.length === 0) return null;

  const rawParts = o["participants"];
  if (!Array.isArray(rawParts)) return null;
  const participants: SealLegibilityParticipant[] = [];
  for (const p of rawParts) {
    if (p === null || typeof p !== "object") return null;
    const po = p as Record<string, unknown>;
    const pubkey = toUint8Array(po["pubkey"]);
    const cf = toNum(po["content_frontier_seq"]);
    const la = toNum(po["last_authored_seq"]);
    const mode = po["attestation_mode"];
    if (!pubkey || cf === null || la === null) return null;
    if (mode !== "live" && mode !== "recovered" && mode !== "absent") return null;
    participants.push({
      pubkey,
      content_frontier_seq: cf,
      last_authored_seq: la,
      attestation_mode: mode as AttestationMode,
    });
  }

  const fmRaw = o["final_message"];
  if (fmRaw === null || typeof fmRaw !== "object") return null;
  const fmo = fmRaw as Record<string, unknown>;
  const senderPubkey = toUint8Array(fmo["sender_pubkey"]);
  const seq = toNum(fmo["seq"]);
  const answered = fmo["answered"];
  if (!senderPubkey || seq === null || typeof answered !== "boolean") return null;

  return {
    attests: "receipt",
    implies_assent: false,
    disclaimer,
    participants,
    final_message: { sender_pubkey: senderPubkey, seq, answered },
  };
}

/**
 * SI-002 client guard. `derivedByHex` maps a party's pubkey-hex to the maximum
 * content_frontier_seq the client can INDEPENDENTLY re-derive from its own local
 * state for that party. The client always includes itself (its own signed frontier =
 * `last_seen_seq`, which it can never be behind on). The counterparty is included
 * only when the client holds complete synchronized state (otherwise a legitimately
 * higher published value — the client being behind — would false-positive). A
 * published frontier that EXCEEDS the re-derived maximum for an included party is the
 * SI-002 violation. Returns the first such party, or null if all are consistent.
 */
export function findUnverifiableFrontier(
  legibility: SealLegibility,
  derivedByHex: Map<string, number>,
): { party: string; publishedFrontier: number; derivedFrontier: number } | null {
  for (const p of legibility.participants) {
    const hex = Buffer.from(p.pubkey).toString("hex");
    const derived = derivedByHex.get(hex);
    if (derived === undefined) continue; // not independently re-derivable by this client
    if (p.content_frontier_seq > derived) {
      return { party: hex, publishedFrontier: p.content_frontier_seq, derivedFrontier: derived };
    }
  }
  return null;
}
