/**
 * Wire-frame value helpers, shared by the seal coordinator and the session-event handlers.
 *
 * Pure: no daemon state, no closure. They lived inside startDaemon only because everything did.
 */
import { Buffer } from "node:buffer";

// CBOR-decoded byte fields arrive as Uint8Array or Buffer; a field may also already be
// a hex string. Hex strings are lowercased so the case-sensitive agent-pubkey match
// (agents store lowercase hex) cannot silently miss (review L2).
export function frameValueToHex(v: unknown): string | null {
  if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
  if (Buffer.isBuffer(v)) return Buffer.from(v as Buffer).toString("hex");
  if (typeof v === "string") return v.toLowerCase();
  return null;
}
// M7-SESSION-004 (AC-005): normalise the wire `legibility` object — CBOR-decoded, so pubkeys
// arrive as Uint8Array/Buffer — into a JSON-safe certificate with hex-encoded pubkeys. Returns
// undefined for an absent or structurally-implausible object (pre-M7 frame, or a malformed
// field), in which case nothing is persisted and the seal still completes. The receipt-not-
// assent constants (attests/implies_assent/disclaimer) and the integers/booleans are carried
// verbatim; only the byte fields are re-encoded. The daemon never invents or alters the
// certificate's meaning — it is the directory's derivation, surfaced.
export function normalizeLegibility(raw: unknown): unknown | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (o["attests"] !== "receipt") return undefined;
  const participantsRaw = o["participants"];
  const finalRaw = o["final_message"];
  if (!Array.isArray(participantsRaw) || !finalRaw || typeof finalRaw !== "object") return undefined;
  // Review finding (low): the disclaimer is the human-readable half of the receipt-not-assent
  // property; a non-string value means a malformed/tampered frame, so REJECT the whole cert
  // rather than surfacing an empty disclaimer (implies_assent:false alone is the machine-readable
  // half, but we do not surface a half-formed certificate).
  if (typeof o["disclaimer"] !== "string" || o["disclaimer"].length === 0) return undefined;
  // Review finding (low): validate attestation_mode against the closed enum — never surface an
  // arbitrary string from a malformed frame on the cert read surface (defensive parity with the
  // coerced fields). An out-of-enum value rejects the whole cert.
  const VALID_MODES = new Set(["live", "recovered", "absent"]);
  const participants: Array<{
    pubkey: string | null; content_frontier_seq: number | null; last_authored_seq: number | null; attestation_mode: string;
  }> = [];
  for (const p of participantsRaw) {
    const pp = p as Record<string, unknown>;
    const mode = pp["attestation_mode"];
    if (typeof mode !== "string" || !VALID_MODES.has(mode)) return undefined;
    participants.push({
      pubkey: frameValueToHex(pp["pubkey"]),
      content_frontier_seq: typeof pp["content_frontier_seq"] === "number" ? pp["content_frontier_seq"] : null,
      last_authored_seq: typeof pp["last_authored_seq"] === "number" ? pp["last_authored_seq"] : null,
      attestation_mode: mode,
    });
  }
  const fm = finalRaw as Record<string, unknown>;
  const final_message = {
    sender_pubkey: frameValueToHex(fm["sender_pubkey"]),
    seq: typeof fm["seq"] === "number" ? fm["seq"] : null,
    answered: fm["answered"] === true,
  };
  return {
    attests: "receipt" as const,
    implies_assent: false as const,
    disclaimer: o["disclaimer"],
    participants,
    final_message,
    /**
     * ⚠️ `countersigned_through_seq` IS DELIBERATELY NOT SET HERE — `DOD-M15-UNILATERAL-1`, F2.
     *
     * It was, computed from the participants just above, and described as "recomputed, cannot be
     * steered". Those participants come off the WIRE. On a solo seal the certificate's TBS binds no
     * legibility at all, and the client verifies only the live party's frontier — so the absent
     * party's numbers, which are exactly the ones that decide this boundary, arrive unchecked.
     * Deriving from them looked like verification and was arithmetic on somebody else's claim.
     *
     * The boundary is stamped by the seal coordinator instead, from this daemon's own signed carry
     * (`countersignedThroughSeqFromCarry`), where the counterparty's own signature covers both
     * inputs. Absent here means "not yet derived", and a receipt that reaches persistence without it
     * says the boundary could not be established rather than guessing one.
     */
  };
}
