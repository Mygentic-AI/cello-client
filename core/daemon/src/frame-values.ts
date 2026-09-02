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
     * `DOD-M15-UNILATERAL-1` — WHERE THIS RECEIPT STOPS BEING AS STRONG AS A BILATERAL ONE.
     *
     * **RECOMPUTED HERE, NEVER READ OFF THE WIRE**, and that is the whole point. The directory
     * publishes the same number, but it is not folded into the legibility hash the seal signature
     * binds — so a value taken from the frame would be a value a tampering path could set. Every
     * INPUT is bound, so deriving it locally costs nothing and cannot be steered.
     *
     * Everything at or below this sequence carries BOTH parties' signatures. Everything above it is
     * the uncountersigned tail: composed and witnessed, never signed for by the party who had gone.
     * A consumer that conflates the two reads "they never answered this" as "they agreed to this".
     */
    countersigned_through_seq: participants.length === 0
      ? 0
      : participants.reduce(
          (lowest, p) => Math.min(lowest, Math.max(p.content_frontier_seq ?? 0, p.last_authored_seq ?? 0)),
          Number.POSITIVE_INFINITY,
        ),
  };
}
