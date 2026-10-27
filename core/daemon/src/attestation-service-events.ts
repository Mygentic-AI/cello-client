/**
 * M10E 005-SVCCLIENT — the client half of service events.
 *
 * A provider marks a service event WHILE a session is open, which mints the counterparty a right to
 * review. The provider proves the session with the stored quorum-signed proof (`session_proofs`,
 * written on the assignment-verified path). The customer lists the rights it holds.
 *
 * COUNTERBALANCE. The provider's own daemon is the adversary: it could try to mark a session it was
 * never in. It cannot — the directory (004) re-verifies the proof's FROST signature against both
 * parties' replicated primary keys, so a fabricated proof is refused THERE, not here. This file's
 * only job is to send the genuine proof and to surface every directory refusal with a next step.
 *
 * Marks share 003's serialization chain, so a namespace write and a mark never overlap (K7).
 *
 * Crypto: Ed25519 → RFC 8032, CBOR → RFC 8949, SHA-256 → FIPS 180-4.
 */
import { extractErrorMessage } from "./error-message.js";
import { randomUUID } from "node:crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  decodeAttestationRight,
  encodeServiceEvent,
  hashAttestationRight,
  hashServiceEvent,
  templateIdForHash,
  type ServiceEvent,
} from "@cello-protocol/protocol-types";
import { serialize, sendAndAwait, toU8, type NamespaceSignaling } from "./attestation-namespaces.js";
import { decodeSessionProof } from "./attestation-session-proof.js";
import type { Logger } from "./types.js";

type Refusal = { ok: false; reason: string; guidance: string };

export interface RightView {
  right_id: string;
  subject_pubkey: string;
  namespace: string;
  session_id: string;
  created_at: number;
  expires_at: number;
  expired: boolean;
  template: "text" | "scored" | null;
}

export interface ServiceEventDeps {
  signaling: NamespaceSignaling;
  keyProvider: Pick<KeyProvider, "sign" | "getPublicKey">;
  /** The selected agent's own K_local pubkey, lowercase 64-hex. The event's subject; never an input. */
  ownerPubkeyHex: string;
  /** Epoch millis. */
  now: () => number;
  logger: Logger;
  /** The stored proof bytes for this agent + session, or null when none was kept. */
  loadSessionProof: (sessionIdHex: string) => Uint8Array | null;
  /** The hash of the last leaf this agent holds for the session, or 32 zero bytes when there is none. */
  chainHeadHash: (sessionIdHex: string) => Uint8Array;
  timeoutMs?: number;
}

/** One sentence each, naming the next step — never a bare code (procedure §Invariant 4). */
const MARK_GUIDANCE: Record<string, string> = {
  session_sealed: "Service events are marked during the session, before it is sealed. This one is sealed.",
  already_marked: "This session already has a service event in that namespace.",
  namespace_closed: "That namespace is closed. Marks need an open namespace.",
  unknown_namespace: "There is no such namespace to mark against. Create it first, or check the name with `cello attestations index`.",
  not_owner: "A service event is marked by the party whose namespace it is. This proof names you as the counterparty, not the subject.",
  proof_mismatch: "The stored proof does not match this session or counterparty. This is a client bug — upgrade @cello-protocol/connect.",
  proof_bad_signature: "The directory could not verify the session proof. This is a client bug — upgrade @cello-protocol/connect.",
  proof_signer_not_a_participant: "The session proof was signed by a key that is not a participant's. Retry; if it repeats, upgrade @cello-protocol/connect.",
  proof_unknown_participant: "The directory does not yet know one of the two parties. Try again shortly; registrations replicate between nodes.",
  bad_record: "The directory could not read the service event. This is a client/version mismatch — upgrade @cello-protocol/connect.",
  bad_proof: "The directory could not read the session proof. This is a client/version mismatch — upgrade @cello-protocol/connect.",
  bad_signature: "The directory could not verify your signature on the event. This is a client bug — upgrade @cello-protocol/connect.",
  unregistered: "This agent is not registered with the directory yet. Run `cello status`.",
  stale_record: "The event's timestamp is too far from the directory's clock. Check this machine's clock and run it again.",
  rate_limited: "Too many marks too fast. Wait a few seconds and run it again.",
  lookup_failed: "The directory could not check the parties. It is a directory-side fault — try again shortly.",
  store_failed: "The directory accepted the event but could not store it. Try again; re-running is safe.",
};

const RIGHTS_GUIDANCE: Record<string, string> = {
  rate_limited: "Too many rights reads too fast. Wait a few seconds and run it again.",
  lookup_failed: "The directory could not read your rights. It is a directory-side fault — try again shortly.",
};

function timeoutRefusal(kind: "mark" | "rights", sawNotAuthenticated: boolean): Refusal {
  if (sawNotAuthenticated) {
    return {
      ok: false,
      reason: "attestations_unsupported_by_node",
      guidance: "The directory node did not recognise the frame — most likely it has not rolled attestation-service-event support yet (nodes deploy independently per region). This is NOT a login failure; retry later.",
    };
  }
  return {
    ok: false,
    reason: `attestation_${kind === "mark" ? "service_event" : "rights"}_timeout`,
    guidance: kind === "mark"
      ? "The directory node did not answer within the timeout. Whether the mark stored is unknown; re-running is safe (the same session+namespace is marked once)."
      : "The directory node did not answer within the timeout. Run it again.",
  };
}

export async function markServiceEvent(
  deps: ServiceEventDeps,
  input: { session_id: string; namespace: string; origin_channel?: string },
): Promise<{ ok: true; status: "stored" | "identical" } | Refusal> {
  const sessionIdHex = input.session_id.toLowerCase();
  const proofBytes = deps.loadSessionProof(sessionIdHex);
  if (!proofBytes) {
    return {
      ok: false,
      reason: "no_session_proof",
      guidance: "This agent kept no proof for that session, so it cannot mark it. A service event is marked during a session THIS agent took part in; sessions opened before this client version stored no proof. Open a fresh session and mark that one.",
    };
  }
  let proof;
  try { proof = decodeSessionProof(proofBytes); } catch {
    return { ok: false, reason: "no_session_proof", guidance: "The stored session proof could not be read. Open a fresh session and mark that one." };
  }
  // The counterparty is the participant who is not us. If we are in neither slot the proof is not
  // ours to mark from — reported as no_session_proof, since there is no session of ours behind it.
  const pubAHex = Buffer.from(proof.pub_a).toString("hex");
  const pubBHex = Buffer.from(proof.pub_b).toString("hex");
  const me = deps.ownerPubkeyHex.toLowerCase();
  const counterparty = pubAHex === me ? pubBHex : pubBHex === me ? pubAHex : null;
  if (!counterparty) {
    return {
      ok: false,
      reason: "no_session_proof",
      guidance: "The stored proof for that session does not name this agent as a participant. Select the agent that took part in the session (cello_use_agent) and mark it with them.",
    };
  }

  const ev: ServiceEvent = {
    session_id: new Uint8Array(Buffer.from(sessionIdHex, "hex")),
    subject_pubkey: me,
    namespace: input.namespace,
    counterparty_pubkey: counterparty,
    chain_head_hash: deps.chainHeadHash(sessionIdHex),
    marked_at: Math.floor(deps.now() / 1000),
    origin_channel: input.origin_channel ?? null,
  };
  const signature = await deps.keyProvider.sign(hashServiceEvent(ev));
  const frame = { type: "attestation_service_event_mark", event: encodeServiceEvent(ev), signature, session_proof: proofBytes };

  return serialize(async (): Promise<{ ok: true; status: "stored" | "identical" } | Refusal> => {
    const correlationId = randomUUID();
    deps.logger.info("attestation.service_event.sent", { session_id: sessionIdHex, namespace: input.namespace, correlationId });
    const out = await sendAndAwait(deps, frame, (reply) =>
      reply["type"] === "attestation_service_event_result" && reply["session_id"] === sessionIdHex && reply["namespace"] === input.namespace);
    if (out.kind === "send_failed") {
      deps.logger.warn("attestation.service_event.replied", { session_id: sessionIdHex, namespace: input.namespace, outcome: out.reason, correlationId });
      return { ok: false, reason: out.reason, guidance: out.guidance ?? `The event was not handed to a directory node (${out.reason}). Re-running is safe.` };
    }
    if (out.kind === "timeout") {
      const r = timeoutRefusal("mark", out.sawNotAuthenticated);
      deps.logger.warn("attestation.service_event.replied", { session_id: sessionIdHex, namespace: input.namespace, outcome: r.reason, correlationId });
      return r;
    }
    const reply = out.reply;
    if (reply["type"] === "attestation_namespace_error") {
      const reason = typeof reply["reason"] === "string" ? reply["reason"] : "unspecified";
      deps.logger.warn("attestation.service_event.replied", { session_id: sessionIdHex, namespace: input.namespace, outcome: reason, correlationId });
      return { ok: false, reason, guidance: MARK_GUIDANCE[reason] ?? `The directory refused the mark: ${reason}.` };
    }
    const status = reply["status"] === "identical" ? "identical" : "stored";
    deps.logger.info("attestation.service_event.replied", { session_id: sessionIdHex, namespace: input.namespace, outcome: status, correlationId });
    return { ok: true, status };
  });
}

export async function listRights(
  deps: ServiceEventDeps,
  after?: string,
): Promise<{ ok: true; rights: RightView[]; next: string | null } | Refusal> {
  const frame: Record<string, unknown> = { type: "attestation_rights_list", ...(after !== undefined ? { after } : {}) };
  return serialize(async (): Promise<{ ok: true; rights: RightView[]; next: string | null } | Refusal> => {
    const out = await sendAndAwait(deps, frame, (reply) => reply["type"] === "attestation_rights");
    if (out.kind === "send_failed") {
      return { ok: false, reason: out.reason, guidance: out.guidance ?? `The rights request was not handed to a directory node (${out.reason}). Try again shortly.` };
    }
    if (out.kind === "timeout") return timeoutRefusal("rights", out.sawNotAuthenticated);
    const reply = out.reply;
    if (reply["type"] === "attestation_namespace_error") {
      const reason = typeof reply["reason"] === "string" ? reply["reason"] : "unspecified";
      return { ok: false, reason, guidance: RIGHTS_GUIDANCE[reason] ?? `The directory could not serve your rights: ${reason}.` };
    }
    const rawEntries = Array.isArray(reply["entries"]) ? (reply["entries"] as Array<Record<string, unknown>>) : [];
    const rights: RightView[] = [];
    for (const e of rawEntries) {
      const rightBytes = toU8(e["right"]);
      if (!rightBytes) {
        // Nothing to show, but never silently: the log is the record that the directory sent it.
        deps.logger.warn("attestation.rights.undecodable", { right_id: typeof e["right_id"] === "string" ? e["right_id"] : "", reason: "not_bytes" });
        continue;
      }
      let decoded;
      try { decoded = decodeAttestationRight(rightBytes); } catch (err: unknown) {
        deps.logger.warn("attestation.rights.undecodable", { right_id: typeof e["right_id"] === "string" ? e["right_id"] : "", reason: extractErrorMessage(err) });
        continue;
      }
      // Recompute the id and TRUST OUR OWN hash, never the directory's. A mismatch is kept — a
      // dropped right is the hide route — with the recomputed id and a warning.
      const recomputed = Buffer.from(hashAttestationRight(decoded)).toString("hex");
      const claimed = typeof e["right_id"] === "string" ? e["right_id"] : "";
      if (claimed !== recomputed) {
        deps.logger.warn("attestation.rights.id_mismatch", { right_id: claimed, recomputed });
      }
      rights.push({
        right_id: recomputed,
        subject_pubkey: decoded.subject_pubkey,
        namespace: decoded.namespace,
        session_id: Buffer.from(decoded.session_id).toString("hex"),
        created_at: decoded.created_at,
        expires_at: decoded.expires_at,
        // OUR clock against the signed expiry, never the directory's flag: a dishonest node that
        // marked a live right "expired" would talk the customer out of a review they are owed.
        expired: Math.floor(deps.now() / 1000) >= decoded.expires_at,
        template: templateIdForHash(decoded.template_hash),
      });
    }
    const next = typeof reply["next"] === "string" ? reply["next"] : null;
    return { ok: true, rights, next };
  });
}
