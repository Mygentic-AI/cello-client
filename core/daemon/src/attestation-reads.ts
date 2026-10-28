/**
 * M10E 015-READ — the reader's half of the public store, and the judge's submit.
 *
 * A buyer must be able to read a namespace's summary and its reviews WITHOUT trusting any one
 * directory. The defence is the signed head:
 *   - `readSummary` asks every reachable validator for its signed head, verifies each signature
 *     against that node's manifest key, and returns the head a MAJORITY of the manifest's validators
 *     agree on byte for byte, apart from each node's own `as_of` clock stamp. Fewer than a majority agree (or answer) ⇒ `no_majority`. A single
 *     node's head is NEVER shown as the answer.
 *   - `readReviews` pages the collection on one node and checks every inclusion proof against the
 *     MAJORITY root. The verified entries must number the majority count; a dropped entry fails that
 *     and refuses with `incomplete_page`, naming the node. Review text is returned ONLY under a
 *     quoted-data field — never a top-level instruction-shaped string.
 *   - `submitRuling` is the judge's client: it builds and signs the ruling exactly as 012's codec
 *     expects, then submits it to EVERY reachable node, because a node countersigns only what is
 *     submitted to it directly. A majority (T) of distinct nodes must each countersign for a removal
 *     to take force, and T follows the current manifest.
 *
 * COUNTERBALANCE. The reader is the adversary's code too, but the property it wants — "is this
 * collection complete?" — is not something it can fake for itself: the count and root are signed by
 * the directory nodes, and a majority of DISTINCT node keys must agree. A buyer running a rewritten
 * client only cheats itself; a provider or a dishonest node cannot fabricate agreement across a
 * majority of keys it does not hold. For the judge, reaching T genuinely requires T distinct nodes to
 * each verify and sign — which one node, or a stolen judge key paired with one node, cannot forge.
 *
 * Crypto: Ed25519 → RFC 8032, CBOR → RFC 8949, SHA-256 → FIPS 180-4, Merkle inclusion → RFC 6962.
 */
import { createHash, randomUUID } from "node:crypto";
import { verify, verifyInclusion } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  encodeCbor,
  decodeAttestationHead,
  encodeAttestationHead,
  hashAttestationHead,
  decodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  decodeAttestationPayload,
  type AttestationHead,
} from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";
import { sendAndAwait, toU8, type NamespaceSignaling } from "./attestation-namespaces.js";

/** A directory node's manifest identity: its stable id and the Ed25519 head-signing key, hex. */
export interface ValidatorKey { nodeId: string; pubkey: string; }
/** A reachable node to query: its roster endpoint plus the stable id that ties it to a manifest key. */
export interface NodeTarget { nodeId: string; peerId: string; multiaddr: string; }
/** One node's signed head, as a summary/collection reply carries it. */
export interface HeadVote { head: Uint8Array; node_id: string; node_signature: Uint8Array | null; }

/**
 * Open a transient channel to one node, send `frame`, await the reply `match` selects, close. Returns
 * null when the node is unreachable or never answers — a missing answer is NOT agreement.
 */
export type NodeQuery = (
  target: NodeTarget,
  frame: Record<string, unknown>,
  match: (reply: Record<string, unknown>) => boolean,
) => Promise<Record<string, unknown> | null>;

export type Refusal = { ok: false; reason: string; guidance: string; answered?: number; agreed?: number };

/** T = majority of the manifest's validators. Zero validators ⇒ Infinity: nothing is ever a
 *  majority without a real consortium, so no count is shown and no ruling takes force by default. */
export function majorityThreshold(validatorCount: number): number {
  return validatorCount === 0 ? Number.POSITIVE_INFINITY : Math.floor(validatorCount / 2) + 1;
}

export type MajorityOutcome =
  | { ok: true; head: AttestationHead; root: Uint8Array; agreed: number; answered: number }
  | { ok: false; agreed: number; answered: number };

/**
 * The head a majority of the manifest's validators agree on byte for byte. Each vote is only counted
 * once per node, only if it carries a signature that verifies against that node's manifest key, and
 * only if that node is a validator. A forged or unsigned vote is dropped — never counted toward a
 * group, which is why it cannot complete a majority.
 */
export function chooseMajorityHead(votes: readonly HeadVote[], validators: readonly ValidatorKey[]): MajorityOutcome {
  const T = majorityThreshold(validators.length);
  const keyOf = new Map(validators.map((v) => [v.nodeId, v.pubkey.toLowerCase()]));
  const answered = new Set<string>();
  const counted = new Set<string>();
  const groups = new Map<string, { head: AttestationHead; nodes: Set<string> }>();
  for (const v of votes) {
    answered.add(v.node_id);
    if (!v.node_signature) continue;             // missing proof is not agreement
    const pub = keyOf.get(v.node_id);
    if (!pub) continue;                          // not a manifest validator
    if (counted.has(v.node_id)) continue;        // one vote per node
    let head: AttestationHead;
    try { head = decodeAttestationHead(v.head); } catch { continue; }
    if (!verify(Buffer.from(pub, "hex"), hashAttestationHead(head), v.node_signature)) continue;
    counted.add(v.node_id);
    // Byte-for-byte grouping over everything except `as_of`: each sovereign node stamps its own clock,
    // so including it would make agreement depend on two nodes answering in the same second.
    const k = Buffer.from(encodeAttestationHead({ ...head, as_of: 0 })).toString("hex");
    const g = groups.get(k) ?? { head, nodes: new Set<string>() };
    g.nodes.add(v.node_id);
    groups.set(k, g);
  }
  let best: { head: AttestationHead; size: number } | null = null;
  for (const g of groups.values()) if (!best || g.nodes.size > best.size) best = { head: g.head, size: g.nodes.size };
  const agreed = best?.size ?? 0;
  if (best && best.size >= T) return { ok: true, head: best.head, root: best.head.merkle_root, agreed, answered: answered.size };
  return { ok: false, agreed, answered: answered.size };
}

/** Pull one signed head per node for a namespace and reduce to the majority. */
async function fetchMajority(
  query: NodeQuery, targets: readonly NodeTarget[], validators: readonly ValidatorKey[],
  owner_pubkey: string, namespace: string,
): Promise<MajorityOutcome> {
  const votes: HeadVote[] = [];
  for (const target of targets) {
    const reply = await query(target, { type: "attestation_summary_get", owner_pubkey, namespace },
      (r) => r["type"] === "attestation_summary");
    if (!reply) continue;
    const heads = Array.isArray(reply["heads"]) ? (reply["heads"] as Array<Record<string, unknown>>) : [];
    for (const hd of heads) {
      const head = toU8(hd["head"]);
      if (!head) continue;
      // Decode to find which namespace this head is for (the all-namespaces reply carries several).
      let ns: string;
      try { ns = decodeAttestationHead(head).namespace; } catch { continue; }
      if (ns !== namespace) continue;
      const nodeId = typeof hd["node_id"] === "string" ? hd["node_id"] : target.nodeId;
      votes.push({ head, node_id: nodeId, node_signature: toU8(hd["node_signature"]) });
    }
  }
  return chooseMajorityHead(votes, validators);
}

export interface SummaryOne {
  namespace: string; count: number; average_rating: number | null;
  removed_count: number; unmarked_claims: number; agreed: number; answered: number;
}

/** The average over scored reviews. A text namespace has no ratings (sum 0) ⇒ null; a scored one
 *  has every rating in 1..5 so sum ≥ count > 0 whenever count > 0. */
function averageRating(h: AttestationHead): number | null {
  return h.count > 0 && h.sum_of_ratings > 0 ? h.sum_of_ratings / h.count : null;
}

/**
 * The summary of ONE namespace, from a majority of directories. `no_majority` when fewer than a
 * majority agree or too few answer — the count is never shown from a single node.
 */
export async function readSummary(args: {
  query: NodeQuery; targets: readonly NodeTarget[]; validators: readonly ValidatorKey[];
  owner_pubkey: string; namespace: string; logger: Logger;
}): Promise<{ ok: true; summaries: SummaryOne[] } | Refusal> {
  const correlationId = randomUUID();
  const m = await fetchMajority(args.query, args.targets, args.validators, args.owner_pubkey, args.namespace);
  if (!m.ok) {
    args.logger.warn("attestation.summary.no_majority", { namespace: args.namespace, answered: m.answered, agreed: m.agreed, validators: args.validators.length, correlationId });
    return {
      ok: false, reason: "no_majority", answered: m.answered, agreed: m.agreed,
      guidance: `Only ${m.agreed} of ${args.validators.length} directories agreed on the summary (${m.answered} answered); a majority is required. No count is shown. Try again — a directory may be mid-roll.`,
    };
  }
  args.logger.info("attestation.summary.majority", { namespace: args.namespace, count: m.head.count, agreed: m.agreed, correlationId });
  return {
    ok: true,
    summaries: [{
      namespace: args.namespace, count: m.head.count, average_rating: averageRating(m.head),
      removed_count: m.head.removed_count, unmarked_claims: m.head.unmarked_claims,
      agreed: m.agreed, answered: m.answered,
    }],
  };
}

export interface ReviewView { index: number; rating: number | null; quoted_text: string; origin_channel: string | null; }
export interface RemovedView { attestation_hash: string; reason: string; evidence_hashes: string[]; }

/**
 * Page a namespace's reviews on ONE node and check every inclusion proof against the MAJORITY root.
 * The verified entries must number the majority count, or the read refuses `incomplete_page` naming
 * the node. Review text rides a quoted-data field; removed reviews are listed with their ruling's
 * reason, never their text.
 */
export async function readReviews(args: {
  query: NodeQuery; targets: readonly NodeTarget[]; validators: readonly ValidatorKey[];
  owner_pubkey: string; namespace: string; logger: Logger;
}): Promise<{ ok: true; count: number; agreed: number; node_id: string; reviews: ReviewView[]; removed: RemovedView[] } | Refusal> {
  const correlationId = randomUUID();
  const m = await fetchMajority(args.query, args.targets, args.validators, args.owner_pubkey, args.namespace);
  if (!m.ok) {
    args.logger.warn("attestation.reviews.no_majority", { namespace: args.namespace, answered: m.answered, agreed: m.agreed, correlationId });
    return {
      ok: false, reason: "no_majority", answered: m.answered, agreed: m.agreed,
      guidance: `Only ${m.agreed} of ${args.validators.length} directories agreed on the summary (${m.answered} answered); a majority is required before any review can be trusted.`,
    };
  }
  const root = m.root;
  const count = m.head.count;

  // Page on the first node that will serve the collection at all.
  for (const target of args.targets) {
    const reviews: ReviewView[] = [];
    // Each index once. Counting entries alone let a node serve one review twice in place of the
    // one it wanted buried: the total still matched the signed count (015 review, HIGH).
    const seen = new Set<number>();
    let duplicated = false;
    let removed: RemovedView[] = [];
    let after: string | undefined;
    let answered = false;
    let pageGuard = 0;
    for (;;) {
      if (pageGuard++ > 10_000) break; // a node that never stops paging is not a complete read
      const frame: Record<string, unknown> = { type: "attestation_collection_get", owner_pubkey: args.owner_pubkey, namespace: args.namespace, ...(after !== undefined ? { after } : {}) };
      const reply = await args.query(target, frame, (r) => r["type"] === "attestation_collection");
      if (!reply) break; // this node did not serve; try the next
      answered = true;
      removed = decodeRulings(reply["rulings"]);
      const entries = Array.isArray(reply["entries"]) ? (reply["entries"] as Array<Record<string, unknown>>) : [];
      for (const e of entries) {
        const envelope = toU8(e["envelope"]);
        const index = typeof e["index"] === "number" ? e["index"] : -1;
        const proof = Array.isArray(e["inclusion_proof"]) ? (e["inclusion_proof"] as unknown[]).map(toU8).filter((x): x is Uint8Array => x !== null) : [];
        if (!envelope || index < 0) continue;
        let leaf: Uint8Array;
        let view: ReviewView;
        try {
          leaf = hashTrustSignalEnvelope(decodeTrustSignalEnvelope(envelope));
          view = decodeReview(envelope, index);
        } catch { continue; } // an undecodable row is not a verified entry
        if (!verifyInclusion(leaf, index, count, proof, root)) continue; // not under the majority root
        if (seen.has(index)) { duplicated = true; continue; }
        seen.add(index);
        reviews.push(view);
      }
      const next = typeof reply["next"] === "string" ? reply["next"] : null;
      if (next === null) break;
      after = next;
    }
    if (!answered) continue; // ask the next node

    if (duplicated || seen.size !== count) {
      args.logger.warn("attestation.reviews.incomplete", { namespace: args.namespace, node: target.nodeId, verified: seen.size, duplicated, expected: count, correlationId });
      return {
        ok: false, reason: "incomplete_page",
        guidance: `Directory '${target.nodeId}' served ${seen.size} distinct verifiable reviews${duplicated ? " (and repeated some)" : ""} but the signed head says ${count}. Some are missing or do not verify against the majority root — the result is refused. Try another directory, or try again shortly.`,
      };
    }
    args.logger.info("attestation.reviews.verified", { namespace: args.namespace, node: target.nodeId, count: reviews.length, removed: removed.length, correlationId });
    return { ok: true, count, agreed: m.agreed, node_id: target.nodeId, reviews, removed };
  }
  return {
    ok: false, reason: "no_collection",
    guidance: `No reachable directory served the reviews for '${args.namespace}'. Try again shortly — a directory may be mid-roll.`,
  };
}

function decodeRulings(raw: unknown): RemovedView[] {
  if (!Array.isArray(raw)) return [];
  const out: RemovedView[] = [];
  for (const r of raw as Array<Record<string, unknown>>) {
    if (typeof r?.["attestation_hash"] !== "string") continue;
    out.push({
      attestation_hash: r["attestation_hash"],
      reason: typeof r["reason"] === "string" ? r["reason"] : "",
      evidence_hashes: Array.isArray(r["evidence_hashes"]) ? (r["evidence_hashes"] as unknown[]).filter((x): x is string => typeof x === "string") : [],
    });
  }
  return out;
}

/** Decode a review envelope's body into rating + the quoted (untrusted) text. */
function decodeReview(envelope: Uint8Array, index: number): ReviewView {
  const env = decodeTrustSignalEnvelope(envelope);
  const p = decodeAttestationPayload(env.payload);
  let rating: number | null = null;
  let text = "";
  if (p.body.length === 2) { rating = typeof p.body[0] === "number" ? p.body[0] : null; text = typeof p.body[1] === "string" ? p.body[1] : ""; }
  else if (p.body.length === 1) { text = typeof p.body[0] === "string" ? p.body[0] : ""; }
  return { index, rating, quoted_text: text, origin_channel: p.origin_channel };
}

/** The deals a channel produced and their average rating, from the HOME directory. */
export async function readDeals(
  deps: { signaling: NamespaceSignaling; timeoutMs?: number; logger: Logger },
  channel_pubkey: string,
): Promise<{ ok: true; deals: number; average_rating: number | null } | Refusal> {
  const out = await sendAndAwait(deps, { type: "attestation_channel_deals_get", channel_pubkey },
    (r) => r["type"] === "attestation_channel_deals" && r["channel_pubkey"] === channel_pubkey);
  if (out.kind === "send_failed") return { ok: false, reason: out.reason, guidance: out.guidance ?? `The deals request was not handed to a directory node (${out.reason}).` };
  if (out.kind === "timeout") return { ok: false, reason: "attestation_deals_timeout", guidance: "The directory node did not answer within the timeout. Re-running is safe." };
  const reply = out.reply;
  if (reply["type"] === "attestation_namespace_error") {
    const reason = typeof reply["reason"] === "string" ? reply["reason"] : "unspecified";
    return { ok: false, reason, guidance: `The directory could not serve the channel's deals: ${reason}.` };
  }
  const deals = typeof reply["deals"] === "number" ? reply["deals"] : 0;
  const average_rating = typeof reply["average_rating"] === "number" ? reply["average_rating"] : null;
  return { ok: true, deals, average_rating };
}

// ─── The judge's submit ───────────────────────────────────────────────────────

/** The canonical ruling the judge signs — byte-identical to 012's `encodeAttestationRuling`. The
 *  field set and order ARE the wire format; the one CBOR encoder (protocol-types) is configured
 *  tagUint8Array:false, useRecords:false, the same as the directory's. */
export interface RulingInput {
  attestation_hash: Uint8Array;
  owner_pubkey: string;
  namespace: string;
  reason: string;
  evidence_hashes: Uint8Array[];
  judge_pubkey: Uint8Array;
  ruled_at: number;
}
export function encodeRuling(r: RulingInput): Uint8Array {
  return new Uint8Array(encodeCbor({
    attestation_hash: r.attestation_hash,
    owner_pubkey: r.owner_pubkey,
    namespace: r.namespace,
    reason: r.reason,
    evidence_hashes: r.evidence_hashes,
    judge_pubkey: r.judge_pubkey,
    ruled_at: r.ruled_at,
  }));
}
export function hashRuling(r: RulingInput): Uint8Array {
  return new Uint8Array(createHash("sha256").update(encodeRuling(r)).digest());
}

export interface RuleNodeResult { node_id: string; in_force?: boolean; countersigns?: number; error?: string; }

/**
 * Build and sign a removal ruling with the judge's own key, submit it to EVERY reachable node, and
 * report each node's answer, the highest countersign count seen, and whether the ruling is in force.
 */
export async function submitRuling(args: {
  query: NodeQuery; targets: readonly NodeTarget[]; keyProvider: Pick<KeyProvider, "sign">;
  judgePubkeyHex: string; owner_pubkey: string; namespace: string;
  attestation_hash: Uint8Array; reason: string; evidence_hashes: Uint8Array[];
  now: () => number; logger: Logger;
}): Promise<{ ok: true; results: RuleNodeResult[]; countersigns: number; in_force: boolean } | Refusal> {
  const correlationId = randomUUID();
  const ruling: RulingInput = {
    attestation_hash: args.attestation_hash, owner_pubkey: args.owner_pubkey, namespace: args.namespace,
    reason: args.reason, evidence_hashes: args.evidence_hashes,
    judge_pubkey: Buffer.from(args.judgePubkeyHex, "hex"), ruled_at: Math.floor(args.now() / 1000),
  };
  const record = encodeRuling(ruling);
  const judge_signature = await args.keyProvider.sign(hashRuling(ruling));
  const attHashHex = Buffer.from(args.attestation_hash).toString("hex");
  args.logger.info("attestation.ruling.submitting", { attestationHash: attHashHex.slice(0, 16), nodes: args.targets.length, correlationId });

  const results: RuleNodeResult[] = [];
  let countersigns = 0;
  let in_force = false;
  for (const target of args.targets) {
    const reply = await args.query(target, { type: "attestation_ruling_submit", ruling: record, judge_signature },
      (r) => r["type"] === "attestation_ruling_result" && r["attestation_hash"] === attHashHex);
    if (!reply) { results.push({ node_id: target.nodeId, error: "unreachable" }); continue; }
    if (reply["type"] === "attestation_namespace_error") {
      results.push({ node_id: target.nodeId, error: typeof reply["reason"] === "string" ? reply["reason"] : "refused" });
      continue;
    }
    const c = typeof reply["countersigns"] === "number" ? reply["countersigns"] : 0;
    const f = reply["in_force"] === true;
    if (c > countersigns) countersigns = c;
    if (f) in_force = true;
    results.push({ node_id: target.nodeId, in_force: f, countersigns: c });
  }
  args.logger.info("attestation.ruling.submitted", { attestationHash: attHashHex.slice(0, 16), countersigns, in_force, correlationId });
  return { ok: true, results, countersigns, in_force };
}
