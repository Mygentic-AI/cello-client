/**
 * SYNC-P1 — the causal derivation. ONE derivation of a document's state for every holder: the
 * fold over the entry DAG in a deterministic total order. Same entry set → same state, everywhere,
 * always. This file replaces the linear epoch replay; the fold rules are M14B Build Journal
 * Entries 48–49 (SYNC-G2's finding plus its admin-floor addendum).
 *
 * The total order is Kahn's topological sort refined by ascending entry hash — a pure function of
 * the entry SET. The hash tie-break resolves only what is semantically arbitrary (which property
 * value wins). It never resolves authority: causal concurrency is author-claimable (a modified
 * daemon backdates its parents at will), so any rule where a concurrent act could beat a removal
 * would make removal defeatable. Hence the fold rules:
 *
 *  F1. A non-removal entry takes effect iff it validates against the folded state at its position
 *      AND it is not concurrent with an ancestor-valid removal of its author.
 *  F2. A removal is judged at its OWN ancestors (the state derived from its ancestor closure) and
 *      is exempt from F1's concurrency void — the exemption is what keeps mutual removals from
 *      being circular. At fold position it is void only by the admin floor: a removal that would
 *      leave zero admins does not take effect.
 *  F3. Content admissibility is R20's (ancestor-based) and is NOT this module's concern.
 *  F4. A void entry stays in the linearization — history, not refusal — and contributes nothing.
 */

import {
  documentAmendmentHash,
  MAX_DOCUMENT_HOLDERS,
  AMENDABLE_PROPERTIES,
  AMENDMENT_SUBJECT_KIND,
  type DocumentAmendmentEnvelope,
  type ArrangementGenesis,
  type SignerPolicy,
} from "./document-amendment.js";
import { collectionStatus } from "./document-multisig.js";

export interface DocumentStateView {
  participants: ReadonlySet<string>;
  admins: ReadonlySet<string>;
  properties: Record<string, string | number | boolean | undefined>;
  /** The total order actually folded (applied AND void entries — F4 keeps voids in history). */
  order: readonly string[];
  /** Heads: included entries no other included entry names as a parent. Ascending. */
  frontier: readonly string[];
  /** Fold-void entries, each with the reason it contributed nothing. */
  voids: readonly { hash: string; reason: string }[];
  /** Entries whose ancestry is not fully present — held out entirely, never guessed at (R14). */
  excluded: readonly { hash: string; reason: string }[];
  /** Highest seq per author among included entries — the watermark seed. */
  authorSeqs: ReadonlyMap<string, number>;
  /** Interim carrier fields until P4 deletes the epoch spine (D7, gated on SYNC-G1). */
  interimMaxEpoch: number;
  interimLastHash: string | null;
}

export type DeriveDocumentStateResult =
  | { ok: true; state: DocumentStateView }
  | { ok: false; reason: string };

type VerifyFn = (agentId: string, tbs: Uint8Array, signature: Uint8Array) => boolean;

/**
 * The STATE-INDEPENDENT admission check — what an inbound path may refuse outright, because no
 * future entry can ever make it good: the collection must bind to this entry, the claimed author
 * must be in the required set, and every claimed signature must verify. Everything else — subject
 * semantics, policy, concurrency — is the fold's ruling, and a fold-void entry is still HISTORY
 * (F4): it must be stored and shared, never bounced at the door, or two holders end up holding
 * different sets.
 */
export function checkEntryAdmissible(
  env: DocumentAmendmentEnvelope,
  verify: VerifyFn,
): { ok: true } | { ok: false; reason: string } {
  const body = env.body;
  if (!env.collection.required_signers.includes(body.author_agent_id)) {
    return {
      ok: false,
      reason:
        `entry_author_not_required: the claimed author ${body.author_agent_id} is not in the ` +
        `collection's required set — accountability is signed, not asserted`,
    };
  }
  if (env.collection.document_id !== body.document_id) {
    return {
      ok: false,
      reason: `amendment_collection_document_mismatch: collection names ${env.collection.document_id}`,
    };
  }
  if (env.collection.subject_kind !== AMENDMENT_SUBJECT_KIND) {
    return {
      ok: false,
      reason: `amendment_collection_kind: collection signs "${env.collection.subject_kind}", not an amendment`,
    };
  }
  const expected = documentAmendmentHash(body);
  if (Buffer.compare(env.collection.subject_hash, expected) !== 0) {
    return {
      ok: false,
      reason:
        "amendment_collection_subject_mismatch: the collection signs a different entry than the " +
        "one it rides with",
    };
  }
  const status = collectionStatus(env.collection, verify);
  if (!status.complete) {
    return {
      ok: false,
      reason:
        `amendment_collection_incomplete: missing [${status.missing.join(", ")}], invalid ` +
        `[${status.invalidSigners.join(", ")}], unknown [${status.unknown.join(", ")}], ` +
        `duplicate [${status.duplicates.join(", ")}]`,
    };
  }
  return { ok: true };
}

interface FoldState {
  participants: Set<string>;
  admins: Set<string>;
  properties: Record<string, string | number | boolean | undefined>;
}

function isRemoval(kind: string): boolean {
  return kind === "remove_holder" || kind === "remove_admin";
}

export function deriveDocumentState(
  genesis: ArrangementGenesis,
  entries: readonly DocumentAmendmentEnvelope[],
  policy: SignerPolicy,
  verify: VerifyFn,
): DeriveDocumentStateResult {
  // ── Genesis — document-level refusals, exactly the linear replay's ─────────────────────────
  const genesisParticipants = new Set([genesis.proposerAgentId, genesis.peerAgentId]);
  const genesisAdmins = new Set(genesis.adminSet);
  if (genesisAdmins.size === 0) {
    return {
      ok: false,
      reason:
        "arrangement_admin_set_empty: a document with no admins can never be amended — the " +
        "creation flow must name at least one",
    };
  }
  for (const admin of genesisAdmins) {
    if (!genesisParticipants.has(admin)) {
      return {
        ok: false,
        reason:
          `arrangement_admin_not_participant: ${admin} holds admin power but is not a holder — ` +
          `admins are always holders`,
      };
    }
  }

  // ── Index by hash (exact duplicates collapse — idempotence is free) ─────────────────────────
  const byHash = new Map<string, DocumentAmendmentEnvelope>();
  for (const env of entries) {
    byHash.set(Buffer.from(documentAmendmentHash(env.body)).toString("hex"), env);
  }

  // ── Exclusion: only entries whose FULL ancestry is present participate (R14 defensively) ────
  const includedMemo = new Map<string, boolean>();
  function isIncluded(hash: string): boolean {
    const known = includedMemo.get(hash);
    if (known !== undefined) return known;
    const env = byHash.get(hash);
    if (env === undefined) {
      includedMemo.set(hash, false);
      return false;
    }
    // Mark in-progress false to break cycles (a hash cycle is unconstructable for honest SHA-256
    // entries, but the walk must not hang on a crafted set).
    includedMemo.set(hash, false);
    const ok = env.body.parents.every((p) => isIncluded(p));
    includedMemo.set(hash, ok);
    return ok;
  }
  const included = new Map<string, DocumentAmendmentEnvelope>();
  const excluded: { hash: string; reason: string }[] = [];
  for (const hash of byHash.keys()) {
    if (isIncluded(hash)) {
      included.set(hash, byHash.get(hash)!);
    } else {
      excluded.push({
        hash,
        reason:
          "entry_ancestry_incomplete: a named parent (or one of its ancestors) is not held — " +
          "the entry is held out, never applied on a guess",
      });
    }
  }

  // ── Ancestor closures (memoized) ────────────────────────────────────────────────────────────
  const closureMemo = new Map<string, Set<string>>();
  function closure(hash: string): Set<string> {
    const known = closureMemo.get(hash);
    if (known !== undefined) return known;
    const out = new Set<string>();
    closureMemo.set(hash, out);
    const env = included.get(hash);
    if (env) {
      for (const p of env.body.parents) {
        out.add(p);
        for (const g of closure(p)) out.add(g);
      }
    }
    return out;
  }

  // ── The deterministic total order: Kahn, ready set by ascending hash ────────────────────────
  function linearize(subset: ReadonlySet<string>): string[] {
    const pending = new Set(subset);
    const done = new Set<string>();
    const order: string[] = [];
    while (pending.size > 0) {
      let next: string | null = null;
      for (const hash of pending) {
        const env = included.get(hash)!;
        const ready = env.body.parents.every((p) => done.has(p) || !subset.has(p));
        if (ready && (next === null || hash < next)) next = hash;
      }
      // Unreachable for included entries (ancestry is complete), kept as a loud invariant.
      if (next === null) throw new Error("entry_linearize_stuck: no ready entry in a nonempty set");
      order.push(next);
      pending.delete(next);
      done.add(next);
    }
    return order;
  }

  // ── Per-entry checks that need no state ─────────────────────────────────────────────────────
  function structuralVoid(env: DocumentAmendmentEnvelope, hash: string): string | null {
    const body = env.body;
    if (body.document_id !== genesis.documentId) {
      return `entry_wrong_document: names ${body.document_id}, deriving ${genesis.documentId}`;
    }
    if (!env.collection.required_signers.includes(body.author_agent_id)) {
      return (
        `entry_author_not_required: the claimed author ${body.author_agent_id} is not in the ` +
        `collection's required set — accountability is signed, not asserted`
      );
    }
    if (env.collection.document_id !== body.document_id) {
      return `amendment_collection_document_mismatch: collection names ${env.collection.document_id}`;
    }
    if (env.collection.subject_kind !== AMENDMENT_SUBJECT_KIND) {
      return `amendment_collection_kind: collection signs "${env.collection.subject_kind}", not an amendment`;
    }
    const expected = documentAmendmentHash(body);
    if (Buffer.compare(env.collection.subject_hash, expected) !== 0) {
      return (
        "amendment_collection_subject_mismatch: the collection signs a different entry than the " +
        "one it rides with"
      );
    }
    if (body.author_seq > 1) {
      // The author's previous entry must be among the ANCESTORS — a direct parent is the common
      // case, but authoring on a frontier that already causally contains your own last entry is
      // the normal shape of concurrent work.
      const ancestors = closure(hash);
      let prevOwn = false;
      for (const p of ancestors) {
        const parent = included.get(p);
        if (
          parent !== undefined &&
          parent.body.author_agent_id === body.author_agent_id &&
          parent.body.author_seq === body.author_seq - 1
        ) {
          prevOwn = true;
          break;
        }
      }
      if (!prevOwn) {
        return (
          `entry_own_chain_broken: seq ${body.author_seq} by ${body.author_agent_id} is not ` +
          `causally after that author's seq ${body.author_seq - 1} — an author's own entries ` +
          `form a chain`
        );
      }
    }
    return null;
  }

  /** Subject semantics + policy + completeness against a given state. Null = takes effect. */
  function effectVoid(env: DocumentAmendmentEnvelope, state: FoldState): string | null {
    const body = env.body;
    const subject = body.subject_agent_id;
    if (body.state_hash !== null && state.properties["assurance_tier"] !== "attested") {
      return (
        `amendment_state_hash_tier: carries a canonical state hash but the document's tier is ` +
        `${JSON.stringify(state.properties["assurance_tier"] ?? null)} — only "attested" (Tier 2) ` +
        `defines that slot`
      );
    }
    switch (body.kind) {
      case "add_holder": {
        if (subject === null) return `amendment_subject_required: add_holder names nobody`;
        if (state.participants.has(subject)) {
          return `amendment_subject_already_holder: ${subject} already holds this document`;
        }
        if (state.participants.size + 1 > MAX_DOCUMENT_HOLDERS) {
          return (
            `amendment_holder_cap: admitting ${subject} would make ` +
            `${state.participants.size + 1} holders and the cap is ${MAX_DOCUMENT_HOLDERS} (D5)`
          );
        }
        break;
      }
      case "remove_holder": {
        if (subject === null) return `amendment_subject_required: remove_holder names nobody`;
        if (!state.participants.has(subject)) {
          return `amendment_subject_not_holder: ${subject} does not hold this document`;
        }
        break;
      }
      case "promote_admin": {
        if (subject === null) return `amendment_subject_required: promote_admin names nobody`;
        if (!state.participants.has(subject)) {
          return `amendment_subject_not_holder: ${subject} does not hold this document`;
        }
        if (state.admins.has(subject)) {
          return `amendment_subject_already_admin: ${subject} is already an admin`;
        }
        break;
      }
      case "remove_admin": {
        if (subject === null) return `amendment_subject_required: remove_admin names nobody`;
        if (!state.admins.has(subject)) {
          return `amendment_subject_not_admin: ${subject} holds no admin power to remove`;
        }
        break;
      }
      case "change_property": {
        if (subject !== null) {
          return `amendment_subject_forbidden: change_property is about the document, not a holder`;
        }
        if (body.property_change === null) {
          return `amendment_property_missing: change_property carries no change`;
        }
        if (!AMENDABLE_PROPERTIES.has(body.property_change.key)) {
          return (
            `amendment_property_not_amendable: "${body.property_change.key}" is not amendable — ` +
            `the amendable set is {${[...AMENDABLE_PROPERTIES].join(", ")}}`
          );
        }
        break;
      }
    }
    const verdict = policy(body.kind, subject, state, env.collection.required_signers);
    if (!verdict.ok) return verdict.reason;
    const status = collectionStatus(env.collection, verify);
    if (!status.complete) {
      return (
        `amendment_collection_incomplete: missing [${status.missing.join(", ")}], invalid ` +
        `[${status.invalidSigners.join(", ")}], unknown [${status.unknown.join(", ")}], ` +
        `duplicate [${status.duplicates.join(", ")}]`
      );
    }
    return null;
  }

  function apply(env: DocumentAmendmentEnvelope, state: FoldState): void {
    const body = env.body;
    switch (body.kind) {
      case "add_holder":
        state.participants.add(body.subject_agent_id!);
        break;
      case "remove_holder":
        state.participants.delete(body.subject_agent_id!);
        state.admins.delete(body.subject_agent_id!);
        break;
      case "promote_admin":
        state.admins.add(body.subject_agent_id!);
        break;
      case "remove_admin":
        state.admins.delete(body.subject_agent_id!);
        break;
      case "change_property":
        state.properties[body.property_change!.key] = body.property_change!.value;
        break;
    }
  }

  // ── F2: is a removal valid at its OWN ancestors? Memoized; recursion strictly shrinks. ──────
  const removalVerdictMemo = new Map<string, { ok: boolean; reason: string | null }>();
  function removalValidAtAncestors(hash: string): { ok: boolean; reason: string | null } {
    const known = removalVerdictMemo.get(hash);
    if (known !== undefined) return known;
    const env = included.get(hash)!;
    const ancestorState = foldSubset(closure(hash)).state;
    const reason = effectVoid(env, ancestorState);
    const verdict = { ok: reason === null, reason };
    removalVerdictMemo.set(hash, verdict);
    return verdict;
  }

  /** F1's concurrency void: an ancestor-valid removal of this author, this entry not ancestral to it. */
  function concurrentRemovalOf(
    subset: ReadonlySet<string>,
    entryHash: string,
    author: string,
  ): string | null {
    for (const other of subset) {
      if (other === entryHash) continue;
      const env = included.get(other)!;
      if (!isRemoval(env.body.kind)) continue;
      if (env.body.subject_agent_id !== author) continue;
      if (!structuralOk(other)) continue;
      if (!removalValidAtAncestors(other).ok) continue;
      const removalAncestors = closure(other);
      if (removalAncestors.has(entryHash)) continue; // the removers had seen it — it stands
      return other;
    }
    return null;
  }

  const structuralMemo = new Map<string, string | null>();
  function structuralOk(hash: string): boolean {
    let cached = structuralMemo.get(hash);
    if (cached === undefined) {
      cached = structuralVoid(included.get(hash)!, hash);
      structuralMemo.set(hash, cached);
    }
    return cached === null;
  }

  // ── The fold — one function, used for the full set and (recursively) for ancestor subsets ───
  function foldSubset(subset: ReadonlySet<string>): {
    state: FoldState;
    order: string[];
    voids: { hash: string; reason: string }[];
  } {
    const state: FoldState = {
      participants: new Set(genesisParticipants),
      admins: new Set(genesisAdmins),
      properties: { ...genesis.properties },
    };
    const order = linearize(subset);
    const voids: { hash: string; reason: string }[] = [];
    for (const hash of order) {
      const env = included.get(hash)!;
      const structural = structuralMemo.get(hash) ?? structuralVoid(env, hash);
      structuralMemo.set(hash, structural);
      if (structural !== null) {
        voids.push({ hash, reason: structural });
        continue;
      }
      if (isRemoval(env.body.kind)) {
        const verdict = removalValidAtAncestors(hash);
        if (!verdict.ok) {
          voids.push({ hash, reason: verdict.reason! });
          continue;
        }
        // The admin floor (Entry 49): a removal that would empty the admin set is void HERE, at
        // its fold position — the one check a removal answers to fold state.
        const subject = env.body.subject_agent_id!;
        const wouldEmptyAdmins =
          state.admins.has(subject) && state.admins.size === 1;
        if (wouldEmptyAdmins) {
          voids.push({
            hash,
            reason:
              `entry_admin_floor: removing ${subject} at this position would leave the document ` +
              `with no admins — it could never be amended again`,
          });
          continue;
        }
        // Idempotence at fold position: the subject may already be gone (a concurrent duplicate
        // removal). Nothing to do is not a conflict.
        apply(env, state);
        continue;
      }
      const removal = concurrentRemovalOf(subset, hash, env.body.author_agent_id);
      if (removal !== null) {
        voids.push({
          hash,
          reason:
            `entry_void_concurrent_removal: authored by ${env.body.author_agent_id} concurrently ` +
            `with their own removal (${removal}) — a removed party's concurrent authority does ` +
            `not stand`,
        });
        continue;
      }
      const ineffective = effectVoid(env, state);
      if (ineffective !== null) {
        voids.push({ hash, reason: ineffective });
        continue;
      }
      apply(env, state);
    }
    return { state, order, voids };
  }

  const allIncluded = new Set(included.keys());
  const { state, order, voids } = foldSubset(allIncluded);

  // ── Derived views for the surface and the authoring path ────────────────────────────────────
  const namedAsParent = new Set<string>();
  for (const env of included.values()) {
    for (const p of env.body.parents) namedAsParent.add(p);
  }
  const frontier = [...included.keys()].filter((h) => !namedAsParent.has(h)).sort();

  const authorSeqs = new Map<string, number>();
  let interimMaxEpoch = 0;
  for (const env of included.values()) {
    const author = env.body.author_agent_id;
    const seq = env.body.author_seq;
    if ((authorSeqs.get(author) ?? 0) < seq) authorSeqs.set(author, seq);
    if (env.body.epoch_id > interimMaxEpoch) interimMaxEpoch = env.body.epoch_id;
  }

  return {
    ok: true,
    state: {
      participants: state.participants,
      admins: state.admins,
      properties: state.properties,
      order,
      frontier,
      voids,
      excluded,
      authorSeqs,
      interimMaxEpoch,
      interimLastHash: order.length > 0 ? order[order.length - 1]! : null,
    },
  };
}
