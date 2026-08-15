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
import { DOCUMENT_FEATURE_VERSION } from "./document-proposal.js";

export interface DocumentStateView {
  participants: ReadonlySet<string>;
  /** Admitted, not yet answered (R22) — a seat at the table, not a voice. Counts toward the cap. */
  invited: ReadonlySet<string>;
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
 * SYNC-G1 — the derivation AT a named governance frontier: the fold restricted to the ancestor
 * closure of `frontierHashes`. This is what content admissibility rules on (R20/R30): was the
 * envelope's author a participant in the world its signed `governance_parents` name? Judged
 * from the named ancestors alone — the same bounded backdating concession Entry 48 accepted
 * for governance: a lying daemon admits exactly what an honest holder AT THAT POSITION could
 * have authored, and the fold's removal dominance keeps it out of governance regardless.
 *
 * A frontier hash not present in `entries` is the caller's signal to reconcile first — this
 * function reports it rather than guessing (`missing`).
 */
export function deriveDocumentStateAt(
  genesis: ArrangementGenesis,
  entries: readonly DocumentAmendmentEnvelope[],
  frontierHashes: readonly string[],
  policy: SignerPolicy,
  verify: VerifyFn,
): { ok: true; state: DocumentStateView } | { ok: false; reason: string; missing?: string[] } {
  const byHash = new Map(
    entries.map((env) => [
      Buffer.from(documentAmendmentHash(env.body)).toString("hex"),
      env,
    ]),
  );
  const missing = frontierHashes.filter((h) => !byHash.has(h));
  if (missing.length > 0) {
    return {
      ok: false,
      reason:
        `derive_frontier_missing: ${missing.length} of the named governance ancestors are not ` +
        `held — reconcile before ruling`,
      missing,
    };
  }
  const wanted = new Set<string>();
  const queue = [...frontierHashes];
  while (queue.length > 0) {
    const h = queue.pop()!;
    if (wanted.has(h)) continue;
    wanted.add(h);
    const env = byHash.get(h);
    if (env) queue.push(...env.body.parents);
  }
  const subset = entries.filter((env) =>
    wanted.has(Buffer.from(documentAmendmentHash(env.body)).toString("hex")),
  );
  return deriveDocumentState(genesis, subset, policy, verify);
}

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
  invited: Set<string>;
  admins: Set<string>;
  /**
   * Declared genesis admins whose grant a removal has SPENT (P2 review F6): once demoted or
   * removed, a declared admin re-admitted later arrives as a plain holder — only an explicit
   * promote_admin, with its signature requirements, re-arms them. A refusal spends nothing.
   */
  spentDeclaredAdmins: Set<string>;
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
  // ── Genesis — document-level refusals ───────────────────────────────────────────────────────
  // R21/R22: the proposer's signature on the proposal IS their consent; the peer is INVITED
  // until their own consent entry applies. Declared admin power activates with participation —
  // a declared-admin peer is briefly powerless, which self-resolves at their consent.
  const genesisParticipants = new Set([genesis.proposerAgentId]);
  const genesisInvited = new Set(
    genesis.peerAgentId === genesis.proposerAgentId ? [] : [genesis.peerAgentId],
  );
  const declaredGenesisAdmins = new Set(genesis.adminSet);
  if (declaredGenesisAdmins.size === 0) {
    return {
      ok: false,
      reason:
        "arrangement_admin_set_empty: a document with no admins can never be amended — the " +
        "creation flow must name at least one",
    };
  }
  for (const admin of declaredGenesisAdmins) {
    if (admin !== genesis.proposerAgentId && admin !== genesis.peerAgentId) {
      return {
        ok: false,
        reason:
          `arrangement_admin_not_participant: ${admin} holds admin power but is not a genesis ` +
          `party — admins are always holders`,
      };
    }
  }
  const genesisAdmins = new Set(
    [...declaredGenesisAdmins].filter((id) => genesisParticipants.has(id)),
  );

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
        if (state.invited.has(subject)) {
          return `amendment_subject_already_invited: ${subject} already holds an open invitation`;
        }
        // Invited seats ARE seats — counting only consented holders would let over-inviting
        // smuggle a 21st past the door.
        const admitted = state.participants.size + state.invited.size;
        if (admitted + 1 > MAX_DOCUMENT_HOLDERS) {
          return (
            `amendment_holder_cap: admitting ${subject} would make ${admitted + 1} admitted ` +
            `seats and the cap is ${MAX_DOCUMENT_HOLDERS} (D5)`
          );
        }
        break;
      }
      case "consent": {
        if (subject === null) return `amendment_subject_required: consent names nobody`;
        if (body.author_agent_id !== subject) {
          return (
            `entry_consent_not_subject: a consent is the subject's own act — authored by ` +
            `${body.author_agent_id}, names ${subject}`
          );
        }
        if (!state.invited.has(subject)) {
          return (
            `amendment_subject_not_invited: ${subject} has no open invitation to answer at this ` +
            `position`
          );
        }
        const expected = `${String(state.properties["assurance_tier"])}/${DOCUMENT_FEATURE_VERSION}`;
        const claimed_to =
          body.property_change?.key === "consents_to" ? String(body.property_change.value) : null;
        if (claimed_to !== expected) {
          return (
            `entry_consents_to_mismatch: the consent claims "${claimed_to ?? "nothing"}" and ` +
            `this document is "${expected}" — what was agreed to must be what stands (R22)`
          );
        }
        break;
      }
      case "refuse_join": {
        if (subject === null) return `amendment_subject_required: refuse_join names nobody`;
        if (body.author_agent_id !== subject) {
          return (
            `entry_consent_not_subject: a refusal is the subject's own act — authored by ` +
            `${body.author_agent_id}, names ${subject}`
          );
        }
        if (!state.invited.has(subject)) {
          return (
            `amendment_subject_not_invited: ${subject} has no open invitation to refuse at this ` +
            `position`
          );
        }
        break;
      }
      case "remove_holder": {
        if (subject === null) return `amendment_subject_required: remove_holder names nobody`;
        // An INVITED seat is removable too — that is invitation retraction (P3): an admin takes
        // back an unanswered offer, and a consent concurrent with the retraction is void under
        // the same removal-dominance every other authority conflict follows.
        if (!state.participants.has(subject) && !state.invited.has(subject)) {
          return `amendment_subject_not_holder: ${subject} neither holds this document nor holds an invitation to it`;
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
        state.invited.add(body.subject_agent_id!);
        break;
      case "consent":
        state.invited.delete(body.subject_agent_id!);
        state.participants.add(body.subject_agent_id!);
        // A declared genesis admin's power arrives WITH their participation (R21) — unless a
        // removal already spent the grant (F6): the re-admitted return as plain holders.
        if (
          declaredGenesisAdmins.has(body.subject_agent_id!) &&
          !state.spentDeclaredAdmins.has(body.subject_agent_id!)
        ) {
          state.admins.add(body.subject_agent_id!);
        }
        break;
      case "refuse_join":
        state.invited.delete(body.subject_agent_id!);
        break;
      case "remove_holder":
        state.participants.delete(body.subject_agent_id!);
        state.invited.delete(body.subject_agent_id!);
        if (state.admins.has(body.subject_agent_id!)) {
          state.spentDeclaredAdmins.add(body.subject_agent_id!);
        }
        state.admins.delete(body.subject_agent_id!);
        break;
      case "promote_admin":
        state.admins.add(body.subject_agent_id!);
        break;
      case "remove_admin":
        state.spentDeclaredAdmins.add(body.subject_agent_id!);
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

  /**
   * F1's concurrency void: an ancestor-valid removal of this author, CONCURRENT with this entry —
   * neither is an ancestor of the other. An entry the removers had seen stands; an entry authored
   * AFTER the removal (removal among its ancestors) is not concurrent either — it is the
   * fold-position state's question, which fails safe: without a re-admission the author is no
   * longer a participant there and the act voids on its own merits, while after a legitimate
   * re-admission it must take effect (the Entry 48 re-admission promise).
   *
   * RULED (M14B Entry 51, review F3): this check consults ancestor-validity, NOT the admin
   * floor — so in the all-admins-remove-each-other race, the floor-voided removal still voids
   * its victim's concurrent non-removal acts. Deterministic on every holder, err-on-the-safe
   * side (the removal was pairwise legitimate), and the alternative needs a second fold pass
   * for a case that takes every admin co-signing against every other to construct.
   */
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
      if (closure(other).has(entryHash)) continue; // the removers had seen it — it stands
      if (closure(entryHash).has(other)) continue; // authored after the removal — not concurrent
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
      invited: new Set(genesisInvited),
      admins: new Set(genesisAdmins),
      spentDeclaredAdmins: new Set(),
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
      invited: state.invited,
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
