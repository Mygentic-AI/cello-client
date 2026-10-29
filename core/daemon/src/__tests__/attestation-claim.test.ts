/**
 * M10E 011-CLAIM — the holder of a right writes a review; the daemon seals it as an `attest`
 * submission and keeps the author's own copy; `claimed` lists those copies with their outcomes.
 *
 * Real keys, a fake signaling object (as in 005's tests). `submitAttest` and the local-copy store are
 * injected so the unit under test is the PAYLOAD it builds and the subject it names — the signing and
 * sealing it delegates to are the endorsement path's, already covered there.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { generateKeypair, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  attestationTemplateHash,
  decodeAttestationPayload,
  encodeAttestationPayload,
  encodeAttestationRight,
  hashAttestationRight,
  type AttestationRight,
} from "@cello-protocol/protocol-types";
import { claimRight, listClaimedAttestations, type ClaimSubmitResult, type ClaimedCopy } from "../attestation-claim.js";
import type { ServiceEventDeps } from "../attestation-service-events.js";
import type { SubmissionResult } from "../signal-submission.js";
import type { Logger } from "../types.js";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

interface FakeSignaling {
  sent: Array<Record<string, unknown>>;
  push: (reply: Record<string, unknown>) => void;
  /** Reply with `reply` the moment a frame of `onType` is sent — so the responder is registered
   *  before the reply arrives, unlike a bare microtask push which races handler registration. */
  replyTo: (onType: string, reply: Record<string, unknown>) => void;
  sendRaw: (frame: unknown) => Promise<{ ok: boolean; reason?: string }>;
  registerInboundHandler: (h: (f: Record<string, unknown>) => void) => () => void;
}
function makeSignaling(): FakeSignaling {
  const sent: Array<Record<string, unknown>> = [];
  const handlers = new Set<(f: Record<string, unknown>) => void>();
  const replies = new Map<string, Record<string, unknown>>();
  const push = (reply: Record<string, unknown>): void => { for (const h of [...handlers]) h(reply); };
  return {
    sent,
    push,
    replyTo: (onType, reply) => { replies.set(onType, reply); },
    sendRaw: async (frame) => {
      const f = frame as Record<string, unknown>;
      sent.push(f);
      const reply = typeof f["type"] === "string" ? replies.get(f["type"] as string) : undefined;
      if (reply) queueMicrotask(() => push(reply));
      return { ok: true };
    },
    registerInboundHandler: (h) => { handlers.add(h); return () => handlers.delete(h); },
  };
}

interface SpyLogger extends Logger { events: Array<{ level: string; event: string }>; }
function makeLogger(): SpyLogger {
  const events: SpyLogger["events"] = [];
  const rec = (level: string) => (event: string) => { events.push({ level, event }); };
  return { events, debug: rec("debug"), info: rec("info"), warn: rec("warn"), error: rec("error") } as SpyLogger;
}

const NOW_MS = 1_800_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);
const SID = "cd".repeat(16); // 16 bytes

let sig: FakeSignaling;
let logger: SpyLogger;
let me: InMemoryKeyProvider;
let them: InMemoryKeyProvider;
let mePub: string;
let themPub: string;

beforeEach(async () => {
  sig = makeSignaling();
  logger = makeLogger();
  me = generateKeypair();
  them = generateKeypair();
  mePub = hex(await me.getPublicKey());
  themPub = hex(await them.getPublicKey());
});

function svcDeps(): ServiceEventDeps {
  return {
    signaling: sig, keyProvider: me, ownerPubkeyHex: mePub, now: () => NOW_MS, logger,
    loadSessionProof: () => null,
    chainHeadHash: () => new Uint8Array(32),
    timeoutMs: 120,
  };
}

/**
 * A right record naming `them` as subject and `me` as holder. The record encoder enforces a 7-day
 * TTL floor, so `expired` is produced by an OLD created_at with a valid TTL — never a tiny TTL — just
 * as `listRights` decides expiry from our clock against the signed expires_at.
 */
const WEEK = 604800;
function rightRecord(template: "text" | "scored", opts: { expired?: boolean } = {}): AttestationRight {
  const createdAt = opts.expired ? NOW_S - WEEK - 100 : NOW_S - 10;
  return {
    service_event_hash: new Uint8Array(32).fill(1), holder_pubkey: mePub, subject_pubkey: themPub,
    namespace: "reviews.alpha", template_hash: attestationTemplateHash(template),
    session_id: new Uint8Array(Buffer.from(SID, "hex")), created_at: createdAt,
    expires_at: createdAt + WEEK, kind: "service_event",
  };
}

/** Arm the directory's `attestation_rights` reply carrying the given rights, and return their ids. */
function pushRights(rights: AttestationRight[]): string[] {
  const entries = rights.map((r) => ({ right: encodeAttestationRight(r), right_id: hex(hashAttestationRight(r)) }));
  sig.replyTo("attestation_rights_list", { type: "attestation_rights", entries, next: null });
  return entries.map((e) => e.right_id);
}

function capturingSubmit(result: ClaimSubmitResult) {
  const calls: Array<{ subject: string; bodyHex: string }> = [];
  const submitAttest = async (subject: string, bodyHex: string): Promise<ClaimSubmitResult> => {
    calls.push({ subject, bodyHex }); return result;
  };
  return { calls, submitAttest };
}

describe("011-CLAIM — claimRight", () => {
  it("A1. builds a payload whose right_id is the right's, submits an attest to the right's subject, keeps a local copy", async () => {
    const [rightId] = pushRights([rightRecord("scored")]);
    const { calls, submitAttest } = capturingSubmit({ queued: true, stored: true, submissionId: "sub-1" });
    const stored: ClaimedCopy[] = [];
    const res = await claimRight(
      { svc: svcDeps(), submitAttest, storeLocalCopy: (c) => stored.push(c as unknown as ClaimedCopy), now: () => NOW_MS, logger },
      { rightId: rightId!, rating: 5, text: "Great to work with" },
    );
    expect(res.ok).toBe(true);
    expect(calls).toHaveLength(1);
    // Signed to the right's SUBJECT, not an input the caller chose.
    expect(calls[0]!.subject).toBe(themPub);
    const payload = decodeAttestationPayload(new Uint8Array(Buffer.from(calls[0]!.bodyHex, "hex")));
    expect(hex(payload.right_id)).toBe(rightId);
    expect(payload.namespace).toBe("reviews.alpha");
    expect(payload.body).toEqual([5, "Great to work with"]);
    // A local copy is KEPT, keyed on the content-derived submission id.
    expect(stored).toHaveLength(1);
    expect(stored[0]!.submissionId).toBe("sub-1");
    expect(hex(stored[0]!.payload)).toBe(calls[0]!.bodyHex);
  });

  it("A2. an expired right, or one not listed, is refused locally and nothing is submitted", async () => {
    const [expiredId] = pushRights([rightRecord("scored", { expired: true })]);
    const s1 = capturingSubmit({ queued: true, submissionId: "x" });
    const expired = await claimRight(
      { svc: svcDeps(), submitAttest: s1.submitAttest, storeLocalCopy: () => {}, now: () => NOW_MS, logger },
      { rightId: expiredId!, rating: 5, text: "late" },
    );
    expect(expired).toMatchObject({ ok: false, reason: "right_expired" });
    expect(s1.calls).toHaveLength(0);

    pushRights([rightRecord("scored")]); // a different, valid right is listed…
    const s2 = capturingSubmit({ queued: true, submissionId: "x" });
    const missing = await claimRight(
      { svc: svcDeps(), submitAttest: s2.submitAttest, storeLocalCopy: () => {}, now: () => NOW_MS, logger },
      { rightId: "ab".repeat(32), rating: 5, text: "unknown" }, // …but not this id
    );
    expect(missing).toMatchObject({ ok: false, reason: "no_such_right" });
    expect(s2.calls).toHaveLength(0);
  });

  it("A3. a scored namespace with no rating is refused rating_required, and nothing is submitted", async () => {
    const [rightId] = pushRights([rightRecord("scored")]);
    const { calls, submitAttest } = capturingSubmit({ queued: true, submissionId: "x" });
    const res = await claimRight(
      { svc: svcDeps(), submitAttest, storeLocalCopy: () => {}, now: () => NOW_MS, logger },
      { rightId: rightId!, text: "no rating" },
    );
    expect(res).toMatchObject({ ok: false, reason: "rating_required" });
    expect(calls).toHaveLength(0);
  });
});

describe("011-CLAIM — claimed", () => {
  it("A8. lists each local copy with its submission outcome", async () => {
    const r = rightRecord("scored");
    const rightId = hex(hashAttestationRight(r));
    // Build a payload exactly as claimRight would, so the stored copy decodes.
    const [listedId] = pushRights([r]);
    const captured = capturingSubmit({ queued: true, submissionId: "sub-7" });
    const stored: ClaimedCopy[] = [];
    await claimRight(
      { svc: svcDeps(), submitAttest: captured.submitAttest, storeLocalCopy: (c) => stored.push(c as unknown as ClaimedCopy), now: () => NOW_MS, logger },
      { rightId: listedId!, rating: 4, text: "solid" },
    );
    expect(rightId).toBe(listedId);

    const result: SubmissionResult = {
      submissionId: "sub-7", outcome: "minted", reason: null, signalHash: "aa".repeat(32), message: null, createdAt: "t",
    };
    const view = await listClaimedAttestations({
      loadLocalCopies: () => stored,
      fetchResults: async () => ({ ok: true, results: [result] }),
      logger,
    });
    expect(view.claimed).toHaveLength(1);
    expect(view.claimed[0]).toMatchObject({
      submission_id: "sub-7", right_id: rightId, subject_pubkey: themPub,
      namespace: "reviews.alpha", rating: 4, text: "solid", outcome: "minted",
    });
  });

  it("a copy with no returned outcome shows pending, never a fabricated success", async () => {
    const r = rightRecord("text");
    const payloadCopy: ClaimedCopy = {
      submissionId: "sub-9", rightId: hex(hashAttestationRight(r)), subject: themPub,
      // encode a real text payload
      payload: encodeAttestationPayload({
        right_id: hashAttestationRight(r), namespace: r.namespace, template_hash: r.template_hash,
        session_id: r.session_id, origin_channel: null, body: ["fine"],
      }),
      createdAt: NOW_S,
    };
    const view = await listClaimedAttestations({
      loadLocalCopies: () => [payloadCopy],
      fetchResults: async () => ({ ok: false, reason: "results_unreachable", guidance: "x" }),
      logger,
    });
    expect(view.claimed[0]!.outcome).toBe("pending");
    expect(view.results_unavailable).toBe("results_unreachable");
  });
});
