/**
 * M10E 016-INBOX — a delivered PRIVATE attestation (a review someone wrote about this agent) is
 * something to READ, so it belongs in the inbox as quoted, untrusted data — NOT in the trust-signal
 * wallet, which holds the signals an agent PRESENTS to others when it connects.
 *
 * Real keys, real SQLCipher (never node:sqlite). The envelope is a genuine canonical trust-signal
 * envelope of type `attestation`, the exact shape the directory delivers down a pickup.
 *
 *   I1 — a delivered private attestation appears in the inbox, with its text in a quoted-data field.
 *   I2 — it is absent from the trust-signal wallet and from any list used to present signals.
 *   I3 — the pickup is acked; a failed inbox write leaves it un-acked.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import {
  ATTESTATION_SIGNAL_TYPE,
  attestationTemplateHash,
  decodeTrustSignalEnvelope,
  encodeAttestationPayload,
  encodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  type AttestationPayload,
  type TrustSignalEnvelope,
} from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureSessionSchema } from "../session-schema.js";
import { AttestationNotices } from "../attestation-notices.js";
import { TrustSignalStore } from "../trust-signal-store.js";
import { createInboundSessions, type InboundSessionDeps } from "../inbound-sessions.js";
import type { Logger } from "../types.js";

const SUBJECT = "a1".repeat(32); // the agent the review is ABOUT (this daemon's agent)
const REVIEWER = "b2".repeat(32); // who wrote the review
const quiet: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

/** A genuine canonical `attestation`-typed trust-signal envelope — exactly what a pickup delivers. */
function buildPrivateReview(text: string, rating: number | null = 5): { bytes: Uint8Array; hash: string } {
  const body: unknown[] = rating === null ? [text] : [rating, text];
  const payload: AttestationPayload = {
    right_id: randomBytes(32),
    namespace: "support.qa",
    template_hash: attestationTemplateHash(rating === null ? "text" : "scored"),
    session_id: randomBytes(16),
    origin_channel: null,
    body,
  };
  const envelope: TrustSignalEnvelope = {
    subject_kind: "agent",
    subject: SUBJECT,
    issuer_kind: "agent",
    issuer_pubkey: REVIEWER,
    type: ATTESTATION_SIGNAL_TYPE,
    schema_version: 1,
    payload: encodeAttestationPayload(payload),
    issued_at: 1_800_000_000,
    expires_at: null,
    supersedes_hash: null,
    same_operator: false,
  };
  const bytes = encodeTrustSignalEnvelope(envelope);
  return { bytes, hash: Buffer.from(hashTrustSignalEnvelope(envelope)).toString("hex") };
}

/** Drive the REAL `handleTrustSignalPickup` with a minimal harness around a real database. */
function buildInbound(db: DaemonDatabase | null) {
  const sessionNodeManager = {
    getDb: () => db,
    resolveAgentId: (name: string) => `aid-${name}`,
  };
  const inbound = createInboundSessions({
    logger: quiet,
    sessionNodeManager,
    agents: [],
    getConnState: () => undefined,
    resolveCurrentAgent: () => null,
    NO_CURRENT_AGENT_RESPONSE: {},
    getKeyProvider: () => undefined,
    sharedSignaling: undefined,
    handleInboundSealInterruptedRequest: async () => {},
    reapDeadHalfOpenSessions: () => {},
    sendAwayResponse: async () => {},
    dispatchSessionStateChangedWithTelegram: () => {},
    sendTelegramDoorbell: async () => {},
    isDeliveryOpenToAgent: () => false,
    isChannelAgent: () => false,
    isSubscribedChannel: () => false,
    sendOver: async () => ({ ok: true }),
    isExplicitlyOffline: () => false,
  } as unknown as InboundSessionDeps);
  return inbound;
}

/** The pickup frame + the agent's key provider (only it can open the content seal). */
function pickup(bytes: Uint8Array, hash: string) {
  const acks: Array<Record<string, unknown>> = [];
  const keyProvider = { openContentSeal: async () => bytes } as never;
  const mgr = { sendRaw: async (f: Record<string, unknown>) => { acks.push(f); return { ok: true }; } } as never;
  const frame = { type: "trust_signal_pickup", id: "p1", signal_kind: "attestation", signal_hash: hash, ciphertext: new Uint8Array([1, 2, 3]) };
  return { frame, keyProvider, mgr, acks };
}

describe("M10E 016-INBOX — a private review is read in the inbox, not stored in the wallet", () => {
  let dir: string;
  let db: DaemonDatabase;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "inbox-private-review-"));
    db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
    ensureSessionSchema(db, quiet, () => {});
  });
  afterEach(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });

  it("I1. a delivered private attestation appears in the inbox, with its text in a quoted-data field", async () => {
    const { bytes, hash } = buildPrivateReview("Fast, clear, would deal again.", 5);
    const { frame, keyProvider, mgr } = pickup(bytes, hash);
    await buildInbound(db).handleTrustSignalPickup(frame, keyProvider, mgr, "alice", "home");

    const notices = new AttestationNotices({ db: () => db, logger: quiet, now: () => 1_800_000_000_000 });
    const surfaced = notices.takeUndelivered("aid-alice");
    expect(surfaced).toEqual([
      expect.objectContaining({
        kind: "private_review",
        namespace: "support.qa",
        subject: SUBJECT,
        issuer_pubkey: REVIEWER,
        rating: 5,
        quoted_text: "Fast, clear, would deal again.",
      }),
    ]);
    // Destructive read: it surfaces once, not forever.
    expect(notices.takeUndelivered("aid-alice")).toEqual([]);
  });

  it("I2. it is absent from the trust-signal wallet and from any list used to present signals", async () => {
    const { bytes, hash } = buildPrivateReview("A review that must never become a presentable signal.");
    const { frame, keyProvider, mgr } = pickup(bytes, hash);
    await buildInbound(db).handleTrustSignalPickup(frame, keyProvider, mgr, "alice", "home");

    const walletCount = (db.prepare("SELECT COUNT(*) AS n FROM wallet_trust_signals").get() as { n: number }).n;
    const contactCount = (db.prepare("SELECT COUNT(*) AS n FROM contact_trust_signals").get() as { n: number }).n;
    expect(walletCount).toBe(0);
    expect(contactCount).toBe(0);

    const store = new TrustSignalStore(db, quiet);
    expect(store.listPresentable({ agentPubkeyHex: SUBJECT, accountId: "acct" })).toEqual([]);

    // And it is in the inbox instead — so it was delivered, not dropped.
    const notices = new AttestationNotices({ db: () => db, logger: quiet, now: () => 1_800_000_000_000 });
    expect(notices.takeUndelivered("aid-alice")).toHaveLength(1);
  });

  it("I3. the pickup is acked once the inbox write succeeds", async () => {
    const { bytes, hash } = buildPrivateReview("Acked only after it is safely in the inbox.");
    const { frame, keyProvider, mgr, acks } = pickup(bytes, hash);
    await buildInbound(db).handleTrustSignalPickup(frame, keyProvider, mgr, "alice", "home");
    expect(acks).toEqual([{ type: "trust_signal_ack", id: "p1" }]);
  });

  it("I3. a failed inbox write leaves the pickup un-acked, so the directory re-delivers", async () => {
    const { bytes, hash } = buildPrivateReview("The database is gone, so nothing is acked.");
    const { frame, keyProvider, mgr, acks } = pickup(bytes, hash);
    await buildInbound(null).handleTrustSignalPickup(frame, keyProvider, mgr, "alice", "home");
    expect(acks).toEqual([]);
  });

  it("notePrivateReview dedupes a re-delivered pickup and still acks it (store-level)", () => {
    const { bytes, hash } = buildPrivateReview("Delivered twice, stored once.");
    const notices = new AttestationNotices({ db: () => db, logger: quiet, now: () => 1_800_000_000_000 });
    const envelope = decodeTrustSignalEnvelope(bytes);
    expect(notices.notePrivateReview("aid-alice", envelope, hash)).toBe("stored");
    expect(notices.notePrivateReview("aid-alice", envelope, hash)).toBe("stored");
    expect(notices.takeUndelivered("aid-alice")).toHaveLength(1);
  });

  it("notePrivateReview reports malformed (acked, never retried) when the payload cannot decode", () => {
    const envelope: TrustSignalEnvelope = {
      subject_kind: "agent", subject: SUBJECT, issuer_kind: "agent", issuer_pubkey: REVIEWER,
      type: ATTESTATION_SIGNAL_TYPE, schema_version: 1, payload: new Uint8Array([0xff, 0x00]),
      issued_at: 1_800_000_000, expires_at: null, supersedes_hash: null, same_operator: false,
    };
    const notices = new AttestationNotices({ db: () => db, logger: quiet, now: () => 1_800_000_000_000 });
    expect(notices.notePrivateReview("aid-alice", envelope, "cc".repeat(32))).toBe("malformed");
    expect(notices.takeUndelivered("aid-alice")).toEqual([]);
  });
});
