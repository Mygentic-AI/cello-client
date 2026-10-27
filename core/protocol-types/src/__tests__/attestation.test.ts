import { describe, it, expect } from "vitest";
import { Buffer } from "node:buffer";
import { hash as sha256 } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  AttestationRecordError,
  ATTESTATION_TEMPLATE_DOMAIN,
  attestationTemplateHash,
  templateIdForHash,
  ATTESTATION_NAMESPACE_DOMAIN,
  ATTESTATION_NAMESPACE_CLOSE_DOMAIN,
  SERVICE_EVENT_DOMAIN,
  ATTESTATION_RIGHT_DOMAIN,
  ATTESTATION_PAYLOAD_DOMAIN,
  SERVICE_RECEIVED_CLAIM_DOMAIN,
  ATTESTATION_HEAD_DOMAIN,
  encodeAttestationNamespace, decodeAttestationNamespace, hashAttestationNamespace,
  encodeAttestationNamespaceClose, decodeAttestationNamespaceClose, hashAttestationNamespaceClose,
  encodeServiceEvent, decodeServiceEvent, hashServiceEvent,
  encodeAttestationRight, decodeAttestationRight, hashAttestationRight,
  encodeAttestationPayload, decodeAttestationPayload, hashAttestationPayload,
  encodeServiceReceivedClaim, decodeServiceReceivedClaim, hashServiceReceivedClaim,
  encodeAttestationHead, decodeAttestationHead, hashAttestationHead,
  rightId,
  type AttestationNamespace,
  type AttestationNamespaceClose,
  type ServiceEvent,
  type AttestationRight,
  type AttestationPayload,
  type ServiceReceivedClaim,
  type AttestationHead,
} from "../attestation.js";

// Deterministic fixtures: fixed bytes and letter-pubkeys so hashes are reproducible forever.
const B16 = (fill: number) => new Uint8Array(16).fill(fill);
const B32 = (fill: number) => new Uint8Array(32).fill(fill);
const PK_A = "a".repeat(64);
const PK_B = "b".repeat(64);
const PK_C = "c".repeat(64);
const NS = "reviews.prop_8821";
const TS = 1_700_000_000;
const SCORED = attestationTemplateHash("scored");
const TEXT = attestationTemplateHash("text");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const validAttestationNamespace = (): AttestationNamespace => ({
  owner_pubkey: PK_A, namespace: NS, mode: "public", template_hash: SCORED,
  right_ttl_s: 604800, condition: "Completed a paid booking", created_at: TS,
});
const validAttestationNamespaceClose = (): AttestationNamespaceClose => ({
  owner_pubkey: PK_A, namespace: NS, closed_at: TS,
});
const validServiceEvent = (): ServiceEvent => ({
  session_id: B16(1), subject_pubkey: PK_A, namespace: NS, counterparty_pubkey: PK_B,
  chain_head_hash: B32(2), marked_at: TS, origin_channel: null,
});
const validAttestationRight = (): AttestationRight => ({
  service_event_hash: B32(3), holder_pubkey: PK_B, subject_pubkey: PK_A, namespace: NS,
  template_hash: SCORED, session_id: B16(1), created_at: TS, expires_at: TS + 1_000_000, kind: "service_event",
});
const validAttestationPayload = (): AttestationPayload => ({
  right_id: B32(4), namespace: NS, template_hash: SCORED, session_id: B16(1),
  origin_channel: null, body: [5, "Great work throughout"],
});
const validServiceReceivedClaim = (): ServiceReceivedClaim => ({
  session_id: B16(1), claimant_pubkey: PK_B, subject_pubkey: PK_A, namespace: NS, claimed_at: TS,
});
const validAttestationHead = (): AttestationHead => ({
  subject_pubkey: PK_A, namespace: NS, count: 2, merkle_root: B32(5), sum_of_ratings: 8,
  removed_count: 0, suspended_count: 0, service_events: 2, unmarked_claims: 0, as_of: TS,
});

const codecs = [
  { name: "AttestationNamespace", v: validAttestationNamespace, enc: encodeAttestationNamespace, dec: decodeAttestationNamespace, h: hashAttestationNamespace },
  { name: "AttestationNamespaceClose", v: validAttestationNamespaceClose, enc: encodeAttestationNamespaceClose, dec: decodeAttestationNamespaceClose, h: hashAttestationNamespaceClose },
  { name: "ServiceEvent", v: validServiceEvent, enc: encodeServiceEvent, dec: decodeServiceEvent, h: hashServiceEvent },
  { name: "AttestationRight", v: validAttestationRight, enc: encodeAttestationRight, dec: decodeAttestationRight, h: hashAttestationRight },
  { name: "AttestationPayload", v: validAttestationPayload, enc: encodeAttestationPayload, dec: decodeAttestationPayload, h: hashAttestationPayload },
  { name: "ServiceReceivedClaim", v: validServiceReceivedClaim, enc: encodeServiceReceivedClaim, dec: decodeServiceReceivedClaim, h: hashServiceReceivedClaim },
  { name: "AttestationHead", v: validAttestationHead, enc: encodeAttestationHead, dec: decodeAttestationHead, h: hashAttestationHead },
] as const;

const expectCode = (fn: () => unknown, code: string) => {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(AttestationRecordError);
    expect((e as AttestationRecordError).code).toBe(code);
    return;
  }
  throw new Error(`expected throw with code ${code}, but nothing threw`);
};

describe("M10E-RECORDS-1 attestation records", () => {
  it("1 each record round-trips", () => {
    for (const c of codecs) {
      const v = c.v();
      const decoded = (c.dec as (b: Uint8Array) => unknown)(c.enc(v as never));
      expect(decoded).toEqual(v);
      expect(hex(c.h(decoded as never))).toBe(hex(c.h(v as never)));
    }
  });

  it("2 golden hashes are pinned", () => {
    // Pinned once, never regenerated. This is the cross-implementation anchor (test spec clause 2).
    const golden: Record<string, string> = {
      AttestationNamespace: "17964019bc7e4d07c01fe0215e3e607f6c467a6f4efbf30ab84d7b1dde6d7e79",
      AttestationNamespaceClose: "873be5d3ad22a47fc802f81e99cd30ac43bc7bdae8c5a312c8fafe00deedfe0f",
      ServiceEvent: "28b380e88e4eea4df6b41148aaa7eefd6eb8905e59886e19d28c6a3c793e5d64",
      AttestationRight: "d5905929d5c89b3c55ec88ec88b59a5d08e4e36dd58ebd5e8d6eb33600efdac7",
      AttestationPayload: "dd90f3914b3bc1458e2803c30eb180be34ccc6b6518d5ee156a18a710ef26832",
      ServiceReceivedClaim: "14ab86733cf8643c1db57e336407846b4dbd7d6f2d2453130381dc027600aaa1",
      AttestationHead: "41192e4be4ad8bf7945fa09f3e8debedce1e061a6d526cde1954828f82cf5faf",
    };
    for (const c of codecs) {
      expect(hex(c.h(c.v() as never))).toBe(golden[c.name]);
    }
  });

  it("3 template hashes are pinned and distinct", () => {
    expect(hex(TEXT)).toBe("GOLDEN_TEXT_TEMPLATE");
    expect(hex(SCORED)).toBe("GOLDEN_SCORED_TEMPLATE");
    expect(hex(TEXT)).not.toBe(hex(SCORED));
    expect(templateIdForHash(TEXT)).toBe("text");
    expect(templateIdForHash(SCORED)).toBe("scored");
    expect(templateIdForHash(new Uint8Array(32))).toBe(null);
  });

  it("4 domains are distinct", () => {
    const domains = [
      ATTESTATION_NAMESPACE_DOMAIN, ATTESTATION_NAMESPACE_CLOSE_DOMAIN, SERVICE_EVENT_DOMAIN,
      ATTESTATION_RIGHT_DOMAIN, ATTESTATION_PAYLOAD_DOMAIN, SERVICE_RECEIVED_CLAIM_DOMAIN,
      ATTESTATION_HEAD_DOMAIN, ATTESTATION_TEMPLATE_DOMAIN,
    ];
    expect(new Set(domains).size).toBe(domains.length);
  });

  it("5 a record decoded under the wrong decoder is refused", () => {
    const bytes = encodeServiceEvent(validServiceEvent());
    expectCode(() => decodeAttestationRight(bytes), "bad_shape");
  });

  it("6 non-NFC text is refused, not normalized", () => {
    const nfd = "café"; // decomposed é
    const nfc = "café";
    expect(nfd.normalize("NFC")).toBe(nfc);
    expectCode(() => encodeAttestationPayload({ ...validAttestationPayload(), body: [5, nfd] }), "not_nfc");
    expect(() => encodeAttestationPayload({ ...validAttestationPayload(), body: [5, nfc] })).not.toThrow();
  });

  it("7 text length counts code points", () => {
    const p = validAttestationPayload();
    expect(() => encodeAttestationPayload({ ...p, body: [5, "😀".repeat(500)] })).not.toThrow();
    expectCode(() => encodeAttestationPayload({ ...p, body: [5, "😀".repeat(501)] }), "bad_text");
    expectCode(() => encodeAttestationPayload({ ...p, body: [5, ""] }), "bad_text");
  });

  it("8 scored template requires a rating 1..5", () => {
    const p = validAttestationPayload();
    expectCode(() => encodeAttestationPayload({ ...p, body: [0, "x"] }), "bad_rating");
    expectCode(() => encodeAttestationPayload({ ...p, body: [6, "x"] }), "bad_rating");
    expectCode(() => encodeAttestationPayload({ ...p, body: [3.5, "x"] }), "bad_rating");
    expectCode(() => encodeAttestationPayload({ ...p, body: [null, "x"] }), "bad_rating");
    expectCode(() => encodeAttestationPayload({ ...p, body: ["x"] }), "bad_shape");
    expect(() => encodeAttestationPayload({ ...p, body: [5, "x"] })).not.toThrow();
  });

  it("9 text template refuses a rating", () => {
    const p = { ...validAttestationPayload(), template_hash: TEXT, body: [4, "x"] };
    expectCode(() => encodeAttestationPayload(p), "bad_shape");
  });

  it("10 namespace rules", () => {
    for (const ns of ["qa", "reviews.prop_8821", "a.b.c"]) {
      expect(() => encodeAttestationNamespace({ ...validAttestationNamespace(), namespace: ns })).not.toThrow();
    }
    for (const ns of ["", "a..b", "a.b.c.d", "Reviews", "reviews.*", "x".repeat(33)]) {
      expectCode(() => encodeAttestationNamespace({ ...validAttestationNamespace(), namespace: ns }), "bad_namespace");
    }
  });

  it("11 right TTL bounds", () => {
    expectCode(() => encodeAttestationNamespace({ ...validAttestationNamespace(), right_ttl_s: 604799 }), "bad_ttl");
    expectCode(() => encodeAttestationNamespace({ ...validAttestationNamespace(), right_ttl_s: 15552001 }), "bad_ttl");
    expect(() => encodeAttestationNamespace({ ...validAttestationNamespace(), right_ttl_s: 604800 })).not.toThrow();
    expect(() => encodeAttestationNamespace({ ...validAttestationNamespace(), right_ttl_s: 15552000 })).not.toThrow();
    expectCode(() => encodeAttestationRight({ ...validAttestationRight(), expires_at: TS + 60 }), "bad_ttl");
  });

  it("12 self-reference is refused", () => {
    expectCode(() => encodeServiceEvent({ ...validServiceEvent(), counterparty_pubkey: PK_A }), "self_reference");
    expectCode(() => encodeAttestationRight({ ...validAttestationRight(), holder_pubkey: PK_A }), "self_reference");
    expectCode(() => encodeServiceReceivedClaim({ ...validServiceReceivedClaim(), claimant_pubkey: PK_A }), "self_reference");
  });

  it("13 unknown fields are refused on encode", () => {
    expectCode(() => encodeServiceEvent({ ...validServiceEvent(), extra: 1 } as never), "unknown_field");
  });

  it("14 origin_channel is explicit null, never absent", () => {
    const seBytes = encodeServiceEvent({ ...validServiceEvent(), origin_channel: PK_C });
    expect(decodeServiceEvent(seBytes).origin_channel).toBe(PK_C);
    // An array one element short decodes to bad_shape.
    const short = encodeCbor([
      SERVICE_EVENT_DOMAIN, B16(1), PK_A, NS, PK_B, B32(2), TS, // origin_channel slot omitted
    ]);
    expectCode(() => decodeServiceEvent(short), "bad_shape");
    const shortP = encodeCbor([
      ATTESTATION_PAYLOAD_DOMAIN, B32(4), NS, SCORED, B16(1), null, // body slot omitted
    ]);
    expectCode(() => decodeAttestationPayload(shortP), "bad_shape");
  });

  it("15 rightId is the right's hash", () => {
    const r = validAttestationRight();
    expect(hex(rightId(r))).toBe(hex(hashAttestationRight(r)));
    const mutations: Array<Partial<AttestationRight>> = [
      { service_event_hash: B32(9) },
      { holder_pubkey: PK_C },
      { subject_pubkey: PK_C },
      { namespace: "qa" },
      { template_hash: TEXT },
      { session_id: B16(9) },
      { created_at: TS + 1 },
      { expires_at: TS + 604800 + 1 },
      { kind: "service_event" }, // only legal value; identity mutation must leave hash unchanged
    ];
    for (const m of mutations) {
      const mutated = { ...r, ...m };
      if (m.kind !== undefined) {
        expect(hex(rightId(mutated))).toBe(hex(rightId(r)));
      } else {
        expect(hex(rightId(mutated))).not.toBe(hex(rightId(r)));
      }
    }
  });

  it("16 head counts", () => {
    expectCode(() => encodeAttestationHead({ ...validAttestationHead(), count: -1 }), "bad_count");
    expectCode(() => encodeAttestationHead({ ...validAttestationHead(), count: 1, sum_of_ratings: 6 }), "bad_count");
  });
});
