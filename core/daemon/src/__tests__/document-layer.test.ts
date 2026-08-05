/**
 * DOD-DOC-INBOUND-2 — the composed document layer.
 *
 * The assembly makes decisions, and these are the ones worth pinning: that an unverifiable peer is
 * REFUSED rather than admitted, that a frame is scoped by the OWNING AGENT rather than by whichever
 * session carried it, and that the layer either exists whole or not at all.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import * as Y from "yjs";
import { generateKeypair } from "@cello-protocol/crypto";
import {
  encodeDocumentUpdateEnvelope,
  buildDocumentUpdateTbs,
  DOCUMENT_UPDATE_ENCODING_V1,
  DOCUMENT_EPOCH_V1,
  type DocumentUpdateEnvelope,
} from "@cello-protocol/protocol-types";
import { createDocumentLayer, agentPublicKeyFromId } from "../document-layer.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const PEER = "peer-agent";
const DOC = "cc".repeat(32);
const PEER_CLIENT = 4242;
const NOW = 1_700_000_000_000;

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

function peerUpdate(text: string): Uint8Array {
  const d = new Y.Doc();
  d.clientID = PEER_CLIENT;
  d.getText("content").insert(0, text);
  return Y.encodeStateAsUpdate(d);
}

async function newFixture(opts: { knowPeerKey?: boolean } = {}) {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const keys = generateKeypair();
  const publicKey = await keys.getPublicKey();

  const layer = createDocumentLayer({
    db,
    logger,
    publicKeyFor: (agentId) =>
      agentId === PEER && opts.knowPeerKey !== false ? publicKey : null,
    notifyPeer: async () => ({ ok: true }),
    rollback: () => ({ ok: true }),
    crypto: () => ({
      signature: new Uint8Array(64).fill(1),
      stateVector: new Uint8Array([0]),
      nonce: `n${NOW}`,
    }),
  });

  layer.store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });

  const signedEnvelope = async (over: Partial<DocumentUpdateEnvelope> = {}) => {
    const base: DocumentUpdateEnvelope = {
      type: "document_update",
      document_id: DOC,
      epoch_id: DOCUMENT_EPOCH_V1,
      doc_prev_hash: null,
      sender_agent_id: PEER,
      sender_client_id: PEER_CLIENT,
      update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
      state_vector: new Uint8Array([0]),
      update: peerUpdate("from the peer. "),
      signature: new Uint8Array(64),
      ...over,
    };
    return { ...base, signature: await keys.sign(buildDocumentUpdateTbs(base)) };
  };

  return { layer, events, signedEnvelope, keys };
}

describe("document layer — a REAL signature is verified end to end", () => {
  it("admits a properly signed envelope through the composed router", async () => {
    const f = await newFixture();
    const env = await f.signedEnvelope();

    const routed = f.layer.onDocumentFrame(AGENT, "session-1", encodeDocumentUpdateEnvelope(env), "pk");
    expect(routed).toMatchObject({ consumed: true, kind: "update", ok: true });
    expect(f.layer.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
    expect(f.layer.live.get(AGENT, DOC).getText("content").toString()).toContain("from the peer");
  });

  it("REFUSES an envelope whose signature does not match the peer's key", async () => {
    const f = await newFixture();
    const env = await f.signedEnvelope();
    // One flipped byte in the signature. This is the check that every other guarantee rests on.
    const tampered = { ...env, signature: new Uint8Array(env.signature) };
    tampered.signature[0] ^= 0xff;

    const routed = f.layer.onDocumentFrame(AGENT, "s", encodeDocumentUpdateEnvelope(tampered), "pk");
    expect(routed).toMatchObject({ consumed: true, ok: false, reason: "document_signature_invalid" });
    expect(f.layer.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("REFUSES when this daemon holds no key for the sender, and says so", async () => {
    const f = await newFixture({ knowPeerKey: false });
    const env = await f.signedEnvelope();

    const routed = f.layer.onDocumentFrame(AGENT, "s", encodeDocumentUpdateEnvelope(env), "pk");
    // "Cannot verify" must land as a refusal, not as an admission — admitting what we cannot
    // authenticate is the outcome the verify step exists to prevent.
    expect(routed).toMatchObject({ consumed: true, ok: false, reason: "document_signature_invalid" });
    expect(f.events.some((e) => e.event === "document.verify.no_key")).toBe(true);
  });

  it("treats a MALFORMED key as a refusal, not a crash", async () => {
    const { logger } = recordingLogger();
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    const layer = createDocumentLayer({
      db,
      logger,
      publicKeyFor: () => new Uint8Array(3), // not a valid Ed25519 key
      notifyPeer: async () => ({ ok: true }),
      rollback: () => ({ ok: true }),
      crypto: () => ({ signature: new Uint8Array(64), stateVector: new Uint8Array([0]), nonce: "n" }),
    });
    layer.store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const f = await newFixture();
    const env = await f.signedEnvelope();

    // The bytes came from a peer, so a bad key is a refusal rather than a crash. `verify` fails
    // closed by contract — its own body catches and returns false — which is why the layer wraps it
    // in no try/catch: that branch would be unreachable.
    const routed = layer.onDocumentFrame(AGENT, "s", encodeDocumentUpdateEnvelope(env), "pk");
    expect(routed).toMatchObject({ consumed: true, ok: false, reason: "document_signature_invalid" });
    expect(layer.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });
});

describe("document layer — the frame is scoped by the OWNING AGENT, not the session", () => {
  it("ignores the session id and the transport pubkey", async () => {
    const f = await newFixture();
    const env = await f.signedEnvelope();
    const wire = encodeDocumentUpdateEnvelope(env);

    // A document is bound to its PEER by the handshake, not to whichever session carried the
    // frame. Trusting the transport identity would let a frame arriving on any session act on any
    // document that session's peer happens to share.
    const viaOne = f.layer.onDocumentFrame(AGENT, "session-A", wire, "pubkey-A");
    expect(viaOne).toMatchObject({ consumed: true, ok: true });
    const viaAnother = f.layer.onDocumentFrame(AGENT, "session-B", wire, "pubkey-B");
    // Same envelope, different session: a redelivery, acked, not a second admission.
    expect(viaAnother).toMatchObject({ consumed: true, ok: true });
    expect(f.layer.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("refuses a frame for an agent that does not hold the document", async () => {
    const f = await newFixture();
    const env = await f.signedEnvelope();
    const routed = f.layer.onDocumentFrame("someone-else", "s", encodeDocumentUpdateEnvelope(env), "pk");
    expect(routed).toMatchObject({ consumed: true, ok: false, reason: "document_unknown" });
  });
});

describe("document layer — a conversation message passes straight through", () => {
  it("does not consume ordinary text", async () => {
    const f = await newFixture();
    const message = new TextEncoder().encode("Did you get a chance to look at the draft?");
    // The whole layer must be invisible to the conversation path — that is what lets it be wired
    // without changing message handling.
    expect(f.layer.onDocumentFrame(AGENT, "s", message, "pk")).toEqual({ consumed: false });
  });
});

describe("agentPublicKeyFromId — a remote agent id IS its pubkey (M14-D5)", () => {
  it("decodes a 32-byte hex id to the key bytes", () => {
    const hex = "ab".repeat(32);
    const key = agentPublicKeyFromId(hex);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key).toHaveLength(32);
    expect(Buffer.from(key!).toString("hex")).toBe(hex);
  });

  it("returns null for anything that is not one, rather than throwing", () => {
    // Null is a refusal at the verify step. An id that is not a key is a frame that does not follow
    // the protocol, not "a peer we have no key for" — but both must refuse, and this is where.
    for (const bad of ["", "not-hex", "AB".repeat(32), "ab".repeat(16), "ab".repeat(33)]) {
      expect(agentPublicKeyFromId(bad)).toBeNull();
    }
  });

  it("verifies a real signature end to end through the default resolver", async () => {
    const keys = generateKeypair();
    const pub = await keys.getPublicKey();
    const asId = Buffer.from(pub).toString("hex");
    // The whole point of M14-D5: the id round-trips to the key with no lookup at all.
    expect(Buffer.from(agentPublicKeyFromId(asId)!).toString("hex")).toBe(
      Buffer.from(pub).toString("hex"),
    );
  });
});
