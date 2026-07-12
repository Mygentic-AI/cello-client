/**
 * SEC-1 — relay-park content authentication.
 *
 * THE DEFECT (design: trustless-cello docs/planning/user-stories/m8c/
 * 2026-07-12_sec-1-relay-park-authentication-design.md):
 *
 * Relay deposit is unauthenticated (content-park-client.ts: "Deposit is OPEN by design — the blob
 * is E2E-encrypted to the recipient") and `sealToRecipient` is an ANONYMOUS public-key seal — so
 * anyone holding the recipient's PUBLIC key can mint a well-formed sealed entry. Recovery then took
 * the sender identity from the SESSION ROW (session-node-manager.ts: `senderPubkey =
 * entry?.counterpartyPubkey ?? record.counterparty_pubkey`), never from the envelope, and the
 * bilateral seal NOTARIZED the resulting leaf. Net: a party who can deposit — above all the RELAY
 * ITSELF, which is handed the session_id in plaintext on every deposit and holds the recipient
 * pubkey as its mailbox key — could forge a receipted message from an honest counterparty.
 *
 * THE FIX: every park envelope carries a per-message SENDER SIGNATURE, inside the seal (so the relay
 * can neither read, strip, nor forge it), over a domain-separated statement bound to
 * (session_id, recipient_pubkey, content_hash). Recovery FAILS CLOSED: no signature / bad signature /
 * signer is not this session's counterparty → REJECT, never ingest.
 *
 * Crypto: Ed25519 (RFC 8032), SHA-256 (FIPS 180-4).
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { encode as cborEncode } from "cbor-x";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { generateKeypair } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { buildParkContentTbs } from "@cello-protocol/protocol-types";
import { encodeParkEnvelope, sealParkEnvelope } from "../park-envelope.js";
import { seedAgents } from "./helpers/seed-agents.js";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_addr: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> { throw new Error("unused"); }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private readonly node: CelloNode) {}
  async createNode(_config: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

async function makeManager(logger: Logger, dbPath: string): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ factory: new ControlledFactory(new FakeNode() as unknown as CelloNode), logger, dbPath });
  await mgr.initialize();
  return mgr;
}

const AGENT = "alice";

describe("SEC-1: relay-park content authentication (fail-closed)", () => {
  let tempDir: string;
  let logger: Logger;
  let events: LogEvent[];

  // The victim (recipient) and the honest counterparty whose identity the attacker wants to wear.
  const victim = generateKeypair();
  const counterparty = generateKeypair();
  const attacker = generateKeypair();

  let victimPub: Uint8Array;
  let counterpartyPub: Uint8Array;
  let counterpartyHex: string;
  const sid = "e".repeat(64);

  beforeAll(async () => {
    victimPub = await victim.getPublicKey();
    counterpartyPub = await counterparty.getPublicKey();
    counterpartyHex = Buffer.from(counterpartyPub).toString("hex");
  });

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-sec1-"));
    const l = makeLogger();
    logger = l.logger;
    events = l.events;
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  /** A session owned by AGENT whose counterparty is the honest `counterparty` keypair. */
  async function makeSession(name: string): Promise<SessionNodeManager> {
    const mgr = await makeManager(logger, join(tempDir, `${name}.db`));
    await seedAgents(mgr.getDb(), [AGENT]);
    await mgr.createSessionNode(sid, AGENT, counterpartyHex, "counterparty-peer-id", "corr-1");
    return mgr;
  }

  /** Sign a park envelope the way an honest sender does. */
  async function signPark(
    signer: KeyProvider,
    opts: { sessionIdHex?: string; recipientPubkey?: Uint8Array; contentHash: Uint8Array },
  ): Promise<Uint8Array> {
    return await signer.sign(
      buildParkContentTbs(
        opts.sessionIdHex ?? sid,
        opts.recipientPubkey ?? victimPub,
        opts.contentHash,
      ),
    );
  }

  // ─── AC3 — THE SEC-1 REGRESSION TEST ────────────────────────────────────────────────────────
  // An adversary holding ONLY the victim's PUBLIC key and a live session_id (both of which the
  // relay is simply handed by the protocol) mints a well-formed sealed entry. Recovery must REFUSE
  // it: nothing enters the transcript, no leaf is appended, the seal root is untouched.
  it("AC3: an adversary's UNSIGNED (bare-content) envelope is REFUSED — no leaf, no transcript row", async () => {
    const mgr = await makeSession("ac3-bare");
    const forged = new TextEncoder().encode("I agree to pay you 10,000 EUR.");
    const forgedHash = msgLeafHash(forged);

    // Exactly what the attacker deposits: the pre-SEC-1 envelope shape (no sender, no signature).
    // This is the shape `decodeParkEnvelope` used to accept and ingest without a single check.
    const adversaryPlaintext = cborEncode([1, forged, null, null]) as Uint8Array;

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, adversaryPlaintext, forgedHash);

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("unsigned_envelope");

    // The security property, asserted on STATE — not just on the return value.
    expect(mgr.getSessionTree(AGENT, sid).indexOfHash(Buffer.from(forgedHash).toString("hex"))).toBe(-1);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);
    expect(events.some((e) => e.event === "content.recover.unauthenticated" && e.level === "warn")).toBe(true);
  });

  it("AC3: raw non-CBOR bare content (the legacy fallback shape) is also REFUSED", async () => {
    const mgr = await makeSession("ac3-raw");
    const forged = new TextEncoder().encode("legacy bare content, not an envelope at all");
    const forgedHash = msgLeafHash(forged);

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, forged, forgedHash);

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("unsigned_envelope");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);
  });

  // ─── AC2 — signer must be THIS session's counterparty ───────────────────────────────────────
  it("AC2: a VALID signature by a key that is NOT the session counterparty is REFUSED (signer_not_counterparty)", async () => {
    const mgr = await makeSession("ac2-wrong-signer");
    const forged = new TextEncoder().encode("forged but properly signed by the attacker");
    const forgedHash = msgLeafHash(forged);

    // The attacker signs correctly — with their OWN key. Cryptographically valid, wrong principal.
    const attackerPub = await attacker.getPublicKey();
    const sig = await signPark(attacker, { contentHash: forgedHash });
    const plaintext = encodeParkEnvelope({
      content: forged,
      senderPubkey: attackerPub,
      parkSig: sig,
    });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, forgedHash);

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("signer_not_counterparty");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);
  });

  it("AC2: a CORRUPTED signature from the real counterparty is REFUSED (bad_signature)", async () => {
    const mgr = await makeSession("ac2-bad-sig");
    const content = new TextEncoder().encode("hello");
    const hash = msgLeafHash(content);

    const sig = await signPark(counterparty, { contentHash: hash });
    sig[0] ^= 0xff; // flip a bit
    const plaintext = encodeParkEnvelope({ content, senderPubkey: counterpartyPub, parkSig: sig });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, hash);

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("bad_signature");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);
  });

  // ─── AC4 — the signature is BOUND to (session_id, recipient_pubkey, content_hash) ────────────
  // One negative per binding: a signature lifted from another session, another mailbox, or another
  // message must not verify here. This is what stops an attacker REPLAYING a genuine signature.
  it("AC4: a genuine signature from ANOTHER SESSION does not verify here", async () => {
    const mgr = await makeSession("ac4-session");
    const content = new TextEncoder().encode("moved between sessions");
    const hash = msgLeafHash(content);

    const sig = await signPark(counterparty, { sessionIdHex: "a".repeat(64), contentHash: hash });
    const plaintext = encodeParkEnvelope({ content, senderPubkey: counterpartyPub, parkSig: sig });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, hash);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("bad_signature");
  });

  it("AC4: a genuine signature for ANOTHER RECIPIENT (mailbox) does not verify here", async () => {
    const mgr = await makeSession("ac4-recipient");
    const content = new TextEncoder().encode("moved between mailboxes");
    const hash = msgLeafHash(content);

    const other = generateKeypair();
    const sig = await signPark(counterparty, { recipientPubkey: await other.getPublicKey(), contentHash: hash });
    const plaintext = encodeParkEnvelope({ content, senderPubkey: counterpartyPub, parkSig: sig });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, hash);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("bad_signature");
  });

  it("AC4: a genuine signature for OTHER CONTENT does not authorize these bytes", async () => {
    const mgr = await makeSession("ac4-content");
    const real = new TextEncoder().encode("the message the counterparty actually sent");
    const swapped = new TextEncoder().encode("the message the attacker wants attributed");

    // Signature legitimately covers `real`; the attacker ships `swapped` under it.
    const sig = await signPark(counterparty, { contentHash: msgLeafHash(real) });
    const plaintext = encodeParkEnvelope({ content: swapped, senderPubkey: counterpartyPub, parkSig: sig });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, msgLeafHash(swapped));
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("bad_signature");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);
  });

  // ─── AC1/AC5 — the honest path still works (the guard is not a wall) ─────────────────────────
  it("AC1: a correctly-signed envelope from the real counterparty IS accepted and ingested", async () => {
    const mgr = await makeSession("ac1-happy");
    const content = new TextEncoder().encode("a genuine parked message");
    const hash = msgLeafHash(content);

    const sig = await signPark(counterparty, { contentHash: hash });
    const plaintext = encodeParkEnvelope({ content, senderPubkey: counterpartyPub, parkSig: sig });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, hash);

    expect(res.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).indexOfHash(Buffer.from(hash).toString("hex"))).toBe(0);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  it("AC5: the crash-backstop shape (signed, but NO ordering record) is still accepted — bare-content stays legal, UNSIGNED does not", async () => {
    const mgr = await makeSession("ac5-backstop");
    const content = new TextEncoder().encode("re-parked after a sender crash");
    const hash = msgLeafHash(content);

    // startupParkFn has no Structure1/2 (retry_queue does not persist them) — it signs anyway.
    const sig = await signPark(counterparty, { contentHash: hash });
    const plaintext = encodeParkEnvelope({
      content,
      senderPubkey: counterpartyPub,
      parkSig: sig,
      // deliberately no structure1Cbor / structure2Cbor
    });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, hash);

    expect(res.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  // ─── AC1 — THE PRODUCER, round-tripped against the REAL consumer ─────────────────────────────
  // Review (hollow-test finding): every test above builds its own envelope, so a PRODUCER that signed
  // the wrong to-be-signed arguments — e.g. its own pubkey where the recipient's belongs — would ship
  // envelopes no recipient could ever accept, and all of them would still pass. Mail would simply
  // stop arriving. These drive `sealParkEnvelope`, the SAME function both daemon park sites call,
  // through the real seal and into the real gate. If the producer signs the wrong statement, this
  // goes red.
  it("AC1: sealParkEnvelope (the production producer, live-park shape) -> openContentSeal -> recoverParkedEntry is ACCEPTED", async () => {
    const mgr = await makeSession("ac1-producer");
    const content = new TextEncoder().encode("produced by the real park path");
    const hash = msgLeafHash(content);
    const s1 = new Uint8Array([0x01, 0x02, 0x03]);
    const s2 = new Uint8Array([0x04, 0x05, 0x06]);

    // Exactly what daemon.ts's content-park hook does — the counterparty is the SENDER here.
    const ciphertext = await sealParkEnvelope({
      signer: counterparty,
      sessionIdHex: sid,
      recipientPubkey: victimPub,
      contentHash: hash,
      content,
      structure1Cbor: s1,
      structure2Cbor: s2,
    });

    // …and exactly what the recover path does: unseal with the RECIPIENT's key, then gate it.
    const unsealed = await victim.openContentSeal!(ciphertext);
    expect(unsealed).not.toBeNull();

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, unsealed!, hash);

    expect(res.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  it("AC1/AC5: the CRASH-BACKSTOP producer shape (no ordering record — retry_queue never persists one) round-trips and is ACCEPTED", async () => {
    const mgr = await makeSession("ac5-producer");
    const content = new TextEncoder().encode("re-parked by startupParkFn after a crash");
    const hash = msgLeafHash(content);

    // startupParkFn signs from ONLY what retry_queue persists: (sessionId, recipient, contentHash,
    // contentBlob) + the owning agent's key. No Structure1/2 — that is the whole point of the §4
    // falsification: had we required the ordering record, this message would be REFUSED and the
    // crash backstop would become a message-loss CAUSE.
    const ciphertext = await sealParkEnvelope({
      signer: counterparty,
      sessionIdHex: sid,
      recipientPubkey: victimPub,
      contentHash: hash,
      content,
    });

    const unsealed = await victim.openContentSeal!(ciphertext);
    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, unsealed!, hash);

    expect(res.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  // ─── Review M1 — the signer check compares BYTES, not hex strings ────────────────────────────
  it("M1: a MIXED-CASE stored counterparty pubkey still accepts genuine parked mail (byte compare, not string compare)", async () => {
    const mgr = await makeManager(logger, join(tempDir, "m1-case.db"));
    await seedAgents(mgr.getDb(), [AGENT]);
    // `sessions.counterparty_pubkey` is persisted VERBATIM from the IPC param — no normalization —
    // so an uppercase pubkey is a perfectly functional session. A hex-STRING compare in the gate
    // would refuse every parked message for it as `signer_not_counterparty`: permanent mail loss,
    // logged as an attack.
    await mgr.createSessionNode(sid, AGENT, counterpartyHex.toUpperCase(), "cp-peer", "corr-1");

    const content = new TextEncoder().encode("genuine mail into an uppercase-keyed session");
    const hash = msgLeafHash(content);
    const ciphertext = await sealParkEnvelope({
      signer: counterparty,
      sessionIdHex: sid,
      recipientPubkey: victimPub,
      contentHash: hash,
      content,
    });
    const unsealed = await victim.openContentSeal!(ciphertext);

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, unsealed!, hash);

    expect(res.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  // ─── Review M4 — a refused entry is remembered, not re-verified forever ──────────────────────
  it("M4: a repeat forgery is refused from the memo (not re-unsealed/re-verified on every reconnect)", async () => {
    const mgr = await makeSession("m4-memo");
    const forged = new TextEncoder().encode("the same forgery, re-pulled every reconnect");
    const forgedHash = msgLeafHash(forged);
    const adversaryPlaintext = cborEncode([1, forged, null, null]) as Uint8Array;

    const first = await mgr.recoverParkedEntry(AGENT, sid, victimPub, adversaryPlaintext, forgedHash);
    const second = await mgr.recoverParkedEntry(AGENT, sid, victimPub, adversaryPlaintext, forgedHash);

    expect(first.ok).toBe(false);
    expect(second.ok).toBe(false);
    // Refused BOTH times (never silently accepted on the second look), and the second refusal is
    // marked as a repeat — i.e. it short-circuited instead of re-doing the crypto.
    expect(events.filter((e) => e.event === "content.recover.unauthenticated").length).toBe(2);
    expect(events.some((e) => e.event === "content.recover.unauthenticated" && e.context["repeat"] === true)).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);
  });

  // ─── AC2 — fail closed when the counterparty is unknowable ───────────────────────────────────
  it("AC2: fail-closed — an unknown session (no counterparty to check against) is REFUSED, never ingested", async () => {
    const mgr = await makeManager(logger, join(tempDir, "ac2-nosession.db"));
    await seedAgents(mgr.getDb(), [AGENT]);
    // No createSessionNode — there is no session row, so no counterparty_pubkey to bind to.
    const content = new TextEncoder().encode("orphan");
    const hash = msgLeafHash(content);
    const sig = await signPark(counterparty, { contentHash: hash });
    const plaintext = encodeParkEnvelope({ content, senderPubkey: counterpartyPub, parkSig: sig });

    const res = await mgr.recoverParkedEntry(AGENT, sid, victimPub, plaintext, hash);

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("counterparty_unknown");
  });
});
