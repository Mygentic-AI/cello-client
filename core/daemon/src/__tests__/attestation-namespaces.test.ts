/**
 * M10E 003-NSCLIENT — the client composes, signs and sends namespaces, and verifies every index
 * entry itself. A forged entry is shown unverified, never dropped and never shown as genuine.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { generateKeypair, verify, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  attestationTemplateHash,
  decodeAttestationNamespace,
  encodeAttestationNamespace,
  encodeAttestationNamespaceClose,
  hashAttestationNamespace,
  hashAttestationNamespaceClose,
  type AttestationNamespace,
} from "@cello-protocol/protocol-types";
import { createNamespace, closeNamespace, readIndex, type NamespaceDeps } from "../attestation-namespaces.js";

const NOW_S = 1_800_000_000;
const NOW_MS = NOW_S * 1000;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

interface FakeSignaling {
  sent: Array<Record<string, unknown>>;
  push: (reply: Record<string, unknown>) => void;
  sendRaw: (frame: unknown) => Promise<{ ok: boolean; reason?: string }>;
  registerInboundHandler: (h: (f: Record<string, unknown>) => void) => () => void;
}
function makeSignaling(): FakeSignaling {
  const sent: Array<Record<string, unknown>> = [];
  const handlers = new Set<(f: Record<string, unknown>) => void>();
  return {
    sent,
    push: (reply) => { for (const h of [...handlers]) h(reply); },
    sendRaw: async (frame) => { sent.push(frame as Record<string, unknown>); return { ok: true }; },
    registerInboundHandler: (h) => { handlers.add(h); return () => handlers.delete(h); },
  };
}
async function waitForSent(sig: FakeSignaling, n: number): Promise<void> {
  for (let i = 0; i < 500 && sig.sent.length < n; i++) await new Promise((r) => setTimeout(r, 2));
}

interface SpyLogger { events: Array<{ level: string; event: string; ctx: Record<string, unknown> }>; debug: (e: string, c: Record<string, unknown>) => void; info: (e: string, c: Record<string, unknown>) => void; warn: (e: string, c: Record<string, unknown>) => void; error: (e: string, c: Record<string, unknown>) => void; }
function makeLogger(): SpyLogger {
  const events: SpyLogger["events"] = [];
  return {
    events,
    debug: (event, ctx) => events.push({ level: "debug", event, ctx }),
    info: (event, ctx) => events.push({ level: "info", event, ctx }),
    warn: (event, ctx) => events.push({ level: "warn", event, ctx }),
    error: (event, ctx) => events.push({ level: "error", event, ctx }),
  };
}

let sig: FakeSignaling;
let logger: SpyLogger;
let key: InMemoryKeyProvider;
let owner: string;
let deps: NamespaceDeps;

beforeEach(async () => {
  sig = makeSignaling();
  logger = makeLogger();
  key = generateKeypair();
  owner = hex(await key.getPublicKey());
  deps = { signaling: sig, keyProvider: key, ownerPubkeyHex: owner, now: () => NOW_MS, logger, timeoutMs: 120 };
});

function result(namespace: string, status: "stored" | "identical" = "stored"): Record<string, unknown> {
  return { type: "attestation_namespace_result", owner_pubkey: owner, namespace, status };
}

/** A signed namespace entry as the index reply carries it, signed by `signer` (owner by default). */
async function entry(over: Partial<AttestationNamespace> = {}, signer: InMemoryKeyProvider = key): Promise<{ record: Uint8Array; signature: Uint8Array; close: { record: Uint8Array; signature: Uint8Array } | null }> {
  const rec: AttestationNamespace = {
    owner_pubkey: owner, namespace: "reviews.alpha", mode: "public",
    template_hash: attestationTemplateHash("scored"), right_ttl_s: 30 * 86400,
    condition: "granted when a booking is confirmed", created_at: NOW_S, ...over,
  };
  return { record: encodeAttestationNamespace(rec), signature: await signer.sign(hashAttestationNamespace(rec)), close: null };
}

describe("003-NSCLIENT — create", () => {
  it("C1. create signs the record the directory will verify", async () => {
    const p = createNamespace(deps, { namespace: "reviews.prop_8821", mode: "public", scored: true, right_ttl_days: 30, condition: "granted when a booking is confirmed" });
    await waitForSent(sig, 1);
    const frame = sig.sent[0]!;
    expect(frame["type"]).toBe("attestation_namespace_put");
    const rec = decodeAttestationNamespace(frame["record"] as Uint8Array);
    expect(rec.owner_pubkey).toBe(owner);
    expect(verify(Buffer.from(owner, "hex"), hashAttestationNamespace(rec), frame["signature"] as Uint8Array)).toBe(true);
    sig.push(result("reviews.prop_8821"));
    expect(await p).toEqual({ ok: true, status: "stored" });
  });

  it("C2. condition is NFC-normalized before signing", async () => {
    // Decomposed "café" (e + U+0301). If it were NOT normalized here, encodeAttestationNamespace
    // would THROW (the 001 codec refuses non-NFC) and nothing would be sent — so a sent frame whose
    // condition is the composed form proves the normalization happened here.
    const p = createNamespace(deps, { namespace: "reviews.x", mode: "public", scored: false, right_ttl_days: 30, condition: "café" });
    await waitForSent(sig, 1);
    const rec = decodeAttestationNamespace(sig.sent[0]!["record"] as Uint8Array);
    expect(rec.condition).toBe("café");
    expect(rec.condition.normalize("NFC")).toBe(rec.condition);
    sig.push(result("reviews.x"));
    await p;
  });

  it("C3. a result reply resolves stored", async () => {
    const p = createNamespace(deps, { namespace: "reviews.r3", mode: "public", scored: true, right_ttl_days: 30, condition: "c" });
    await waitForSent(sig, 1);
    sig.push(result("reviews.r3", "stored"));
    expect(await p).toEqual({ ok: true, status: "stored" });
  });

  it("C4. a refusal carries its reason and a next step", async () => {
    const p = createNamespace(deps, { namespace: "reviews.r4", mode: "public", scored: true, right_ttl_days: 30, condition: "c" });
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_namespace_error", reason: "namespace_immutable" });
    const res = await p;
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("namespace_immutable");
    expect(res.guidance).toContain("new one");
  });

  it("C9. ttl outside 7..180 days is refused before sending", async () => {
    const res = await createNamespace(deps, { namespace: "reviews.r9", mode: "public", scored: true, right_ttl_days: 3, condition: "c" });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("bad_ttl");
    expect(sig.sent).toHaveLength(0);
  });

  it("C7. two concurrent creates do not cross replies", async () => {
    const p1 = createNamespace(deps, { namespace: "reviews.one", mode: "public", scored: true, right_ttl_days: 30, condition: "c" });
    const p2 = createNamespace(deps, { namespace: "reviews.two", mode: "public", scored: true, right_ttl_days: 30, condition: "c" });
    await waitForSent(sig, 1);
    // The SECOND frame is not sent until the first resolves: writes are serialized.
    expect(sig.sent).toHaveLength(1);
    expect(sig.sent[0]!["type"]).toBe("attestation_namespace_put");
    sig.push(result("reviews.one"));
    expect(await p1).toEqual({ ok: true, status: "stored" });
    await waitForSent(sig, 2);
    expect(sig.sent).toHaveLength(2);
    sig.push(result("reviews.two"));
    expect(await p2).toEqual({ ok: true, status: "stored" });
  });

  it("C8. an old directory is not reported as a failed login", async () => {
    const p = createNamespace(deps, { namespace: "reviews.r8", mode: "public", scored: true, right_ttl_days: 30, condition: "c" });
    await waitForSent(sig, 1);
    // An older node answers not_authenticated for a frame it cannot decode, then never acks. The
    // timeout must name version skew, not an auth failure.
    sig.push({ type: "not_authenticated" });
    const res = await p;
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("attestation_namespaces_unsupported_by_node");
  });
});

describe("003-NSCLIENT — read index", () => {
  it("C5. the index shows closed namespaces", async () => {
    const e = await entry();
    const closeRec = { owner_pubkey: owner, namespace: "reviews.alpha", closed_at: NOW_S + 100 };
    e.close = { record: encodeAttestationNamespaceClose(closeRec), signature: await key.sign(hashAttestationNamespaceClose(closeRec)) };
    const p = readIndex(deps, owner);
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_index", owner_pubkey: owner, entries: [e], next: null });
    const res = await p;
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.entries).toHaveLength(1);
    expect(res.entries[0]!.closed_at).toBe(NOW_S + 100);
    expect(res.entries[0]!.verified).toBe(true);
  });

  it("C6. a forged entry is shown unverified, not dropped", async () => {
    // Record names the real owner, but it is signed by a DIFFERENT key — the forgery a dishonest
    // directory would inject. The reader keeps it, flagged, and logs exactly one unverified entry.
    const forger = generateKeypair();
    const e = await entry({}, forger);
    const p = readIndex(deps, owner);
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_index", owner_pubkey: owner, entries: [e], next: null });
    const res = await p;
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.entries).toHaveLength(1);
    expect(res.entries[0]!.verified).toBe(false);
    expect(res.entries[0]!.namespace).toBe("reviews.alpha");
    expect(logger.events.filter((ev) => ev.event === "attestation.index.unverified_entry")).toHaveLength(1);
  });
});

describe("003-NSCLIENT — close", () => {
  it("close signs a close record and resolves stored", async () => {
    const p = closeNamespace(deps, "reviews.alpha");
    await waitForSent(sig, 1);
    expect(sig.sent[0]!["type"]).toBe("attestation_namespace_close");
    sig.push(result("reviews.alpha"));
    expect(await p).toEqual({ ok: true, status: "stored" });
  });
});
