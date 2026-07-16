/**
 * DOD-REGISTRY-1 (client half) — registry poll tests.
 *
 * The client fetches the signed registry from the directory, verifies the inner
 * Ed25519 signature against a pinned pubkey, enforces anti-rollback, and caches
 * in-memory. A failed poll never blanks the last-good classification. An absent
 * registry (404) is a benign state — all types are unclassified (INV-TYPE-CARRY).
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { generateKeypair } from "@cello-protocol/crypto";
import { pollRegistryOverHttp } from "../registry-poll.js";
import { TypeRegistry } from "../type-registry.js";
import type { IRegistryVersionStore } from "../registry-version-store-db.js";

const noopLogger = { debug() {}, info() {}, warn() {}, error() {} };

class InMemoryRegistryVersionStore implements IRegistryVersionStore {
  #version: number | null = null;
  getLastSeenVersion(): number | null { return this.#version; }
  persistVersion(v: number): void { this.#version = v; }
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}

function canonicalBody(doc: Record<string, unknown>): Uint8Array {
  const body: Record<string, unknown> = {};
  for (const key of Object.keys(doc)) {
    if (key !== "signature") body[key] = doc[key];
  }
  return new TextEncoder().encode(JSON.stringify(body, sortedReplacer));
}

async function makeSignedRegistry(
  version: number,
  types: Record<string, unknown>,
  signer: { sign(d: Uint8Array): Promise<Uint8Array>; getPublicKey(): Promise<Uint8Array> },
): Promise<{ doc: Record<string, unknown>; pubkeyHex: string }> {
  const doc: Record<string, unknown> = { version, types };
  const bodyBytes = canonicalBody(doc);
  const sig = await signer.sign(bodyBytes);
  doc.signature = Buffer.from(sig).toString("hex");
  return { doc, pubkeyHex: Buffer.from(await signer.getPublicKey()).toString("hex") };
}

let servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  servers = [];
});

async function serveRegistry(getBody: () => { status: number; body: unknown; version?: number } | null): Promise<string> {
  const server = createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/registry") {
      const result = getBody();
      if (!result) { res.writeHead(503); res.end(); return; }
      if (result.status === 404) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "no_registry_published" }));
        return;
      }
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (result.version != null) headers["x-cello-registry-version"] = String(result.version);
      res.writeHead(result.status, headers);
      res.end(JSON.stringify(result.body));
      return;
    }
    res.writeHead(404); res.end();
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return `http://127.0.0.1:${port}`;
}

function makeDeps(pubkeyHex: string) {
  const versionStore = new InMemoryRegistryVersionStore();
  const typeRegistry = new TypeRegistry();
  return {
    versionStore,
    typeRegistry,
    deps: {
      typeRegistry,
      registryVersionStore: versionStore,
      registryPubkey: pubkeyHex,
      logger: noopLogger,
    },
  };
}

describe("DOD-REGISTRY-1 client registry poll", () => {
  it("adopts a valid signed registry and classifies types", async () => {
    const signer = generateKeypair();
    const types = {
      phone: { class: 1, label: "Phone verification", lifecycle: "immutable", default_ttl_days: null },
      email: { class: 1, label: "Email verification", lifecycle: "immutable", default_ttl_days: 365 },
    };
    const { doc, pubkeyHex } = await makeSignedRegistry(1, types, signer);
    const url = await serveRegistry(() => ({ status: 200, body: doc, version: 1 }));
    const { versionStore, typeRegistry, deps } = makeDeps(pubkeyHex);

    const out = await pollRegistryOverHttp({ directoryUrl: url, ...deps });

    expect(out).toMatchObject({ ok: true, adopted: true, oldVersion: null, newVersion: 1 });
    expect(typeRegistry.currentVersion).toBe(1);
    expect(typeRegistry.classify("phone")).toMatchObject({ classified: true, class: 1, label: "Phone verification" });
    expect(typeRegistry.classify("email")).toMatchObject({ classified: true, defaultTtlDays: 365 });
    expect(versionStore.getLastSeenVersion()).toBe(1);
  });

  it("INV-TYPE-CARRY: absent type returns unclassified, not an error", async () => {
    const signer = generateKeypair();
    const { doc, pubkeyHex } = await makeSignedRegistry(1, { phone: { class: 1, label: "Phone", lifecycle: "immutable", default_ttl_days: null } }, signer);
    const url = await serveRegistry(() => ({ status: 200, body: doc, version: 1 }));
    const { typeRegistry, deps } = makeDeps(pubkeyHex);

    await pollRegistryOverHttp({ directoryUrl: url, ...deps });

    expect(typeRegistry.classify("unknown_type")).toEqual({ type: "unknown_type", classified: false });
  });

  it("an empty/never-published registry (404) is benign — all unclassified", async () => {
    const signer = generateKeypair();
    const pubkeyHex = Buffer.from(await signer.getPublicKey()).toString("hex");
    const url = await serveRegistry(() => ({ status: 404, body: { error: "no_registry_published" } }));
    const { typeRegistry, deps } = makeDeps(pubkeyHex);

    const out = await pollRegistryOverHttp({ directoryUrl: url, ...deps });

    expect(out).toMatchObject({ ok: false, reason: "registry_not_published" });
    expect(typeRegistry.currentVersion).toBeNull();
    expect(typeRegistry.classify("phone")).toEqual({ type: "phone", classified: false });
  });

  it("REFUSES a forged signature — last-good cache untouched", async () => {
    const realSigner = generateKeypair();
    const fakeSigner = generateKeypair();
    const types = { phone: { class: 1, label: "Phone", lifecycle: "immutable", default_ttl_days: null } };

    // Seed a good v1
    const { doc: goodDoc, pubkeyHex } = await makeSignedRegistry(1, types, realSigner);
    const url1 = await serveRegistry(() => ({ status: 200, body: goodDoc, version: 1 }));
    const { typeRegistry, deps } = makeDeps(pubkeyHex);
    await pollRegistryOverHttp({ directoryUrl: url1, ...deps });
    expect(typeRegistry.currentVersion).toBe(1);

    // Serve a v2 signed by a DIFFERENT key
    const { doc: forgedDoc } = await makeSignedRegistry(2, { ...types, evil: { class: 9, label: "Evil", lifecycle: "x", default_ttl_days: null } }, fakeSigner);
    const url2 = await serveRegistry(() => ({ status: 200, body: forgedDoc, version: 2 }));

    const out = await pollRegistryOverHttp({ directoryUrl: url2, ...deps });

    expect(out).toMatchObject({ ok: false, reason: "registry_signature_invalid" });
    expect(typeRegistry.currentVersion).toBe(1); // last-good untouched
    expect(typeRegistry.classify("evil")).toEqual({ type: "evil", classified: false });
  });

  it("ANTI-ROLLBACK: refuses version <= last seen; cache untouched", async () => {
    const signer = generateKeypair();
    const types = { phone: { class: 1, label: "Phone", lifecycle: "immutable", default_ttl_days: null } };
    const { doc: v2Doc, pubkeyHex } = await makeSignedRegistry(2, types, signer);
    const url = await serveRegistry(() => ({ status: 200, body: v2Doc, version: 2 }));
    const { versionStore, typeRegistry, deps } = makeDeps(pubkeyHex);

    await pollRegistryOverHttp({ directoryUrl: url, ...deps });
    expect(versionStore.getLastSeenVersion()).toBe(2);

    // Now serve v1 (rollback)
    const { doc: v1Doc } = await makeSignedRegistry(1, { old: { class: 0, label: "Old", lifecycle: "x", default_ttl_days: null } }, signer);
    const url2 = await serveRegistry(() => ({ status: 200, body: v1Doc, version: 1 }));

    const out = await pollRegistryOverHttp({ directoryUrl: url2, ...deps });

    expect(out).toMatchObject({ ok: false, reason: "registry_version_rollback" });
    expect(typeRegistry.currentVersion).toBe(2); // untouched
  });

  it("equal version is a no-op (already current)", async () => {
    const signer = generateKeypair();
    const types = { phone: { class: 1, label: "Phone", lifecycle: "immutable", default_ttl_days: null } };
    const { doc, pubkeyHex } = await makeSignedRegistry(3, types, signer);
    const url = await serveRegistry(() => ({ status: 200, body: doc, version: 3 }));
    const { deps } = makeDeps(pubkeyHex);

    const first = await pollRegistryOverHttp({ directoryUrl: url, ...deps });
    expect(first).toMatchObject({ ok: true, adopted: true, newVersion: 3 });

    const second = await pollRegistryOverHttp({ directoryUrl: url, ...deps });
    expect(second).toMatchObject({ ok: true, adopted: false, oldVersion: 3, newVersion: 3 });
  });

  it("network error leaves cache untouched", async () => {
    const signer = generateKeypair();
    const types = { phone: { class: 1, label: "Phone", lifecycle: "immutable", default_ttl_days: null } };
    const { doc, pubkeyHex } = await makeSignedRegistry(1, types, signer);

    // Seed v1
    const url1 = await serveRegistry(() => ({ status: 200, body: doc, version: 1 }));
    const { typeRegistry, deps } = makeDeps(pubkeyHex);
    await pollRegistryOverHttp({ directoryUrl: url1, ...deps });

    // Now poll an unreachable URL
    const out = await pollRegistryOverHttp({ directoryUrl: "http://127.0.0.1:1", ...deps });

    expect(out).toMatchObject({ ok: false, reason: "registry_http_unreachable" });
    expect(typeRegistry.currentVersion).toBe(1); // untouched
  });

  it("malformed JSON leaves cache untouched", async () => {
    const signer = generateKeypair();
    const pubkeyHex = Buffer.from(await signer.getPublicKey()).toString("hex");
    const url = await serveRegistry(() => ({ status: 200, body: "not json {{{", version: 1 }));
    const { typeRegistry, deps } = makeDeps(pubkeyHex);

    const out = await pollRegistryOverHttp({ directoryUrl: url, ...deps });

    expect(out).toMatchObject({ ok: false, reason: "registry_malformed" });
    expect(typeRegistry.currentVersion).toBeNull();
  });

  it("a forward version (v1 → v3) adopts successfully", async () => {
    const signer = generateKeypair();
    const { doc: v1Doc, pubkeyHex } = await makeSignedRegistry(1, { a: { class: 1, label: "A", lifecycle: "x", default_ttl_days: null } }, signer);
    const url1 = await serveRegistry(() => ({ status: 200, body: v1Doc, version: 1 }));
    const { typeRegistry, deps } = makeDeps(pubkeyHex);

    await pollRegistryOverHttp({ directoryUrl: url1, ...deps });

    const { doc: v3Doc } = await makeSignedRegistry(3, { a: { class: 1, label: "A-updated", lifecycle: "x", default_ttl_days: null }, b: { class: 2, label: "B", lifecycle: "y", default_ttl_days: 90 } }, signer);
    const url2 = await serveRegistry(() => ({ status: 200, body: v3Doc, version: 3 }));

    const out = await pollRegistryOverHttp({ directoryUrl: url2, ...deps });

    expect(out).toMatchObject({ ok: true, adopted: true, oldVersion: 1, newVersion: 3 });
    expect(typeRegistry.classify("b")).toMatchObject({ classified: true, class: 2, label: "B" });
  });
});
