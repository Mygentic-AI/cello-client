/**
 * M10E 013-PRIVATE — the client half of a private namespace's reader list.
 *
 * Real keys and a fake signaling object (mirrors the 005/007 harness). The golden vector pins the
 * cross-repo wire contract: the directory's reader-list.test asserts the SAME hex, so a drift on
 * either side fails one of the two.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair, verify, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  encodeReaderList,
  decodeReaderList,
  hashReaderList,
  canonicalReaders,
  readersList,
  readersUpdate,
  type ReaderListRecord,
} from "../attestation-readers.js";
import type { NamespaceDeps, NamespaceSignaling } from "../attestation-namespaces.js";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const NOW_MS = 1_800_000_000_000;
const silentLogger = { info() {}, warn() {}, error() {}, debug() {} } as unknown as NamespaceDeps["logger"];

/** A signaling stub that answers readers_get from its held `current` and stores a readers_set. */
function fakeSignaling(): NamespaceSignaling & { current: { version: number; record: Uint8Array } | null; lastSet?: { record: Uint8Array; signature: Uint8Array } } {
  let handler: ((f: Record<string, unknown>) => void) | null = null;
  const owner = () => ownerHex;
  let ownerHex = "";
  const api = {
    current: null as { version: number; record: Uint8Array } | null,
    lastSet: undefined as { record: Uint8Array; signature: Uint8Array } | undefined,
    registerInboundHandler(h: (f: Record<string, unknown>) => void) { handler = h; return () => { handler = null; }; },
    async sendRaw(frame: unknown): Promise<{ ok: boolean }> {
      const f = frame as Record<string, unknown>;
      ownerHex = String(f["owner_pubkey"] ?? ownerHex);
      queueMicrotask(() => {
        if (!handler) return;
        if (f["type"] === "attestation_readers_get") {
          handler({ type: "attestation_readers", owner_pubkey: owner(), namespace: f["namespace"], version: api.current ? api.current.version : null, record: api.current ? api.current.record : null, signature: api.current ? new Uint8Array(64) : null });
        } else if (f["type"] === "attestation_readers_set") {
          const record = f["record"] as Uint8Array;
          api.lastSet = { record, signature: f["signature"] as Uint8Array };
          const rec = decodeReaderList(record);
          api.current = { version: rec.version, record };
          handler({ type: "attestation_readers_result", owner_pubkey: rec.owner, namespace: rec.namespace, version: rec.version, status: "stored" });
        }
      });
      return { ok: true };
    },
  };
  return api;
}

async function makeDeps(): Promise<{ deps: NamespaceDeps; key: InMemoryKeyProvider; owner: string; sig: ReturnType<typeof fakeSignaling> }> {
  const key = generateKeypair();
  const owner = hex(await key.getPublicKey());
  const sig = fakeSignaling();
  return { deps: { signaling: sig, keyProvider: key, ownerPubkeyHex: owner, now: () => NOW_MS, logger: silentLogger, timeoutMs: 2000 }, key, owner, sig };
}

const R1 = "1".repeat(64);
const R2 = "2".repeat(64);

describe("013-PRIVATE client — codec", () => {
  it("round-trips", () => {
    const r: ReaderListRecord = { owner: "a".repeat(64), namespace: "support_qa", readers: [R1, R2], version: 1, issued_at: 1_800_000_000 };
    expect(decodeReaderList(encodeReaderList(r))).toEqual(r);
  });

  it("GOLDEN: matches the directory's pinned bytes and hash", () => {
    const r: ReaderListRecord = { owner: "a".repeat(64), namespace: "support_qa", readers: [R1, R2], version: 1, issued_at: 1_800_000_000 };
    expect(hex(encodeReaderList(r))).toBe(
      "866e43454c4c4f2d41524452532d76317840616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616a737570706f72745f716182784031313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131784032323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232011a6b49d200");
    expect(hex(hashReaderList(r))).toBe("c1d06edbb7ee4eb893a46f5347af7c661bab1428c7794220af41c3e98ac0f179");
  });

  it("canonicalReaders lowercases, dedupes and sorts", () => {
    expect(canonicalReaders([R2, R1, R1.toUpperCase()])).toEqual([R1, R2]);
  });
});

describe("013-PRIVATE client — add/remove/list", () => {
  it("add builds and signs version 1 with the reader, verifiable under the owner key", async () => {
    const { deps, key, owner, sig } = await makeDeps();
    const res = await readersUpdate(deps, "support_qa", { add: [R1] });
    expect(res).toMatchObject({ ok: true, status: "stored", version: 1, readers: [R1] });
    const rec = decodeReaderList(sig.lastSet!.record);
    expect(rec).toMatchObject({ owner, namespace: "support_qa", readers: [R1], version: 1 });
    expect(verify(await key.getPublicKey(), hashReaderList(rec), sig.lastSet!.signature)).toBe(true);
  });

  it("a second add builds version 2 on top of version 1 and keeps both readers sorted", async () => {
    const { deps } = await makeDeps();
    await readersUpdate(deps, "support_qa", { add: [R2] });
    const res = await readersUpdate(deps, "support_qa", { add: [R1] });
    expect(res).toMatchObject({ ok: true, version: 2, readers: [R1, R2] });
  });

  it("remove drops a reader in the next version", async () => {
    const { deps } = await makeDeps();
    await readersUpdate(deps, "support_qa", { add: [R1, R2] });
    const res = await readersUpdate(deps, "support_qa", { remove: [R1] });
    expect(res).toMatchObject({ ok: true, version: 2, readers: [R2] });
  });

  it("list returns the current readers and version", async () => {
    const { deps } = await makeDeps();
    await readersUpdate(deps, "support_qa", { add: [R1] });
    expect(await readersList(deps, "support_qa")).toEqual({ ok: true, view: { version: 1, readers: [R1] } });
  });

  it("surfaces a directory refusal with guidance (not_permitted)", async () => {
    const key = generateKeypair();
    const owner = hex(await key.getPublicKey());
    let hh: ((f: Record<string, unknown>) => void) | null = null;
    const errSignaling: NamespaceSignaling = {
      registerInboundHandler: (h) => { hh = h; return () => { hh = null; }; },
      sendRaw: async () => { queueMicrotask(() => hh?.({ type: "attestation_namespace_error", reason: "not_permitted" })); return { ok: true }; },
    };
    const deps: NamespaceDeps = { signaling: errSignaling, keyProvider: key, ownerPubkeyHex: owner, now: () => NOW_MS, logger: silentLogger, timeoutMs: 2000 };
    const res = await readersList(deps, "support_qa");
    expect(res).toMatchObject({ ok: false, reason: "not_permitted" });
    expect((res as { guidance: string }).guidance).toMatch(/owner/i);
  });
});
