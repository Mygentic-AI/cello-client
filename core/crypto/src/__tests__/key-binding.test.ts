/**
 * 002-PQKEYS — the v2 key binding: one statement naming all four of an agent's keys (K_local, the
 * FROST group key, the ML-DSA key, the ML-KEM key), signed by BOTH K_local (Ed25519) and the ML-DSA
 * key (Contract 2 frame, `cello-mldsa-key-binding-v1`). Supersedes 038-KEYBIND's v1.
 *
 * REAL CRYPTO, no mocks. Every negative is another party's GENUINE signature, never a corrupted
 * blob: a verifier that checked only one half would still refuse a corrupted blob.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateKeypair,
  buildKeyBindingTbs,
  verifyKeyBinding,
  verifyRegisteredKeys,
  CONTEXT_KEY_BINDING,
  CONTEXT_SESSION_ESTABLISHMENT,
  mlDsaGenerateSeed,
  mlDsaProviderFromSeed,
  mlKemGenerateSeed,
  mlKemKeypairFromSeed,
  signMlDsa,
} from "../index.js";

const GROUP = new Uint8Array(32).fill(0x11);

/** A real agent: K_local, a group key, and real ML-DSA / ML-KEM keys. */
async function agent(group: Uint8Array = GROUP) {
  const kLocal = generateKeypair();
  const mlDsa = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
  const keys = {
    kLocal: await kLocal.getPublicKey(),
    group,
    mlDsa: await mlDsa.getPublicKey(),
    mlKem: (await mlKemKeypairFromSeed(mlKemGenerateSeed())).publicKey,
  };
  const tbs = buildKeyBindingTbs(keys);
  return {
    kLocalSigner: kLocal,
    mlDsaSigner: mlDsa,
    keys,
    signature: await kLocal.sign(tbs),
    signaturePq: await signMlDsa(mlDsa, "cello-mldsa-key-binding-v1", tbs),
  };
}

describe("002-PQKEYS test 1 — round trip", () => {
  it("both signatures over the v2 TBS verify", async () => {
    const a = await agent();
    expect(await verifyKeyBinding({ keys: a.keys, signature: a.signature, signaturePq: a.signaturePq })).toEqual({ ok: true });
  });
});

describe("002-PQKEYS test 2 — D5's exemplar: genuine Ed25519 beside ANOTHER agent's genuine ML-DSA", () => {
  it("B's real ML-DSA key signs A's exact TBS; A's Ed25519 is genuine → key_binding_pq_signature_mismatch", async () => {
    const a = await agent();
    const b = await agent();
    const bSignsATbs = await signMlDsa(b.mlDsaSigner, "cello-mldsa-key-binding-v1", buildKeyBindingTbs(a.keys));
    expect(await verifyKeyBinding({ keys: a.keys, signature: a.signature, signaturePq: bSignsATbs }))
      .toEqual({ ok: false, reason: "key_binding_pq_signature_mismatch" });
  });
});

describe("002-PQKEYS test 3 — genuine ML-DSA beside another K_local's genuine Ed25519", () => {
  it("→ key_binding_signature_mismatch", async () => {
    const a = await agent();
    const other = generateKeypair();
    const otherSigns = await other.sign(buildKeyBindingTbs(a.keys));
    expect(await verifyKeyBinding({ keys: a.keys, signature: otherSigns, signaturePq: a.signaturePq }))
      .toEqual({ ok: false, reason: "key_binding_signature_mismatch" });
  });
});

describe("002-PQKEYS test 4 — an attacker swaps only the ML-KEM key", () => {
  it("both old signatures kept → the Ed25519 check (first) refuses", async () => {
    const a = await agent();
    const swapped = { ...a.keys, mlKem: (await mlKemKeypairFromSeed(mlKemGenerateSeed())).publicKey };
    expect(await verifyKeyBinding({ keys: swapped, signature: a.signature, signaturePq: a.signaturePq }))
      .toEqual({ ok: false, reason: "key_binding_signature_mismatch" });
  });

  it("Ed25519 re-made over the swapped TBS by the REAL K_local, old ML-DSA kept → the ML-DSA check refuses", async () => {
    const a = await agent();
    const swapped = { ...a.keys, mlKem: (await mlKemKeypairFromSeed(mlKemGenerateSeed())).publicKey };
    const reSigned = await a.kLocalSigner.sign(buildKeyBindingTbs(swapped));
    expect(await verifyKeyBinding({ keys: swapped, signature: reSigned, signaturePq: a.signaturePq }))
      .toEqual({ ok: false, reason: "key_binding_pq_signature_mismatch" });
  });
});

describe("002-PQKEYS test 4a — verifyRegisteredKeys: the subject is the key the CALLER asked about", () => {
  const profile = (a: Awaited<ReturnType<typeof agent>>) => ({
    k_local_pubkey: a.keys.kLocal,
    primary_pubkey: a.keys.group,
    ml_dsa_pubkey: a.keys.mlDsa,
    ml_kem_pubkey: a.keys.mlKem,
    key_binding: a.signature,
    key_binding_pq: a.signaturePq,
  });

  it("asked about Y, answered with X's genuine, fully valid profile → key_binding_subject_mismatch", async () => {
    const x = await agent();
    const y = await agent();
    expect(await verifyRegisteredKeys(y.keys.kLocal, profile(x)))
      .toEqual({ ok: false, reason: "key_binding_subject_mismatch" });
  });

  it("asked about X, answered with X's profile → the two PQ keys", async () => {
    const x = await agent();
    const r = await verifyRegisteredKeys(x.keys.kLocal, profile(x));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Buffer.from(r.mlDsa)).toEqual(Buffer.from(x.keys.mlDsa));
      expect(Buffer.from(r.mlKem)).toEqual(Buffer.from(x.keys.mlKem));
    }
  });

  it("asked about X, X's profile with a third party's ML-DSA binding signature → the binding refusal, not subject", async () => {
    const x = await agent();
    const z = await agent();
    const forged = await signMlDsa(z.mlDsaSigner, "cello-mldsa-key-binding-v1", buildKeyBindingTbs(x.keys));
    expect(await verifyRegisteredKeys(x.keys.kLocal, { ...profile(x), key_binding_pq: forged }))
      .toEqual({ ok: false, reason: "key_binding_pq_signature_mismatch" });
  });
});

describe("002-PQKEYS test 5 — presence is checked before anything else", () => {
  it("signaturePq undefined → key_binding_pq_missing; signature undefined → key_binding_missing", async () => {
    const a = await agent();
    expect(await verifyKeyBinding({ keys: a.keys, signature: a.signature, signaturePq: undefined }))
      .toEqual({ ok: false, reason: "key_binding_pq_missing" });
    expect(await verifyKeyBinding({ keys: a.keys, signature: undefined, signaturePq: a.signaturePq }))
      .toEqual({ ok: false, reason: "key_binding_missing" });
  });

  it("wrong widths → key_binding_malformed, and verify never throws", async () => {
    const a = await agent();
    const cases = [
      { keys: a.keys, signature: a.signature.slice(0, 63), signaturePq: a.signaturePq },
      { keys: a.keys, signature: a.signature, signaturePq: a.signaturePq.slice(0, 2419) },
      { keys: { ...a.keys, mlKem: a.keys.mlKem.slice(0, 1183) }, signature: a.signature, signaturePq: a.signaturePq },
      { keys: { ...a.keys, mlDsa: a.keys.mlDsa.slice(0, 1311) }, signature: a.signature, signaturePq: a.signaturePq },
      { keys: { ...a.keys, kLocal: new Uint8Array(31) }, signature: a.signature, signaturePq: a.signaturePq },
      { keys: { ...a.keys, group: new Uint8Array(33) }, signature: a.signature, signaturePq: a.signaturePq },
    ];
    for (const c of cases) {
      expect(await verifyKeyBinding(c)).toEqual({ ok: false, reason: "key_binding_malformed" });
    }
  });

  it("a K_local that is not a curve point is a signature refusal, not an exception", async () => {
    const a = await agent();
    const bad = { ...a.keys, kLocal: new Uint8Array(32).fill(0xff) };
    expect(await verifyKeyBinding({ keys: bad, signature: a.signature, signaturePq: a.signaturePq }))
      .toEqual({ ok: false, reason: "key_binding_signature_mismatch" });
  });
});

describe("domain separation", () => {
  it("an Ed25519 signature over the same body under the session-establishment context is refused", async () => {
    const a = await agent();
    const tbs = buildKeyBindingTbs(a.keys);
    const ctx = new TextEncoder().encode(CONTEXT_KEY_BINDING);
    const body = tbs.subarray(ctx.length + 1);
    const est = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
    const wrongDomain = new Uint8Array([...est, 0x00, ...body]);
    const sig = await a.kLocalSigner.sign(wrongDomain);
    expect(await verifyKeyBinding({ keys: a.keys, signature: sig, signaturePq: a.signaturePq }))
      .toEqual({ ok: false, reason: "key_binding_signature_mismatch" });
  });

  it("an ML-DSA signature over the same TBS under a different PqContext is refused", async () => {
    const a = await agent();
    const wrongCtx = await signMlDsa(a.mlDsaSigner, "cello-mldsa-endorsement-v1", buildKeyBindingTbs(a.keys));
    expect(await verifyKeyBinding({ keys: a.keys, signature: a.signature, signaturePq: wrongCtx }))
      .toEqual({ ok: false, reason: "key_binding_pq_signature_mismatch" });
  });
});

describe("002-PQKEYS test 6 — the exact bytes, against a hand-built array", () => {
  it("\"cello-key-binding-v2\" ‖ 0x00 ‖ k_local(32) ‖ group(32) ‖ ml_dsa(1312) ‖ ml_kem(1184)", () => {
    const keys = {
      kLocal: new Uint8Array(32).fill(0xaa),
      group: new Uint8Array(32).fill(0xbb),
      mlDsa: new Uint8Array(1312).fill(0xcc),
      mlKem: new Uint8Array(1184).fill(0xdd),
    };
    const expected = new Uint8Array([
      ...Buffer.from("cello-key-binding-v2", "utf8"), 0x00,
      ...keys.kLocal, ...keys.group, ...keys.mlDsa, ...keys.mlKem,
    ]);
    expect(CONTEXT_KEY_BINDING).toBe("cello-key-binding-v2");
    expect(Buffer.from(buildKeyBindingTbs(keys))).toEqual(Buffer.from(expected));
    expect(expected.length).toBe(21 + 32 + 32 + 1312 + 1184);
  });

  it("refuses to BUILD over a wrong-width key (a truncated binding would verify against itself)", () => {
    const ok = { kLocal: new Uint8Array(32), group: new Uint8Array(32), mlDsa: new Uint8Array(1312), mlKem: new Uint8Array(1184) };
    expect(() => buildKeyBindingTbs({ ...ok, kLocal: new Uint8Array(31) })).toThrow(/k_local/);
    expect(() => buildKeyBindingTbs({ ...ok, group: new Uint8Array(16) })).toThrow(/group/);
    expect(() => buildKeyBindingTbs({ ...ok, mlDsa: new Uint8Array(1311) })).toThrow(/ml_dsa/);
    expect(() => buildKeyBindingTbs({ ...ok, mlKem: new Uint8Array(1185) })).toThrow(/ml_kem/);
  });
});

describe("002-PQKEYS test 7 — v1 is gone from every client source", () => {
  it("the string cello-key-binding-v1 appears nowhere in core/*/src outside tests", () => {
    const core = fileURLToPath(new URL("../../../", import.meta.url));
    const hits: string[] = [];
    const walk = (d: string): void => {
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) {
          if (n !== "__tests__" && n !== "node_modules" && !n.startsWith("dist")) walk(p);
        } else if (n.endsWith(".ts") && readFileSync(p, "utf8").includes("cello-key-binding-v1")) {
          hits.push(p);
        }
      }
    };
    for (const pkg of readdirSync(core)) {
      try { if (statSync(join(core, pkg, "src")).isDirectory()) walk(join(core, pkg, "src")); } catch { /* no src */ }
    }
    expect(hits).toEqual([]);
  });
});
