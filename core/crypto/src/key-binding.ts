/**
 * key-binding.ts — 038-KEYBIND, extended to four keys by M9D 002-PQKEYS. The signature that says
 * "these keys are mine".
 *
 * ─── The problem this closes ───────────────────────────────────────────────────────────────────
 *
 * An agent holds FOUR keys. `K_local` is the 64-hex identity operators paste around: minted
 * locally, before registration, and its private half is a seed on that machine. The FROST group
 * keypair comes out of the DKG: its private half NEVER EXISTS anywhere — only shares do — and its
 * public half (`primary_pubkey`) is what threshold signatures verify under. The ML-DSA-44 key signs
 * beside K_local so every signature has a post-quantum twin, and the ML-KEM-768 key is what content
 * sealed to this agent is encapsulated to. Both post-quantum keys are minted on this machine at
 * registration and fixed for life.
 *
 * A FROST DKG cannot produce `K_local` as its group key: the group key is the sum of every
 * participant's commitment, so by construction it is nobody's existing key. The multi-key structure
 * is inherent. What was missing is the LINK between them.
 *
 * Without that link, a responder receiving its first session assignment from a stranger verified
 * the assignment's threshold signature against `signer_pubkey` — a field of the very document being
 * verified — and then wrote that key down as the counterparty's identity forever. The signature
 * always verified. It established nothing about who signed. The same holds for post-quantum keys:
 * a directory naming any ML-KEM key it liked would receive everything sealed to it.
 *
 * ─── What the binding is ───────────────────────────────────────────────────────────────────────
 *
 * The agent signs ONE statement naming all four keys, twice: with K_local (Ed25519) and with its
 * ML-DSA key (the Contract 2 frame, context `cello-mldsa-key-binding-v1`). The signers are keys NO
 * DIRECTORY HOLDS, so a hostile directory can neither forge a binding nor lift one onto another
 * identity. It can only WITHHOLD it — and an absent binding is a refusal, never a tolerated shape.
 *
 * Both halves are required. The Ed25519 half is what a classical verifier trusts today; the ML-DSA
 * half is what still holds when Ed25519 does not. A quantum attacker who forges K_local's signature
 * over a binding naming THEIR ML-DSA key can also produce a matching ML-DSA signature — the binding
 * alone is self-certifying on the post-quantum side. That gap is closed elsewhere: the directory
 * checks the binding at registration against the signaling-authenticated K_local and never accepts
 * a second set of keys for an agent (keys are fixed at registration), and 007-PQBUNDLE puts a digest
 * of both parties' keys into the establishment statement FROST and T directories sign.
 *
 * ─── Who checks it ─────────────────────────────────────────────────────────────────────────────
 *
 * The directory, at registration, before it writes the profile — it holds every input: K_local
 * from signaling auth, the PQ keys from `register_request`, the group key from the DKG. And every
 * client, on every counterparty it learns about. Neither replaces the other: the client is the
 * adversary's code, so the directory cannot rely on it, and a directory can be compromised, so the
 * client cannot rely on it either.
 *
 * ─── ALL FOUR keys are signed over, and that is load-bearing ───────────────────────────────────
 *
 * Naming K_local means a binding verified against B's K_local is a statement B made about B: an
 * attacker cannot replay A's binding while claiming to be B. Naming the other three means none of
 * them can be swapped under a kept signature.
 *
 * ─── Encoding ──────────────────────────────────────────────────────────────────────────────────
 *
 *   tbs = "cello-key-binding-v2" 0x00 <k_local 32B> <group 32B> <ml_dsa 1312B> <ml_kem 1184B>
 *
 * The `<context>\0<body>` framing is the one this project already uses for FROST domain separation
 * (`frost/types.ts`), so a signature produced here can never be replayed as a session-establishment
 * or seal signature, or vice versa. The body is RAW CONCATENATION rather than CBOR because every
 * part is fixed-width — there is no width ambiguity to resolve.
 *
 * Ed25519 per RFC 8032, ML-DSA-44 per FIPS 204. Both are PLAIN signatures by the agent, NOT threshold
 * signatures — `CONTEXT_KEY_BINDING` is deliberately not a member of `FrostContext`, so it cannot be
 * handed to the FROST verifier by mistake.
 */

import { verify } from "./ed25519.js";
import { ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SIGNATURE_BYTES } from "./ml-dsa.js";
import { ML_KEM_PUBLIC_KEY_BYTES } from "./ml-kem.js";
import { verifyMlDsa } from "./pq-frame.js";

/**
 * Domain-separation context for the four-key binding. A NEW constant, never a reused one: sharing a
 * context with the session-establishment or seal signatures would make a binding replayable as one
 * of those (and vice versa).
 */
export const CONTEXT_KEY_BINDING = "cello-key-binding-v2" as const;

const ED25519_KEY_BYTES = 32;
const ED25519_SIG_BYTES = 64;

export interface BoundKeys {
  kLocal: Uint8Array;
  group: Uint8Array;
  mlDsa: Uint8Array;
  mlKem: Uint8Array;
}

/**
 * The bytes BOTH binding signatures are over — the single builder for signer and verifier.
 *
 * Throws on a wrong-width key rather than signing or verifying something shorter: a binding over
 * truncated bytes would verify against itself and mean nothing, and every caller has a real key or
 * a real fault.
 */
export function buildKeyBindingTbs(k: BoundKeys): Uint8Array {
  const widths: Array<[keyof BoundKeys, string, number]> = [
    ["kLocal", "k_local pubkey", ED25519_KEY_BYTES],
    ["group", "group pubkey", ED25519_KEY_BYTES],
    ["mlDsa", "ml_dsa pubkey", ML_DSA_PUBLIC_KEY_BYTES],
    ["mlKem", "ml_kem pubkey", ML_KEM_PUBLIC_KEY_BYTES],
  ];
  for (const [field, label, n] of widths) {
    if (!(k[field] instanceof Uint8Array) || k[field].length !== n) {
      throw new Error(`key binding: ${label} must be ${n} bytes, got ${k[field]?.length}`);
    }
  }
  const context = new TextEncoder().encode(CONTEXT_KEY_BINDING);
  const out = new Uint8Array(context.length + 1 + 32 + 32 + ML_DSA_PUBLIC_KEY_BYTES + ML_KEM_PUBLIC_KEY_BYTES);
  let o = 0;
  out.set(context, o); o += context.length;
  out[o++] = 0x00;
  for (const [field] of widths) { out.set(k[field], o); o += k[field].length; }
  return out;
}

/** Why a binding was refused — five different things, never collapsed (procedure Invariant 3). */
export const KEY_BINDING_REFUSALS = [
  "key_binding_missing",
  "key_binding_pq_missing",
  "key_binding_malformed",
  "key_binding_signature_mismatch",
  "key_binding_pq_signature_mismatch",
] as const;
export type KeyBindingRefusal = (typeof KEY_BINDING_REFUSALS)[number];

/**
 * Verify a four-key binding: did the holder of `keys.kLocal` AND of `keys.mlDsa` both sign this exact
 * set of four keys?
 *
 * Never throws. Checks, in this order, returning the first failure: presence of each signature,
 * widths, the Ed25519 signature, the ML-DSA signature. Both signatures are over bytes from the same
 * `buildKeyBindingTbs`. The callers are refusal paths that name their own reason and guidance.
 */
export async function verifyKeyBinding(opts: {
  keys: BoundKeys;
  signature: Uint8Array | undefined;
  signaturePq: Uint8Array | undefined;
}): Promise<{ ok: true } | { ok: false; reason: KeyBindingRefusal }> {
  const { keys, signature, signaturePq } = opts;
  if (signature === undefined) return { ok: false, reason: "key_binding_missing" };
  if (signaturePq === undefined) return { ok: false, reason: "key_binding_pq_missing" };
  if (signature.length !== ED25519_SIG_BYTES || signaturePq.length !== ML_DSA_SIGNATURE_BYTES) {
    return { ok: false, reason: "key_binding_malformed" };
  }
  let tbs: Uint8Array;
  try {
    tbs = buildKeyBindingTbs(keys);
  } catch {
    return { ok: false, reason: "key_binding_malformed" };
  }
  let classical = false;
  try {
    // `verify` takes (publicKey, data, signature) — NOT the (sig, msg, key) order @noble uses.
    classical = verify(keys.kLocal, tbs, signature);
  } catch {
    // A K_local that is not a valid curve point makes @noble throw. That is a refusal, not a crash.
    classical = false;
  }
  if (!classical) return { ok: false, reason: "key_binding_signature_mismatch" };
  if (!(await verifyMlDsa(keys.mlDsa, "cello-mldsa-key-binding-v1", tbs, signaturePq))) {
    return { ok: false, reason: "key_binding_pq_signature_mismatch" };
  }
  return { ok: true };
}

/**
 * THE function any party uses to accept an agent's post-quantum keys from anywhere a directory serves
 * a profile. Nobody reimplements it.
 *
 * `expectedKLocal` is the key the CALLER asked about — never a value taken from the response. If the
 * profile names a different K_local the answer is `key_binding_subject_mismatch` before any signature
 * is checked: otherwise a directory could answer a question about agent Y with agent X's genuine,
 * perfectly valid profile.
 */
export async function verifyRegisteredKeys(expectedKLocal: Uint8Array, p: {
  k_local_pubkey: Uint8Array;
  primary_pubkey: Uint8Array;
  ml_dsa_pubkey: Uint8Array;
  ml_kem_pubkey: Uint8Array;
  key_binding: Uint8Array;
  key_binding_pq: Uint8Array;
}): Promise<{ ok: true; mlDsa: Uint8Array; mlKem: Uint8Array }
          | { ok: false; reason: KeyBindingRefusal | "key_binding_subject_mismatch" }> {
  if (!bytesEqual(expectedKLocal, p.k_local_pubkey)) {
    return { ok: false, reason: "key_binding_subject_mismatch" };
  }
  const r = await verifyKeyBinding({
    keys: { kLocal: p.k_local_pubkey, group: p.primary_pubkey, mlDsa: p.ml_dsa_pubkey, mlKem: p.ml_kem_pubkey },
    signature: p.key_binding,
    signaturePq: p.key_binding_pq,
  });
  if (!r.ok) return r;
  return { ok: true, mlDsa: p.ml_dsa_pubkey, mlKem: p.ml_kem_pubkey };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
