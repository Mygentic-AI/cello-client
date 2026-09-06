/**
 * key-binding.ts — 038-KEYBIND. The signature that says "this group key is mine".
 *
 * ─── The problem this closes ───────────────────────────────────────────────────────────────────
 *
 * An agent holds TWO keypairs. `K_local` is the 64-hex identity operators paste around: minted
 * locally, before registration, and its private half is a seed on that machine. The FROST group
 * keypair comes out of the DKG: its private half NEVER EXISTS anywhere — only shares do — and its
 * public half (`primary_pubkey`) is what threshold signatures verify under.
 *
 * A FROST DKG cannot produce `K_local` as its group key: the group key is the sum of every
 * participant's commitment, so by construction it is nobody's existing key. The two-key structure
 * is inherent. What was missing is the LINK between them.
 *
 * Without that link, a responder receiving its first session assignment from a stranger verified
 * the assignment's threshold signature against `signer_pubkey` — a field of the very document being
 * verified — and then wrote that key down as the counterparty's identity forever. The signature
 * always verified. It established nothing about who signed. A directory naming any group key it
 * liked was indistinguishable from an honest one.
 *
 * ─── What the binding is, and why it is not a directory signature ──────────────────────────────
 *
 * `K_local` signs a statement naming the group key. The signer is therefore a key NO DIRECTORY
 * HOLDS, which is the entire value: a hostile directory can neither forge a binding nor lift one
 * onto another identity. It can only WITHHOLD it — and an absent binding is a refusal, never a
 * tolerated shape.
 *
 * Substituting a directory signature here would convert "unverifiable" into "a directory says so",
 * and one dishonest directory would still get through. That is worth adding SEPARATELY as defence
 * in depth; it is not this.
 *
 * ─── BOTH keys are signed over, and that is load-bearing ───────────────────────────────────────
 *
 * The signed bytes name the K_local public key AND the group public key. Signing the group key
 * alone would let a valid binding be lifted onto a different identity: an attacker replays A's
 * binding while claiming to be B, and a verifier checking only "someone vouched for G" accepts it.
 * Naming both means a binding verified against B's K_local is a statement B made about B.
 *
 * ─── Encoding ──────────────────────────────────────────────────────────────────────────────────
 *
 *   framed = <context UTF-8 bytes> 0x00 <k_local_pubkey 32B> <group_pubkey 32B>
 *
 * The `<context>\0<body>` framing is the one this project already uses for FROST domain separation
 * (`frost/types.ts`), so a signature produced here can never be replayed as a session-establishment
 * or seal signature, or vice versa. The body is RAW CONCATENATION rather than CBOR because both
 * halves are fixed-width 32-byte keys — there is no width ambiguity to resolve, and this keeps the
 * package free of a CBOR dependency it does not otherwise need. Same reasoning as
 * `computeGenesisPrevRoot`, which also concatenates fixed-width values.
 *
 * Ed25519 per RFC 8032. This is a PLAIN Ed25519 signature by K_local, NOT a threshold signature —
 * `CONTEXT_KEY_BINDING` is deliberately not a member of `FrostContext`, so it cannot be handed to
 * the FROST verifier by mistake.
 */

import { verify } from "./ed25519.js";

/**
 * Domain-separation context for the K_local→group-key binding.
 *
 * A NEW constant, never a reused one: sharing a context with the session-establishment or seal
 * signatures would make a binding replayable as one of those (and vice versa), which is the exact
 * class of forgery domain separation exists to prevent.
 */
export const CONTEXT_KEY_BINDING = "cello-key-binding-v1" as const;

const KEY_BYTES = 32;

/**
 * The bytes `K_local` signs to bind itself to a FROST group key.
 *
 * Throws on a wrong-length key rather than signing or verifying something shorter: a binding over
 * truncated bytes would verify against itself and mean nothing, and both callers (the daemon at
 * registration, the verifier on an inbound assignment) have a real key or a real fault.
 */
export function buildKeyBindingTbs(kLocalPubkey: Uint8Array, groupPubkey: Uint8Array): Uint8Array {
  if (kLocalPubkey.length !== KEY_BYTES) {
    throw new Error(`key binding: k_local pubkey must be ${KEY_BYTES} bytes, got ${kLocalPubkey.length}`);
  }
  if (groupPubkey.length !== KEY_BYTES) {
    throw new Error(`key binding: group pubkey must be ${KEY_BYTES} bytes, got ${groupPubkey.length}`);
  }
  const context = new TextEncoder().encode(CONTEXT_KEY_BINDING);
  const framed = new Uint8Array(context.length + 1 + KEY_BYTES + KEY_BYTES);
  framed.set(context, 0);
  framed[context.length] = 0x00;
  framed.set(kLocalPubkey, context.length + 1);
  framed.set(groupPubkey, context.length + 1 + KEY_BYTES);
  return framed;
}

/**
 * Verify a key binding: does the holder of `kLocalPubkey` claim `groupPubkey` as its group key?
 *
 * Returns FALSE — never throws — for every rejectable input, including a malformed signature or a
 * wrong-length key. The callers are refusal paths that must name their own reason and guidance; a
 * throw escaping into an inbound frame handler would take a different exit than the one the
 * operator gets told about.
 */
export function verifyKeyBinding(
  signature: Uint8Array,
  kLocalPubkey: Uint8Array,
  groupPubkey: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  if (kLocalPubkey.length !== KEY_BYTES || groupPubkey.length !== KEY_BYTES) return false;
  try {
    // `verify` takes (publicKey, data, signature) — NOT the (sig, msg, key) order @noble uses.
    return verify(kLocalPubkey, buildKeyBindingTbs(kLocalPubkey, groupPubkey), signature);
  } catch {
    // A pubkey that is not a valid curve point makes @noble throw. That is a refusal, not a crash.
    return false;
  }
}
