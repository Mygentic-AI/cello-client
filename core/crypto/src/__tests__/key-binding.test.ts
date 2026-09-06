/**
 * 038-KEYBIND — the binding primitive.
 *
 * REAL CRYPTO, no mocks: the whole subject is a signature, so a stubbed primitive would test
 * nothing. Every key here comes from `generateKeypair`.
 *
 * The two properties that matter, and both are attacks that work if the encoding is wrong:
 *  - a binding is not transferable to another identity (both keys are signed over, not just G);
 *  - a binding cannot be replayed as a session-establishment or seal signature (domain separation).
 */
import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  buildKeyBindingTbs,
  verifyKeyBinding,
  CONTEXT_KEY_BINDING,
  CONTEXT_SESSION_ESTABLISHMENT,
} from "../index.js";

const GROUP = new Uint8Array(32).fill(0x11);
const OTHER_GROUP = new Uint8Array(32).fill(0x22);

describe("038-KEYBIND: a K_local signature naming a FROST group key", () => {
  it("VERIFIES a binding the identity key actually made", async () => {
    const kp = generateKeypair();
    const kLocal = await kp.getPublicKey();
    const sig = await kp.sign(buildKeyBindingTbs(kLocal, GROUP));

    expect(verifyKeyBinding(sig, kLocal, GROUP)).toBe(true);
  });

  it("REFUSES a binding lifted onto a different identity — the whole reason both keys are signed", async () => {
    // A signs a binding for group key G. B replays it while claiming G is B's.
    const a = generateKeypair();
    const b = generateKeypair();
    const aLocal = await a.getPublicKey();
    const bLocal = await b.getPublicKey();
    const sig = await a.sign(buildKeyBindingTbs(aLocal, GROUP));

    expect(verifyKeyBinding(sig, aLocal, GROUP), "control: A's own binding must still hold").toBe(true);
    expect(
      verifyKeyBinding(sig, bLocal, GROUP),
      "if this passed, one agent's binding would vouch for any other agent's claim to the same group key",
    ).toBe(false);
  });

  it("REFUSES when the group key is swapped after signing", async () => {
    const kp = generateKeypair();
    const kLocal = await kp.getPublicKey();
    const sig = await kp.sign(buildKeyBindingTbs(kLocal, GROUP));

    expect(verifyKeyBinding(sig, kLocal, OTHER_GROUP)).toBe(false);
  });

  it("REFUSES a signature by a key that is not the named identity", async () => {
    const owner = generateKeypair();
    const impostor = generateKeypair();
    const kLocal = await owner.getPublicKey();
    // The impostor signs the RIGHT bytes — naming the owner — with the WRONG key.
    const sig = await impostor.sign(buildKeyBindingTbs(kLocal, GROUP));

    expect(verifyKeyBinding(sig, kLocal, GROUP)).toBe(false);
  });

  it("REFUSES a signature produced under the session-establishment context — domain separation holds", async () => {
    const kp = generateKeypair();
    const kLocal = await kp.getPublicKey();
    // Same body, different context prefix: what a replay from another signing domain looks like.
    const enc = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
    const wrongDomain = new Uint8Array(enc.length + 1 + 64);
    wrongDomain.set(enc, 0);
    wrongDomain[enc.length] = 0x00;
    wrongDomain.set(kLocal, enc.length + 1);
    wrongDomain.set(GROUP, enc.length + 33);
    const sig = await kp.sign(wrongDomain);

    expect(verifyKeyBinding(sig, kLocal, GROUP)).toBe(false);
  });

  it("REFUSES a malformed signature and a malformed key WITHOUT throwing — these are refusal paths", async () => {
    const kp = generateKeypair();
    const kLocal = await kp.getPublicKey();
    const sig = await kp.sign(buildKeyBindingTbs(kLocal, GROUP));

    expect(verifyKeyBinding(new Uint8Array(0), kLocal, GROUP)).toBe(false);
    expect(verifyKeyBinding(new Uint8Array(64), kLocal, GROUP)).toBe(false);
    expect(verifyKeyBinding(sig, new Uint8Array(31), GROUP)).toBe(false);
    expect(verifyKeyBinding(sig, kLocal, new Uint8Array(33))).toBe(false);
    // A 32-byte value that is not a valid curve point: @noble throws, and this must still be a
    // `false`, not an exception escaping into an inbound frame handler.
    expect(verifyKeyBinding(sig, new Uint8Array(32).fill(0xff), GROUP)).toBe(false);
  });

  it("REFUSES to build a TBS over a wrong-length key — a truncated binding would verify against itself", () => {
    expect(() => buildKeyBindingTbs(new Uint8Array(31), GROUP)).toThrow(/k_local pubkey must be 32 bytes/);
    expect(() => buildKeyBindingTbs(new Uint8Array(32), new Uint8Array(16))).toThrow(/group pubkey must be 32 bytes/);
  });

  it("frames the TBS as <context>\\0<k_local><group> — the exact bytes a second implementation must produce", () => {
    const kLocal = new Uint8Array(32).fill(0xaa);
    const tbs = buildKeyBindingTbs(kLocal, GROUP);
    const context = new TextEncoder().encode(CONTEXT_KEY_BINDING);

    expect(tbs.length).toBe(context.length + 1 + 64);
    expect(Buffer.from(tbs.subarray(0, context.length)).toString("utf8")).toBe("cello-key-binding-v1");
    expect(tbs[context.length]).toBe(0x00);
    expect(Buffer.from(tbs.subarray(context.length + 1, context.length + 33))).toEqual(Buffer.from(kLocal));
    expect(Buffer.from(tbs.subarray(context.length + 33))).toEqual(Buffer.from(GROUP));
  });
});
