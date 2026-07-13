/**
 * ONE CBOR encoding. This test is the thing that keeps it that way.
 *
 * The defect it exists to prevent (§1.1) was not exotic: `new Encoder({ tagUint8Array: false })` was
 * copy-pasted into fourteen files, and two files quietly used cbor-x's bare `encode` instead. Those
 * two wrote TAG-64 typed arrays into the same DB columns the others wrote as raw byte strings. It
 * survived review because cbor-x's decoder accepts both — the corruption is invisible until somebody
 * reads the column with a non-cbor-x reader, and by then every agent on disk is a mix.
 *
 * A comment saying "use the shared encoder" would not have stopped that. This does.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { encodeCbor, decodeCbor } from "../cbor.js";
import { Encoder, encode as bareEncode } from "cbor-x";

const here = dirname(fileURLToPath(import.meta.url));
const CORE = join(here, "..", "..", "..");            // core/
const CANONICAL = join(CORE, "protocol-types", "src", "cbor.ts");

/** Every production .ts under core/<pkg>/src (tests excluded — they may encode however they like). */
function productionSources(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (entry === "__tests__" || entry === "node_modules" || entry === "dist") continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".ts")) out.push(full);
    }
  };
  for (const pkg of readdirSync(CORE)) {
    const src = join(CORE, pkg, "src");
    try { if (statSync(src).isDirectory()) walk(src); } catch { /* package has no src */ }
  }
  return out;
}

describe("§1.1 — there is exactly ONE CBOR encoder", () => {
  it("no production file constructs its own cbor-x Encoder", () => {
    const offenders = productionSources()
      .filter((f) => f !== CANONICAL)
      .filter((f) => /new\s+Encoder\s*\(/.test(readFileSync(f, "utf8")))
      .map((f) => relative(CORE, f));

    expect(
      offenders,
      "construct no Encoder — import { encodeCbor } from @cello-protocol/protocol-types. " +
      "A second encoder is a second wire format in the same column.",
    ).toEqual([]);
  });

  it("no production file imports cbor-x's bare `encode`", () => {
    // The exact hole: `import { encode } from "cbor-x"` gets you tagUint8Array:true — TAG-64 — and
    // nothing complains, because cbor-x decodes its own tags back just fine. Importing `decode` is
    // fine and expected (it must read both encodings).
    const IMPORTS_BARE_ENCODE = /import\s*\{[^}]*\bencode\b(?!\s*:)[^}]*\}\s*from\s*["']cbor-x["']/;
    const offenders = productionSources()
      .filter((f) => f !== CANONICAL)
      .filter((f) => IMPORTS_BARE_ENCODE.test(readFileSync(f, "utf8")))
      .map((f) => relative(CORE, f));

    expect(
      offenders,
      "do not import `encode` (or `encode as x`) from cbor-x — it is TAG-64. Use encodeCbor.",
    ).toEqual([]);
  });

  it("guards against a vacuous pass — it really is scanning the tree", () => {
    const files = productionSources();
    expect(files.length).toBeGreaterThan(30);
    expect(files).toContain(CANONICAL);
  });

  // The property the whole thing is about. If this ever fails, the two encodings are NOT
  // interchangeable and every claim above matters more, not less.
  it("canonical encoding differs from cbor-x's default — this is a real divergence, not a nit", () => {
    const payload = { share: new Uint8Array([1, 2, 3, 4]) };
    const canonical = encodeCbor(payload);
    const tagged = new Uint8Array(bareEncode(payload) as Uint8Array);

    expect(Buffer.from(canonical).equals(Buffer.from(tagged))).toBe(false);
    // 0xd8 0x40 is CBOR tag 64 (uint8 typed array). The canonical form must not contain it.
    expect(Buffer.from(canonical).includes(Buffer.from([0xd8, 0x40]))).toBe(false);
    expect(Buffer.from(tagged).includes(Buffer.from([0xd8, 0x40]))).toBe(true);

    // ...and both still decode to the same BYTES, which is precisely why this went unnoticed for so
    // long. (cbor-x hands a raw byte string back as a Node Buffer and a tag-64 back as a Uint8Array,
    // so compare the bytes, not the container — the container difference is itself a smell.)
    const fromCanonical = (decodeCbor(canonical) as { share: Uint8Array }).share;
    const fromTagged = (decodeCbor(tagged) as { share: Uint8Array }).share;
    expect(new Uint8Array(fromCanonical)).toEqual(payload.share);
    expect(new Uint8Array(fromTagged)).toEqual(payload.share);
  });

  it("canonical encoding round-trips a raw Uint8Array as a byte string", () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const round = decodeCbor(encodeCbor({ b: bytes })) as { b: Uint8Array };
    expect(new Uint8Array(round.b)).toEqual(bytes);
  });

  it("the Encoder import is still available (the guard above is not fooled by a missing dep)", () => {
    expect(typeof Encoder).toBe("function");
  });
});
