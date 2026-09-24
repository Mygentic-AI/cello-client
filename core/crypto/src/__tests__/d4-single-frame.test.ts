/**
 * 001-PQPRIM Part D — D4 as a failing test: the Contract 2 frame is the ONLY way to produce or check
 * an ML-DSA signature in the tree.
 *
 * Scans every NON-TEST source in core/*\/src with the TypeScript compiler API and fails on, outside
 * `pq-frame.ts` and `ml-dsa.ts`:
 *   1. any reach for `sign` on a receiver whose type is an ML-DSA provider declared by `ml-dsa.ts`
 *      (`MlDsaKeyProvider`, `InMemoryMlDsaKeyProvider`): `p.sign(x)`, `p.sign.call/bind`, `p["sign"]`,
 *      `const { sign } = p`;
 *   2. a `sign`/`verify` call on a Web Crypto receiver — matched by name (`subtle`, `crypto`) OR by
 *      type (`SubtleCrypto`, so an alias is caught) — with an argument that names ML-DSA by text
 *      (/ML[-_]?DSA/i) or by resolved literal type (so `{ name: LABEL }` in a variable is caught);
 *   3. a string literal "ML-DSA-44" or "ML-KEM-768" anywhere outside ml-dsa.ts, ml-kem.ts, pq-frame.ts
 *      (and pq-warnings.ts, which only matches Node's warning text).
 *
 * Rule 1 matches the DECLARED ML-DSA types rather than "anything assignable to MlDsaKeyProvider":
 * the Ed25519 `KeyProvider` has the identical shape (`getPublicKey`, `sign`), so assignability would
 * flag every Ed25519 signature in the tree and the test would have to be ignored to be passed.
 *
 * Tests are exempt: the reference harness (ACVP vectors, the hand-built frame check) calls Node
 * directly on purpose.
 */
import { describe, it, expect } from "vitest";
import ts from "typescript";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../../../../", import.meta.url));
const CORE = join(REPO, "core");
const FRAME_FILES = new Set(["crypto/src/pq-frame.ts", "crypto/src/ml-dsa.ts"]);
// pq-warnings.ts names the algorithms only to MATCH Node's ExperimentalWarning text; it never calls
// a primitive (rules 1 and 2 still apply to it).
const LITERAL_FILES = new Set([...FRAME_FILES, "crypto/src/ml-kem.ts", "crypto/src/pq-warnings.ts"]);
const PQ_LITERALS = new Set(["ML-DSA-44", "ML-KEM-768"]);

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "__tests__" || name === "node_modules" || name === "dist") continue;
      walk(p, out);
    } else if (name.endsWith(".ts") && !name.endsWith(".test.ts") && !name.endsWith(".d.ts")) {
      out.push(p);
    }
  }
}

function sources(): string[] {
  const out: string[] = [];
  for (const pkg of readdirSync(CORE)) {
    const src = join(CORE, pkg, "src");
    try {
      if (statSync(src).isDirectory()) walk(src, out);
    } catch {
      /* package without src */
    }
  }
  return out;
}

const rel = (f: string): string => relative(CORE, f).split(sep).join("/");

const ML_DSA_PROVIDER_TYPES = new Set(["MlDsaKeyProvider", "InMemoryMlDsaKeyProvider"]);

/**
 * Is this the ML-DSA provider type declared by crypto's ml-dsa module? Matched on the declaring
 * FILE NAME and the TYPE NAME, never on the directory: a caller in another package sees the built
 * declarations through `node_modules` at their REAL path, and `dist` is a symlink to `dist.nosync`
 * here (the iCloud workaround) — a directory match once made every cross-package call invisible.
 */
function declaredInMlDsa(type: ts.Type): boolean {
  const types = type.isUnionOrIntersection() ? type.types : [type];
  for (const t of types) {
    const sym = t.getSymbol() ?? t.aliasSymbol;
    if (!sym || !ML_DSA_PROVIDER_TYPES.has(sym.getName())) continue;
    for (const d of sym.getDeclarations() ?? []) {
      if (/(^|[\\/])ml-dsa\.(d\.)?ts$/.test(d.getSourceFile().fileName)) return true;
    }
  }
  return false;
}

/** Does this argument's TYPE name ML-DSA — a string literal type, or an object whose `name` is one? */
function namesMlDsa(checker: ts.TypeChecker, arg: ts.Expression): boolean {
  const literal = (t: ts.Type | undefined): boolean => !!t && t.isStringLiteral() && /ML-DSA/.test(t.value);
  const t = checker.getTypeAtLocation(arg);
  if (literal(t)) return true;
  const nameProp = t.getProperty("name");
  return !!nameProp && literal(checker.getTypeOfSymbolAtLocation(nameProp, arg));
}

export function scan(files: string[]): string[] {
  const program = ts.createProgram(files, {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    strict: true,
    skipLibCheck: true,
    noEmit: true,
    esModuleInterop: true,
  });
  const checker = program.getTypeChecker();
  const offences: string[] = [];

  for (const file of files) {
    const sf = program.getSourceFile(file);
    if (!sf) throw new Error(`d4 scan: ${file} not in the program`);
    const r = rel(file);
    const where = (n: ts.Node): string => `core/${r}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}`;

    const visit = (node: ts.Node): void => {
      if (ts.isStringLiteralLike(node) && PQ_LITERALS.has(node.text) && !LITERAL_FILES.has(r)) {
        offences.push(`${where(node)} literal "${node.text}" outside ml-dsa.ts/ml-kem.ts/pq-frame.ts`);
      }
      if (!FRAME_FILES.has(r)) {
        // Rule 1 — ANY reach for an ML-DSA provider's `sign`, not only a direct call: `p.sign(x)`,
        // `p.sign.call(..)`, `p.sign.bind(..)`, `p["sign"](x)`, and `const { sign } = p`.
        const isMlDsa = (e: ts.Expression): boolean => declaredInMlDsa(checker.getTypeAtLocation(e));
        if (ts.isPropertyAccessExpression(node) && node.name.text === "sign" && isMlDsa(node.expression)) {
          offences.push(`${where(node)} raw ML-DSA provider.sign() outside the Contract 2 frame`);
        }
        if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)
            && node.argumentExpression.text === "sign" && isMlDsa(node.expression)) {
          offences.push(`${where(node)} raw ML-DSA provider["sign"] outside the Contract 2 frame`);
        }
        if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)
            && (node.propertyName ?? node.name).getText(sf) === "sign"
            && ts.isVariableDeclaration(node.parent.parent) && node.parent.parent.initializer
            && isMlDsa(node.parent.parent.initializer)) {
          offences.push(`${where(node)} raw ML-DSA provider sign destructured outside the Contract 2 frame`);
        }
        // Rule 2 — a Web Crypto / node:crypto sign or verify with an ML-DSA algorithm. The receiver is
        // matched by TYPE (so an aliased `const s = crypto.subtle` is caught) as well as by name, and
        // the algorithm by its resolved literal type (so `{ name: LABEL }` in a variable is caught).
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const callee = node.expression;
          const method = callee.name.text;
          const recvText = callee.expression.getText(sf);
          const recvType = checker.typeToString(checker.getTypeAtLocation(callee.expression));
          const isCryptoRecv = /(^|\.)(subtle|crypto)$/.test(recvText) || /SubtleCrypto/.test(recvType);
          if ((method === "sign" || method === "verify") && isCryptoRecv
              && node.arguments.some((a) => /ML[-_]?DSA/i.test(a.getText(sf)) || namesMlDsa(checker, a))) {
            offences.push(`${where(node)} ${recvText}.${method}(ML-DSA…) outside the Contract 2 frame`);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return offences;
}

describe("001-PQPRIM Part D — D4: the Contract 2 frame is the only ML-DSA route", () => {
  it("scans a non-trivial number of production sources, including the frame itself", () => {
    const files = sources().map(rel);
    expect(files.length).toBeGreaterThan(100);
    expect(files).toContain("crypto/src/pq-frame.ts");
    expect(files).toContain("daemon/src/registration-manager.ts");
  });

  it("POSITIVE CONTROL: reports EVERY line marked OFFENCE in core/daemon's d4-offender fixture", () => {
    const fixture = join(CORE, "daemon/src/__tests__/fixtures/d4-offender.ts");
    const marked = readFileSync(fixture, "utf8").split("\n")
      .map((line, i) => (line.includes("// OFFENCE:") ? i + 1 : 0))
      .filter((n) => n > 0);
    expect(marked.length).toBeGreaterThanOrEqual(9);
    const offences = scan([fixture]);
    const reported = new Set(offences.map((o) => Number(/:(\d+) /.exec(o)?.[1])));
    const missed = marked.filter((n) => !reported.has(n));
    expect(missed, `unreported OFFENCE lines: ${missed.join(", ")}\n${offences.join("\n")}`).toEqual([]);
  });

  it("finds no ML-DSA signature produced or checked outside pq-frame.ts / ml-dsa.ts", () => {
    const offences = scan(sources());
    expect(offences, offences.join("\n")).toEqual([]);
  });
}, 120_000);
