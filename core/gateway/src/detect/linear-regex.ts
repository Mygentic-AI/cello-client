/**
 * LinearRegex — a linear-time (RE2) regular expression behind ONE interface, used for any pattern
 * that runs against adversary-controlled content (injection-pattern matching, the gitleaks set).
 *
 * RE2 guarantees time linear in the input — no catastrophic backtracking, so a crafted message can
 * never peg the gateway (ReDoS), which would otherwise be both a DoS and a way to force a timeout
 * verdict. We prefer the MAINTAINED native engine (`re2`, an optionalDependency) and fall back to
 * the WASM build (`re2-wasm`, a regular dependency that always installs with no compile) when the
 * native addon did not build on the operator's machine. Either way: real RE2, same guarantee.
 *
 * `initLinearRegex()` MUST be awaited once at gateway startup (the WASM fallback is an async import).
 * After that, `new LinearRegex(...)` is synchronous.
 */
import { createRequire } from "node:module";

type Re2Instance = { test(s: string): boolean; exec(s: string): RegExpExecArray | null };
type Re2Factory = (pattern: string, flags: string) => Re2Instance;

let factory: Re2Factory | null = null;
let engine: "native" | "wasm" | "uninitialized" = "uninitialized";

/**
 * Resolve the RE2 engine: native first, WASM fallback. Idempotent. Returns which engine is live.
 * Throws only if NEITHER engine can load (re2-wasm is a hard dependency, so that should not happen).
 */
export async function initLinearRegex(): Promise<"native" | "wasm"> {
  if (factory) return engine as "native" | "wasm";

  // Native `re2` is CommonJS; load it through createRequire so this ESM module can require() it.
  // A missing/failed-to-build optional addon throws here — caught, and we fall through to WASM.
  try {
    const require = createRequire(import.meta.url);
    const NativeRE2 = require("re2") as new (p: string, f?: string) => Re2Instance;
    factory = (pattern, flags) => new NativeRE2(pattern, flags);
    engine = "native";
    return "native";
  } catch {
    /* native not available — fall back to WASM */
  }

  // `re2-wasm` is ESM and requires the unicode ('u') flag.
  const wasm = (await import("re2-wasm")) as { RE2: new (p: string, f: string) => Re2Instance };
  factory = (pattern, flags) => new wasm.RE2(pattern, flags.includes("u") ? flags : flags + "u");
  engine = "wasm";
  return "wasm";
}

/** Which RE2 engine is live (`native`, `wasm`, or `uninitialized`). For the gateway `doctor` report. */
export function linearRegexEngine(): "native" | "wasm" | "uninitialized" {
  return engine;
}

/** A compiled linear-time pattern. Construct only after `initLinearRegex()` has resolved. */
export class LinearRegex {
  readonly #re: Re2Instance;

  /** @param flags RegExp-style flags (e.g. "i"). The unicode flag is forced on for the WASM engine. */
  constructor(pattern: string, flags = "") {
    if (!factory) {
      throw new Error("LinearRegex: call and await initLinearRegex() before constructing patterns");
    }
    this.#re = factory(pattern, flags);
  }

  /** True iff the pattern matches anywhere in `s`. Linear time, guaranteed. */
  test(s: string): boolean {
    return this.#re.test(s);
  }

  /** The first matched substring, or null. */
  match(s: string): string | null {
    const m = this.#re.exec(s);
    return m ? m[0] : null;
  }

  /** The first match as a `RegExpExecArray` (with `.index` and capture groups), or null. */
  exec(s: string): RegExpExecArray | null {
    return this.#re.exec(s);
  }
}
