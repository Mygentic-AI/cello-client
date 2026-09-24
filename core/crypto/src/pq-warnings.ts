/**
 * 001-PQPRIM decision 13 — drop Node's ExperimentalWarning for the five post-quantum Web Crypto
 * APIs, and ONLY those.
 *
 * Node 24.7+ prints `ExperimentalWarning: The <name> Web Crypto API … is an experimental feature`
 * on the first use of ML-KEM-768, ML-DSA-44, getPublicKey, encapsulateBits and decapsulateBits.
 * Every cello CLI command, the daemon, the MCP shim, the directory, the relay and the portal would
 * print five of them on every run.
 *
 * On import this replaces `process`'s `warning` listeners with one that drops a warning when its
 * name is ExperimentalWarning AND its message names one of those five APIs, and hands every other
 * warning to the listeners it replaced. A future experimental warning for anything else still
 * prints. `ml-kem.ts` and `ml-dsa.ts` import this first, so every process that loads the primitives
 * gets the filter without an entry-point change.
 *
 * Exports nothing. Idempotent within one module instance (a module-level flag). A second installed
 * copy of this package wraps the first filter, which forwards to the originals — one print, no drop.
 */
const PQ_APIS = ["ML-KEM-768", "ML-DSA-44", "getPublicKey", "encapsulateBits", "decapsulateBits"] as const;
const PATTERN = new RegExp(`^The (${PQ_APIS.join("|")}) Web Crypto API `);

let installed = false;

function install(): void {
  if (installed) return;
  installed = true;
  const replaced = process.listeners("warning");
  process.removeAllListeners("warning");
  process.on("warning", (w: Error) => {
    if (w.name === "ExperimentalWarning" && PATTERN.test(w.message)) return;
    for (const listener of replaced) listener(w);
  });
}

install();

export {};
