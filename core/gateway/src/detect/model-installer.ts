/**
 * DOD-M9C-SCREENINSTALL-1 — the screener model installer.
 *
 * The model is NOT bundled (~131 MB): the gateway downloads it ONCE, only with explicit operator
 * consent, verifies every file's pinned SHA-256 (so a compromised mirror cannot swap the model), and
 * caches it locally. When it is absent, Layer-2 is simply off — the gateway never fails closed on a
 * missing OPTIONAL model, and Layer-1 still runs.
 *
 * Consent surfaces at `cello screener install` and at `cello login` when no screener is present.
 * Until DOD-M9C-SCREENINSTALL-1 built those, this comment claimed three surfaces — a CLI verb, a
 * daemon guidance field and the portal — and a search for any of them found nothing, which is how a
 * defence with no caller survived in a public repository for four months.
 */
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, stat, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { SCREENER_MODEL, localPathOf } from "./screener-model-manifest.js";

/** SHA-256 of a file on disk (streamed — never loads the whole 96 MB graph into memory). */
export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const rs = createReadStream(path);
    rs.on("error", reject);
    rs.on("data", (chunk) => hash.update(chunk));
    rs.on("end", () => resolve(hash.digest("hex")));
  });
}

/** Are all the model files present under `dir`? (Existence check; integrity is the SHA verify.) */
export async function isModelInstalled(dir: string): Promise<boolean> {
  for (const f of SCREENER_MODEL.files) {
    try {
      await stat(join(dir, localPathOf(f)));
    } catch {
      return false;
    }
  }
  return true;
}

export interface InstallResult {
  installed: boolean;
  /** true when the model was absent and consent was withheld — nothing was downloaded. */
  needsConsent?: boolean;
  error?: string;
}

export interface InstallOptions {
  dir: string;
  /** The operator's explicit consent to the download. Without it, nothing is fetched. */
  consent: boolean;
  /** Injectable fetch (defaults to global fetch) — tests pass a fake; production uses the network. */
  fetchImpl?: typeof fetch;
  onProgress?: (file: string, index: number, total: number) => void;
}

/**
 * Install the model under `dir`. No-ops (returns installed) if already present. Requires `consent`
 * to download; verifies every pinned SHA-256 and deletes + fails on any mismatch (no partial/tampered
 * model is ever left in place). `screenerModelTotalBytes()` is what the consent prompt quotes.
 */
export async function installModel(opts: InstallOptions): Promise<InstallResult> {
  if (await isModelInstalled(opts.dir)) return { installed: true };
  if (!opts.consent) return { installed: false, needsConsent: true };


  const doFetch = opts.fetchImpl ?? fetch;
  const total = SCREENER_MODEL.files.length;
  for (let i = 0; i < total; i++) {
    const f = SCREENER_MODEL.files[i];
    opts.onProgress?.(f.path, i, total);
    const dest = join(opts.dir, localPathOf(f));
    await mkdir(dirname(dest), { recursive: true });
    let res: Response;
    try {
      res = await doFetch(SCREENER_MODEL.baseUrl + f.path);
    } catch (err) {
      return { installed: false, error: `download failed for ${f.path}: ${err instanceof Error ? err.message : String(err)}` };
    }
    if (!res.ok || !res.body) return { installed: false, error: `download failed for ${f.path}: HTTP ${res.status}` };
    await pipeline(Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]), createWriteStream(dest));
    // Size first (it catches truncation without hashing 96 MB), then the pinned digest.
    const downloaded = await stat(dest);
    if (downloaded.size !== f.size) {
      await rm(dest, { force: true });
      return { installed: false, error: `size mismatch for ${f.path}: expected ${f.size}, got ${downloaded.size} — removed` };
    }
    // Every manifest file carries a digest (the type makes it non-optional), so this always runs.
    const got = await sha256File(dest);
    if (got !== f.sha256) {
      await rm(dest, { force: true });
      return { installed: false, error: `checksum mismatch for ${f.path} — the file was NOT trusted and has been removed` };
    }
  }
  return { installed: true };
}
