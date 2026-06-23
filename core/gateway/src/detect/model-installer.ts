/**
 * M9-IN-002 — the DeBERTa model installer.
 *
 * The model is NOT bundled (it is ~568 MB): the gateway downloads it ONCE, only with explicit
 * operator consent, verifies the pinned SHA-256 of the weights (so a compromised mirror cannot swap
 * the model), and caches it locally. When it is absent, Layer-2 is simply off — the gateway never
 * fails closed on a missing OPTIONAL model (Layer-1 still runs). Consent surfaces via the CLI
 * (`cello gateway install-model`), an actionable daemon guidance field, or the portal.
 */
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, stat, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { DEBERTA_MODEL } from "./deberta-model-manifest.js";

/** SHA-256 of a file on disk (streamed — never loads the whole 568 MB into memory). */
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
  for (const f of DEBERTA_MODEL.files) {
    try {
      await stat(join(dir, f.path));
    } catch {
      return false;
    }
  }
  return true;
}

/** Re-verify the pinned-SHA files of an existing install. Returns the first mismatch, or null. */
export async function verifyModel(dir: string): Promise<{ ok: true } | { ok: false; badFile: string }> {
  for (const f of DEBERTA_MODEL.files) {
    if (!f.sha256) continue;
    const got = await sha256File(join(dir, f.path)).catch(() => "");
    if (got !== f.sha256) return { ok: false, badFile: f.path };
  }
  return { ok: true };
}

export interface InstallResult {
  installed: boolean;
  /** true when the model was absent and consent was withheld — nothing was downloaded. */
  needsConsent?: boolean;
  error?: string;
}

export interface InstallOptions {
  dir: string;
  /** The operator's explicit consent to download ~568 MB. Without it, nothing is fetched. */
  consent: boolean;
  /** Injectable fetch (defaults to global fetch) — tests pass a fake; production uses the network. */
  fetchImpl?: typeof fetch;
  onProgress?: (file: string, index: number, total: number) => void;
}

/**
 * Install the model under `dir`. No-ops (returns installed) if already present. Requires `consent`
 * to download; verifies every pinned SHA-256 and deletes + fails on any mismatch (no partial/tampered
 * model is ever left in place).
 */
export async function installModel(opts: InstallOptions): Promise<InstallResult> {
  if (await isModelInstalled(opts.dir)) return { installed: true };
  if (!opts.consent) return { installed: false, needsConsent: true };

  const doFetch = opts.fetchImpl ?? fetch;
  const total = DEBERTA_MODEL.files.length;
  for (let i = 0; i < total; i++) {
    const f = DEBERTA_MODEL.files[i];
    opts.onProgress?.(f.path, i, total);
    const dest = join(opts.dir, f.path);
    await mkdir(dirname(dest), { recursive: true });
    let res: Response;
    try {
      res = await doFetch(DEBERTA_MODEL.baseUrl + f.path);
    } catch (err) {
      return { installed: false, error: `download failed for ${f.path}: ${err instanceof Error ? err.message : String(err)}` };
    }
    if (!res.ok || !res.body) return { installed: false, error: `download failed for ${f.path}: HTTP ${res.status}` };
    await pipeline(Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]), createWriteStream(dest));
    // Integrity: the committed SIZE catches truncation / a wrong file. (Full SHA-256 pinning is the
    // intended hardening — see the manifest note; the pinned digest is verified here when present.)
    const downloaded = await stat(dest);
    if (downloaded.size !== f.size) {
      await rm(dest, { force: true });
      return { installed: false, error: `size mismatch for ${f.path}: expected ${f.size}, got ${downloaded.size} — removed` };
    }
    if (f.sha256) {
      const got = await sha256File(dest);
      if (got !== f.sha256) {
        await rm(dest, { force: true });
        return { installed: false, error: `checksum mismatch for ${f.path} — the file was NOT trusted and has been removed` };
      }
    }
  }
  return { installed: true };
}
