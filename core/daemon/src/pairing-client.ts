/**
 * Pairing over HTTP, to directories and nothing else.
 *
 * The daemon opens a pairing on any directory and polls it with daemon-key signatures. The approve
 * link the directory returns points at the portal; it is printed and handed to the OS opener, never
 * fetched here.
 */
import { createRequire } from "node:module";
import os from "node:os";
import { pairingPollBytes, signWithDaemonKey } from "@cello-protocol/crypto";
import type { DaemonCredential, KeyProvider } from "@cello-protocol/crypto";
import type { IManifestProvider } from "@cello-protocol/transport";
import { BUNDLED_CONSORTIUM_MANIFEST } from "./bundled-consortium-manifest.js";
import { mapEndpointToBootstrapBase } from "./directory-bootstrap.js";
import { extractErrorMessage } from "./error-message.js";

export type FetchFn = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal }) => Promise<Response>;

export const PAIRING_HTTP_TIMEOUT_MS = 10_000;
const FACT_MAX = 128;

/** Every directory of the verified manifest (or the bundled one), shuffled; `CELLO_DIRECTORY_URL` first. */
export function directoryBases(
  manifestProvider: IManifestProvider | undefined,
  env: Record<string, string | undefined> = process.env,
): string[] {
  const nodes = (manifestProvider?.getCurrentManifest()?.nodes ?? BUNDLED_CONSORTIUM_MANIFEST.nodes) as ReadonlyArray<{ endpoint?: unknown }>;
  const bases = nodes
    .map((n) => (typeof n.endpoint === "string" ? mapEndpointToBootstrapBase(n.endpoint) : null))
    .filter((b): b is string => b !== null);
  for (let i = bases.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [bases[i], bases[j]] = [bases[j]!, bases[i]!];
  }
  const pinned = env["CELLO_DIRECTORY_URL"] ? mapEndpointToBootstrapBase(env["CELLO_DIRECTORY_URL"]) : null;
  return pinned ? [pinned, ...bases.filter((b) => b !== pinned)] : bases;
}

export interface DeviceFacts {
  hostname: string;
  os: string;
  client_version: string;
}

export function deviceFacts(): DeviceFacts {
  const version = (createRequire(import.meta.url)("../package.json") as { version: string }).version;
  const cut = (s: string): string => s.slice(0, FACT_MAX);
  return { hostname: cut(os.hostname()), os: cut(`${os.platform()} ${os.release()}`), client_version: cut(version) };
}

async function postJson(
  fetchFn: FetchFn,
  url: string,
  body: unknown,
): Promise<{ kind: "answer"; status: number; body: Record<string, unknown> } | { kind: "unreachable"; error: string }> {
  try {
    const res = await fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(PAIRING_HTTP_TIMEOUT_MS),
    });
    let parsed: unknown = null;
    try { parsed = await res.json(); } catch { parsed = null; }
    const obj = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
    return { kind: "answer", status: res.status, body: obj };
  } catch (err: unknown) {
    return { kind: "unreachable", error: extractErrorMessage(err) };
  }
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

export type OpenPairingResult =
  | { ok: true; base: string; pairing_code: string; approve_url: string; expires_at: number }
  | { ok: false; reason: string; guidance: string; failures: Array<{ base: string; status?: number; error?: string }> };

/**
 * Open a pairing on the first directory that answers. A network error, a timeout or a 5xx moves on;
 * a 400 or 429 is the directory's answer and stops, carrying its guidance.
 */
export async function openPairing(
  bases: readonly string[],
  daemonPubkeyHex: string,
  facts: DeviceFacts,
  fetchFn: FetchFn,
): Promise<OpenPairingResult> {
  const failures: Array<{ base: string; status?: number; error?: string }> = [];
  for (const base of bases) {
    const r = await postJson(fetchFn, `${base}/pairing`, { daemon_pubkey: daemonPubkeyHex, device_facts: facts });
    if (r.kind === "unreachable") { failures.push({ base, error: r.error }); continue; }
    if (r.status >= 500) { failures.push({ base, status: r.status }); continue; }
    if (r.status === 201) {
      const code = str(r.body["pairing_code"]);
      const approve = str(r.body["approve_url"]);
      const expires = Date.parse(String(r.body["expires_at"]));
      if (code && approve && Number.isFinite(expires)) {
        return { ok: true, base, pairing_code: code, approve_url: approve, expires_at: expires };
      }
      failures.push({ base, status: r.status, error: "malformed pairing response" });
      continue;
    }
    return {
      ok: false,
      reason: r.status === 429 ? "pairing_rate_limited" : "pairing_refused",
      guidance: str(r.body["guidance"]) ?? `The directory refused to open a pairing (HTTP ${r.status}${str(r.body["error"]) ? `, ${String(r.body["error"])}` : ""}). Run 'cello register-agent <name>' again later.`,
      failures,
    };
  }
  return {
    ok: false,
    reason: "directory_unreachable",
    guidance: "Could not reach any CELLO directory to pair this device. Check this machine's internet connection, then run 'cello register-agent <name>' again.",
    failures,
  };
}

export type PollResult =
  | { kind: "pending" }
  | { kind: "approved"; credential: DaemonCredential }
  | { kind: "refused"; status: number; guidance?: string }
  | { kind: "unreachable"; status?: number; error?: string };

/** One poll, signed by the daemon key over the code and the current second. */
export async function pollOnce(
  base: string,
  code: string,
  keyProvider: KeyProvider,
  fetchFn: FetchFn,
  now: () => number = Date.now,
): Promise<PollResult> {
  const unixSeconds = Math.floor(now() / 1000);
  const signature = await signWithDaemonKey(pairingPollBytes(code, unixSeconds), keyProvider);
  const r = await postJson(fetchFn, `${base}/pairing/poll`, { pairing_code: code, unix_seconds: unixSeconds, signature });
  if (r.kind === "unreachable") return { kind: "unreachable", error: r.error };
  if (r.status >= 500) return { kind: "unreachable", status: r.status };
  if (r.status === 200 && r.body["status"] === "pending") return { kind: "pending" };
  if (r.status === 200 && r.body["status"] === "approved" && typeof r.body["credential"] === "object" && r.body["credential"] !== null) {
    return { kind: "approved", credential: r.body["credential"] as DaemonCredential };
  }
  const guidance = str(r.body["guidance"]);
  return { kind: "refused", status: r.status, ...(guidance !== undefined ? { guidance } : {}) };
}
