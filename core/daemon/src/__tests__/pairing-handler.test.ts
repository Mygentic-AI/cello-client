/**
 * cello_pair_start / cello_pair_await against local directories that verify every poll signature.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeypair, signDaemonCredential, signWithDaemonKey, pairingPollBytes } from "@cello-protocol/crypto";
import { openEncryptedDatabase, resolveDbKey, dbKeyPathFor, type DaemonDatabase } from "../sqlcipher-db.js";
import { DbPairingStore } from "../pairing-store.js";
import { registerPairingHandlers } from "../pairing-handler.js";
import type { FetchFn } from "../pairing-client.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";
import { startFakeDirectory, type Answer, type FakeDirectory } from "./helpers/fake-pairing-directory.js";

const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const issuer = generateKeypair();
const ACCOUNT = "3f0c8a2e-1b7d-4e5f-9a6b-2c4d6e8f0a1b";

async function credentialFor(daemonPubkey: string) {
  return signDaemonCredential(
    { v: 1, daemon_pubkey: daemonPubkey, account_id: ACCOUNT, nonce: "cd".repeat(16), issued_at: "2026-10-28T00:00:00Z" },
    issuer,
  );
}

describe("pairing handlers", () => {
  let dir: string;
  let db: DaemonDatabase;
  let store: DbPairingStore;
  const dirs: FakeDirectory[] = [];
  const urls: string[] = [];
  const fetchFn: FetchFn = (url, init) => { urls.push(url); return fetch(url, init); };

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-pairing-handler-"));
    const dbPath = join(dir, "cello.db");
    db = openEncryptedDatabase(dbPath, resolveDbKey(dbPath, dbKeyPathFor(dbPath)));
    store = new DbPairingStore(db, logger);
    urls.length = 0;
  });
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((d) => d.close()));
    db.close();
    await rm(dir, { recursive: true, force: true });
  });

  function handlersFor(bases: string[]): { start: IpcHandler; wait: IpcHandler } {
    const handlers = new Map<string, IpcHandler>();
    registerPairingHandlers({ handlers, logger, pairingStore: store, getBases: () => bases, fetchFn, pollIntervalMs: 10 });
    return { start: handlers.get("cello_pair_start")!, wait: handlers.get("cello_pair_await")! };
  }

  /** Answers in order, the last one repeating. */
  const sequence = (answers: Answer[]) => (_b: Record<string, unknown>, n: number): Answer => answers[Math.min(n, answers.length - 1)]!;

  it("3. a second cello_pair_start while one is pending returns the same code, and opens ONE pairing", async () => {
    // A short expiry so the poller ends inside the test.
    const d = await startFakeDirectory({
      onPair: () => ({ status: 201, body: { pairing_code: "KQ7M4TXP", expires_at: new Date(Date.now() + 300).toISOString(), approve_url: "https://portal.example.test/device?code=KQ7M-4TXP" } }),
    });
    dirs.push(d);
    const h = handlersFor([d.base]);
    const first = (await h.start(undefined, "c")) as Record<string, unknown>;
    const second = (await h.start(undefined, "c")) as Record<string, unknown>;
    expect(first).toMatchObject({ ok: true, paired: false, pairing_code: "KQ7M4TXP" });
    expect(second).toEqual(first);
    expect(d.pairBodies).toHaveLength(1);
    expect(await h.wait(undefined, "c")).toMatchObject({ ok: false, reason: "pairing_expired" });
  });

  it("4. the poller collects an approval and stores the credential; polls are really signed", async () => {
    const key = store.daemonKey().pubkeyHex;
    const cred = await credentialFor(key);
    const d = await startFakeDirectory({
      onPoll: sequence([{ status: 200, body: { status: "pending" } }, { status: 200, body: { status: "pending" } }, { status: 200, body: { status: "approved", credential: cred } }]),
    });
    dirs.push(d);
    const h = handlersFor([d.base]);
    await h.start(undefined, "c");
    expect(await h.wait(undefined, "c")).toEqual({ ok: true, account_id: ACCOUNT });
    expect(store.credential()).toEqual(cred);
    expect(store.pending()).toBeNull();
    expect((await h.start(undefined, "c"))).toEqual({ ok: true, paired: true });

    // The server's check has teeth: a poll signed over the wrong bytes is refused.
    const unix = Math.floor(Date.now() / 1000);
    const badSig = await signWithDaemonKey(pairingPollBytes("WRONGCODE", unix), store.daemonKey().keyProvider);
    const res = await fetch(`${d.base}/pairing/poll`, { method: "POST", body: JSON.stringify({ pairing_code: "KQ7M4TXP", unix_seconds: unix, signature: badSig }) });
    expect(res.status).toBe(401);
  });

  it("4b. a credential naming another daemon key is not stored", async () => {
    const cred = await credentialFor("ef".repeat(32));
    const d = await startFakeDirectory({ onPoll: () => ({ status: 200, body: { status: "approved", credential: cred } }) });
    dirs.push(d);
    const h = handlersFor([d.base]);
    await h.start(undefined, "c");
    expect(await h.wait(undefined, "c")).toMatchObject({ ok: false, reason: "pairing_credential_mismatch" });
    expect(store.credential()).toBeNull();
  });

  it("5. a 404 from a directory other than the opener does not end the pairing", async () => {
    const key = store.daemonKey().pubkeyHex;
    const cred = await credentialFor(key);
    // The opener fails once, so the poller tries the other directory, which has not seen the
    // request yet; it then goes back to the opener, which approves.
    const opener = await startFakeDirectory({
      onPoll: sequence([{ status: 503, body: {} }, { status: 200, body: { status: "pending" } }, { status: 200, body: { status: "approved", credential: cred } }]),
    });
    const other = await startFakeDirectory({ daemonPubkey: () => key, onPoll: () => ({ status: 404, body: { error: "not_found", guidance: "run setup again to get a new code" } }) });
    dirs.push(opener, other);
    const h = handlersFor([opener.base, other.base]);
    await h.start(undefined, "c");
    expect(await h.wait(undefined, "c")).toEqual({ ok: true, account_id: ACCOUNT });
    expect(other.pollBodies.length, "the other directory must actually have been polled").toBeGreaterThan(0);
  });

  it("5. a 404 from the opener ends as pairing_not_found; a 410 ends as pairing_expired naming the command", async () => {
    const gone = await startFakeDirectory({ onPoll: () => ({ status: 404, body: { error: "not_found" } }) });
    dirs.push(gone);
    let h = handlersFor([gone.base]);
    await h.start(undefined, "c");
    expect(await h.wait(undefined, "c")).toMatchObject({ ok: false, reason: "pairing_not_found" });

    const expired = await startFakeDirectory({ onPoll: () => ({ status: 410, body: { status: "expired" } }) });
    dirs.push(expired);
    h = handlersFor([expired.base]);
    await h.start(undefined, "c");
    const out = (await h.wait(undefined, "c")) as { ok: boolean; reason: string; guidance: string };
    expect(out.reason).toBe("pairing_expired");
    expect(out.guidance).toBe("The code was not approved in time. Run 'cello register-agent <name>' again for a new code.");
    expect(store.pending()).toBeNull();
  });

  it("cello_pair_await with nothing pending and no credential → not_pairing with the command", async () => {
    const h = handlersFor([]);
    expect(await h.wait(undefined, "c")).toEqual({ ok: false, reason: "not_pairing", guidance: "Run 'cello register-agent <name>' to pair this device." });
  });

  it("10. every request goes to a directory base; the approve link's host is never fetched", async () => {
    const key = store.daemonKey().pubkeyHex;
    const cred = await credentialFor(key);
    const a = await startFakeDirectory({ onPoll: sequence([{ status: 503, body: {} }, { status: 200, body: { status: "approved", credential: cred } }]) });
    const b = await startFakeDirectory({ daemonPubkey: () => key, onPoll: () => ({ status: 404, body: {} }) });
    dirs.push(a, b);
    const h = handlersFor([a.base, b.base]);
    const start = (await h.start(undefined, "c")) as { approve_url: string };
    await h.wait(undefined, "c");
    const origins = new Set(urls.map((u) => new URL(u).origin));
    expect(origins).toEqual(new Set([a.base, b.base]));
    expect(urls.some((u) => new URL(u).host === new URL(start.approve_url).host)).toBe(false);
  });
});
