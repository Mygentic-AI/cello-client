/**
 * MONIKER-3 — local address book pet name (M8C-MONIKER-SPEC §MONIKER-3).
 *
 * Tests are written RED-first per SPARC Phase R.
 *
 * The receiver's own name for a pubkey — the top tier of whoLabel. Real daemon
 * over IPC (same harness family as moniker-1): the contacts table gains a
 * nullable moniker via a PRAGMA-guarded idempotent ALTER; add accepts an
 * optional validated moniker; set_moniker renames or clears; added_at keeps its
 * never-refresh rule.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

let tempDir = "";
let handle: DaemonHandle | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "moniker3-"));
});
afterEach(async () => {
  for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
  clients.length = 0;
  if (handle) { await handle.stop(); handle = null; }
  await rm(tempDir, { recursive: true, force: true });
});

function makeConfig(): DaemonConfig {
  return {
      securityGateway: new PassthroughGatewayClient(),
    celloDir: tempDir,
    socketPath: join(tempDir, "daemon.sock"),
    lockFilePath: join(tempDir, "daemon.lock"),
    maxConnections: 16,
    version: "0.0.1-test",
    logger: makeLogger(),
  };
}

async function connect(socketPath: string): Promise<IpcClient> {
  const client = await connectToDaemon(socketPath);
  clients.push(client);
  await client.send("ipc.connect", { clientType: "mcp" });
  return client;
}

const PEER = "ab".repeat(32);

type ContactRow = { pubkey: string; added_at: number; moniker: string | null };
type ListResult = { ok: boolean; contacts: ContactRow[] };

describe("MONIKER-3 AC1 — guarded idempotent migration", () => {
  it("the contacts table has a nullable moniker column, surviving a daemon restart (second ensure)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });
    await client.send("cello_contact_add", { agent: "alice", pubkey: PEER, moniker: "Bob" });

    // Restart — schema init runs again on a DB where the column already exists (no
    // ADD COLUMN IF NOT EXISTS in SQLite: this is the double-migration crash case).
    await handle.stop();
    handle = await startDaemon(config);
    const client2 = await connect(config.socketPath);

    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      const cols = (db.prepare("PRAGMA table_info(contacts)").all() as Array<{ name: string }>).map((c) => c.name);
      expect(cols).toContain("moniker");
    } finally {
      db.close();
    }
    // Data survived the second migration pass.
    const list = (await client2.send("cello_contact_list", { agent: "alice" })) as ListResult;
    expect(list.contacts.find((c) => c.pubkey === PEER)?.moniker).toBe("Bob");
  });
});

describe("MONIKER-3 AC2/AC3 — add, rename, clear, list", () => {
  it("add with a moniker persists it; list returns {pubkey, added_at, moniker}", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });

    const add = (await client.send("cello_contact_add", { agent: "alice", pubkey: PEER, moniker: "Bob" })) as { ok: boolean; moniker?: string | null };
    expect(add.ok).toBe(true);
    expect(add.moniker).toBe("Bob"); // review F3: the response echoes what was stored

    const list = (await client.send("cello_contact_list", { agent: "alice" })) as ListResult;
    const row = list.contacts.find((c) => c.pubkey === PEER)!;
    expect(row.moniker).toBe("Bob");
    expect(typeof row.added_at).toBe("number");
  });

  it("re-add with a NEW non-null moniker updates it; added_at never refreshes; absent moniker keeps the old", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });

    await client.send("cello_contact_add", { agent: "alice", pubkey: PEER, moniker: "Bob" });
    const before = ((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts[0];

    await new Promise((r) => setTimeout(r, 5));
    await client.send("cello_contact_add", { agent: "alice", pubkey: PEER, moniker: "Robert" });
    const renamed = ((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts[0];
    expect(renamed.moniker).toBe("Robert");
    expect(renamed.added_at).toBe(before.added_at); // never-refresh rule intact

    // Re-add WITHOUT a moniker → stored pet name untouched (absence is not a clear).
    const readd = (await client.send("cello_contact_add", { agent: "alice", pubkey: PEER })) as { ok: boolean; moniker?: string | null };
    expect(readd.ok).toBe(true);
    // Review F3: the response must NOT claim the pet name is unset when it isn't — the field
    // is omitted when no moniker rode the request (never a misreporting `null`).
    expect("moniker" in readd).toBe(false);
    const kept = ((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts[0];
    expect(kept.moniker).toBe("Robert");
  });

  it("cello_contact_set_moniker renames and clears; missing key and unknown contact fail loud", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });
    await client.send("cello_contact_add", { agent: "alice", pubkey: PEER });

    const set = (await client.send("cello_contact_set_moniker", { agent: "alice", pubkey: PEER, moniker: "Bob" })) as { ok: boolean; moniker?: string | null };
    expect(set.ok).toBe(true);
    expect(set.moniker).toBe("Bob");
    expect(((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts[0].moniker).toBe("Bob");

    const cleared = (await client.send("cello_contact_set_moniker", { agent: "alice", pubkey: PEER, moniker: null })) as { ok: boolean; moniker?: string | null };
    expect(cleared.ok).toBe(true);
    expect(((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts[0].moniker).toBeNull();

    // Absence is NOT a clear (Entry-66-F3 lesson).
    const missing = (await client.send("cello_contact_set_moniker", { agent: "alice", pubkey: PEER })) as { ok: boolean; reason?: string };
    expect(missing.ok).toBe(false);
    expect(missing.reason).toBe("missing_params");

    // Unknown contact → loud, specific failure.
    const ghost = (await client.send("cello_contact_set_moniker", { agent: "alice", pubkey: "ff".repeat(32), moniker: "Ghost" })) as { ok: boolean; reason?: string };
    expect(ghost.ok).toBe(false);
    expect(ghost.reason).toBe("contact_not_found");
  });

  it("an invalid moniker is rejected on BOTH surfaces and never stored (strip-oracle discipline)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });

    const badAdd = (await client.send("cello_contact_add", { agent: "alice", pubkey: PEER, moniker: "not a name" })) as { ok: boolean; reason?: string };
    expect(badAdd.ok).toBe(false);
    expect(badAdd.reason).toBe("invalid_moniker");
    // The add did NOT go through half-way: no contact row either (reject the request whole).
    expect(((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts).toHaveLength(0);

    await client.send("cello_contact_add", { agent: "alice", pubkey: PEER, moniker: "Bob" });
    const badSet = (await client.send("cello_contact_set_moniker", { agent: "alice", pubkey: PEER, moniker: "C*E*L*L*O" })) as { ok: boolean; reason?: string };
    expect(badSet.ok).toBe(false);
    expect(badSet.reason).toBe("invalid_moniker");
    expect(((await client.send("cello_contact_list", { agent: "alice" })) as ListResult).contacts[0].moniker).toBe("Bob");

    // Reviewer teeth-gap: a NON-STRING moniker over raw IPC (the shim's zod never sees this) —
    // a coercing implementation (String(42) → "42") would wrongly accept it.
    const numeric = (await client.send("cello_contact_add", { agent: "alice", pubkey: "cc".repeat(32), moniker: 42 })) as { ok: boolean; reason?: string };
    expect(numeric.ok).toBe(false);
    expect(numeric.reason).toBe("invalid_moniker");
  });
});
