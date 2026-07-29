/**
 * DOD-M9C-SURFACE-1 — the control surface, and INV-10: the loosen gate has no side door.
 *
 * The central assertion is not "the verb works" — it is that an MCP caller CANNOT weaken a guard,
 * and that a refused loosening leaves NO ROW. A refusal that still persisted would be the whole
 * gate gone while looking enforced.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { GatewayConfigStore, GatewayRecordStore } from "@cello-protocol/gateway";
import { registerGatewayConfigHandlers } from "../gateway-config-handlers.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("DOD-M9C-SURFACE-1 — gateway config surface + the loosen gate", () => {
  let dir: string;
  let handlers: Map<string, IpcHandler>;
  let clientTypes: Map<string, string>;
  let restarts: number;
  let restartFails: boolean;

  const call = (method: string, params: Record<string, unknown>, connectionId = "cli-conn") =>
    handlers.get(method)!(params, connectionId) as Promise<Record<string, unknown>>;

  const openStore = () =>
    new GatewayConfigStore(join(dir, "gateway.db"), join(dir, "sessions.db.key"));

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-m9c-surface-"));
    await writeFile(join(dir, "sessions.db.key"), randomBytes(32), { mode: 0o600 });
    handlers = new Map();
    clientTypes = new Map([["cli-conn", "cli"], ["mcp-conn", "mcp"]]);
    restarts = 0;
    restartFails = false;
    registerGatewayConfigHandlers({
      handlers,
      celloDir: dir,
      logger: noopLogger,
      getClientType: (id) => clientTypes.get(id),
      restartSecurityGateway: async () => {
        restarts++;
        if (restartFails) throw new Error("sidecar did not come back up");
      },
    });
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("INV-10: an MCP caller CANNOT loosen a guard — refused, and NO row is written", async () => {
    const res = await call("cello_config_set", { key: "autonomous_override", value: true }, "mcp-conn");
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("loosen_requires_cli");
    expect(String(res.guidance)).toContain("cello config set autonomous_override");

    // The gate is only real if the refusal PERSISTED NOTHING. A stored-but-unapplied loosening
    // would read as enforced while the next gateway boot picked it up.
    const store = openStore();
    expect(store.history("autonomous_override")).toEqual([]);
    store.close();
    expect(restarts).toBe(0);
  });

  it("F1: a connection that NEVER declared a client type cannot confirm a loosening", async () => {
    // The hole this closes: `getClientType` returns undefined for a raw socket that skipped
    // `ipc.connect`, and the daemon ALSO defaults a handshake with no clientType to "cli". With
    // `!== "mcp"` meaning "cli", ten lines of node against ~/.cello/daemon.sock could land a
    // confirmed loosening with no human anywhere near it — and verifyChain would attest it as
    // human-confirmed forever. The permissive side must never be the default.
    const res = await call(
      "cello_config_set",
      { key: "autonomous_override", value: true, confirmed: true },
      "unknown-conn", // not in clientTypes → getClientType returns undefined
    );
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("loosen_requires_cli");

    const store = openStore();
    expect(store.history("autonomous_override")).toEqual([]);
    store.close();
  });

  it("F1: an MCP caller passing confirmed:true directly is still refused — the flag is not a key", async () => {
    const res = await call(
      "cello_config_set",
      { key: "autonomous_override", value: true, confirmed: true },
      "mcp-conn",
    );
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("loosen_requires_cli");
    const store = openStore();
    expect(store.history("autonomous_override")).toEqual([]);
    store.close();
  });

  it("F6: an out-of-range value is invalid_value, never internal_error", async () => {
    const res = await call("cello_config_set", { key: "rate_window_ms", value: 0 });
    expect(res.reason).toBe("invalid_value");
    expect(String(res.guidance)).toContain("greater than 0");
  });

  it("F7: the needs_confirmation refusal carries the CURRENT value, so a replacement cannot hide a drop", async () => {
    await call("cello_config_set", { key: "pii_whitelist", value: "a@x.example,b@x.example", confirmed: true });
    const res = await call("cello_config_set", { key: "pii_whitelist", value: "c@x.example" });
    expect(res.reason).toBe("needs_confirmation");
    expect(res.from).toEqual(["a@x.example", "b@x.example"]);
  });

  it("a CLI caller without confirmation is refused with needs_confirmation — and still writes no row", async () => {
    const res = await call("cello_config_set", { key: "autonomous_override", value: true });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("needs_confirmation");
    expect(res.direction).toBe("loosen");

    const store = openStore();
    expect(store.history("autonomous_override")).toEqual([]);
    store.close();
  });

  it("a CONFIRMED loosening from the CLI applies, is marked confirmed, and restarts the sidecar", async () => {
    const res = await call("cello_config_set", { key: "autonomous_override", value: true, confirmed: true });
    expect(res.ok).toBe(true);
    expect(res.direction).toBe("loosen");
    expect(res.confirmed).toBe(true);
    expect(res.applied).toBe(true);
    expect(restarts).toBe(1);

    const store = openStore();
    const history = store.history("autonomous_override");
    expect(history).toHaveLength(1);
    expect(history[0]!.confirmed).toBe(true);
    expect(store.verifyChain("autonomous_override")).toBe(true);
    store.close();
  });

  it("a TIGHTENING needs no confirmation — from MCP too", async () => {
    await call("cello_config_set", { key: "autonomous_override", value: true, confirmed: true });
    const res = await call("cello_config_set", { key: "autonomous_override", value: false }, "mcp-conn");
    expect(res.ok).toBe(true);
    expect(res.direction).toBe("tighten");
    expect(res.confirmed).toBe(false);
  });

  it("a restart failure reports STORED BUT NOT APPLIED — never a bare ok", async () => {
    restartFails = true;
    const res = await call("cello_config_set", { key: "autonomous_override", value: true, confirmed: true });
    // The change IS stored (the row exists), so ok:true is honest — but the operator must not
    // believe the running gateway changed.
    expect(res.ok).toBe(true);
    expect(res.applied).toBe(false);
    expect(res.warning).toBe("stored_but_not_applied");
    expect(String(res.guidance)).toContain("NOT yet");
  });

  it("list reports the GOVERNANCE — value, version, direction, confirmed — and null for unset", async () => {
    await call("cello_config_set", { key: "rate_max_per_window", value: 10 });
    const res = await call("cello_config_list", {});
    const rows = res.config as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(5);
    const rate = rows.find((r) => r.key === "rate_max_per_window")!;
    expect(rate.value).toBe(10);
    expect(rate.version).toBe(1);
    expect(rate.lastChange).toBe("tighten"); // 0 (no cap) is the loosest — setting a cap tightens
    const untouched = rows.find((r) => r.key === "pii_whitelist")!;
    // null, not a fabricated default: "never configured" must not look like "set to this value".
    expect(untouched.value).toBeNull();
    expect(untouched.version).toBe(0);
  });

  it("each refusal names its own cause — unknown key and bad value never share one label", async () => {
    const unknown = await call("cello_config_set", { key: "not_a_key", value: 1 });
    expect(unknown.reason).toBe("unknown_key");
    const bad = await call("cello_config_set", { key: "rate_max_per_window", value: "banana" });
    expect(bad.reason).toBe("invalid_value");
    const missing = await call("cello_config_set", { key: "rate_max_per_window" });
    expect(missing.reason).toBe("missing_params");
  });

  it("get reports the value plus its chain validity", async () => {
    await call("cello_config_set", { key: "rate_window_ms", value: 120000 });
    const res = await call("cello_config_get", { key: "rate_window_ms" });
    expect(res.ok).toBe(true);
    expect(res.value).toBe(120000);
    expect(res.chainValid).toBe(true);
  });

  // ─── DOD-M9C-AUDIT-1: what did my policy do? ───────────────────────────────────────────────

  it("the policy log reports what the layer did, newest first, with the rule that fired", async () => {
    const records = new GatewayRecordStore(join(dir, "gateway.db"), join(dir, "sessions.db.key"));
    records.record({ direction: "outbound", disposition: "clean", contentHash: "aa".repeat(32) });
    records.record({
      direction: "outbound", disposition: "redact", contentHash: "bb".repeat(32),
      reason: "secret:aws-access-key", correlationId: "corr-1",
    });
    records.close();

    const res = await call("cello_policy_log", {});
    expect(res.ok).toBe(true);
    const entries = res.entries as Array<Record<string, unknown>>;
    expect(entries).toHaveLength(2);
    // Newest first — the question is nearly always "what just happened".
    expect(entries[0]!.disposition).toBe("redact");
    expect(entries[0]!.reason).toBe("secret:aws-access-key");
    expect(entries[0]!.correlationId).toBe("corr-1");
    // A clean pass is recorded too: an ABSENT record for a delivered message is itself evidence.
    expect(entries[1]!.disposition).toBe("clean");
    // The shape carries `source` from day one so reachability entries can join later.
    expect(entries[0]!.source).toBe("security");
    expect(res.chainValid).toBe(true);
  });

  it("the policy log reports chainValid:false when the record log was TAMPERED with", async () => {
    const records = new GatewayRecordStore(join(dir, "gateway.db"), join(dir, "sessions.db.key"));
    records.record({ direction: "outbound", disposition: "block", contentHash: "cc".repeat(32), reason: "injection" });
    records.close();

    // Rewrite the stored disposition — the exact edit someone covering their tracks would make.
    // Opened WITH the key, because after STORE-1 that is the only door into the file at all; the
    // chain never claimed to stop a key-holder, only to make the edit detectable.
    const { openEncryptedStoreDb } = await import("@cello-protocol/gateway");
    const db = openEncryptedStoreDb(join(dir, "gateway.db"), join(dir, "sessions.db.key"));
    db.prepare("UPDATE security_records SET disposition = 'clean' WHERE seq = 1").run();
    db.close();

    const res = await call("cello_policy_log", {});
    expect(res.ok).toBe(true);
    // The operator must be told the log itself is untrustworthy BEFORE reasoning from it.
    expect(res.chainValid).toBe(false);
  });

  it("limit is bounded and the log survives having no records at all", async () => {
    const empty = await call("cello_policy_log", {});
    expect(empty.ok).toBe(true);
    expect(empty.entries).toEqual([]);

    const records = new GatewayRecordStore(join(dir, "gateway.db"), join(dir, "sessions.db.key"));
    for (let i = 0; i < 5; i++) {
      records.record({ direction: "inbound", disposition: "clean", contentHash: String(i).repeat(64).slice(0, 64) });
    }
    records.close();
    const limited = await call("cello_policy_log", { limit: 2 });
    expect((limited.entries as unknown[]).length).toBe(2);
    expect(limited.total).toBe(5);
  });

  it("a comma-separated list is parsed, and an EMPTY string clears rather than storing an empty member", async () => {
    const set = await call("cello_config_set", {
      key: "pii_whitelist", value: "me@example.com, you@example.com", confirmed: true,
    });
    expect(set.ok).toBe(true);
    const got = await call("cello_config_get", { key: "pii_whitelist" });
    expect(got.value).toEqual(["me@example.com", "you@example.com"]);

    const cleared = await call("cello_config_set", { key: "pii_whitelist", value: "" });
    expect(cleared.ok).toBe(true);
    expect(cleared.direction).toBe("tighten"); // removing members tightens
    const after = await call("cello_config_get", { key: "pii_whitelist" });
    expect(after.value).toEqual([]);
  });
});
