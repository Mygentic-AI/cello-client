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
import { GatewayConfigStore } from "@cello-protocol/gateway";
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
