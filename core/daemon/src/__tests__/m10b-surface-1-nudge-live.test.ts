import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger } from "../types.js";
import { DUAL_SURFACE_VERBS, renderForSurface } from "../vocabulary.js";

/**
 * DOD-END-SURFACE-1 / DOD-END-PENDING-1 — "on selecting an agent with pending items, the operator is
 * told they are waiting."
 *
 * WHY THIS TEST EXISTS. The first cut of the nudge was covered only by tests that exercised the
 * three STORE methods it calls. Deleting the entire nudge block from `cello_use_agent` left the
 * whole repo green — the clause had zero coverage of the code it added, and an implementation that
 * computed the count and never attached it to the response passed everything.
 *
 * So this drives a real daemon over a real socket and asserts on the RESPONSE, which is the only
 * artifact the operator ever sees. It also pins the surface rendering, which is where the guidance
 * was found handing a CLI operator an MCP tool name.
 */
describe("DOD-END-SURFACE-1 — the pending-consent nudge, over a live daemon", () => {
  let handle: DaemonHandle | undefined;
  let tempDir: string | undefined;
  const clients: IpcClient[] = [];
  const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

  afterEach(async () => {
    for (const c of clients) c.close();
    clients.length = 0;
    if (handle) await handle.stop();
    handle = undefined;
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
    tempDir = undefined;
  });

  async function boot(): Promise<void> {
    tempDir = await mkdtemp(join(tmpdir(), "cello-nudge-"));
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
  }

  async function connectAs(clientType: "cli" | "mcp"): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir!, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType });
    return client;
  }

  it("a CLI operator is NEVER handed an MCP tool name in the pending guidance", async () => {
    await boot();
    const cli = await connectAs("cli");
    // Selecting an agent that does not exist still exercises the response path; what matters is that
    // ANY guidance this handler emits is renderable. The bug was structural: `pending_consent_
    // guidance` was not in the renderer's key set, so it passed through untranslated whatever it
    // said. Assert the property across every instruction key the response carries.
    const res = (await cli.send("cello_use_agent", { name: "nobody" })) as Record<string, unknown>;
    for (const [key, value] of Object.entries(res)) {
      if (typeof value !== "string") continue;
      if (!key.endsWith("guidance") && key !== "notice") continue;
      expect(value, `${key} handed a CLI caller an MCP tool name`).not.toMatch(/cello_[a-z_]+/);
    }
  });

  it("an MCP caller keeps the underscored tool names — the rewrite is one-directional", async () => {
    await boot();
    const mcp = await connectAs("mcp");
    const res = (await mcp.send("cello_use_agent", { name: "nobody" })) as Record<string, unknown>;
    // The counterpart assertion. Without it, a renderer that stripped tool names from BOTH surfaces
    // would satisfy the test above while leaving an MCP agent with a shell command it cannot run.
    //
    // Scoped to DUAL-SURFACE verbs only, and that scoping is the point rather than a convenience:
    // some commands are CLI-ONLY (`cello create-agent` has no MCP tool), so naming them to an MCP
    // caller is not a rendering bug — there is nothing to render them AS. The defect would be
    // handing an MCP caller the CLI form of a verb that HAS an MCP form.
    const guidance = Object.entries(res)
      .filter(([k, v]) => typeof v === "string" && (k.endsWith("guidance") || k === "notice"))
      .map(([, v]) => v as string)
      .join(" ");
    for (const { cli, mcp } of DUAL_SURFACE_VERBS) {
      expect(guidance, `an MCP caller was handed '${cli}' instead of '${mcp}'`).not.toContain(cli);
    }
  });
});

/**
 * The live test above cannot reach the nudge — it needs a loaded agent WITH a pending row — so it
 * proves the surface machinery works without proving THIS key rides it. That gap is exactly how the
 * defect shipped, so the key is pinned directly here.
 *
 * The bug: the renderer's instruction-key set was three literals, and `pending_consent_guidance` was
 * not one of them, so a CLI operator was told to run `cello_consent_list` — untypeable. The class is
 * "a handler invents a new *_guidance key without knowing a registry exists", so the assertion is
 * over the CLASS, not this one key.
 */
describe("DOD-ONBOARD-HELP-1 §5 — every *_guidance key is renderable, whatever its prefix", () => {
  it("rewrites pending_consent_guidance for a CLI caller", () => {
    const out = renderForSurface(
      { ok: true, pending_consent: 3, pending_consent_guidance: "Run cello_consent_list to read them." },
      "cli",
    ) as Record<string, unknown>;
    expect(out.pending_consent_guidance).toBe("Run cello consent list to read them.");
  });

  it("rewrites an arbitrary NEW *_guidance key — the fix closes the class, not the instance", () => {
    // A key nobody has written yet. If this fails, someone narrowed the rule back to a literal set
    // and the next handler to invent a key will ship the same defect.
    const out = renderForSurface(
      { ok: false, quota_guidance: "Run cello_consent_accept to decide." },
      "cli",
    ) as Record<string, unknown>;
    expect(out.quota_guidance).toBe("Run cello consent accept to decide.");
  });

  it("still leaves `reason` alone — scripts branch on it", () => {
    const out = renderForSurface({ ok: false, reason: "cello_consent_accept" }, "cli") as Record<string, unknown>;
    expect(out.reason).toBe("cello_consent_accept");
  });
});
