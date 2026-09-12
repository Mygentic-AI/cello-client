/**
 * 074-DOCSFLAG clause 3 — the ADVERTISED MCP tool list carries no `cello_doc_*` tool.
 *
 * This is the surface that matters, and the reason is in the order: a human can be told "documents
 * are pre-alpha, don't use them"; an agent cannot. It reads the tool list and calls what is on it.
 *
 * ── THE HOLLOW-TEST TRAP THE CLAUSE NAMES, AND HOW THIS AVOIDS IT ─────────────────────────────
 *
 * "Assert on the advertised list, not on an internal registry." A test that imported a names table
 * and found no document entry would prove nothing about what an agent receives — the shim could
 * still be calling `server.tool("cello_doc_propose", …)` beside it. So this spawns the REAL BUILT
 * BINARY, completes the MCP handshake, and reads `tools/list` off the wire. What is asserted is the
 * bytes the client gets.
 *
 * ⚠️ IT RUNS AGAINST `dist/`, SO A STALE BUILD IS A FALSE GREEN. `pnpm run build` before trusting a
 * run of this file. The ON case is what makes a stale build visible rather than silent: if `dist/`
 * predates the gate, the ON case still passes and the OFF case fails — a build problem reads as a
 * missing gate, never the other way round.
 *
 * No daemon is started. The shim advertises its tools before it has ever spoken to one (that is the
 * property `onboarding-stranded-shim` pins), so the tool list is observable with nothing else
 * running — which is also the state in which an agent first reads it.
 */
import { describe, it, expect } from "vitest";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { DOCUMENTS_FLAG_ENV } from "@cello-protocol/daemon";

const here = dirname(fileURLToPath(import.meta.url));
const BIN = resolve(here, "../../dist/bin/cello-mcp.js");

const DOC_TOOLS = [
  "cello_doc_propose", "cello_doc_invite", "cello_doc_remove", "cello_doc_inbox",
  "cello_doc_accept", "cello_doc_refuse", "cello_doc_list", "cello_doc_read",
  "cello_doc_diff", "cello_doc_watch", "cello_doc_write", "cello_doc_publish",
  "cello_doc_close", "cello_doc_kill",
] as const;

/** Spawn the built shim with the flag in the given state and return its advertised tool names. */
async function advertisedTools(flag: "on" | "off"): Promise<string[]> {
  const celloDir = mkdtempSync(resolve(tmpdir(), "cello-docsflag-mcp-"));
  const env = { ...process.env, CELLO_DIR: celloDir };
  if (flag === "on") env[DOCUMENTS_FLAG_ENV] = "1";
  else delete env[DOCUMENTS_FLAG_ENV];

  const proc = spawn(process.execPath, [BIN], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  }) as ChildProcessWithoutNullStreams;

  let stdoutBuf = "";
  const waiters = new Map<number, (v: Record<string, unknown>) => void>();
  proc.stdout.on("data", (c: Buffer) => {
    stdoutBuf += c.toString();
    for (;;) {
      const nl = stdoutBuf.indexOf("\n");
      if (nl < 0) break;
      const line = stdoutBuf.slice(0, nl).trim();
      stdoutBuf = stdoutBuf.slice(nl + 1);
      if (!line) continue;
      try {
        const frame = JSON.parse(line) as Record<string, unknown>;
        const w = waiters.get(frame["id"] as number);
        if (w) { waiters.delete(frame["id"] as number); w(frame); }
      } catch { /* the shim tees diagnostics to stderr; a non-frame line is not ours */ }
    }
  });
  // Drained so a chatty startup cannot fill the pipe and wedge the child.
  proc.stderr.on("data", () => {});

  const rpc = (method: string, params: Record<string, unknown>, id: number) =>
    new Promise<Record<string, unknown>>((res, rej) => {
      const timer = setTimeout(() => rej(new Error(`no MCP response to ${method} within 15s`)), 15_000);
      waiters.set(id, (frame) => { clearTimeout(timer); res(frame); });
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });

  try {
    await rpc("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "docsflag-test", version: "0" },
    }, 1);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const listed = await rpc("tools/list", {}, 2) as { result?: { tools?: Array<{ name: string }> } };
    return (listed.result?.tools ?? []).map((t) => t.name);
  } finally {
    proc.kill("SIGKILL");
    rmSync(celloDir, { recursive: true, force: true });
  }
}

describe("074-DOCSFLAG clause 3 — what an agent is actually offered", () => {
  it("OFF: tools/list carries ZERO cello_doc_* tools", async () => {
    const names = await advertisedTools("off");
    // The search had reach before the negative is believed: this is a real, populated tool list.
    expect(names.length).toBeGreaterThan(30);
    expect(names).toContain("cello_send");

    expect(names.filter((n) => n.startsWith("cello_doc_"))).toEqual([]);
    for (const tool of DOC_TOOLS) expect(names, `${tool} is still advertised`).not.toContain(tool);
  }, 60_000);

  it("ON: all fourteen document tools are advertised again", async () => {
    const names = await advertisedTools("on");
    for (const tool of DOC_TOOLS) expect(names, `${tool} is missing with the flag ON`).toContain(tool);
  }, 60_000);

  it("ON advertises exactly fourteen more tools than OFF, and nothing else moved", async () => {
    const off = await advertisedTools("off");
    const on = await advertisedTools("on");
    expect(on.length - off.length).toBe(14);
    expect(new Set(on.filter((n) => !n.startsWith("cello_doc_")))).toEqual(new Set(off));
  }, 120_000);
});
