/**
 * M15D contract C2, the shim's half: an IpcProxy built with `caller` stamps it on every request's
 * envelope; one built without it sends none (a plugin socket that sent one would be refused).
 */
import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { IpcProxy } from "../ipc-proxy.js";

describe("M15D IpcProxy caller envelope", () => {
  let server: Server | undefined;
  let dir: string | undefined;

  afterEach(() => {
    server?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  async function capture(opts: ConstructorParameters<typeof IpcProxy>[1]): Promise<Array<Record<string, unknown>>> {
    dir = mkdtempSync(join(tmpdir(), "m15d-proxy-"));
    const sock = join(dir, "s.sock");
    const frames: Array<Record<string, unknown>> = [];
    server = createServer((c) => {
      let buf = "";
      c.on("data", (d) => {
        buf += d.toString();
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const f = JSON.parse(buf.slice(0, i)) as Record<string, unknown>;
          buf = buf.slice(i + 1);
          frames.push(f);
          c.write(JSON.stringify({ id: f["id"], result: { ok: true } }) + "\n");
        }
      });
    });
    await new Promise<void>((r) => server!.listen(sock, r));
    const proxy = new IpcProxy(sock, opts);
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: opts?.clientType ?? "mcp" });
    await proxy.call("cello_receive", { session_id: "s" });
    proxy.close();
    return frames;
  }

  it("stamps the caller on every frame when built with one", async () => {
    const frames = await capture({ clientType: "endpoint", caller: { id: "oauth:abc", label: "ChatGPT" } });
    expect(frames.map((f) => f["caller"])).toEqual([
      { id: "oauth:abc", label: "ChatGPT" },
      { id: "oauth:abc", label: "ChatGPT" },
    ]);
  });

  it("sends no caller key at all when built without one", async () => {
    const frames = await capture({ clientType: "mcp" });
    expect(frames.every((f) => !("caller" in f))).toBe(true);
    expect(frames).toHaveLength(2);
  });
});
