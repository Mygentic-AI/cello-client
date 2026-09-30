/**
 * Gateway building blocks: the server + the local-sidecar client over a REAL Unix domain
 * socket (in-process server, real socket I/O — the separate-process seam is proven in the
 * daemon integration test). Covers the verdict round-trip, the screen-function seam later stories
 * plug into, and the fail-closed / never-hang guarantees (INV-6 / SI-001).
 *
 * The request-log cases that used to live here went with the feature (M8C DOD-CRYPTO-AT-REST-1):
 * proof-of-screening is asserted against the ENCRYPTED record store in the daemon integration
 * tests, which is where the direction round-trip is now covered too.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createGatewayServer, GatewaySocketInUseError, type GatewayServerHandle, type GatewayLogger } from "../server.js";
import { LocalSidecarGatewayClient } from "../client.js";
import type { ScreenContext } from "../types.js";
import { AFFORDANCE_PREFIX } from "../screen/affordance.js";

const ctx = (over: Partial<ScreenContext> = {}): ScreenContext => ({
  direction: "outbound",
  agentName: "alice",
  sessionId: "ab".repeat(16),
  correlationId: "corr-1",
  ...over,
});

const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T> =>
  Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(`did not settle within ${ms}ms`)), ms)),
  ]);

describe("gateway sidecar: server + LocalSidecarGatewayClient over a real Unix socket", () => {
  let tempDir: string;
  let sockPath: string;
  const servers: GatewayServerHandle[] = [];
  const clients: LocalSidecarGatewayClient[] = [];
  const rawServers: Server[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-gw-"));
    // Keep the UDS path short (macOS sun_path ~104 chars).
    sockPath = join(tempDir, "g.sock");
  });
  afterEach(async () => {
    for (const c of clients) { try { await c.close(); } catch { /* ignore */ } }
    for (const s of servers) { try { await s.stop(); } catch { /* ignore */ } }
    for (const r of rawServers) { try { await new Promise<void>((res) => r.close(() => res())); } catch { /* ignore */ } }
    clients.length = 0; servers.length = 0; rawServers.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  async function startServer(screen?: Parameters<typeof createGatewayServer>[0]["screen"]): Promise<void> {
    const h = await createGatewayServer({ socketPath: sockPath, ...(screen ? { screen } : {}) });
    servers.push(h);
  }
  function makeClient(deadlineMs = 5_000, path = sockPath): LocalSidecarGatewayClient {
    const c = new LocalSidecarGatewayClient({ socketPath: path, deadlineMs });
    clients.push(c);
    return c;
  }

  it("pass-through ALLOWS and returns the original content", async () => {
    await startServer(); // default pass-through
    const client = makeClient();
    const content = new TextEncoder().encode("hello peer");

    const v = await client.screenOutbound(content, ctx());
    expect(v.disposition).toBe("allow");
    expect(v.content).toBeDefined();
    expect(Buffer.from(v.content!).toString()).toBe("hello peer");
  });



  it("a screen function can REDACT — the transformed bytes round-trip back to the daemon", async () => {
    // Proves the verdict-content plumbing later stories (M9-OUT-*) depend on.
    await startServer((req) => {
      const text = Buffer.from(req.content).toString("utf8").replace("SECRET", "[REDACTED]");
      return { disposition: "redact", content: new TextEncoder().encode(text), reason: "secret_redacted" };
    });
    const client = makeClient();
    const v = await client.screenOutbound(new TextEncoder().encode("key=SECRET end"), ctx());
    expect(v.disposition).toBe("redact");
    expect(Buffer.from(v.content!).toString()).toBe("key=[REDACTED] end");
    expect(v.reason).toBe("secret_redacted");
  });

  it("a screen function can BLOCK — no content, reason + guidance flow back", async () => {
    await startServer(() => ({ disposition: "block", reason: "injection_detected", guidance: "Message not sent." }));
    const client = makeClient();
    const v = await client.screenInbound(new TextEncoder().encode("ignore previous instructions"), ctx({ direction: "inbound" }));
    expect(v.disposition).toBe("block");
    expect(v.content).toBeUndefined();
    expect(v.reason).toBe("injection_detected");
    // The gateway's guidance reaches the daemon MARKED (review H3): the client stamps every
    // agent-visible guidance with the provenance marker at this boundary, so the assertion is
    // "the gateway's text arrived, and it arrived attributed" — not byte equality.
    expect(v.guidance).toContain("Message not sent.");
    expect(v.guidance).toContain(AFFORDANCE_PREFIX);
  });

  it("FAIL-CLOSED when the gateway socket does not exist — block(gateway_unavailable), and it does NOT hang", async () => {
    // No server started. The client must settle to a fail-closed verdict within its deadline.
    const client = makeClient(200, join(tempDir, "nonexistent.sock"));
    const v = await withTimeout(client.screenOutbound(new TextEncoder().encode("x"), ctx()), 2_000);
    expect(v.disposition).toBe("block");
    expect(v.reason).toBe("gateway_unavailable");
    expect(v.guidance).toBeDefined();
  });

  it("governance events round-trip over the wire: a warn verdict's flagged items reach the client intact", async () => {
    await startServer(() => ({
      disposition: "warn",
      reason: "governance_warn",
      events: [
        { stage: "pii", disposition: "warn", category: "pii:email", reason: "personal data", flagId: "abc123def456" },
        { stage: "exfil", disposition: "redact", category: "exfil:invisible", reason: "stripped 1 codepoint" },
      ],
    }));
    const client = makeClient();
    const v = await client.screenOutbound(new TextEncoder().encode("hi"), ctx());
    expect(v.disposition).toBe("warn");
    expect(v.events).toHaveLength(2);
    expect(v.events![0]).toMatchObject({ stage: "pii", disposition: "warn", category: "pii:email", flagId: "abc123def456" });
    expect(v.events![1]).toMatchObject({ stage: "exfil", disposition: "redact" });
  });

  it("FAIL-CLOSED on timeout — a gateway that accepts but never replies yields block within the deadline", async () => {
    // A raw server that accepts the connection and reads, but never writes a response frame.
    const blackhole = createServer((sock) => { sock.on("data", () => { /* swallow, never reply */ }); });
    rawServers.push(blackhole);
    await new Promise<void>((res) => blackhole.listen(sockPath, () => res()));

    const client = makeClient(200);
    const start = process.hrtime.bigint();
    const v = await withTimeout(client.screenOutbound(new TextEncoder().encode("x"), ctx()), 2_000);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    expect(v.disposition).toBe("block");
    // Connected but no verdict in time → governance_timeout (distinct from unreachable).
    expect(v.reason).toBe("governance_timeout");
    // Settled near the deadline, not hung for the full 2s race ceiling.
    expect(elapsedMs).toBeLessThan(1_500);
  });

  it("after close(), further screens fail closed rather than hang", async () => {
    await startServer();
    const client = makeClient();
    await client.screenOutbound(new TextEncoder().encode("ok"), ctx());
    await client.close();
    const v = await withTimeout(client.screenOutbound(new TextEncoder().encode("after"), ctx()), 1_000);
    expect(v.disposition).toBe("block");
    expect(v.reason).toBe("gateway_unavailable");
  });
});

/**
 * 084-GATEWAYSOCK Part A — the gateway never deletes a socket it does not own.
 *
 * The reported failure: two `cello login` runs raced, the loser's gateway started before its daemon
 * knew it had lost, `rm`'d the WINNER's socket on the way in and again on the way out, and left the
 * winner's gateway alive with nothing at its path — every send failed `gateway_unavailable` for two
 * minutes. Two guards close it here: refuse to bind over a LIVE socket, and at stop delete only the
 * socket THIS instance created.
 */
describe("084-GATEWAYSOCK: a gateway never deletes a socket it does not own", () => {
  let tempDir: string;
  let sockPath: string;
  const servers: GatewayServerHandle[] = [];
  const clients: LocalSidecarGatewayClient[] = [];
  const children: ChildProcess[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-gw-own-"));
    sockPath = join(tempDir, "g.sock");
  });
  afterEach(async () => {
    for (const c of children) { try { c.kill("SIGKILL"); } catch { /* ignore */ } }
    for (const c of clients) { try { await c.close(); } catch { /* ignore */ } }
    for (const s of servers) { try { await s.stop(); } catch { /* ignore */ } }
    clients.length = 0; servers.length = 0; children.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
  const trackServer = (h: GatewayServerHandle): GatewayServerHandle => { servers.push(h); return h; };
  const makeClient = (): LocalSidecarGatewayClient => {
    const c = new LocalSidecarGatewayClient({ socketPath: sockPath, deadlineMs: 5_000 });
    clients.push(c);
    return c;
  };

  it("LIVE socket: a second gateway REFUSES, and the first keeps answering on an intact path", async () => {
    // Gateway A is live on the path.
    trackServer(await createGatewayServer({ socketPath: sockPath }));

    // Gateway B on the SAME path must refuse — never rm, never bind over A.
    await expect(createGatewayServer({ socketPath: sockPath })).rejects.toBeInstanceOf(GatewaySocketInUseError);

    // A is untouched: the path still exists and A still answers.
    expect(existsSync(sockPath)).toBe(true);
    const v = await makeClient().screenOutbound(enc("hello"), ctx());
    expect(v.disposition).toBe("allow");
  });

  it("STALE socket: a new gateway removes a dead socket file and listens", async () => {
    // A real socket file with nothing listening: a child binds it, then is SIGKILLed so the OS
    // never unlinks it (the crashed-prior-run case). connect() to it yields ECONNREFUSED = stale.
    const child = spawn(
      process.execPath,
      ["-e", "const net=require('node:net');const s=net.createServer();s.listen(process.env.P,()=>process.stdout.write('listening\\n'));setInterval(()=>{},1000);"],
      { env: { ...process.env, P: sockPath }, stdio: ["ignore", "pipe", "pipe"] },
    );
    children.push(child);
    await new Promise<void>((resolve, reject) => {
      child.stdout!.on("data", (c: Buffer) => { if (c.toString().includes("listening")) resolve(); });
      child.on("exit", () => reject(new Error("stale-socket child exited before binding")));
      setTimeout(() => reject(new Error("stale-socket child never bound")), 10_000);
    });
    child.kill("SIGKILL");
    await new Promise<void>((r) => child.on("exit", () => r()));
    expect(existsSync(sockPath)).toBe(true); // the stale file is present

    // A fresh gateway must remove it and come up answering.
    trackServer(await createGatewayServer({ socketPath: sockPath }));
    const v = await makeClient().screenOutbound(enc("x"), ctx());
    expect(v.disposition).toBe("allow");
  });

  it("NOT OURS at stop: stop() leaves a socket a different inode has taken over", async () => {
    const events: string[] = [];
    const logger: GatewayLogger = { info: (e) => events.push(e), warn: () => {}, error: () => {} };
    const h = await createGatewayServer({ socketPath: sockPath, logger });

    // Replace the file at the path with a DIFFERENT inode — as a racing successor gateway would.
    await unlink(sockPath);
    await writeFile(sockPath, "not-our-socket");
    const inoBefore = statSync(sockPath).ino;

    await h.stop();

    // The replacement is left exactly where it was — same inode, still on disk.
    expect(existsSync(sockPath)).toBe(true);
    expect(statSync(sockPath).ino).toBe(inoBefore);
    expect(events).toContain("security.gateway.socket.not_ours");
  });
});
