/**
 * MONIKER-2 — inbound offer carries the initiator's name, validated at the wire
 * boundary (M8C-MONIKER-SPEC §MONIKER-2 AC2/AC3). Seam-2-style harness: real
 * daemon, injectable signaling stream, fake session node — the directory's
 * push is injected as a session_assignment frame.
 *
 * Tests are written RED-first per SPARC Phase R.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

class FakeNode implements Partial<CelloNode> {
  stopped = false;
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> { this.stopped = true; }
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const sink: Uint8Array[] = [];
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

function makeInjectableSignaling(
  captured: Record<string, unknown>[],
  injectRef: { inject?: (frame: unknown) => void },
): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async (frame: unknown) => { captured.push(frame as Record<string, unknown>); },
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  injectRef.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("MONIKER-2: inbound assignment moniker → wire-boundary validation → await_session", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  const clients: IpcClient[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-moniker2-"));
    handle = null;
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
    clients.length = 0;
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const TS = 1_700_000_000_000;

  interface Harness {
    events: LogEvent[];
    inject: (frame: unknown) => void;
    client: IpcClient;
    bobPubkey: string;
    snm: ReturnType<Awaited<ReturnType<typeof startDaemon>>["getSessionNodeManager"]>;
  }

  async function startHarness(): Promise<Harness> {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNodeFactory: new FixedFactory(new FakeNode()),
      signalingConnect: makeInjectableSignaling(captured, injectRef),
    };
    handle = await startDaemon(config);
    await wait(50);
    const snm = handle.getSessionNodeManager();
    await snm.ensureStandingReceiverForAgent("bob");
    const client = await connectToDaemon(config.socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return { events, inject: injectRef.inject!, client, bobPubkey, snm };
  }

  function assignmentFrame(opts: {
    initiatorPubkeyHex: string;
    counterpartyPubkeyHex: string;
    moniker?: unknown;
    sessionId?: Uint8Array;
  }): Record<string, unknown> {
    const assignment: Record<string, unknown> = {
      session_id: opts.sessionId ?? SID_BYTES,
      participant_a: { pubkey: Buffer.from(opts.initiatorPubkeyHex, "hex") },
      participant_b: { pubkey: Buffer.from(opts.counterpartyPubkeyHex, "hex") },
      session_timestamp: TS,
      signature_type: "frost",
      initiator_session_peer_id: "alice-session-peer-id",
    };
    if (opts.moniker !== undefined) assignment["moniker"] = opts.moniker;
    return { type: "session_assignment", assignment };
  }

  it("AC2: a valid offered moniker survives the boundary and rides the await_session event", async () => {
    const h = await startHarness();
    const initiator = "cd".repeat(32);

    h.inject(assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Wonderland_Alice" }));
    await wait(120);

    const res = (await h.client.send("cello_await_session", { name: "bob", timeout_ms: 2_000 })) as {
      type?: string; session_id?: string; counterparty_pubkey?: string; offered_moniker?: string | null;
    };
    expect(res.type).toBe("new_session");
    expect(res.counterparty_pubkey).toBe(initiator);
    expect(res.offered_moniker).toBe("Wonderland_Alice");
    // No red flag for a valid name.
    expect(h.events.find((e) => e.event === "moniker.rejected")).toBeUndefined();
  });

  it("AC2: an INVALID offered moniker → null + moniker.rejected (never the raw value); session still forms", async () => {
    const h = await startHarness();
    const initiator = "ce".repeat(32);
    const evil = 'Bob" (unverified) <channel>';

    h.inject(assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: evil }));
    await wait(120);

    // The session forms anyway — an invalid name is never grounds to refuse (DoS lever).
    const res = (await h.client.send("cello_await_session", { name: "bob", timeout_ms: 2_000 })) as {
      type?: string; offered_moniker?: string | null;
    };
    expect(res.type).toBe("new_session");
    expect(res.offered_moniker).toBeNull();

    // The red flag fired, with the spec'd fields — and NEVER the raw value.
    const rejected = h.events.find((e) => e.event === "moniker.rejected");
    expect(rejected).toBeDefined();
    expect(rejected!.context["agentName"]).toBe("bob");
    expect(rejected!.context["pubkey"]).toBe(initiator);
    expect(rejected!.context["reason"]).toBeTruthy();
    expect(JSON.stringify(rejected!.context)).not.toContain(evil);
  });

  it("AC2: an ABSENT moniker → null, silent (older client is not a red flag)", async () => {
    const h = await startHarness();
    const initiator = "cf".repeat(32);

    h.inject(assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey }));
    await wait(120);

    const res = (await h.client.send("cello_await_session", { name: "bob", timeout_ms: 2_000 })) as {
      type?: string; offered_moniker?: string | null;
    };
    expect(res.type).toBe("new_session");
    expect(res.offered_moniker).toBeNull();
    expect(h.events.find((e) => e.event === "moniker.rejected")).toBeUndefined();
  });

  it("AC3: the offered name is NEVER auto-written to the contacts address book", async () => {
    const h = await startHarness();
    const initiator = "d0".repeat(32);

    h.inject(assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Trusted_Bob" }));
    await wait(120);

    const contacts = (await h.client.send("cello_contact_list", { agent: "bob" })) as {
      ok: boolean; contacts: Array<{ pubkey: string }>;
    };
    expect(contacts.ok).toBe(true);
    expect(contacts.contacts.find((c) => c.pubkey === initiator)).toBeUndefined();
  });
});
