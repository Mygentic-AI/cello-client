/**
 * CELLO-M8C-CONTACT-1 — binary per-agent contact whitelist
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note):
 * - K1: cello_contact_add/remove/list persist a per-agent whitelist; identity pins to the pubkey
 *   at add time (re-adding is a no-op, never refreshes added_at); known stays known until removed.
 * - K2 (D6): initiating a session to X auto-adds X as a contact.
 * - K3 (CC-1, 2026-07-07 — SUPERSEDES the old D6 auto-add-on-accept): accepting an inbound request
 *   does NOT auto-add the sender. Accepting the *connection* must not grant *trust*. Promotion to
 *   "known" requires operator ENGAGEMENT: an outbound initiate, the operator replying INTO the
 *   session (cello_send), or an explicit cello_contact_add. An unattended stranger stays unknown —
 *   so the ABUSE-1 acceptance caps keep applying to them. (D21 / four-level-screening-policy.)
 * - K4: an UNKNOWN sender's session request gets the minimal "Dispatched." text (not the fuller
 *   AWAY-1 text), and they STAY unknown until the operator engages.
 * - K5: a KNOWN contact's away response uses the normal, richer AWAY-1 per-type text.
 * - K6: --agent resolves explicitly, else falls back to the connection's current/sole-online agent
 *   (F18), matching cello_check_notifications' own resolution.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
import type { SessionNegotiator } from "../transport-selector.js";
import type { Stream } from "@libp2p/interface";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
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
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}
class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

function makeInjectableSignaling(injectRef: { inject?: (frame: unknown) => void }): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async () => {},
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  injectRef.inject = (frame: unknown) => inbound?.(frame);
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("M8C-CONTACT-1: contact whitelist", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-contact-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function start(opts: {
    logger: Logger; node: CelloNode; signalingConnect?: () => Promise<ConnectResult>; sessionNegotiator?: SessionNegotiator;
  }): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger: opts.logger, sessionNodeFactory: new FixedFactory(opts.node),
      signalingConnect: opts.signalingConnect, sessionNegotiator: opts.sessionNegotiator,
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  async function connectAs(agent: string): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: agent });
    return client;
  }

  it("K1: add/remove/list — idempotent add, no-op re-add, remove reports whether it existed", async () => {
    await makeAgentDir("alice");
    await start({ logger: makeLogger().logger, node: new FakeNode() });
    const client = await connectAs("alice");

    const cp = "aa".repeat(32);
    const add1 = (await client.send("cello_contact_add", { pubkey: cp })) as Record<string, unknown>;
    expect(add1).toMatchObject({ ok: true, agent: "alice", pubkey: cp });

    const listAfterFirst = (await client.send("cello_contact_list", {})) as { contacts: Array<{ pubkey: string; added_at: number }> };
    const originalAddedAt = listAfterFirst.contacts[0].added_at;

    // Reviewer finding (a619ca33, test-teeth): re-adding must NOT refresh added_at — an
    // INSERT OR REPLACE (which WOULD refresh it) must fail this, not just "still one row."
    await new Promise((r) => setTimeout(r, 5)); // ensure a re-refreshed timestamp would differ
    const add2 = (await client.send("cello_contact_add", { pubkey: cp })) as Record<string, unknown>; // idempotent
    expect(add2.ok).toBe(true);

    const list = (await client.send("cello_contact_list", {})) as { ok: boolean; contacts: Array<{ pubkey: string; added_at: number }> };
    expect(list.contacts.map((c) => c.pubkey)).toEqual([cp]); // exactly one row despite two adds
    expect(list.contacts[0].added_at).toBe(originalAddedAt); // identity pinned at the FIRST add time

    const remove1 = (await client.send("cello_contact_remove", { pubkey: cp })) as Record<string, unknown>;
    expect(remove1).toMatchObject({ ok: true, removed: true });

    const remove2 = (await client.send("cello_contact_remove", { pubkey: cp })) as Record<string, unknown>;
    expect(remove2).toMatchObject({ ok: true, removed: false }); // already gone

    const emptyList = (await client.send("cello_contact_list", {})) as { contacts: unknown[] };
    expect(emptyList.contacts).toHaveLength(0);
  });

  it("K6: --agent (params.agent) resolves an explicit agent, independent of this connection's current agent", async () => {
    await makeAgentDir("alice");
    await makeAgentDir("bob");
    await start({ logger: makeLogger().logger, node: new FakeNode() });
    const client = await connectAs("alice"); // current agent is alice
    await client.send("cello_start_agent", { name: "bob" }); // bob online but not selected here

    const cp = "bb".repeat(32);
    const add = (await client.send("cello_contact_add", { pubkey: cp, agent: "bob" })) as Record<string, unknown>;
    expect(add).toMatchObject({ ok: true, agent: "bob" });

    const bobList = (await client.send("cello_contact_list", { agent: "bob" })) as { contacts: Array<{ pubkey: string }> };
    expect(bobList.contacts.map((c) => c.pubkey)).toEqual([cp]);
    const aliceList = (await client.send("cello_contact_list", {})) as { contacts: unknown[] }; // defaults to current (alice)
    expect(aliceList.contacts).toHaveLength(0); // alice's whitelist is untouched
  });

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const TS = 1_700_000_000_000;
  function assignmentFrame(initiatorPubkeyHex: string, counterpartyPubkeyHex: string): Record<string, unknown> {
    return {
      type: "session_assignment",
      assignment: {
        session_id: SID_BYTES,
        participant_a: { pubkey: Buffer.from(initiatorPubkeyHex, "hex") },
        participant_b: { pubkey: Buffer.from(counterpartyPubkeyHex, "hex") },
        session_timestamp: TS,
        signature_type: "frost",
        initiator_session_peer_id: "alice-session-peer-id",
        // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint.
        counterparty_session_peer_id: "bob-session-peer-id",
      },
    };
  }

  it("K3/K4 (CC-1): an inbound request from an UNKNOWN sender gets 'Dispatched.' and does NOT auto-whitelist them — accepting the connection ≠ trusting the sender", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node: new FakeNode(), signalingConnect: makeInjectableSignaling(injectRef) });
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob"); // bob unattended — no client connected

    const strangerPubkey = "cd".repeat(32);
    expect(h.getSessionNodeManager().isContact("bob", strangerPubkey)).toBe(false);
    injectRef.inject!(assignmentFrame(strangerPubkey, bobPubkey));
    await wait(150);

    const sentEvent = events.find((e) => e.event === "session.away.response.sent");
    expect(sentEvent?.context).toMatchObject({ kind: "request", isKnown: false });
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")[0]?.text).toBe("Dispatched.");

    // CC-1 teeth: the stranger must STILL be unknown after knocking. The old code auto-added them
    // here — which then exempted them from the ABUSE-1 caps. An unattended knock grants no trust.
    expect(h.getSessionNodeManager().isContact("bob", strangerPubkey)).toBe(false);
  });

  it("K3 (CC-1): the operator replying INTO an inbound session (cello_send) promotes the sender to a known contact", async () => {
    await makeAgentDir("alice");
    const h = await start({ logger: makeLogger().logger, node: new FakeNode() });
    const snm = h.getSessionNodeManager();
    const strangerPubkey = "7c".repeat(32);
    // An inbound-originated active session whose counterparty is NOT yet a contact (the CC-1 world:
    // accepting the connection did not add them). A brand-new empty session → first send needs no
    // read-before-write catch-up (M8C-CURSOR-1 C3).
    await snm.createSessionNode(SID_HEX, "alice", strangerPubkey, "stranger-peer", "corr");
    expect(snm.isContact("alice", strangerPubkey)).toBe(false);

    const client = await connectAs("alice");
    const res = (await client.send("cello_send", { session_id: SID_HEX, content: "thanks for reaching out" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);

    // Engagement = trust. A committed reply promotes them; without CC-1's addContact in cello_send
    // this stays false (the teeth).
    expect(snm.isContact("alice", strangerPubkey)).toBe(true);
  });

  it("K5: a KNOWN contact's inbound request gets the fuller AWAY-1 text, not 'Dispatched.'", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node: new FakeNode(), signalingConnect: makeInjectableSignaling(injectRef) });
    await wait(50);
    await h.getSessionNodeManager().ensureStandingReceiverForAgent("bob");

    const knownPubkey = "ef".repeat(32);
    h.getSessionNodeManager().addContact("bob", knownPubkey); // already known BEFORE this session

    injectRef.inject!(assignmentFrame(knownPubkey, bobPubkey));
    await wait(150);

    const sentEvent = events.find((e) => e.event === "session.away.response.sent");
    expect(sentEvent?.context).toMatchObject({ kind: "request", isKnown: true });
    const { messages } = h.getSessionNodeManager().readTranscript("bob", SID_HEX);
    expect(messages.filter((m) => m.direction === "sent")[0]?.text).toContain("session request has been received and queued");
  });

  it("K4/K5 (message-kind): an unknown sender's message on an existing session ALSO gets the minimal text; a known one gets the richer text", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start({ logger, node: new FakeNode() });
    const snm = h.getSessionNodeManager();
    const SID_UNKNOWN = "11".repeat(32);
    const SID_KNOWN = "22".repeat(32);
    await snm.createSessionNode(SID_UNKNOWN, "alice", "strangerpubkeyhex", "peer-1", "corr-1");
    await snm.createSessionNode(SID_KNOWN, "alice", "knownpubkeyhex", "peer-2", "corr-2");
    snm.addContact("alice", "knownpubkeyhex"); // pre-established as known; strangerpubkeyhex is not

    const m1 = new TextEncoder().encode("from stranger");
    await snm.ingestReceivedContent("alice", SID_UNKNOWN, m1, msgLeafHash(m1), "c1");
    const m2 = new TextEncoder().encode("from known");
    await snm.ingestReceivedContent("alice", SID_KNOWN, m2, msgLeafHash(m2), "c2");
    await wait(30);

    const unknownEvent = events.find((e) => e.event === "session.away.response.sent" && e.context.sessionId === SID_UNKNOWN);
    expect(unknownEvent?.context).toMatchObject({ kind: "message", isKnown: false });
    const knownEvent = events.find((e) => e.event === "session.away.response.sent" && e.context.sessionId === SID_KNOWN);
    expect(knownEvent?.context).toMatchObject({ kind: "message", isKnown: true });

    const unknownSent = snm.readTranscript("alice", SID_UNKNOWN).messages.filter((m) => m.direction === "sent");
    expect(unknownSent[0]?.text).toBe("Dispatched.");
    const knownSent = snm.readTranscript("alice", SID_KNOWN).messages.filter((m) => m.direction === "sent");
    expect(knownSent[0]?.text).toContain("message has been received");
  });

  it("K2: cello_initiate_session auto-adds the target as a contact", async () => {
    await makeAgentDir("alice");
    const targetPubkey = "99".repeat(32);
    const negotiator: SessionNegotiator = {
      async negotiate() {
        return {
          ok: true,
          assignment: {
            session_id: SID_BYTES,
            participant_a: { pubkey: Buffer.alloc(32), peer_id: "", multiaddrs: [] },
            participant_b: { pubkey: Buffer.from(targetPubkey, "hex"), peer_id: "", multiaddrs: [] },
            relay_endpoint: { peer_id: "", multiaddrs: [] },
            directory_endpoint: { peer_id: "", multiaddrs: [] },
            session_timestamp: TS,
            directory_pubkey: new Uint8Array(32),
            directory_signature: new Uint8Array(64),
            transport_mode: "direct",
            // No counterparty_session_addrs → connectToCounterparty is skipped (no real dial needed).
            counterparty_session_peer_id: "target-peer-id",
            counterparty_session_addrs: [],
            signature_type: "frost",
            signer_pubkey: new Uint8Array(32),
          },
        };
      },
    };
    const { logger } = makeLogger();
    const h = await start({ logger, node: new FakeNode(), sessionNegotiator: negotiator });
    const client = await connectAs("alice");

    expect(h.getSessionNodeManager().isContact("alice", targetPubkey)).toBe(false);
    const res = (await client.send("cello_initiate_session", { target_pubkey: targetPubkey })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect(h.getSessionNodeManager().isContact("alice", targetPubkey)).toBe(true);
    // DOD-TIER-1 AC5 (end-to-end): the initiate path stamps provenance 'initiated' (I opened the
    // session). This drives the REAL production handler — a manager-level test that passes the value
    // directly cannot catch a call site that forgets to pass it. Goes red if daemon.ts drops the arg.
    const provRow = h.getSessionNodeManager().getDb()
      .prepare("SELECT provenance FROM contacts WHERE pubkey = ?")
      .get(targetPubkey) as { provenance: string | null };
    expect(provRow.provenance).toBe("initiated");
  });
});
