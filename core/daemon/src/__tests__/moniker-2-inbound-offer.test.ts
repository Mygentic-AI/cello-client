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
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { TIER } from "../contacts-tier-migration.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { makeSignedAssignmentFrame, registerFixtureSigner, fixtureIdentity } from "./helpers/signed-assignment.js";
import type { Logger, DaemonConfig, IpcNotification } from "../types.js";
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
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    // 038-KEYBIND: a REAL agent, so the assignment fixture can sign a key binding as it.
    registerFixtureSigner(hex, kp);
    return hex;
  }

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const TS = 1_700_000_000_000;

  interface Harness {
    events: LogEvent[];
    inject: (frame: unknown) => void;
    client: IpcClient;
    bobPubkey: string;
    // DOD-MONIKER-6: a SECOND local agent on the SAME daemon — the only configuration in which
    // the session-id-keyed offer box can be misread (spec §10: "the bug requires initiator and
    // receiver to share one daemon").
    alicePubkey: string;
    socketPath: string;
    snm: ReturnType<Awaited<ReturnType<typeof startDaemon>>["getSessionNodeManager"]>;
  }

  async function startHarness(): Promise<Harness> {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const alicePubkey = await makeAgentDir("alice");
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
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
    await snm.ensureStandingReceiverForAgent("alice");
    const client = await connectToDaemon(config.socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return { events, inject: injectRef.inject!, client, bobPubkey, alicePubkey, socketPath: config.socketPath, snm };
  }

  // session_state_changed is routed ONLY to connections whose current agent matches, so each
  // agent's doorbell needs its own connection — exactly as two MCP servers on one machine.
  async function connectAs(socketPath: string, agentName: string): Promise<{ client: IpcClient; notifications: IpcNotification[] }> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    const notifications: IpcNotification[] = [];
    client.onNotification((n) => notifications.push(n));
    await client.send("ipc.connect", { clientType: "mcp" });
    await client.send("cello_use_agent", { name: agentName });
    return { client, notifications };
  }

  /**
   * DOD-M15-RESPONDER-VERIFY-1: the responder VERIFIES inbound assignments, so this fixture mints a
   * genuinely signed frame instead of one whose signature was absent. What MONIKER-2 is about — the
   * offered name at the wire boundary — is unchanged; the frame now reaches that code through the
   * real gate rather than past a check that was not there.
   *
   * The moniker is attached AFTER signing on purpose: it is not covered by the session-establishment
   * TBS, so attaching it is not tampering. That is the protocol's own shape — the self-declared name
   * rides beside the signed document and was never attested by the directory, which is exactly why
   * it has to be validated here.
   *
   * `signWith` carries a caller-supplied quorum key. The FIRST accepted session PINS its signer as
   * that counterparty's threshold key, so a second offer from the same initiator under a fresh key
   * is an identity substitution and is correctly refused. Tests that drive several sessions from one
   * initiator pass one key for all of them — what a repeat counterparty actually looks like.
   */
  async function assignmentFrame(opts: {
    initiatorPubkeyHex: string;
    counterpartyPubkeyHex: string;
    moniker?: unknown;
    sessionId?: Uint8Array;
    signWith?: ReturnType<typeof generateKeypair>;
  }): Promise<Record<string, unknown>> {
    const { frame } = await makeSignedAssignmentFrame({
      sessionId: opts.sessionId ?? SID_BYTES,
      initiatorPubkey: Uint8Array.from(Buffer.from(opts.initiatorPubkeyHex, "hex")),
      responderPubkey: Uint8Array.from(Buffer.from(opts.counterpartyPubkeyHex, "hex")),
      sessionTimestamp: TS,
      initiatorSessionPeerId: "alice-session-peer-id",
      // DOD-INBOUND-GUARD-1: a complete assignment carries the responder's accepted endpoint;
      // frames without it are refused (they mean nobody accepted the offer).
      counterpartySessionPeerId: "bob-session-peer-id",
      ...(opts.signWith !== undefined ? { signWith: opts.signWith } : {}),
    });
    if (opts.moniker !== undefined) {
      (frame["assignment"] as Record<string, unknown>)["moniker"] = opts.moniker;
    }
    return frame;
  }

  it("DOD-RENAME-1: a differing self-declared name from a NAMED contact surfaces a rename notice in cello_check_notifications (INBOX, not a push)", async () => {
    const h = await startHarness();
    const initiator = fixtureIdentity().pubkeyHex;
    const sid = (n: number): Uint8Array => Uint8Array.from(Array.from({ length: 16 }, (_, b) => (n * 16 + b) & 0xff));
    // bob KNOWS and has PERSONALLY NAMED the initiator — the precondition for Option-C rename notices.
    h.snm.addContact("bob", initiator, undefined, "accepted", TIER.KNOWN);
    h.snm.setContactMoniker("bob", initiator, "Mum");
    // One quorum key across both offers — see assignmentFrame: the first session pins it.
    const quorum = generateKeypair();

    // First offer establishes the baseline (no notice); a later DIFFERING name fires the notice.
    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Alice", sessionId: sid(1), signWith: quorum }));
    await wait(120);
    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "AliceCorp", sessionId: sid(2), signWith: quorum }));
    await wait(120);

    const bob = await connectAs(h.socketPath, "bob");
    const inbox = (await bob.client.send("cello_check_notifications", {})) as {
      agents: Array<{ agent: string; rename_notices: Array<{ pubkey: string; claimed_name: string; notice: string }> }>;
    };
    const bobAgent = inbox.agents.find((a) => a.agent === "bob")!;
    expect(bobAgent.rename_notices).toHaveLength(1);
    expect(bobAgent.rename_notices[0]).toMatchObject({ pubkey: initiator, claimed_name: "AliceCorp" });
    expect(bobAgent.rename_notices[0].notice).toContain('"AliceCorp"'); // rendered as a quoted, untrusted claim
    // AC2: the operator's local pet name is never overwritten by the offered name.
    expect(h.snm.getContactMoniker("bob", initiator)).toBe("Mum");
  });

  it("DOD-RENAME-1 AC5: a NO-moniker offer fires nothing and does NOT clear the baseline", async () => {
    const h = await startHarness();
    const initiator = fixtureIdentity().pubkeyHex;
    const sid = (n: number): Uint8Array => Uint8Array.from(Array.from({ length: 16 }, (_, b) => (n * 16 + b) & 0xff));
    h.snm.addContact("bob", initiator, undefined, "accepted", TIER.KNOWN);
    h.snm.setContactMoniker("bob", initiator, "Mum");
    // One quorum key across all three offers — see assignmentFrame: the first session pins it.
    const quorum = generateKeypair();

    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Alice", sessionId: sid(1), signWith: quorum })); // baseline "Alice"
    await wait(120);
    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, sessionId: sid(2), signWith: quorum })); // NO moniker → nothing
    await wait(120);
    // The baseline must have SURVIVED: a later DIFFERING name still fires exactly one notice (a bypass
    // that let the null offer through would have NULLed the baseline, making this a silent first-offer).
    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Bob", sessionId: sid(3), signWith: quorum }));
    await wait(120);

    const bob = await connectAs(h.socketPath, "bob");
    const inbox = (await bob.client.send("cello_check_notifications", {})) as {
      agents: Array<{ agent: string; rename_notices: Array<{ pubkey: string; claimed_name: string }> }>;
    };
    const notices = inbox.agents.find((a) => a.agent === "bob")!.rename_notices;
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ pubkey: initiator, claimed_name: "Bob" }); // compared against surviving "Alice"
  });

  it("DOD-RENAME-1 / DEC-AB-4: a BLOCKED named contact's differing-name offer drives NO notice (a refused peer can't touch the baseline)", async () => {
    const h = await startHarness();
    const initiator = fixtureIdentity().pubkeyHex;
    const sid = (n: number): Uint8Array => Uint8Array.from(Array.from({ length: 16 }, (_, b) => (n * 16 + b) & 0xff));
    h.snm.addContact("bob", initiator, undefined, "accepted", TIER.KNOWN);
    h.snm.setContactMoniker("bob", initiator, "Mum");
    h.snm.setContactTier("bob", initiator, TIER.BLOCKED); // blocked → offers are refused at the bound

    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "AliceEvil", sessionId: sid(1) }));
    await wait(120);

    const bob = await connectAs(h.socketPath, "bob");
    const inbox = (await bob.client.send("cello_check_notifications", {})) as {
      agents: Array<{ agent: string; rename_notices: unknown[] }>;
    };
    expect(inbox.agents.find((a) => a.agent === "bob")!.rename_notices).toHaveLength(0);
  });

  it("AC2: a valid offered moniker survives the boundary and rides the await_session event", async () => {
    const h = await startHarness();
    const initiator = fixtureIdentity().pubkeyHex;

    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Wonderland_Alice" }));
    await wait(120);

    const res = (await h.client.send("cello_await_session", { agent: "bob", timeout_ms: 2_000 })) as {
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
    const initiator = fixtureIdentity().pubkeyHex;
    const evil = 'Bob" (self-declared) <channel>';

    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: evil }));
    await wait(120);

    // The session forms anyway — an invalid name is never grounds to refuse (DoS lever).
    const res = (await h.client.send("cello_await_session", { agent: "bob", timeout_ms: 2_000 })) as {
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
    const initiator = fixtureIdentity().pubkeyHex;

    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey }));
    await wait(120);

    const res = (await h.client.send("cello_await_session", { agent: "bob", timeout_ms: 2_000 })) as {
      type?: string; offered_moniker?: string | null;
    };
    expect(res.type).toBe("new_session");
    expect(res.offered_moniker).toBeNull();
    expect(h.events.find((e) => e.event === "moniker.rejected")).toBeUndefined();
  });

  // Review F1: the offeredMonikers map must actually shrink on the states production EMITS
  // ("interrupted", "counterparty_closing" — never "sealed"/"closed" through this wrapper), else
  // every valid inbound offer is a permanent, remote-fed entry for the daemon's lifetime.
  it("F1: the session-scoped offered name is DROPPED when the session leaves 'created' (production states)", async () => {
    process.env["CELLO_ENV"] = "test"; // gates __test_emit_session_event
    try {
      const h = await startHarness();
      const initiator = fixtureIdentity().pubkeyHex;
      const sidHex = Buffer.from(SID_BYTES).toString("hex");

      h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Ephemeral_Bob" }));
      await wait(120);

      // A production-real state transition (session node destroyed → "interrupted").
      await h.client.send("__test_emit_session_event", {
        type: "destroyed",
        state: "interrupted",
        sessionId: sidHex,
        agentName: "bob",
        counterpartyPubkey: initiator,
      });

      const dropped = h.events.filter((e) => e.event === "moniker.offer.dropped");
      expect(dropped).toHaveLength(1);
      expect(dropped[0].context["sessionId"]).toBe(sidHex);

      // A second transition must NOT log a second drop — the entry is genuinely gone,
      // not merely logged about on every state change.
      await h.client.send("__test_emit_session_event", {
        type: "destroyed",
        state: "interrupted",
        sessionId: sidHex,
        agentName: "bob",
        counterpartyPubkey: initiator,
      });
      expect(h.events.filter((e) => e.event === "moniker.offer.dropped")).toHaveLength(1);
    } finally {
      delete process.env["CELLO_ENV"];
    }
  });

  it("F1: an EXPIRED unclaimed offer drops its offered name at reap time", async () => {
    process.env["CELLO_ENV"] = "test"; // gates __test_enqueue_inbound_session
    try {
      const h = await startHarness();
      const initiator = fixtureIdentity().pubkeyHex;
      const sidHex = Buffer.from(SID_BYTES).toString("hex");

      // Real inbound path populates the map…
      h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Stale_Bob" }));
      await wait(120);

      // …then a backdated duplicate queue entry for the SAME session id ages past the TTL,
      // and the next queue read reaps it.
      await h.client.send("__test_enqueue_inbound_session", {
        agentName: "bob",
        sessionId: sidHex,
        counterpartyPubkey: initiator,
        enqueuedAtOverride: 1, // epoch — decades past any TTL
      });
      // cello_await_session reaps expired entries for the NAMED agent before reading the queue
      // (scope:"current" notifications would need a current agent this harness never selects).
      await h.client.send("cello_await_session", { agent: "bob", timeout_ms: 1_000 });

      const dropped = h.events.filter((e) => e.event === "moniker.offer.dropped");
      expect(dropped.length).toBeGreaterThanOrEqual(1);
      expect(dropped[0].context["sessionId"]).toBe(sidHex);
    } finally {
      delete process.env["CELLO_ENV"];
    }
  });

  // ─── DOD-MONIKER-6 (spec §10, "fix A") ────────────────────────────────────────
  // The offer box is written by the RECEIVING side and keyed by session id alone, so on a daemon
  // that hosts BOTH participants the initiator reads the box that was filled in for her
  // counterparty — and is told she messaged herself. Two machines never hit this: an initiator's
  // daemon never receives an offer for its own outbound session. Hence the whole tier tested green.
  describe("DOD-MONIKER-6: the offered-name box is scoped to the agent it was written for", () => {
    it("AC2: alice initiates to bob on ONE daemon — alice's doorbell never shows alice's own name", async () => {
      process.env["CELLO_ENV"] = "test"; // gates __test_emit_session_event (registered at startup)
      try {
        const h = await startHarness();
        const sidHex = Buffer.from(SID_BYTES).toString("hex");
        const alice = await connectAs(h.socketPath, "alice");
        const bob = await connectAs(h.socketPath, "bob");

        // Alice opens a session to Bob. The daemon receives the assignment on BOB's behalf and
        // records Alice's offered name — display material for BOB, and for nobody else.
        h.inject(await assignmentFrame({ initiatorPubkeyHex: h.alicePubkey, counterpartyPubkeyHex: h.bobPubkey, moniker: "Ms_Chelly" }));
        await wait(150);

        // Bob's inbound doorbell DOES name her. Asserted here so this test also pins read-key ==
        // write-key: a partial fix that scoped only the write would leave alice clean (her
        // unscoped read simply misses) but would break this positive resolution.
        const bobCreated = bob.notifications.find(
          (n) => n.notification === "session_state_changed" && n.data["agentName"] === "bob",
        );
        expect(bobCreated).toBeDefined();
        expect(bobCreated!.data["who"]).toBe("Ms_Chelly");

        // Bob's session node comes up and Alice's own doorbell fires for the same session id.
        await h.client.send("__test_emit_session_event", {
          type: "created",
          sessionId: sidHex,
          agentName: "alice",
          counterpartyPubkey: h.bobPubkey,
        });
        await wait(50);

        const created = alice.notifications.find(
          (n) => n.notification === "session_state_changed" && n.data["agentName"] === "alice",
        );
        expect(created).toBeDefined();
        // The bug: "Ms_Chelly" — alice reading the box that was filled in for bob.
        expect(created!.data["who"]).not.toBe("Ms_Chelly");
        // Alice has no name for bob at all, so she must degrade to his fingerprint (spec §8 tiers).
        expect(created!.data["who"]).toBe(`agent ${h.bobPubkey.slice(0, 8)}…`);
        expect(created!.data["whoKnown"]).toBe(false);
        // §11: the anchor rides along regardless.
        expect(created!.data["counterpartyPubkey"]).toBe(h.bobPubkey);
      } finally {
        delete process.env["CELLO_ENV"];
      }
    });

    // Entry 76: the live run produced a WRONG verdict because `moniker.resolved` carried no sessionId.
    // `source:"offered"` is CORRECT for a receiver and wrong only for an INITIATOR, so a line cannot be
    // classified without knowing who opened that session — and a grep for `agentName=X source=offered`
    // flags correct lines as bugs. sessionId makes the event joinable against `session.inbound.accepted`
    // (which names the RECEIVER for a session id); anything else on that session is the initiator.
    it("moniker.resolved carries sessionId, so a line can be attributed to its session", async () => {
      process.env["CELLO_ENV"] = "test";
      try {
        const h = await startHarness();
        const sidHex = Buffer.from(SID_BYTES).toString("hex");
        await connectAs(h.socketPath, "bob");

        h.inject(await assignmentFrame({ initiatorPubkeyHex: h.alicePubkey, counterpartyPubkeyHex: h.bobPubkey, moniker: "Ms_Chelly" }));
        await wait(150);

        const resolved = h.events.filter((e) => e.event === "moniker.resolved");
        expect(resolved.length).toBeGreaterThanOrEqual(1);
        const bobLine = resolved.find((e) => e.context["agentName"] === "bob");
        expect(bobLine).toBeDefined();
        // The four fields a diagnosis needs: who resolved, for which counterparty, on WHICH session, how.
        expect(bobLine!.context["sessionId"]).toBe(sidHex);
        expect(bobLine!.context["agentName"]).toBe("bob");
        expect(bobLine!.context["pubkey"]).toBe(h.alicePubkey);
        expect(bobLine!.context["source"]).toBe("offered");
        expect(bobLine!.context["whoKnown"]).toBe(false);
        // The label itself is display material and MUST NOT be logged — the offered name is
        // attacker-chosen (MONIKER-2 AC2 logs `moniker.rejected` without the raw value; same rule).
        expect(JSON.stringify(bobLine!.context)).not.toContain("Ms_Chelly");

        // The join that classifies it: session.inbound.accepted names the RECEIVER for this session id.
        const accepted = h.events.find((e) => e.event === "session.inbound.accepted" && e.context["sessionId"] === sidHex);
        expect(accepted).toBeDefined();
        expect(accepted!.context["agentName"]).toBe("bob"); // ⇒ bob is the receiver ⇒ source=offered is correct
      } finally {
        delete process.env["CELLO_ENV"];
      }
    });

    it("AC3: a state change on alice's session must not drop bob's offered name", async () => {
      process.env["CELLO_ENV"] = "test";
      try {
        const h = await startHarness();
        const sidHex = Buffer.from(SID_BYTES).toString("hex");
        const bob = await connectAs(h.socketPath, "bob");

        h.inject(await assignmentFrame({ initiatorPubkeyHex: h.alicePubkey, counterpartyPubkeyHex: h.bobPubkey, moniker: "Ms_Chelly" }));
        await wait(150);

        // Alice's half of the session is interrupted. Bob's box belongs to bob and must survive.
        await h.client.send("__test_emit_session_event", {
          type: "destroyed",
          state: "interrupted",
          sessionId: sidHex,
          agentName: "alice",
          counterpartyPubkey: h.bobPubkey,
        });
        await wait(50);

        // Bob's own doorbell still names the caller.
        await h.client.send("__test_emit_session_event", {
          type: "created",
          sessionId: sidHex,
          agentName: "bob",
          counterpartyPubkey: h.alicePubkey,
        });
        await wait(50);

        const created = bob.notifications.filter(
          (n) => n.notification === "session_state_changed" && n.data["agentName"] === "bob" && n.data["state"] === "created",
        );
        expect(created.length).toBeGreaterThanOrEqual(1);
        expect(created[created.length - 1].data["who"]).toBe("Ms_Chelly");
        expect(created[created.length - 1].data["whoKnown"]).toBe(false);
      } finally {
        delete process.env["CELLO_ENV"];
      }
    });
  });

  it("AC3: the offered name is NEVER auto-written to the contacts address book", async () => {
    const h = await startHarness();
    const initiator = fixtureIdentity().pubkeyHex;

    h.inject(await assignmentFrame({ initiatorPubkeyHex: initiator, counterpartyPubkeyHex: h.bobPubkey, moniker: "Trusted_Bob" }));
    await wait(120);

    const contacts = (await h.client.send("cello_contact_list", { agent: "bob" })) as {
      ok: boolean; contacts: Array<{ pubkey: string }>;
    };
    expect(contacts.ok).toBe(true);
    expect(contacts.contacts.find((c) => c.pubkey === initiator)).toBeUndefined();
  });
});
