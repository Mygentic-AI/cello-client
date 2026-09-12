/**
 * DOD-M15-AWAYSCOPE-1 units 2+3, client side — attendance leaves this daemon, and comes back in.
 *
 * ── WHAT THIS REPLACES ───────────────────────────────────────────────────────────────────────────
 *
 * An unattended agent used to tell its counterparty so by SENDING ITS GREETING INTO THE CONVERSATION.
 * That greeting took a hash-chain leaf; on session `e7dd3f43…` the seal over that chain could not be
 * certified on either machine and two operators lost a completed conversation's receipt for good.
 *
 * The fact was always worth telling — a counterparty mid-exchange needs to know whether to wait —
 * but it is a fact ABOUT the session, not a sentence IN it. So it travels out of band on the relay's
 * liveness frame, takes no leaf, enters no transcript, and reaches the operator as session STATUS.
 *
 * ── THE THREE TRANSITIONS, AND WHY EACH MATTERS SEPARATELY ──────────────────────────────────────
 *
 * Attendance changes at exactly three moments, and the middle one is the one the whole order is
 * about: an operator's client going away is normally invisible, and it is the state during which
 * the old code did its damage. The third, `offline`, must be distinguishable from it — "nobody is
 * watching, it will be read later" and "deliberately not accepting" are opposite instructions to
 * the far side, which is why there are three values and not two.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { AgentRelayClient, LivenessAnswer } from "../session-relay-client.js";

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

/**
 * A relay client that records what it was told and answers what it is configured to.
 *
 * Stubbed at the RELAY CLIENT rather than at the wire: the wire codec and the relay's own handling
 * of this frame are pinned in their own suites (`protocol-types`' codec tests, and
 * `trustless-cello`'s `dod-m15-awayscope-1-wire` / `m7-session-003`, which drive a real relay over a
 * real stream). What is under test HERE is the daemon's half — whether it announces at the right
 * moments and surfaces what comes back — and a fake relay in this file would only re-prove the
 * other side's code while adding a way for the two to drift.
 */
function makeFakeRelayClient(): {
  client: AgentRelayClient;
  announced: Array<{ attendance: string }>;
  answer: { value: LivenessAnswer | null };
} {
  const announced: Array<{ attendance: string }> = [];
  const answer: { value: LivenessAnswer | null } = { value: null };
  const client = {
    announceAttendance(_node: unknown, _sid: Uint8Array, attendance: string) { announced.push({ attendance }); },
    async queryLiveness(): Promise<LivenessAnswer> {
      return answer.value ?? { liveness: "unknown", observedAt: 0 };
    },
    registerSession() {},
    unregisterSession() {},
    hasSessions() { return true; },
  } as unknown as AgentRelayClient;
  return { client, announced, answer };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("DOD-M15-AWAYSCOPE-1: the daemon announces its own attendance, and never by sending a message", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-attendance-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");
  const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

  async function setup() {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger: noopLogger,
      sessionNodeFactory: new FixedFactory(new FakeNode()),
    };
    const h = await startDaemon(config);
    handle = h;
    const snm = h.getSessionNodeManager();
    snm.setSessionGenesisForTest("alice", SID_HEX, new Uint8Array(32).fill(0x9c));
    await snm.createSessionNode(SID_HEX, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.setSessionContentKeyForTest("alice", SID_HEX, new Uint8Array(32).fill(0x7e));
    const fake = makeFakeRelayClient();
    snm.patchRelayClientForTest("alice", SID_HEX, fake.client, SID_BYTES);
    return { h, snm, fake };
  }

  async function connectAs(agent: string): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: agent });
    return client;
  }

  it("★★ attaching announces 'attended', and sends NOTHING into the session", async () => {
    const { snm, fake } = await setup();
    const treeBefore = snm.getSessionTree("alice", SID_HEX).size();

    await connectAs("alice");
    await wait(50);

    expect(fake.announced.map((a) => a.attendance)).toEqual(["attended"]);
    // THE POINT OF THE WHOLE ORDER, asserted next to the announcement rather than in another file:
    // the fact travelled and the receipt did not change.
    expect(snm.getSessionTree("alice", SID_HEX).size(), "attendance must never take a chain leaf").toBe(treeBefore);
    expect(snm.readTranscript("alice", SID_HEX).messages, "and never a transcript row").toHaveLength(0);
  });

  it("★★ the LAST attendee leaving announces 'unattended' — the state the old code answered from", async () => {
    const { snm, fake } = await setup();
    const client = await connectAs("alice");
    await wait(50);
    fake.announced.length = 0;

    client.close();
    await wait(150);

    expect(fake.announced.map((a) => a.attendance), "the counterparty learns it without being messaged")
      .toEqual(["unattended"]);
    expect(snm.getSessionTree("alice", SID_HEX).size()).toBe(0);
    expect(snm.getSessionRecord("alice", SID_HEX)?.status, "and the session stays open for the return").toBe("active");
  });

  it("★★ a CO-ATTENDED agent losing one client announces nothing — attendance did not change", async () => {
    /**
     * Co-attendance is legitimate and permanent, and this is where a naive "on disconnect, say
     * unattended" would lie: one of two clients closing would tell the counterparty nobody is
     * reading while somebody still is. The count is read AFTER the connection is released, which is
     * what makes the difference visible at all.
     */
    const { fake } = await setup();
    const first = await connectAs("alice");
    await connectAs("alice");
    await wait(50);
    fake.announced.length = 0;

    first.close();
    await wait(150);

    expect(fake.announced, "one of two clients closing is not an absence").toEqual([]);
  });

  it("★★ going OFFLINE announces 'offline', and does it BEFORE the sessions are torn down", async () => {
    /**
     * The ordering is the correctness. `cello_set_agent_offline` destroys every session node for the
     * agent, and the relay client rides on the node — announce afterwards and there is nothing left
     * to announce through, leaving the counterparty on the last thing they heard: 'unattended',
     * which says "it will be read later". That is the opposite of a kill switch.
     */
    const { fake } = await setup();
    const client = await connectAs("alice");
    await wait(50);
    fake.announced.length = 0;

    await client.send("cello_set_agent_offline", { name: "alice" });
    await wait(150);

    expect(fake.announced.map((a) => a.attendance), "'offline' is not 'unattended' — they are opposite instructions")
      .toEqual(["offline"]);
  });

  it("★★ cello_status reports the far side as online-but-unattended, with what the relay observed", async () => {
    const { fake } = await setup();
    const client = await connectAs("alice");
    fake.answer.value = { liveness: "alive", observedAt: 1_700_000_000_000, attendance: "unattended" };

    const res = (await client.send("cello_status", {})) as Record<string, unknown>;
    const active = res["active_sessions"] as Array<Record<string, unknown>>;
    const mine = active.find((s) => s["sessionId"] === SID_HEX);
    expect(mine, "the session must be listed at all").toBeDefined();
    expect(mine!["counterpartyAttendance"], "this is what the operator reads instead of a message").toBe("unattended");
    expect(mine!["relayLiveness"]).toBe("alive");
    expect(mine!["relayObservedAt"], "as of a timestamp — a status with no age is not actionable").toBe(1_700_000_000_000);
  });

  it("★★ cello_list_sessions carries it too, because that is where an agent looks", async () => {
    const { fake } = await setup();
    const client = await connectAs("alice");
    fake.answer.value = { liveness: "alive", observedAt: 1_700_000_000_001, attendance: "unattended" };

    const res = (await client.send("cello_list_sessions", { filter: "all" })) as Record<string, unknown>;
    const sessions = res["sessions"] as Array<Record<string, unknown>>;
    const mine = sessions.find((s) => s["sessionId"] === SID_HEX);
    expect(mine).toBeDefined();
    expect(mine!["counterpartyAttendance"]).toBe("unattended");
    expect(mine!["attendanceObservedAt"]).toBe(1_700_000_000_001);
  });

  it("★★ the daemon-wide listing carries it too — one field, not one per surface", async () => {
    /**
     * `cello sessions` and `cello sessions --all-agents` are two renderings of the same rows, and an
     * operator moves between them. A field on one and not the other teaches the wrong lesson:
     * absent would read as "nobody is attending" rather than "this surface does not ask", which is
     * the opposite of what absence is defined to mean everywhere else in this order.
     */
    const { fake } = await setup();
    const client = await connectAs("alice");
    fake.answer.value = { liveness: "alive", observedAt: 1_700_000_000_002, attendance: "unattended" };

    const res = (await client.send("list_sessions", { filter: "all" })) as Record<string, unknown>;
    const mine = (res["sessions"] as Array<Record<string, unknown>>).find((s) => s["sessionId"] === SID_HEX);
    expect(mine, "the daemon-wide listing must include the session at all").toBeDefined();
    expect(mine!["counterpartyAttendance"]).toBe("unattended");
  });

  it("★★ when the relay knows nothing, the field is ABSENT — never defaulted to a value", async () => {
    /**
     * A default is the failure that matters here. 'attended' would report a person present who is
     * not; 'unattended' would report an absence nobody observed. Absent is the only honest reading
     * of "the relay did not say", and a reader can tell it from a value.
     */
    const { fake } = await setup();
    const client = await connectAs("alice");
    fake.answer.value = { liveness: "unknown", observedAt: 0 };

    const res = (await client.send("cello_status", {})) as Record<string, unknown>;
    const mine = (res["active_sessions"] as Array<Record<string, unknown>>).find((s) => s["sessionId"] === SID_HEX);
    expect(mine!["counterpartyAttendance"]).toBeUndefined();
    expect("counterpartyAttendance" in mine!, "absent means the key is gone, not present-and-undefined").toBe(false);
    expect(mine!["relayLiveness"], "and the relay's own answer is still reported").toBe("unknown");
  });

  it("★★ the two livenesses are reported SEPARATELY — they answer different questions", async () => {
    /**
     * `liveness` is daemon-local: does THIS process hold a libp2p connection for the session.
     * `relayLiveness` is the relay's observation of the counterparty's standing connection, visible
     * even when this daemon has no direct link — which on a relay-mediated session is the normal
     * case. They disagree routinely and legitimately, so collapsing them into one word would make
     * the commoner state read as a fault.
     */
    const { fake } = await setup();
    const client = await connectAs("alice");
    fake.answer.value = { liveness: "alive", observedAt: 1, attendance: "attended" };

    const res = (await client.send("cello_status", {})) as Record<string, unknown>;
    const mine = (res["active_sessions"] as Array<Record<string, unknown>>).find((s) => s["sessionId"] === SID_HEX);
    expect(mine!["liveness"], "this daemon has no direct connection in this fixture").toBe("unknown");
    expect(mine!["relayLiveness"], "and the relay says the far side is right there").toBe("alive");
  });
});
