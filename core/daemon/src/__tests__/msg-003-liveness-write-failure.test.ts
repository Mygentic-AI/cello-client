/**
 * DOD-M12B-ACK-1 (second half) — a session whose writes are failing must stop reporting `alive`.
 *
 * Liveness is derived ONLY from libp2p's peer-connect / peer-disconnect events
 * (`#wireSessionLiveness`), so it answers "is there a connection object?" while every surface
 * that prints it — `cello status`, `cello_status`, `cello_sessions` — is read as "can I talk to
 * them?". When the two diverge, the operator is told the conversation is healthy while nothing
 * leaves the machine.
 *
 * Measured on a live daemon, 2026-08-17 (M12B Entry 10): session `d35eef58a266` reported `alive`
 * for **70 minutes** after every write had started failing, and `de55efd683e8` never stopped —
 * it was still claiming `alive` at the end of the log with 62 failed writes behind it. That is
 * what made the whole defect invisible for a day.
 *
 * `gone` is deliberately NOT reused for this. `gone` means the connection dropped, and it feeds
 * the unilateral-seal gate — so driving it from a transient write failure would let one failed
 * send push a session toward a seal the counterparty never agreed to. `impaired` is a separate
 * state: the connection is up, and delivery on it is not working.
 *
 * Revert test: delete the `#markSessionImpaired` call from `sendContent`'s catch and this fails —
 * liveness stays `alive` through a failed send.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair, msgLeafHash } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgentKeys, wireAgentKeyProviders } from "./helpers/seed-agents.js";
import { agreeSessionGenesis } from "./helpers/session-genesis.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

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

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function pollFor<T>(fn: () => T | null | undefined | false, tries = 200, stepMs = 25): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    const v = fn();
    if (v) return v as T;
    await wait(stepMs);
  }
  return null;
}

describe("DOD-M12B-ACK-1: liveness stops claiming `alive` when writes fail", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg003-"));
    managers.length = 0;
  });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* already down */ } }
    managers.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeManager(): { manager: SessionNodeManager; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `snm-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new RealNodeFactory(), logger, dbPath });
    managers.push(manager);
    return { manager, events };
  }

  const SID = "55".repeat(16);
  /**
   * DOD-M15-AUTHORSHIP-ABSENT-1: THE COUNTERPARTY KEYS ARE THE REAL ONES NOW.
   *
   * They were `"aa".repeat(32)` / `"bb".repeat(32)` — placeholders standing in for identities
   * nothing checked. Every content frame carries the sender's signature over its own Structure 1
   * and the receiver matches the signer against `counterparty_pubkey`; against a placeholder, alice
   * signing with alice's own key is a stranger and her message is refused. Seeded per test, since
   * each builds its own managers with their own agent rows.
   */

  async function liveSession(): Promise<{ A: ReturnType<typeof makeManager>; B: ReturnType<typeof makeManager> }> {
    const A = makeManager();
    const B = makeManager();
    await A.manager.initialize();
    await B.manager.initialize();
    const A_PUB = (await seedAgentKeys(A.manager.getDb(), ["alice"])).get("alice")!.pubkeyHex;
    const B_PUB = (await seedAgentKeys(B.manager.getDb(), ["bob"])).get("bob")!.pubkeyHex;
    // Production always wires the key providers too — without them A cannot sign what it sends.
    await wireAgentKeyProviders(A.manager, A.manager.getDb());
    await wireAgentKeyProviders(B.manager, B.manager.getDb());
    await B.manager.ensureStandingReceiverForAgent("bob");
    const bInfo = B.manager.getStandingReceiverInfo("bob");
    expect(bInfo).not.toBeNull();
    // Both sides agree the session's starting point before either builds its node — see
    // `helpers/session-genesis.ts` for why the order and the sharing are both load-bearing.
    agreeSessionGenesis(SID, [
      { mgr: A.manager, agentName: "alice" },
      { mgr: B.manager, agentName: "bob" },
    ]);
    const created = await A.manager.createSessionNode(SID, "alice", B_PUB, bInfo!.peerId, "corr-A");
    expect(created.ok).toBe(true);
    if (!created.ok) throw new Error("createSessionNode failed");
    expect((await A.manager.connectToCounterparty("alice", SID, bInfo!.addrs)).ok).toBe(true);
    expect((await B.manager.acceptSession(SID, "bob", A_PUB, created.peerId, "corr-B")).ok).toBe(true);
    /**
     * ⚠️ **THE CONTENT KEY IS THE REAL ONE HERE, NOT A SEEDED CONSTANT** —
     * `DOD-M15-AUTHORSHIP-ABSENT-1`.
     *
     * Both ends used to be handed `0x7e…`, because a FakeNode counterparty can never complete the
     * ephemeral key exchange. This file's transport is REAL, and the identity keys wired above were
     * the last thing that exchange was missing — so it completes on its own now, moments after the
     * seed would have been written, and overwrites it on whichever side finishes last. Two ends
     * sealing under different keys is `decrypt_failed` on every message.
     *
     * So the seed is gone and the test waits for the agreement it was standing in for.
     */
    expect(await pollFor(() => A.events.find((e) => e.event === "session.key.agreed")), "A must hold an agreed content key before it can send").not.toBeNull();
    expect(await pollFor(() => B.events.find((e) => e.event === "session.key.agreed")), "and B must hold the same one before it can open the message").not.toBeNull();
    return { A, B };
  }

  async function send(A: ReturnType<typeof makeManager>, text: string): Promise<{ ok: boolean }> {
    const content = new TextEncoder().encode(text);
    return A.manager.sendContent("alice", SID, content, msgLeafHash(content), `corr-${text}`) as Promise<{ ok: boolean }>;
  }

  it("a failed direct send moves liveness off `alive`, and a later success restores it", async () => {
    const { A, B } = await liveSession();

    // Baseline: a real delivery over a real connection — `alive` here is TRUE, and the rest of the
    // test is about the moment it stops being true.
    await send(A, "first");
    expect(await pollFor(() => B.manager.takeReceivedContent("bob", SID))).not.toBeNull();
    expect(A.manager.getSessionLiveness("alice", SID)).toBe("alive");

    // One failed write. The connection is untouched — the fault is injected after newStream — so
    // libp2p fires no disconnect and the old code left liveness saying `alive`.
    A.manager.injectSendFault(1);
    await send(A, "second");
    expect(A.events.find((e) => e.event === "session.content.direct.send.failed")).toBeDefined();
    expect(A.manager.getSessionLiveness("alice", SID)).toBe("impaired");

    // NOT `gone`: `gone` means the connection dropped and it feeds the unilateral-seal gate. A
    // failed write must never be able to push a session toward sealing without the counterparty.
    expect(A.manager.getSessionLiveness("alice", SID)).not.toBe("gone");

    // Recovery is observed, not assumed — an impaired flag that never clears would report a dead
    // conversation for every session that ever had one bad write.
    await send(A, "third");
    expect(await pollFor(() => B.manager.takeReceivedContent("bob", SID))).not.toBeNull();
    expect(A.manager.getSessionLiveness("alice", SID)).toBe("alive");
  }, 60_000);

  it("an UNKNOWN session whose writes fail is impaired too — the lie just moves lanes otherwise", async () => {
    const { A } = await liveSession();
    // A session whose recorded counterparty peer id has gone stale never sees a matching
    // peer-connect, so liveness sits at `unknown` while every send fails forever. cello_receive
    // renders `unknown` as healthy-and-quiet ("do not resend your last message"), so guarding the
    // downgrade on `alive` alone would relocate the 70-minute lie rather than fix it.
    A.manager.markSessionLivenessForTest("alice", SID, "gone");
    A.manager.markSessionLivenessForTest("alice", SID, "alive");
    // Force the true starting state by using a session the connect event never labelled.
    const UNSEEN = "66".repeat(16);
    // A starting point for this one too. It is a solo session — nobody receives from it — but a
    // send with nothing to chain to is REFUSED before it can reach the transport, and this test's
    // subject is what the FAILED TRANSPORT does to liveness. Without it the send would fail one
    // step earlier, for a different reason, and the assertion below would pass by accident.
    agreeSessionGenesis(UNSEEN, [{ mgr: A.manager, agentName: "alice" }]);
    // A counterparty key nobody will ever check: this session has no peer, never connects, and the
    // assertion is about LIVENESS. `B_PUB` is now seeded per test inside `liveSession`, and reaching
    // for it here would tie an unrelated test to that session's identity.
    await A.manager.createSessionNode(UNSEEN, "alice", "bb".repeat(32), "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn", "corr-U");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    A.manager.setSessionContentKeyForTest("alice", UNSEEN, new Uint8Array(32).fill(0x7e));
    expect(A.manager.getSessionLiveness("alice", UNSEEN)).toBe("unknown");

    const content = new TextEncoder().encode("into the void");
    await A.manager.sendContent("alice", UNSEEN, content, msgLeafHash(content), "corr-U");
    expect(A.manager.getSessionLiveness("alice", UNSEEN)).toBe("impaired");
  }, 60_000);

  it("a failed ACK impairs, and a later successful ACK clears it — the listening side must not latch", async () => {
    const { A, B } = await liveSession();

    // B is the LISTENER here: it sends no content, only acknowledgements — which is exactly why
    // the direct-send fault cannot reach it, and why the ACK path needs its own seam.
    B.manager.injectAckFault(1);
    await send(A, "first");
    const impaired = await pollFor(() => B.manager.getSessionLiveness("bob", SID) === "impaired" || null);
    expect(impaired, "a failed delivery ACK must impair the session it was owed on").not.toBeNull();

    // The cause names the ACK, not the caller's own send — B's operator sent nothing at all, so a
    // surface that talks about "your last message" would be describing one they never wrote.
    expect(B.manager.getSessionImpairment("bob", SID)?.cause).toBe("delivery_ack");

    // The next ACK succeeds. If clearing only ever happened on the CONTENT path, a listening agent
    // would report a broken conversation for the rest of the session.
    await send(A, "second");
    const cleared = await pollFor(() => B.manager.getSessionLiveness("bob", SID) === "alive" || null);
    expect(cleared, "a successful ACK must clear the impairment it set").not.toBeNull();
    expect(B.manager.getSessionImpairment("bob", SID)).toBeNull();
  }, 60_000);

  it("`impaired` does not override a counterparty that is genuinely gone (the `gone` guard in #markSessionImpaired)", async () => {
    const { A, B } = await liveSession();
    await send(A, "first");
    expect(await pollFor(() => B.manager.takeReceivedContent("bob", SID))).not.toBeNull();

    // B disappears entirely — the connection drops and liveness is legitimately `gone`.
    await B.manager.gracefulShutdown();
    const gone = await pollFor(() => A.manager.getSessionLiveness("alice", SID) === "gone" || null);
    expect(gone, "liveness never went gone after the counterparty shut down").not.toBeNull();

    // Sends now fail for the real reason. `gone` is the stronger, more actionable statement — the
    // guidance built on it tells the operator no reply can arrive — so a write failure must not
    // downgrade it to `impaired`.
    await send(A, "second");
    expect(A.manager.getSessionLiveness("alice", SID)).toBe("gone");
  }, 60_000);
});
