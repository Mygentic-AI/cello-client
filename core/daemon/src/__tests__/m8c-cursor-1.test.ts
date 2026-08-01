/**
 * CELLO-M8C-CURSOR-1 — per-connection, per-session read cursor (read-before-write gating)
 *
 * M8D-D1: the daemon + two-connections-on-one-agent scaffolding this file used to define inline
 * (FakeNode, FixedFactory, start, connectAs, seedReceived, msgLeafHash) now lives in
 * `helpers/two-connection-fixture.ts`. It was EXTRACTED from here unchanged, because this was the
 * only harness in the repo that could attend one agent from two connections and M8D needs exactly
 * that. Every clause below keeps its original assertions; only the plumbing moved.
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note):
 * - C1: a fresh connection with unread history is refused cello_send with session_not_current +
 *   current_seq + last_read_seq + guidance, BEFORE any transmission attempt.
 * - C2: cello_get_transcript (covers both directions) advances the connection's cursor and
 *   unblocks the send.
 * - C3: a connection's OWN sent message auto-advances its OWN cursor (no self-block).
 * - C4 (the WhatsApp-group-chat model): two connections attending the SAME agent's SAME session —
 *   one sends, the other is blocked until it reads, including a message the FIRST connection
 *   authored (not just counterparty-received content).
 * - C5 (regression lock for the SINCESEQ gap): since_seq is received-only per its own spec, so it
 *   does NOT unblock a connection stuck behind a LOCAL (same-agent) sent message — only
 *   cello_get_transcript does. This proves why the gate's guidance points there.
 * - C6: the cursor is connection-scoped, in-memory — a fresh connection (e.g. after reconnect)
 *   starts over at -1, even though the agent/session already has history.
 * - C7 (reviewer HIGH finding, aa5928e2, fixed): the exact interleaving the original since_seq/
 *   live-drain "advance to max observed" logic got wrong — a LOCAL sent leaf followed by a
 *   counterparty-RECEIVED leaf at a higher sequence. Draining only the received leaf must NOT
 *   silently unblock a send that skips over the unread local-sent leaf.
 * - C8 (reviewer finding, per-session isolation): one connection attending TWO different sessions
 *   on the same agent — advancing the cursor on session A must not affect session B's gating.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

describe("M8C-CURSOR-1: per-connection read cursor", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-cursor-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  /** Seed a RECEIVED message the same way the real inbound-content path does: append the tree
   *  leaf (bumps message_count) AND the readable transcript row, so record.message_count reflects
   *  it exactly like production. */
  const seedReceived = (agent: string, sessionId: string, text: string): number =>
    fx.seedReceived(agent, sessionId, text);

  const SID = "cd".repeat(32);

  it("C1: a fresh connection with unread history is refused session_not_current with current_seq/last_read_seq/guidance", async () => {
    await fx.createSession(SID, "alice");
    seedReceived("alice", SID, "hello from bob"); // message_count → 1, currentSeq → 0

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
    expect(res).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });
    // DOD-ONBOARD-HELP-1 §5: assert the SUBSTANCE, not the spelling. The daemon now renders the
    // remedy for the surface that asked (a CLI caller is told `cello transcript`, an MCP caller
    // `cello_transcript`), so pinning one spelling here would pin the wrong one for half the
    // callers. Both renderings are locked end-to-end in dod-onboard-help-1-vocabulary.test.ts.
    expect(String(res.guidance)).toMatch(/transcript/);
    expect(String(res.guidance)).toMatch(/unread/i);
  });

  it("C2: cello_get_transcript advances the cursor and unblocks the send", async () => {
    await fx.createSession(SID, "alice");
    seedReceived("alice", SID, "hello from bob");

    const client = await fx.connectAs("alice");
    const blocked = (await client.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
    expect(blocked.reason).toBe("session_not_current");

    await client.send("cello_get_transcript", { session_id: SID }); // catches up (max seq 0)

    const res = (await client.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect(typeof res.sequence_number).toBe("number");
  });

  it("C3: sending auto-advances the sender's OWN cursor (no self-block on the next send)", async () => {
    await fx.createSession(SID, "alice");
    // Brand-new empty session: current_seq starts at -1, so the FIRST send needs no catch-up.

    const client = await fx.connectAs("alice");
    const first = (await client.send("cello_send", { session_id: SID, content: "hi" })) as Record<string, unknown>;
    expect(first.ok).toBe(true);

    // A second send from the SAME connection must not be blocked by its own first message.
    const second = (await client.send("cello_send", { session_id: SID, content: "again" })) as Record<string, unknown>;
    expect(second.ok).toBe(true);
  });

  // ─── DOD-CURSOR-DURABLE-1 (2026-07-11, Andre's explicit go) — C4/C5/C6/C7 CHANGE ON PURPOSE ───
  //
  // These four clauses asserted that a connection is blocked by a message THIS AGENT SENT from a
  // DIFFERENT local connection. That is no longer true, and the change is deliberate, not a
  // regression. The gate now passes if EITHER the connection cursor is caught up (unchanged) OR the
  // agent has no unread RECEIVED messages (new, durable, persisted).
  //
  // WHY the old rule had to go: the cursor is in-memory and per-connection. A stateless client — the
  // `cello` CLI, a fresh process per command — always presents cursor -1, so it could never satisfy
  // it. Once the counterparty spoke, EVERY CLI send was refused forever, even though the agent had
  // demonstrably read the message. A bash agent could speak once and then never reply. The same bug
  // silently hit any RECONNECTING MCP client (fresh connectionId → cursor -1).
  //
  // The line the gate now draws, exactly:
  //   • unread COUNTERPARTY content still blocks — fully preserved, and now durable (C1, C2, C8,
  //     and the D-clauses below). This is the guarantee that matters: never reply to something
  //     nobody on your side has seen.
  //   • a message YOUR OWN AGENT sent from another window no longer blocks — RELAXED. The agent
  //     authored it; the daemon cannot referee which of an operator's own windows a human is
  //     looking at, and a socket is not a trust boundary. The principal is the agent.
  //
  // The clauses below are rewritten to lock the NEW boundary — including, explicitly, that the
  // counterparty half did NOT weaken.
  it("C4/C5 (rewritten, DOD-CURSOR-DURABLE-1): a second connection on the same agent is NO LONGER blocked by the first connection's own SENT message — but IS still blocked by unread COUNTERPARTY content", async () => {
    await fx.createSession(SID, "alice");

    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice"); // second attended connection, SAME agent

    const sendA = (await connA.send("cello_send", { session_id: SID, content: "from A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true); // A's own send is never blocked

    // THE DELIBERATE CHANGE: B has read nothing, but the only thing it hasn't seen is a message THIS
    // AGENT sent. There is no unread counterparty content, so B may send. (Old behavior: refused.)
    const bNowAllowed = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(bNowAllowed.ok).toBe(true);

    // THE HALF THAT DID NOT WEAKEN: now the COUNTERPARTY speaks. Nobody on alice's side has read it.
    await fx.ingestReceived("alice", SID, "from bob", "corr-in");

    const refused = (await connB.send("cello_send", { session_id: SID, content: "blind reply" })) as Record<string, unknown>;
    expect(refused).toMatchObject({ ok: false, reason: "session_not_current" });
    expect(refused.unread_received).toBe(1); // the gate names WHY: one unread counterparty message

    // And connA — which also never read bob — is refused too. Unread counterparty content blocks
    // EVERY connection on the agent, exactly as before.
    const refusedA = (await connA.send("cello_send", { session_id: SID, content: "also blind" })) as Record<string, unknown>;
    expect(refusedA).toMatchObject({ ok: false, reason: "session_not_current" });
  });

  it("C6 (rewritten, DOD-CURSOR-DURABLE-1): a fresh connection is no longer blocked by the agent's OWN prior send — this is the stateless-CLI path (a new process per command)", async () => {
    await fx.createSession(SID, "alice");

    const conn1 = await fx.connectAs("alice");
    const sent = (await conn1.send("cello_send", { session_id: SID, content: "hi" })) as Record<string, unknown>;
    expect(sent.ok).toBe(true);
    conn1.close();

    // Exactly what `cello send` does twice in a row: a brand-new connectionId, cursor -1, on a
    // session that already has history. The only unread leaf is this agent's OWN message.
    const conn2 = await fx.connectAs("alice");
    const res = (await conn2.send("cello_send", { session_id: SID, content: "again" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
  });

  it("C7 (reviewer HIGH fix, live reproduction of the reported bypass): draining ONLY a later counterparty-received message must not silently unblock a send that skips an unread local-sent leaf", async () => {
    await fx.createSession(SID, "alice");

    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    // leaf 0: connA sends (a LOCAL sent message connB has not read).
    const sendA = (await connA.send("cello_send", { session_id: SID, content: "from A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true);

    // leaf 1: counterparty content arrives (received), buffered for delivery.
    await fx.ingestReceived("alice", SID, "from counterparty", "corr-inbound");

    // connB drains ONLY the buffered received content (leaf 1) via live cello_receive — it has
    // still never read leaf 0 (connA's sent message).
    const recv = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as Record<string, unknown>;
    expect(recv.content).toBe("from counterparty");
    expect(recv.sequence_number).toBe(1);

    // DOD-CURSOR-DURABLE-1 (rewritten): connB has now READ the counterparty's message (leaf 1), so
    // the durable clause is satisfied — there is no unread received content. The only leaf it has
    // not seen is leaf 0, which THIS AGENT sent. Under the per-agent rule that no longer blocks, so
    // the send is allowed. (Old behavior: refused, because the per-connection cursor was still -1.)
    //
    // The C7 hazard the original clause guarded — "advance to max observed silently marks an
    // earlier leaf read" — is still guarded where it matters: safeCursorAdvance/safeWatermarkAdvance
    // both refuse to vault past a gap, so an unread RECEIVED leaf can never be skipped. That is
    // proved by D3 below (a hole in the transcript keeps the counterparty message unread).
    const nowAllowed = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(nowAllowed.ok).toBe(true);
  });

  // ─── DOD-CURSOR-DURABLE-1 — the new durable clauses ────────────────────────────────────────
  describe("DOD-CURSOR-DURABLE-1: read-before-write survives the connection", () => {
    it("D1 (the fix): a FRESH connection may send once the AGENT has read the counterparty — the stateless-CLI case", async () => {
      await fx.createSession(SID, "alice");
      seedReceived("alice", SID, "hello from bob");

      // Connection 1 = `cello receive`. It reads, advancing the PERSISTED watermark, then exits.
      const reader = await fx.connectAs("alice");
      const got = (await reader.send("cello_receive", { session_id: SID, since_seq: -1 })) as Record<string, unknown>;
      expect(got.count).toBe(1);
      reader.close();

      // Connection 2 = `cello send`, a brand-new process. Its cursor is -1 and always will be.
      // Before this fix it was refused forever; now the agent's durable read unblocks it.
      const sender = await fx.connectAs("alice");
      const res = (await sender.send("cello_send", { session_id: SID, content: "reply from bash" })) as Record<string, unknown>;
      expect(res.ok).toBe(true);
    });

    it("D2 (the guarantee HOLDS): unread counterparty content still refuses a fresh connection — the fix is not a bypass", async () => {
      await fx.createSession(SID, "alice");
      seedReceived("alice", SID, "hello from bob"); // NOBODY reads it

      const sender = await fx.connectAs("alice");
      const res = (await sender.send("cello_send", { session_id: SID, content: "blind reply" })) as Record<string, unknown>;
      expect(res).toMatchObject({ ok: false, reason: "session_not_current", unread_received: 1 });

      // ...and it stays refused across a reconnect. The block is durable, not an artifact of one socket.
      sender.close();
      const sender2 = await fx.connectAs("alice");
      const again = (await sender2.send("cello_send", { session_id: SID, content: "still blind" })) as Record<string, unknown>;
      expect(again).toMatchObject({ ok: false, reason: "session_not_current" });
    });

    it("D3 (AC3 + hole safety): cello_get_transcript advances the PERSISTED watermark, and a gap in the transcript keeps later messages unread", async () => {
      await fx.createSession(SID, "alice");

      // Attend FIRST (as C8 does): seeding while unattended trips M8C-AWAY-1's auto-ack, which
      // appends its own SENT leaf and muddies the exact sequence numbers this clause is about.
      const attendant = await fx.connectAs("alice");

      seedReceived("alice", SID, "bob 1"); // received leaf 0
      expect(fx.snm.getLastDeliveredSeq("alice", SID)).toBe(-1); // nothing read yet

      // A fresh connection reads the TRANSCRIPT (not cello_receive) — the remedy the gate's guidance
      // names. Before AC3 this advanced only the dying connection cursor, so the next process was
      // still blocked and the documented remedy was a dead end for any stateless client.
      const reader = await fx.connectAs("alice");
      await reader.send("cello_get_transcript", { session_id: SID });
      reader.close();
      expect(fx.snm.getLastDeliveredSeq("alice", SID)).toBe(0); // PERSISTED — survives the socket
      expect(fx.snm.getUnreadReceivedCount("alice", SID)).toBe(0);

      const sender = await fx.connectAs("alice");
      const res = (await sender.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
      expect(res.ok).toBe(true); // sent leaf (seq 2 after the reply)

      // Hole safety: append a leaf with NO transcript row (the shape an undecryptable/failed write
      // leaves), then a real received message BEYOND it. The contiguous walk must stop at the gap,
      // so the later counterparty message can never be silently marked read.
      fx.snm.appendSessionLeaf("alice", SID, "msg", "bb".repeat(32), "hole"); // no transcript row
      const bob2Seq = seedReceived("alice", SID, "bob 2 (beyond the hole)");

      const reader2 = await fx.connectAs("alice");
      await reader2.send("cello_get_transcript", { session_id: SID });
      // The walk may advance THROUGH rows it actually saw (the reply it sent), but it must STOP at
      // the hole — so the watermark never reaches bob 2, and bob 2 stays unread. That is the whole
      // point: a message the agent has not seen cannot be marked read by a gap.
      expect(fx.snm.getLastDeliveredSeq("alice", SID)).toBeLessThan(bob2Seq);
      expect(fx.snm.getUnreadReceivedCount("alice", SID)).toBeGreaterThan(0); // "bob 2" still unread

      // ...and because it is still unread, the gate still refuses the send. Hole safety is not
      // cosmetic — it is what stops the fix becoming a bypass.
      const refused = (await reader2.send("cello_send", { session_id: SID, content: "blind" })) as Record<string, unknown>;
      expect(refused).toMatchObject({ ok: false, reason: "session_not_current" });
      attendant.close();
    });

    it("D4 (the safety property): the long-lived single-connection path is UNCHANGED — read-then-send behaves exactly as before", async () => {
      await fx.createSession(SID, "alice");
      seedReceived("alice", SID, "hello from bob");

      // This is the MCP shim's shape: ONE socket for the whole session. It is refused before reading
      // and allowed after — identical to pre-fix behavior, satisfied by the connection-cursor clause.
      const mcp = await fx.connectAs("alice");
      const blocked = (await mcp.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
      expect(blocked).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });

      await mcp.send("cello_get_transcript", { session_id: SID });
      const ok = (await mcp.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
      expect(ok.ok).toBe(true);
    });
  });

  it("C8 (reviewer finding, per-session isolation): one connection attending two different sessions — advancing one's cursor must not unblock the other", async () => {
    const SID_A = "aa".repeat(32);
    const SID_B = "bb".repeat(32);
    await fx.createSession(SID_A, "alice", "bobpubkeyhex", "bob-peer-id-a");
    await fx.createSession(SID_B, "alice", "carolpubkeyhex", "carol-peer-id-b");

    // Attend FIRST (M8C-AWAY-1 is now live in this daemon too — seeding while unattended would
    // trigger its own auto-ack, adding an extra leaf this CURSOR-only test isn't about).
    const client = await fx.connectAs("alice");

    // Seed unread history on BOTH sessions.
    await fx.ingestReceived("alice", SID_A, "on A", "corr-a");
    await fx.ingestReceived("alice", SID_B, "on B", "corr-b");

    // Catch up ONLY on session A.
    await client.send("cello_get_transcript", { session_id: SID_A });

    const sendA = (await client.send("cello_send", { session_id: SID_A, content: "reply A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true); // A is caught up

    // A hollow Map<connectionId, number> (dropping the per-session dimension) would let this
    // through too, since it never read B's history — must still be refused.
    const sendB = (await client.send("cello_send", { session_id: SID_B, content: "reply B" })) as Record<string, unknown>;
    expect(sendB).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });
  });

  // The read-before-write gate FAILS CLOSED when it cannot count.
  //
  // getUnreadReceivedCount answers one question for the send gate: "is there counterparty content
  // this agent has not read?" A 0 means "caught up" and UNBLOCKS a send. So every path that cannot
  // actually answer must return a POSITIVE count, never 0 — a 0 guessed from a broken DB silently
  // defeats the gate, which is the one thing the gate exists to prevent.
  //
  // SCOPE — read this before trusting it as coverage. This pins ONLY the reachable branch (a closed
  // DB). The other absent-input branch (the query returning no row) is UNREACHABLE — SELECT COUNT(*)
  // with no GROUP BY always yields exactly one row — so it cannot be driven without inventing a DB
  // seam that exists only for the test. That branch was still corrected (a fail-OPEN default inside a
  // gate documented as FAILS CLOSED is a defect whether or not today's SQL spares us), but this test
  // does NOT cover it: revert that line and this still passes. It guards the branch beside it.
  it("a closed DB refuses the send — the gate never guesses 'caught up' (reachable branch only)", async () => {
    await fx.createSession(SID, "alice");

    await fx.ingestReceived("alice", SID, "unread counterparty content", "corr-inbound");
    expect(fx.snm.getUnreadReceivedCount("alice", SID)).toBeGreaterThan(0);

    // Tear the DB out from under the gate. It can no longer count anything.
    await fx.snm.gracefulShutdown();

    // It must STILL refuse — "I don't know" is not "you're caught up".
    expect(fx.snm.getUnreadReceivedCount("alice", SID)).toBeGreaterThan(0);
  });

  // An unwitnessed append is announced ONLY when a witness was expected.
  //
  // The relay witness is an independent attestation — a (content_hash → sequence) binding derived
  // from the sender's own signed leaf. With it, received content is checked against a hash the sender
  // committed to a third party; without it, the only hash available rode in the same frame as the
  // content, so the check is the sender's claim against the sender's claim.
  //
  // Unwitnessed content is still INGESTED: refusing it would make the relay a precondition for
  // reading mail, and a relay outage would render the inbox unreadable.
  //
  // But a session with NO relay attached has no witness BY DESIGN. Warning there would fire on every
  // message of a normal no-relay session and bury the one case that means something. A signal that
  // fires on the normal case is not a signal.
  it("a no-relay session does NOT warn — the signal must not fire on a designed benign state", async () => {
    // createSessionNode attaches NO relay client — the no-relay session, exactly as designed.
    await fx.createSession(SID, "alice");

    const res = await fx.ingestReceived("alice", SID, "no relay on this session", "corr-norelay") as { ok: boolean };
    expect(res.ok).toBe(true); // ingested, not refused — availability is preserved

    // Teeth: drop the "was a witness expected?" guard and this fires, once per message, forever.
    expect(
      fx.eventsNamed("session.content.unwitnessed").filter((e) => e.level === "warn"),
      "a session with no relay must not warn about a witness it was never going to get",
    ).toHaveLength(0);
  });

  // NOT COVERED HERE, deliberately: the case the warn EXISTS for — a relay IS attached, so the
  // sender's leaf should have been submitted and witnessed, and it was not. Reaching it means
  // attaching a live relay client to the session (#activeNodes is private, and a seam added purely
  // to fake one would test the seam). It belongs in the live spine, against a real relay.

});

