/**
 * DOD-COATTEND-VISIBLE-1 AC6 — a session can learn it is not alone WITHOUT having seen a doorbell.
 *
 * THE FINDING, from the live two-session journey (journal Entry 33). Asked an open question with no
 * mention of co-attendance, the second real session answered:
 *
 *   "Co-attendance did not come up on its own… Structurally, the transcript and the wire protocol
 *    are silent on it."
 *
 * It was right, and "not visible" is too coarse a description of why. Attendance IS carried on the
 * PUSH — the doorbell text says "N sessions are attending this agent" and the tag carries
 * `attendance` — and on `cello_status`. Every READ surface is silent: `cello_receive` and
 * `cello_get_transcript` return no attendance at all.
 *
 * So the sessions that cannot learn they are co-attended are exactly the ones that never saw a
 * doorbell: a freshly connected MCP client, EVERY `cello` CLI invocation (a new connection per
 * command), and any session that attached after the last message arrived. Those are not edge cases —
 * the CLI is the whole stateless-client story, and a reconnecting shim is the normal state.
 *
 * The daemon already computes the number for the push. This is a read-surface change, not a new
 * mechanism, which is why it is one unit and not a design.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "3d".repeat(32);

describe("DOD-COATTEND-VISIBLE-1 AC6: the READ surfaces say whether this session is alone", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-ac6-", agents: ["alice", "bob"] });
  });
  afterEach(async () => { await fx.cleanup(); });

  it("V1: cello_receive reports attendance — a delivered message says how many sessions hold this agent", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "from bob");

    const got = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(got.content).toBe("from bob");
    expect(got.attendance, "the read surface must carry what the push already carries").toBe(2);
    void connB;
  });

  it("V2: cello_receive reports it on the EMPTY answer too — the case a lone reader is most likely to hit", async () => {
    // A session that attaches and finds nothing waiting is precisely the one with no doorbell to
    // have learned from. If attendance only rode on delivered content, the gap this AC names would
    // survive in the shape most likely to produce it.
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    const quiet = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 300 })) as Record<string, unknown>;
    expect(quiet.content).toBeNull();
    expect(quiet.attendance, "an empty read must still say whether you are alone").toBe(2);
    void connB;
  });

  it("V3: cello_get_transcript reports attendance — the surface the live session called 'silent'", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");
    fx.seedReceived("alice", SID, "history");

    const tr = (await connA.send("cello_get_transcript", { session_id: SID })) as Record<string, unknown>;
    expect(tr.ok).toBe(true);
    expect(tr.attendance, "the transcript is where a caught-up session looks — it must say too").toBe(2);
    void connB;
  });

  it("V4: a SOLE session reports 1 — the field must distinguish alone from co-attended", async () => {
    // Asserting only the co-attended case would pass on an implementation that hardcodes a number
    // or reports the agent's total sessions regardless. `1` is the answer that makes the field mean
    // something, and it is what an operator reading a quiet session needs to see.
    await fx.createSession(SID, "alice");
    const only = await fx.connectAs("alice");

    const quiet = (await only.send("cello_receive", { session_id: SID, timeout_ms: 300 })) as Record<string, unknown>;
    expect(quiet.attendance, "one attending session must read as 1, not as absent or 2").toBe(1);

    const tr = (await only.send("cello_get_transcript", { session_id: SID })) as Record<string, unknown>;
    expect(tr.attendance).toBe(1);
  });

  it("V5: it TRACKS — a sibling detaching drops the number back", async () => {
    // The count is only trustworthy if it falls as well as rises. A field that never decreases would
    // tell a session it is co-attended long after it is alone, which is the same defect inverted:
    // the operator stops believing the number.
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    expect(((await connA.send("cello_receive", { session_id: SID, timeout_ms: 200 })) as Record<string, unknown>).attendance).toBe(2);

    connB.close();
    await new Promise((r) => setTimeout(r, 200));

    expect(
      ((await connA.send("cello_receive", { session_id: SID, timeout_ms: 200 })) as Record<string, unknown>).attendance,
      "after the sibling goes, this session is alone again and must be told so",
    ).toBe(1);
  });

  it("V6 (review F1): the since_seq CATCH-UP exit carries it — the stateless door the AC exists for", async () => {
    // `cello receive <id> --since-seq -1` is the away-then-return door, and it is a FRESH
    // connection every time, so it never saw a doorbell. The `session_not_live` refusal points
    // callers here BY NAME. Shipping attendance on the live exits and not this one leaves the
    // defect alive in the exact shape the unit's own rationale invokes.
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");
    fx.seedReceived("alice", SID, "history");

    const batch = (await connA.send("cello_receive", { session_id: SID, since_seq: -1 })) as Record<string, unknown>;
    expect(batch.ok).toBe(true);
    expect(batch.attendance, "the catch-up batch must say whether you are alone").toBe(2);
    void connB;
  });

  it("V8 (review F3): the count is AGENT-SCOPED — a window on a DIFFERENT agent is not co-attendance", async () => {
    // THE HOLLOWNESS THE REVIEW PROVED. Replace the predicate in countAttendance with "count every
    // connection" and V1-V5 stay green, as does the whole daemon package — nothing anywhere pinned
    // the field's actual semantic. On the first-wedge setup (one window per agent, which is how
    // this product is used daily) that implementation tells BOTH windows they are co-attended by a
    // session that is attending something else entirely.
    await fx.createSession(SID, "alice");
    const onAlice = await fx.connectAs("alice");
    const onBob = await fx.connectAs("bob"); // a sibling window on a DIFFERENT agent

    const r = (await onAlice.send("cello_receive", { session_id: SID, timeout_ms: 300 })) as Record<string, unknown>;
    expect(r.attendance, "a window attending bob does not make alice co-attended").toBe(1);
    void onBob;
  });
});

/**
 * V7 needs its own fixture: the sole-online fallback only fires when there IS exactly one online
 * agent, so a two-agent fixture cannot reach the path under test — it returns "no current agent"
 * instead, which is a different (and correct) refusal.
 */
describe("AC6 review F2: a reader that never selected the agent", () => {
  let fx: TwoConnectionFixture;
  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-ac6-solo-" });
  });
  afterEach(async () => { await fx.cleanup(); });

  it("V7 (review F2): a connection that never selected the agent still reads a TRUTHFUL count, never 0", async () => {
    // `resolveCurrentAgent` falls back to the sole online agent, so a connection can read an
    // agent's data with `currentAgent === null` — every `cello` CLI invocation with no persisted
    // selection, and any MCP client that skipped cello_use_agent. The count walked only explicitly
    // attending connections, so such a reader was told ZERO sessions attend the agent it is
    // reading. That is worse than the absent field this unit set out to fix: not missing, but a
    // definite negative that is false. A response the caller is holding can never honestly say 0.
    await fx.createSession(SID, "alice");

    // Bring alice ONLINE and then leave with nobody attending — the daemon keeps an agent running
    // after the connection that started it goes away. That is the CLI's ordinary state: the daemon
    // starts persisted agents at boot and every `cello` command is a fresh connection that never
    // attends. So the agent is online with an attendance of ZERO.
    const starter = await fx.connectAs("alice");
    starter.close();
    await new Promise((r) => setTimeout(r, 200));

    // A fresh connection reads. `resolveCurrentAgent` falls back to the sole online agent, so this
    // succeeds — and the count walked only explicitly attending connections, so it answered 0.
    const unattached = await fx.connect(); // NO cello_use_agent
    const quiet = (await unattached.send("cello_receive", { session_id: SID, timeout_ms: 300 })) as Record<string, unknown>;
    expect(quiet.ok, "the sole-online fallback lets this read succeed").toBe(true);
    expect(quiet.attendance, "the reader itself attends — 0 is never a truthful answer here").toBe(1);
  });
});
