/**
 * DOD-M15-CLOSEDSESSION-1 — a closed session says so.
 *
 * MEASURED LIVE, 2026-09-10, session `9d253bce…`, and the log ordering is the whole specification:
 *
 * ```
 * session.seal.leaf.submitted        ← Mac_Coder_1 closed
 * session.seal.awaiting_counterparty
 * session.seal.leaf.submitted        ← Miss_Chelly's own half committed
 * session.seal.autoacknowledged
 * session.relay.session.gone
 * session.relay.hash.submit.failed   reason=relay_session_gone
 * session.tree.own_leaf_unwitnessed
 * session.content.sent               ← ok:true, delivered:true, witnessed:false
 * session.content.refused            reason=ack_hash_unknown_content
 * ```
 *
 * Her side had ALREADY committed its half of the seal and her send still went out. It could not be
 * caught by any status check in the daemon, because the status row still read `active` — the seal
 * had not finished writing. The answer she got was true and about the wrong subject: a paragraph on
 * relay witnessing and ordering divergence, when the operative fact is that the conversation was
 * over.
 *
 * WHAT THESE TESTS PIN, and why each is not the same as its neighbour:
 *  1. A CLOSED STATUS refuses. The easy half — a status check would have caught it.
 *  2. A COMMITTED SEAL LEAF on a row that still says `active` refuses. THE MEASURED CASE, and the
 *     one no status check can reach.
 *  3. The refusal happens BEFORE the wire: no leaf, no transcript row, no `delivered`.
 *  4. The guidance is one line and one affordance, and says nothing about relays.
 *  5. A healthy active session is untouched — the gate must not cost an ordinary send.
 *  6. `relay_session_gone` is NOT made terminal by this unit.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as lp from "it-length-prefixed";
import { encodeCbor, encodeStructure1 } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent } from "@cello-protocol/crypto";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { LEAF_KIND_MSG } from "../session-relay-client.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";
import { wireContentHash } from "../wire-content-hash.js";
import { TERMINAL_REFUSAL_REASONS } from "../session-node-types.js";
import { SESSION_CLOSED_REASON } from "../session-closed.js";

const SID = "c1".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const BODY = new TextEncoder().encode("one more thing, after it was over");
/** The key `createSession` agrees for content encryption — the fixture's completed key exchange. */
const CONTENT_KEY = new Uint8Array(32).fill(0x7e);
/** The fixture's real session starting point, so the self-chain check passes and is not what refuses. */
const GENESIS = new Uint8Array(32).fill(0x9c);

/**
 * Write the status ROW directly, deliberately.
 *
 * `updateSessionStatus` on a terminal status also tears the node down, which would make the send
 * fail for a second, unrelated reason — and a test that cannot tell those apart proves nothing
 * about the gate. The row alone is the state the gate reads.
 */
/** A content frame exactly as production writes one — the leaf domain and the encryption included. */
function inboundFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "content_frame",
    leaf_kind: LEAF_KIND_MSG,
    session_id: SID,
    content_hash: wireContentHash(BODY),
    content_bytes: sealSessionContent(CONTENT_KEY, BODY),
    content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
    ...fields,
  }) as Uint8Array).subarray();
}

function setStatus(fx: TwoConnectionFixture, sessionId: string, status: string): void {
  fx.snm.getDb().prepare("UPDATE sessions SET status = ? WHERE session_id = ?").run(status, sessionId);
}

describe("DOD-M15-CLOSEDSESSION-1: a send into a closed session is refused by that name", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-closedsession-" });
  });
  afterEach(async () => { await fx.cleanup(); });

  for (const status of ["sealed", "seal_interrupted_pending", "abandoned"] as const) {
    it(`a '${status}' session refuses the send by name, and places nothing`, async () => {
      await fx.createSession(SID, "alice");
      const conn = await fx.connectAs("alice");
      setStatus(fx, SID, status);
      const leavesBefore = fx.snm.getSessionTree("alice", SID).size();

      const res = (await conn.send("cello_send", { session_id: SID, content: "one more thing" })) as Record<string, unknown>;

      expect(res.ok, JSON.stringify(res)).toBe(false);
      expect(res.reason).toBe(SESSION_CLOSED_REASON);
      // NOT `delivered` in any form. The complaint that opened this unit is a send that reported
      // success into a conversation that had ended.
      expect(res.delivered, "a refused send must not report delivery").toBeUndefined();
      expect(fx.snm.getSessionTree("alice", SID).size(), "nothing may be appended to a signed record")
        .toBe(leavesBefore);
    });
  }

  it("THE MEASURED CASE: this side has committed its seal leaf, the row still says active — refused", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    // Exactly the state the log shows: the seal half is committed and the status write has not
    // happened yet. Every status check in the daemon reads `active` here.
    fx.markSealLeafCommittedForTest("alice", SID);
    expect(fx.snm.getSessionRecord("alice", SID)!.status, "the fixture must reproduce the state that DEFEATED the status checks").toBe("active");
    const leavesBefore = fx.snm.getSessionTree("alice", SID).size();

    const res = (await conn.send("cello_send", { session_id: SID, content: "one more thing" })) as Record<string, unknown>;

    expect(res.ok, JSON.stringify(res)).toBe(false);
    expect(res.reason).toBe(SESSION_CLOSED_REASON);
    expect(res.delivered).toBeUndefined();
    expect(fx.snm.getSessionTree("alice", SID).size(), "the leaf that stranded 9d253bce must not be placed")
      .toBe(leavesBefore);
    // ...and it never reached the relay: the unwitnessed-append path is what produced the wrong
    // answer, so its own ERROR must not fire either.
    expect(fx.eventsNamed("session.tree.own_leaf_unwitnessed"), "the send was refused before the wire")
      .toHaveLength(0);
    expect(fx.eventsNamed("session.content.sent"), "nothing was sent").toHaveLength(0);
  });

  it("the guidance is ONE line and ONE affordance — and says nothing about relays or ordering", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    setStatus(fx, SID, "sealed");

    const res = (await conn.send("cello_send", { session_id: SID, content: "one more thing" })) as Record<string, unknown>;
    const guidance = String(res.guidance);
    // BOTH FIELDS. The shim JSON-stringifies the whole result, so a relay paragraph re-appearing in
    // `impact` reaches the reader exactly as it did before — asserting on `guidance` alone leaves
    // the defect a door.
    const everythingTheReaderSees = `${guidance} ${String(res.impact)}`;

    expect(guidance, "the operator's own sentence: this session is closed, it cannot be added to")
      .toMatch(/closed and cannot be added to/i);
    expect(guidance, "the affordance — the one thing they can actually do").toMatch(/start a new session/i);
    // THE POINT OF THE UNIT. Every one of these was in the answer that prompted it, and every one
    // of them belongs to a DIFFERENT condition that this session is not in.
    for (const wrongSubject of [/relay/i, /witness/i, /diverg/i, /ordering/i, /receipt/i]) {
      expect(everythingTheReaderSees, `the wrong subject leaked back into the answer: ${String(wrongSubject)}`)
        .not.toMatch(wrongSubject);
    }
    // One sentence of fact plus one of remedy. A paragraph is the defect.
    expect(guidance.split(/(?<=\.)\s/).filter((s) => s.trim().length > 0).length).toBeLessThanOrEqual(2);
  });

  it("an ordinary ACTIVE send is untouched by the gate", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    const leavesBefore = fx.snm.getSessionTree("alice", SID).size();

    const res = (await conn.send("cello_send", { session_id: SID, content: "hello" })) as Record<string, unknown>;

    expect(res.ok, `a healthy send must still work: ${JSON.stringify(res)}`).toBe(true);
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(leavesBefore + 1);
  });

  it("WHAT MUST NOT CHANGE: relay_session_gone is not terminal", () => {
    // `delivery-session-suspects.ts` refuses this on evidence — the relay defaults to an in-memory
    // store, so a restart tells every client the same string for sessions that are perfectly alive.
    // This unit keys on THIS SIDE'S OWN state and must not have widened that set on the way past.
    expect([...TERMINAL_REFUSAL_REASONS]).not.toContain("relay_session_gone");
    expect([...TERMINAL_REFUSAL_REASONS]).toContain("session_committed");
  });
});

describe("DOD-M15-CLOSEDSESSION-1: the receiving side says the same thing", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /**
   * ⚠️ **THE REAL STREAM PATH, NOT `ingestReceivedContent` DIRECTLY** — and the distinction is the
   * entire defect.
   *
   * `ingestReceivedContent` has checked the session status since long before this unit: sealed,
   * `seal_interrupted_pending` and `abandoned` are all refused there as `session_committed`, with
   * the exact wording this unit wants. A test that called it would have been green on the broken
   * daemon and proved nothing.
   *
   * The frame path runs the AUTHORSHIP verification first, and that is where 9d253bce was answered:
   * the counterparty acknowledges a hash our sealed record does not hold, so `ack_hash_unknown_content`
   * fires and the status is never consulted. This drives the same door the wire drives.
   */
  async function deliverAfterClose(status: string): Promise<{ reason: string | undefined; received: number }> {
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const structure1 = encodeStructure1({
      contentHash: wireContentHash(BODY),
      senderPubkey,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      // A position and a hash this side does not hold — which is what a message composed after the
      // seal looks like from here, and what produced `ack_hash_unknown_content` live.
      lastSeenSeq: 6,
      timestamp: 1_750_000_000_000,
      lastSeenHash: new Uint8Array(32).fill(0xee),
      prevOwnHash: GENESIS,
    });
    const signature = await kp.sign(structure1);

    fx = await startTwoConnectionFixture({ dirPrefix: "cello-closedsession-in-" });
    await fx.createSession(SID, "alice", Buffer.from(senderPubkey).toString("hex"), PEER);
    setStatus(fx, SID, status);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: structure1,
      sender_signature: signature,
    }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    return {
      reason: notice?.reason,
      received: fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received").length,
    };
  }

  it("content arriving for a SEALED session is refused as closed, not as a hash it did not recognise", async () => {
    const { reason, received } = await deliverAfterClose("sealed");
    // `ack_hash_unknown_content` describes a hash. `session_committed` describes the situation, and
    // its notice already carried the right words — it was simply not what this path returned.
    expect(reason, "the situation, not the hash").toBe("session_committed");
    expect(received, "nothing may enter a signed record").toBe(0);
  }, 60_000);

  it("...and for an ABANDONED one too — the status is what decides, not which one it is", async () => {
    const { reason } = await deliverAfterClose("abandoned");
    expect(reason).toBe("session_committed");
  }, 60_000);

  it("the refused message is RETAINED, in plaintext — the evidence an operator later wants to produce", async () => {
    /**
     * ⚠️ NEW BEHAVIOUR ON THIS PATH, and it was untested. Before this unit a post-seal straggler
     * arriving on the DIRECT stream kept nothing — `sealed_session_annex` covers the park-drain and
     * held-drift routes, not this exit. Two wrong implementations pass every other test in this
     * file: one that refuses without quarantining at all, and one that runs the check a line
     * EARLIER, before the decrypt, and so retains ciphertext nobody can read. Both are caught here
     * and only here.
     */
    await deliverAfterClose("sealed");
    const retained = fx!.snm.readQuarantined("alice", SID);
    expect(retained.length, "something arriving into a signed conversation must be keepable").toBeGreaterThanOrEqual(1);
    // THE PLAINTEXT, not the sealed bytes — which is what pins the check to its position AFTER the
    // decrypt. A pre-decrypt refusal stores the ciphertext and this comparison goes red.
    expect(Buffer.from(retained[0]!.content).equals(Buffer.from(BODY)), "the retained bytes must be the message, not the ciphertext").toBe(true);
    expect(retained[0]!.reason).toBe("session_committed");
  }, 60_000);

  it("the refusal is TERMINAL — the same content is never worked on again", async () => {
    /**
     * The retention call is also what STOPS THE WORK: `quarantineRefusedContent` runs the terminal
     * funnel, and `session_committed` is the one reason in it. Without that the relay's next
     * redelivery re-armed a park fetch that drained, verified, arrived and was refused again —
     * measured at ~2 per second for 62 hours on one message. The direct path reaches that funnel
     * for the first time in this unit, so it is asserted here.
     */
    await deliverAfterClose("sealed");
    const agentId = fx!.snm.getDb().prepare("SELECT agent_id FROM sessions WHERE session_id = ?").get(SID) as { agent_id: string };
    const row = fx!.snm.getDb()
      .prepare("SELECT reason FROM terminal_content_refusals WHERE agent_id = ? AND session_id = ? AND content_hash = ?")
      .get(agentId.agent_id, SID, Buffer.from(wireContentHash(BODY)).toString("hex")) as { reason: string } | undefined;
    expect(row, "a refusal that can never succeed must be marked terminal, or it is retried forever").toBeDefined();
    expect(row!.reason).toBe("session_committed");
  }, 60_000);

  it("the check that WAS firing is still there for a live session — this is a reorder, not a removal", async () => {
    /**
     * ⚠️ THE HALF THAT STOPS THIS BEING A DELETION. Moving the status check in front of authorship
     * would be indistinguishable from switching authorship off if nothing asserted that an ACTIVE
     * session still refuses an acknowledgement of content it has never held. Same frame, same
     * unheld hash, only the session is open.
     */
    const { reason, received } = await deliverAfterClose("active");
    expect(reason, "the acknowledgement check must still refuse on a live session").toBe("ack_hash_unknown_content");
    expect(received).toBe(0);
  }, 60_000);
});
