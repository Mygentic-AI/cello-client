/**
 * THE ENCRYPTION GATE'S REFUSALS REACH THE OPERATOR — the last three silent ones on this path.
 *
 * ─── The failure, from the operator's chair ────────────────────────────────────────────────────
 *
 * A message arrives that this side cannot open — the frame does not say it is encrypted under this
 * session's key, or no key was ever agreed, or it does not decrypt. All three are refused, for good
 * reasons, and all three wrote a full explanation into a log file the operator has no reason to
 * open. From where they sit the message simply never arrived and the conversation went quiet, so
 * they conclude the other person stopped replying.
 *
 * That is the defect `DOD-M15-NO-SILENT-REFUSAL-1` exists to end. It was ended for the refusals
 * BELOW these three on the same path and never for these — found while closing
 * `DOD-M15-AUTHORSHIP-ABSENT-1`, whose refusal sits four checks further down and files its notice
 * correctly.
 *
 * ─── What each test holds ──────────────────────────────────────────────────────────────────────
 *
 * One per cause, because the causes are three different things to tell somebody and a shared
 * sentence would be the `REFUSAL_KINDS` mistake one level down: an unknown scheme is a peer running
 * something that is not CELLO, a missing key is this side's own exchange having failed, and a failed
 * decrypt is either tampering or a key disagreement. Plus the sentence all three now carry, which is
 * the one that stops an operator waiting for a message that already arrived by the other route.
 */

import { describe, it, expect, afterEach } from "vitest";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { wireContentHash } from "../wire-content-hash.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";

const SID = "5d".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const BODY = new TextEncoder().encode("a message this side cannot open");
/** The key `createSession` agrees — the fixture's completed exchange. */
const AGREED = new Uint8Array(32).fill(0x7e);

function frame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "content_frame",
    session_id: SID,
    content_hash: wireContentHash(BODY),
    content_bytes: sealSessionContent(AGREED, BODY),
    content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
    ...fields,
  }) as Uint8Array).subarray();
}

describe("the encryption gate's refusals are HEARD, not just logged", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a frame that does not name this session's scheme is refused INTO THE INBOX", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-encref-scheme-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, frame({ content_encryption: "rot13-v1" }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(
      notice,
      `the operator must be told. Only the log knew:\n${JSON.stringify(fx.eventsNamed("session.content.refused"))}`,
    ).toBeDefined();
    expect(notice!.reason).toBe("content_encryption_absent_or_unknown");
    expect(notice!.guidance, "and it names the move that works — this one is not fixable locally").toMatch(/OUT OF BAND/);
    // The forensic record keeps what the notice must not repeat: the peer's own unbounded string.
    expect(fx.eventsNamed("session.content.refused").at(-1)!.ctx["declared"]).toBe("rot13-v1");
  }, 60_000);

  it("★ an ABSENT scheme is refused the same way — absence is not a pass", async () => {
    /**
     * The exemplar the clause names: `content_encryption` OMITTED, not set to something wrong.
     * Stripping one field is what an attacker does to get a body read in the clear, and it must not
     * be quieter than naming a scheme nobody has heard of.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-encref-absent-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, frame({ content_encryption: undefined }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, "an omitted marker must be as loud as a wrong one").toBeDefined();
    expect(notice!.reason).toBe("content_encryption_absent_or_unknown");
    expect(fx.eventsNamed("session.content.refused").at(-1)!.ctx["declared"]).toBe("(absent)");
  }, 60_000);

  it("★ NO AGREED KEY is refused into the inbox, and blames this side rather than the counterparty", async () => {
    /**
     * The one whose cause is LOCAL. `CONTENT_ENCRYPTION_GUIDANCE` already distinguishes four
     * reasons and two of them say "do not ask them to upgrade" — none of which reached anybody.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-encref-nokey-" });
    // No `createSession` agreement: the session exists and no content key was ever derived.
    await fx.snm.createSessionNode(SID, "alice", "bb".repeat(32), PEER, "corr");

    await fx.snm.handleContentFrameForTest("alice", SID, frame({}), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, "a session that never agreed a key must say so to the person, not the log").toBeDefined();
    expect(notice!.reason).toBe("no_session_key");
    expect(notice!.guidance.length, "the reason-specific guidance is carried, not a generic stub").toBeGreaterThan(40);
  }, 60_000);

  it("★ a body that DOES NOT DECRYPT is refused into the inbox", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-encref-decrypt-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    // Sealed under a key this session never agreed — what a modified frame, or a key disagreement,
    // looks like from here. GCM cannot tell the two apart and this side must not pretend it can.
    const wrongKey = new Uint8Array(32).fill(0x11);
    await fx.snm.handleContentFrameForTest("alice", SID, frame({
      content_bytes: sealSessionContent(wrongKey, BODY),
    }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice).toBeDefined();
    expect(notice!.reason).toBe("decrypt_failed");
    expect(
      notice!.impact,
      "it must not claim to know which of the two it was — that would be branching on the attacker's input",
    ).toMatch(/modified in flight, or it was encrypted under a different key/);
  }, 60_000);

  it("★★ all three tell the operator the message MAY STILL ARRIVE by the other route", async () => {
    /**
     * ⚠️ **THE SENTENCE THAT STOPS SOMEBODY WAITING FOR A MESSAGE THAT ALREADY ARRIVED.**
     *
     * A refusal sends back no delivery acknowledgement, so the sender's backstop parks a copy in the
     * relay mailbox — sealed to the LONG-TERM IDENTITY key, not the session key — and recovery opens
     * that one whatever went wrong here. Every one of these wordings previously said some form of
     * "nothing was stored", which is true of the copy in front of it and reads as a verdict on the
     * message.
     *
     * Asserted across all three causes in one place: a per-cause assertion would let one branch lose
     * the sentence silently, which is how the original three lost their notice.
     */
    const seen: string[] = [];
    for (const [prefix, mutate, agree] of [
      ["scheme", { content_encryption: "rot13-v1" }, true],
      ["nokey", {}, false],
      ["decrypt", { content_bytes: sealSessionContent(new Uint8Array(32).fill(0x11), BODY) }, true],
    ] as Array<[string, Record<string, unknown>, boolean]>) {
      const f = await startTwoConnectionFixture({ dirPrefix: `cello-encref-all-${prefix}-` });
      try {
        if (agree) await f.createSession(SID, "alice", "bb".repeat(32), PEER);
        else await f.snm.createSessionNode(SID, "alice", "bb".repeat(32), PEER, "corr");
        await f.snm.handleContentFrameForTest("alice", SID, frame(mutate), PEER);
        const [n] = f.snm.takeContentRefusals("alice", SID, "op");
        expect(n, `${prefix}: no notice at all`).toBeDefined();
        seen.push(n!.reason);
        expect(n!.guidance, `${prefix}: the operator is left waiting for a message that may have arrived`)
          .toMatch(/MAY STILL REACH YOU BY THE OTHER ROUTE/);
      } finally {
        await f.cleanup();
      }
    }
    // The three are DISTINCT causes, not one sentence wearing three names.
    expect(new Set(seen).size, "three causes, three reasons").toBe(3);
  }, 120_000);
});

describe("the encryption gate still refuses — the notice is an addition, not a substitution", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ nothing is ingested, and the forensic ERROR is still there", async () => {
    /**
     * The regression guard. `LOUD MEANS THE LOG *AND* THE AGENT` — a fix that moved the sentence
     * out of the log and into the notice would satisfy the operator surface and destroy the record
     * every debugging protocol in this project depends on.
     */
    const kp = generateKeypair();
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-encref-both-" });
    await fx.createSession(SID, "alice", Buffer.from(await kp.getPublicKey()).toString("hex"), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, frame({ content_encryption: "rot13-v1" }), PEER);

    const logged = fx.eventsNamed("session.content.refused");
    expect(logged, "the durable forensic record survives").toHaveLength(1);
    expect(logged[0]!.level, "and it is still an ERROR").toBe("error");
    expect(String(logged[0]!.ctx["impact"]).length).toBeGreaterThan(40);
    expect(
      fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received"),
      "and a body nobody could open never becomes a delivered message",
    ).toHaveLength(0);
  }, 60_000);
});
